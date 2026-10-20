package a2aproxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// A2A 内容安全接入（P2-2 T-4）。
//
// 冻结契约（设计 doc §T-4 + 冻结清单 R-1 L3 + 事件 schema a2a_content_action）：
//
//   - 层界：内容检查是**独立层 L3**（R-1），仅本层可读 parts（可信域明文轨）；
//     不把正文写入治理判定、不落正文（R-2）；产出动作/档位元数据。
//   - 适配：解析 A2A Part（Text/File/Data/URL 形态）映射到既有检查管线（档位体系复用
//     output-guard/qwen3guard；执行点＝网关侧检查组件或独立服务，归集成接线）。
//   - 动作：拒绝（deny，阻断响应）/ 脱敏（redact，改写 parts）/ 放行（allow）；
//     审计留痕 a2a_content_action（元数据级，不落正文）。
//   - 约束：R-1（密态不触碰）；不新选分类器；MVP 无 SSE，逐事件检查不做。
//   - 不做：密态内容检查（预留）；分类器选型（复用资产）。
//
// 本文件只提供 A2A 数据面的**适配层**：Part 解析、决策模型、默认实现与审计事件；
// 真正的档位/分类逻辑由 ContentSafety 接口的实现者（集成期接 output-guard 服务）提供，
// 与 Governance.Observer 的接线模式对称。

// PartKind 是 A2A Part 的形态枚举（规范 v1.0）。
type PartKind string

const (
	// PartKindText 文本 Part（content_safety 主检对象）。
	PartKindText PartKind = "text"
	// PartKindFile 文件 Part（name/mimeType/uri/bytes 元数据级检查）。
	PartKindFile PartKind = "file"
	// PartKindData 结构化数据 Part（mimeType + 原始 JSON）。
	PartKindData PartKind = "data"
)

// Part 是 A2A message/result 中一个 Part 的归一化视图（只读抽取，不持正文副本外必要字段）。
//
// 仅抽取安全检查所需字段；不保留任意未知大字段（R-2）。
type Part struct {
	Kind     PartKind        `json:"kind"`
	Text     string          `json:"text,omitempty"`     // TextPart
	MimeType string          `json:"mimeType,omitempty"` // File/Data Part
	File     PartFile        `json:"file,omitempty"`     // FilePart
	Data     json.RawMessage `json:"data,omitempty"`     // DataPart（原始 JSON，不解析正文）
}

// PartFile 是 FilePart 的元数据视图（bytes 为 base64 解码后的内容，供检查；不落盘）。
type PartFile struct {
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	URI      string `json:"uri,omitempty"`
	Bytes    []byte `json:"-"`
}

// extractParts 从 A2A 请求/响应 JSON 中抽取所有 parts 数组内的 Part（message/result/artifact 各级）。
//
// 解析失败或 parts 缺失时返回空切片与 nil（内容安全层对不可解析正文不阻断协议）。
func extractParts(raw []byte) ([]Part, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var top any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return nil, fmt.Errorf("a2aproxy: 解析 parts 失败: %w", err)
	}
	var out []Part
	walkParts(top, &out)
	return out, nil
}

// walkParts 递归收集任意 "parts" 数组中的 Part。
func walkParts(v any, out *[]Part) {
	switch x := v.(type) {
	case map[string]any:
		if arr, ok := x["parts"]; ok {
			if parts, ok := arr.([]any); ok {
				for _, p := range parts {
					if part, ok := parsePart(p); ok {
						*out = append(*out, part)
					}
				}
			}
		}
		for _, val := range x {
			walkParts(val, out)
		}
	case []any:
		for _, item := range x {
			walkParts(item, out)
		}
	}
}

// parsePart 将一个 Part JSON 对象归一化为 Part（失败返回 ok=false）。
//
// kind 缺失时的**兜底推断**（T-7 验收发现）：A2A v1.0 以 `kind` 作为判别字段，但实测
// 载荷（含本仓测试夹具与 testagent 回显的 history）存在不带 `kind` 的 Part。若仅按
// `kind` 严格判别，这类 Part 会被静默丢弃——对内容检查而言是**漏检**（安全相关）。
// 因此 kind 缺失时按 `text`/`file`/`data` 字段存在性推断；三者皆无则仍丢弃。
func parsePart(v any) (Part, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return Part{}, false
	}
	kind, _ := m["kind"].(string)
	if kind == "" {
		switch {
		case hasKey(m, "text"):
			kind = string(PartKindText)
		case hasKey(m, "file"):
			kind = string(PartKindFile)
		case hasKey(m, "data"):
			kind = string(PartKindData)
		}
	}
	switch PartKind(kind) {
	case PartKindText:
		text, _ := m["text"].(string)
		return Part{Kind: PartKindText, Text: text}, true
	case PartKindFile:
		p := Part{Kind: PartKindFile}
		if f, ok := m["file"].(map[string]any); ok {
			p.File.Name, _ = f["name"].(string)
			p.File.MimeType, _ = f["mimeType"].(string)
			p.File.URI, _ = f["uri"].(string)
			if b, ok := f["bytes"].(string); ok && b != "" {
				if dec, err := base64.StdEncoding.DecodeString(b); err == nil {
					p.File.Bytes = dec
				}
			}
		}
		return p, true
	case PartKindData:
		mt, _ := m["mimeType"].(string)
		if raw, err := json.Marshal(m["data"]); err == nil {
			return Part{Kind: PartKindData, MimeType: mt, Data: raw}, true
		}
		return Part{Kind: PartKindData, MimeType: mt}, true
	default:
		return Part{}, false
	}
}

// hasKey 判断 map 中是否存在该键（值可为 null，仍视为存在）。
func hasKey(m map[string]any, k string) bool {
	_, ok := m[k]
	return ok
}

// ContentAction 是内容检查的动作枚举。
type ContentAction string

const (
	// ContentActionAllow 放行（不改动、不审计）。
	ContentActionAllow ContentAction = "allow"
	// ContentActionDeny 拒绝（阻断响应，回 JSON-RPC content_blocked）。
	ContentActionDeny ContentAction = "deny"
	// ContentActionRedact 脱敏（改写响应 parts 为 [REDACTED]）。
	ContentActionRedact ContentAction = "redact"
)

// ContentCheckRequest 是交给 ContentSafety 的检查请求（元数据 + 抽取出的 parts）。
type ContentCheckRequest struct {
	Tenant     string
	Agent      string
	Skill      string
	Method     string
	IsResponse bool // true=模型输出（响应），false=用户输入（请求）
	Parts      []Part
}

// ContentCheckDecision 是检查决策（档位由实现者填充，复用 output-guard 档位体系）。
type ContentCheckDecision struct {
	Action ContentAction
	// Tier 是命中的策略档位/等级（如 output-guard 的 mode/policy 标识）；
	// 仅作审计归因，不参与协议判定。
	Tier string
	// Reason 是命中说明（类目/关键词，不含正文）。
	Reason string
}

// ContentSafety 是内容检查层（L3）的接口。其实现者对接既有检查管线
// （档位体系复用 output-guard/qwen3guard；本包不内置分类器）。
type ContentSafety interface {
	Check(ctx context.Context, req ContentCheckRequest) (ContentCheckDecision, error)
}

// DenyAllContentSafety 是 fail-closed 默认：任何检查都拒绝（用于“配置了但检查器不可用”的严苛档位）。
type DenyAllContentSafety struct{}

// Check 始终拒绝（无检查器可用时按 fail-closed 处置内容）。
func (DenyAllContentSafety) Check(_ context.Context, _ ContentCheckRequest) (ContentCheckDecision, error) {
	return ContentCheckDecision{Action: ContentActionDeny, Reason: "no_content_safety_configured"}, nil
}

// StaticContentSafety 将检查委托给一个函数（集成期接 output-guard 服务/独立服务）。
type StaticContentSafety struct {
	Checker func(ctx context.Context, req ContentCheckRequest) (ContentCheckDecision, error)
}

// Check 委托给 Checker；Checker 为空时放行（与 Governance.Observer 对称：未接线则不介入）。
func (s StaticContentSafety) Check(ctx context.Context, req ContentCheckRequest) (ContentCheckDecision, error) {
	if s.Checker == nil {
		return ContentCheckDecision{Action: ContentActionAllow}, nil
	}
	return s.Checker(ctx, req)
}

// ContentActionEvent 是 a2a_content_action 审计事件（元数据级，R-2 不落正文）。
type ContentActionEvent struct {
	EventID   string `json:"event_id"`
	Timestamp string `json:"timestamp"` // RFC3339Nano
	RequestID string `json:"request_id,omitempty"`
	TraceID   string `json:"trace_id,omitempty"`
	Tenant    string `json:"tenant"`
	Agent     string `json:"agent"`
	Skill     string `json:"skill"`
	Method    string `json:"method"`
	Tier      string `json:"tier,omitempty"` // 命中档位（output-guard 档位体系）
	Action    string `json:"action"`         // deny | redact | error
	Result    string `json:"result"`         // blocked | redacted | error
	ErrorCode string `json:"error_code,omitempty"`
}

// redactParts 返回一个将所有 "parts" 数组替换为单一 [REDACTED] 文本 Part 的新 JSON。
//
// 采用泛型结构解码→改写→重编码：对未命中 parts 的字段逐字节保留语义（重编码可能调整
// key 顺序/数字格式，响应正文不被签名，MVP 可接受）。返回 nil 表示无需改写/解析失败。
func redactParts(raw []byte) []byte {
	var top any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&top); err != nil {
		return nil
	}
	redacted := json.RawMessage(`[{"kind":"text","text":"[REDACTED]"}]`)
	rewriteParts(top, redacted)
	out, err := json.Marshal(top)
	if err != nil {
		return nil
	}
	return out
}

// rewriteParts 递归将所有 "parts" 数组替换为 redacted（json.RawMessage 实现 Marshaler，直接赋值即可）。
func rewriteParts(v any, redacted json.RawMessage) {
	switch x := v.(type) {
	case map[string]any:
		if _, ok := x["parts"]; ok {
			x["parts"] = redacted
		}
		for _, val := range x {
			rewriteParts(val, redacted)
		}
	case []any:
		for _, item := range x {
			rewriteParts(item, redacted)
		}
	}
}
