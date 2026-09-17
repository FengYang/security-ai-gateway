package main

// 段① 信封客户端（P1b）：SSE 分块解密与流式重组。
//
// tee-infer 流式响应（tee_gpu 引擎，P2 接线）经 K_enc 逐块加密回传：
//
//	Content-Type: text/event-stream
//	data: <hex(s2c 信封)>        （外层：全局 s2c 计数器 → nonce 唯一 + 反重放窗口）
//	data: <hex(s2c 信封)>
//	...
//
// 信封内明文为流分片 JSON（内层）：
//
//	{"seq":1,"delta":"Hello","finish":""}
//	{"seq":2,"delta":" world","finish":"stop"}
//
// seq 为流内严格递增序号（1 起，跳号/回退/重复即拒绝），防止流内容被重排。
// 双层设计原因：外层计数器全局唯一（GCM nonce 安全），内层 seq 绑定流位置
// （并发流交错时仍可严格校验单流顺序）。
//
// 插件解密后重组为客户端标准 OpenAI SSE：data: choices[].delta.content 分片 + data: [DONE]。

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"security-ai-gateway/protocol/go"
)

// streamChunk SSE 信封内明文分片。
type streamChunk struct {
	Seq    uint64      `json:"seq"`              // 流内序号（1 起严格递增）
	Delta  string      `json:"delta"`            // 增量文本
	Finish string      `json:"finish,omitempty"` // 终止标记（""=继续，"stop"=正常结束，"content_filter"=内容安全终止）
	Guard  *chunkGuard `json:"guard,omitempty"`  // 输出侧内容审查注解（可选；通常仅终止帧携带，OG-16 透传客户端）
}

// chunkGuard 输出侧内容审查 chunk-meta（与 tee-infer chunkGuardMeta 同构，§4.6.1）。
// 字段一律按 wire 原样透传，插件不补充、不改写；红线：不含命中词/原文/正则，category 仅内部类目 ID。
type chunkGuard struct {
	Detected      bool   `json:"detected"`               // 本请求至少一次命中（含 shadow 命中）
	Filtered      bool   `json:"filtered"`               // 实际拦截/遮蔽（enforcing 下 block/mask）
	Action        string `json:"action,omitempty"`       // block | mask | flag
	Category      string `json:"category,omitempty"`     // 内部类目 ID（A1-06 等）
	PolicyVersion string `json:"policy_version"`         // 聚合策略版本
	RuleVersion   string `json:"rule_version,omitempty"` // 命中条目所在词库版本
	Mode          string `json:"mode"`                   // shadow | enforcing
}

// sseDelta OpenAI 流式 delta 载荷（choices[].delta）。
type sseDelta struct {
	Content string `json:"content,omitempty"`
}

// sseChoice OpenAI 流式 choice（正常 chunk 带 content；finish chunk 带 finish_reason）。
type sseChoice struct {
	Index        int      `json:"index"`
	Delta        sseDelta `json:"delta,omitempty"`
	FinishReason string   `json:"finish_reason,omitempty"`
}

// sseChunk 客户端标准 OpenAI Chat Completions SSE 单块。
type sseChunk struct {
	ID      string      `json:"id"`
	Object  string      `json:"object"`
	Created int64       `json:"created"`
	Model   string      `json:"model"`
	Choices []sseChoice `json:"choices"`
	Guard   *chunkGuard `json:"guard,omitempty"` // OG-16：审核注解自定义扩展字段；标准客户端忽略未知键
}

// sseStreamDecryptor 单条 SSE 流的解密状态（请求级，onResponseBody 内创建）。
type sseStreamDecryptor struct {
	lastSeq uint64 // 已见最大流内序号（严格递增校验）
}

// decryptSSEChunk 解密单个 SSE 分片：外层信封（K_enc + 反重放窗口）→ 内层 seq 严格递增。
func (d *sseStreamDecryptor) decryptSSEChunk(dataLine string) (*streamChunk, error) {
	wire, err := hex.DecodeString(strings.TrimSpace(dataLine))
	if err != nil {
		return nil, fmt.Errorf("envelope: SSE 分片非 hex: %w", err)
	}
	pt, err := Session.openPayload(protocol.EndpointInfer, wire)
	if err != nil {
		return nil, fmt.Errorf("envelope: SSE 分片解密失败: %w", err)
	}
	var chunk streamChunk
	if err := json.Unmarshal(pt, &chunk); err != nil {
		return nil, fmt.Errorf("envelope: SSE 分片 JSON 无效: %w", err)
	}
	if err := protocol.CheckStreamSequence(d.lastSeq, chunk.Seq); err != nil {
		return nil, err
	}
	d.lastSeq = chunk.Seq
	return &chunk, nil
}

// writeSSEChunk 将单个解密分片编译为标准 OpenAI SSE data 行。
// 正常块：choices[].delta.content = delta；finish=="stop"/"content_filter" 块：
// delta 置空 + 对应 finish_reason（content_filter 块同时透传 guard 注解，OG-16）。
func writeSSEChunk(sb *strings.Builder, reqID, model string, chunk *streamChunk) error {
	line, err := sseLine(reqID, model, chunk)
	if err != nil {
		return err
	}
	sb.Write(line)
	return nil
}

// decryptSSEBody 解密整段 tee-infer SSE 响应体，重组为客户端标准 OpenAI SSE。
// 任一分片解密失败/序号乱序/重放 → 整流拒绝（fail-closed，不输出半截明文）。
func decryptSSEBody(body []byte, reqID, model string) ([]byte, error) {
	dec := &sseStreamDecryptor{}
	var sb strings.Builder
	sawAny := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue // 空行/注释行（SSE 帧分隔），忽略
		}
		if strings.TrimSpace(data) == "[DONE]" {
			continue // tee 侧流结束标记（P2 服务端发送；解密侧由 finish 判定）
		}
		chunk, err := dec.decryptSSEChunk(data)
		if err != nil {
			return nil, err
		}
		sawAny = true
		if err := writeSSEChunk(&sb, reqID, model, chunk); err != nil {
			return nil, err
		}
		if chunk.Finish != "" {
			// finish="stop" 为正常终止；finish="content_filter"（OG-16）为内容安全审核终止：
			// 违规片段不在密文流内，插件以 finish_reason=content_filter + [DONE] 正常收尾，
			// 客户端可解析、可提示（安全语义不变：不伪装 stop、不下发违规内容）。
			// 其他值（如 "error"/"filter"）为异常终止，一律 fail-closed（防客户端误判成功）。
			switch chunk.Finish {
			case "stop", "content_filter":
			default:
				return nil, fmt.Errorf("envelope: SSE 流异常终止（finish=%q）", chunk.Finish)
			}
			sb.WriteString("data: [DONE]\n\n")
			return []byte(sb.String()), nil
		}
	}
	if !sawAny {
		return nil, errors.New("envelope: SSE 流无有效加密分片")
	}
	// 无 finish 标记即截断的流：拒绝（fail-closed，防截断攻击导致静默丢尾）
	return nil, errors.New("envelope: SSE 流未正常终止（缺 finish 分片）")
}

// isSSEBody 响应体是否为 tee-infer 加密 SSE 流（按 data: 行首判定）。
func isSSEBody(body []byte) bool {
	for _, line := range strings.Split(string(body), "\n") {
		if strings.HasPrefix(strings.TrimRight(line, "\r"), "data:") {
			return true
		}
	}
	return false
}

// SSEStreamDecoder 增量 SSE 密文流解密状态机（P1b 流式外发）。
//
// 与整包 decryptSSEBody 的差异：后者在 endOfStream 一次性收全 body 再解密；
// 本状态机把 tee-infer 密文 body 的字节流（逐 frame 到达）跨 frame 拼合为
// 完整 data: 行，逐帧即时解密并追加输出，从而可配合 ProcessStreamingResponseBody
// 逐片外发，规避 Envoy 响应整体缓冲的大响应挂起（§4.2）。
//
// 安全语义与整包版等价：任一分片解密失败 / 外层计数器重放 / 内层 seq 乱序 →
// 整流拒绝（err 非 nil，外层不再外发），不输出半截明文；已外发的合法前缀由
// 外层以 fail-closed 截断丢弃（HTTP 上表现为流中断）。
type SSEStreamDecoder struct {
	dec           *sseStreamDecryptor
	reqID         string
	model         string
	done          bool   // 已收到正常终止（stop/content_filter）并输出 [DONE]
	contentFilter bool   // 已观察到 finish="content_filter"（OG-16 网关层独立指标用）
	first         bool   // 是否已见到首个 data: 行（判空流）
	pending       []byte // 跨 frame 未拼合完整行的残留字节
	err           error  // 首个不可恢复错误（整流拒绝后不再处理新帧）
}

// NewSSEStreamDecoder 创建增量解密状态机。
func NewSSEStreamDecoder(reqID, model string) *SSEStreamDecoder {
	return &SSEStreamDecoder{dec: &sseStreamDecryptor{}, reqID: reqID, model: model}
}

// ContentFiltered 报告本流是否以 finish="content_filter" 审核终止（OG-16）。
// 外层在 Feed 正常收尾后读取一次，用于网关层 content_filter 独立计数。
func (d *SSEStreamDecoder) ContentFiltered() bool {
	return d.contentFilter
}

// Feed 喂入一个响应 body 分帧（后续末尾帧的 isLastChunk=true），返回本帧拼合后
// 可外发的明文字节。返回非 nil err 表示整流拒绝，此后任何 Feed 均返回该 err。
func (d *SSEStreamDecoder) Feed(chunk []byte, isLastChunk bool) ([]byte, error) {
	if d.err != nil {
		return nil, d.err
	}
	d.pending = append(d.pending, chunk...)
	var out []byte
	for {
		idx := bytes.IndexByte(d.pending, '\n')
		if idx < 0 {
			break // 无完整行，等下一帧
		}
		line := strings.TrimRight(string(d.pending[:idx]), "\r")
		d.pending = d.pending[idx+1:]
		dataLine, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue // 注释/空行，忽略
		}
		if strings.TrimSpace(dataLine) == "[DONE]" {
			continue // tee 侧流结束标记，解密收尾由 finish 分片判定
		}
		sc, err := d.dec.decryptSSEChunk(dataLine)
		if err != nil {
			d.err = err
			return nil, err
		}
		d.first = true
		bs, err := sseLine(d.reqID, d.model, sc)
		if err != nil {
			d.err = err
			return nil, err
		}
		out = append(out, bs...)
		if sc.Finish != "" {
			// stop=正常结束；content_filter=内容安全审核终止（OG-16，正常收尾可提示）；
			// 其他值（error/未知码）整流拒绝。
			if sc.Finish != "stop" && sc.Finish != "content_filter" {
				d.err = fmt.Errorf("envelope: SSE 流异常终止（finish=%q）", sc.Finish)
				return nil, d.err
			}
			if sc.Finish == "content_filter" {
				d.contentFilter = true
			}
			out = append(out, "data: [DONE]\n\n"...)
			d.done = true
			return out, nil
		}
	}
	// 流结束（isLastChunk）时强制收尾校验
	if isLastChunk {
		if !d.first {
			return nil, errors.New("envelope: SSE 流无有效加密分片")
		}
		if len(d.pending) != 0 {
			return nil, errors.New("envelope: SSE 流被截断（残留未完成帧）")
		}
		if d.done == false {
			return nil, errors.New("envelope: SSE 流未正常终止（缺 finish 分片）")
		}
	}
	return out, d.err
}

// sseLine 将单个解密分片编译为标准 OpenAI SSE data 行（含行尾 \n\n）。
// 正常块：choices[].delta.content = delta；finish=="stop"/"content_filter" 块：delta 置空
// + 同名 finish_reason（OpenAI 标准）；content_filter 块同时在顶层透传 guard 注解。
// 其他 finish 值（error/未知码）返回错误，由外层整流 fail-closed。
func sseLine(reqID, model string, chunk *streamChunk) ([]byte, error) {
	choice := sseChoice{Index: 0}
	switch chunk.Finish {
	case "":
		choice.Delta.Content = chunk.Delta
	case "stop", "content_filter":
		choice.FinishReason = chunk.Finish // OpenAI 标准 finish_reason 与内层 finish 同名
	default:
		return nil, fmt.Errorf("envelope: SSE 流异常终止（finish=%q）", chunk.Finish)
	}
	payload, err := json.Marshal(sseChunk{
		ID:      reqID,
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []sseChoice{choice},
		Guard:   chunk.Guard,
	})
	if err != nil {
		return nil, err
	}
	line := make([]byte, 0, len(payload)+len("data: ")+2)
	line = append(line, "data: "...)
	line = append(line, payload...)
	line = append(line, '\n', '\n')
	return line, nil
}
