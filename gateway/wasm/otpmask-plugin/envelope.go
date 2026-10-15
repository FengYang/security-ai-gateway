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
	// B1 强标标识（GB 45438-2025）：合规标识随标识帧走（head/repeat/tail），独立字段不并入 guard。
	// omitempty 透传，旧版本插件忽略未知字段（混部时隐式标识丢失但不 fail-closed）。
	Label *chunkLabel `json:"content_label,omitempty"`
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

// chunkLabel 强标标识 chunk-meta（B1；与 tee-infer chunkLabelMeta 同构）。
// 不含文案（与 delta 冗余防漂移）、不含用户内容。
type chunkLabel struct {
	Std      string `json:"std"`      // 标准号（默认 GB45438-2025）
	Position string `json:"position"` // head | repeat | tail
	// 上游 tee-infer 随标识帧携带的**溯源要素**，本插件**透传**至客户端（标准客户端忽略未知键）。
	// 不得据此宣称"已满足 GB 45438-2025 6.1"。字段语义对应标准附录 E。
	Synthetic bool   `json:"synthetic,omitempty"`  // 生成合成标签要素
	Producer  string `json:"producer,omitempty"`   // 生成合成服务提供者要素
	ContentID string `json:"content_id,omitempty"` // 内容制作编号要素
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
	Guard   *chunkGuard `json:"guard,omitempty"`         // OG-16：审核注解自定义扩展字段；标准客户端忽略未知键
	Label   *chunkLabel `json:"content_label,omitempty"` // B1：强标标识自定义扩展字段；标准客户端忽略未知键
}

// B1：标识位置（与 tee-infer labelPosition* 同构）。
const (
	labelPositionHead   = "head"
	labelPositionRepeat = "repeat"
	labelPositionTail   = "tail"
)

// defaultContentLabelText 缺省标识文案（与 tee-infer 缺省同源；空配置兜底）。
const defaultContentLabelText = "内容由人工智能生成"

// buildLabelSSELine 构造一帧强标标识 OpenAI SSE data 行（head 注入用）。
// 复用 sseChunk 标准形态：choices[].delta.content = 标识文案 + 顶层 label 注解；
// 文案为平台固定文本，不参与 PII mask 改写（mask 只作用于引擎 delta）。
func buildLabelSSELine(text, position, reqID, model string) []byte {
	payload, _ := json.Marshal(sseChunk{
		ID:      reqID,
		Object:  "chat.completion.chunk",
		Created: time.Now().Unix(),
		Model:   model,
		Choices: []sseChoice{{Index: 0, Delta: sseDelta{Content: text}}},
		Label:   &chunkLabel{Std: "GB45438-2025", Position: position},
	})
	line := make([]byte, 0, len(payload)+len("data: ")+2)
	line = append(line, "data: "...)
	line = append(line, payload...)
	line = append(line, '\n', '\n')
	return line
}

// sseStreamDecryptor 单条 SSE 流的解密状态（请求级，onResponseBody 内创建）。
type sseStreamDecryptor struct {
	lastSeq uint64 // 已见最大流内序号（严格递增校验）
}

// decryptSSEChunk 解密单个 SSE 分片：外层信封（K_enc + 反重放窗口）→ 内层 seq 严格递增。
//
// CPS（proxy-wasm 无阻塞 HTTP，§4.7）：解密经 cryptop sidecar（Session.openPayload），
// 结果经 cb 交付。
func (d *sseStreamDecryptor) decryptSSEChunk(dataLine string, cb func(*streamChunk, error)) {
	wire, err := hex.DecodeString(strings.TrimSpace(dataLine))
	if err != nil {
		cb(nil, fmt.Errorf("envelope: SSE 分片非 hex: %w", err))
		return
	}
	Session.openPayload(protocol.EndpointInfer, wire, func(pt []byte, oerr error) {
		if oerr != nil {
			cb(nil, fmt.Errorf("envelope: SSE 分片解密失败: %w", oerr))
			return
		}
		var chunk streamChunk
		if err := json.Unmarshal(pt, &chunk); err != nil {
			cb(nil, fmt.Errorf("envelope: SSE 分片 JSON 无效: %w", err))
			return
		}
		if err := protocol.CheckStreamSequence(d.lastSeq, chunk.Seq); err != nil {
			cb(nil, err)
			return
		}
		d.lastSeq = chunk.Seq
		cb(&chunk, nil)
	})
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
// 与整包 decryptSSEBody 的差异：后者在 endOfStream 一次性收齐 body 再解密；
// 本状态机把 tee-infer 密文 body 的字节流（逐 frame 到达）跨 frame 拼合为
// 完整 data: 行，逐帧即时解密并追加输出，从而可配合 ProcessStreamingResponseBody
// 逐片外发，规避 Envoy 响应整体缓冲的大响应挂起（§4.2）。
//
// 批量模式（batchSize > 1）：攒满 batchSize 个 data: 行后调一次 /v1/batch
// 批量解密，减少 sidecar 调用次数（T-5.4-7）。不满一批的尾帧在 isLastChunk 时冲刷。
// batchSize <= 1 等价于逐帧模式（T-5.4-2），与改造前行为一致。
//
// 安全语义与整包版等价：任一分片解密失败 / 外层计数器重放 / 内层 seq 乱序 →
// 整流拒绝（err 非 nil，外层不再外发），不输出半截明文；已外发的合法前缀由
// 外层以 fail-closed 截断丢弃（HTTP 上表现为流中断）。
type SSEStreamDecoder struct {
	dec           *sseStreamDecryptor
	reqID         string
	model         string
	done          bool   // 已收到正常终止（stop/content_filter）并输出 [DONE]
	completed     bool   // 流完整结束（finish 终态校验通过；P1-6 M2.1：TTFT 候选唯一提交依据）
	contentFilter bool   // 已观察到 finish="content_filter"（OG-16 网关层独立指标用）
	labelSeen     bool   // B1：上游已携带 label meta（SawLabel 去重注入的依据）
	first         bool   // 是否已见到首个 data: 行（判空流）
	pending       []byte // 跨 frame 未拼合完整行的残留字节
	err           error  // 首个不可恢复错误（整流拒绝后不再处理新帧）

	// ---- 批量模式 ----
	batchSize int      // 批大小（<=1 = 逐帧，等价原行为）
	batched   [][]byte // 已攒的待解密密文信封（hex 解码前的 data: 行原始字符串 bytes，含空格）
	emitQueue []byte   // 已解密待输出的明文 SSE 字节（顺序排列）
	inBatch   bool     // 是否正在等批量解密回调（防止重入）
	// 批结束时需要延续的状态（供 flushBatch 回调恢复 drain 上下文）
	batchOut  []byte                      // 批回调时累积的 out
	batchLast bool                        // 批回调时的 isLastChunk
	batchCb   func(out []byte, err error) // 批回调时的 cb
}

// NewSSEStreamDecoder 创建增量解密状态机（默认逐帧，batchSize=1）。
func NewSSEStreamDecoder(reqID, model string) *SSEStreamDecoder {
	return &SSEStreamDecoder{dec: &sseStreamDecryptor{}, reqID: reqID, model: model, batchSize: 1}
}

// NewSSEStreamDecoderWithBatch 创建带批量解密的增量解密状态机。
// batchSize <= 1 等价于逐帧模式（T-5.4-2）；>1 启用批量（T-5.4-7）。
func NewSSEStreamDecoderWithBatch(reqID, model string, batchSize int) *SSEStreamDecoder {
	bs := batchSize
	if bs < 1 {
		bs = 1
	}
	return &SSEStreamDecoder{dec: &sseStreamDecryptor{}, reqID: reqID, model: model, batchSize: bs}
}

// ContentFiltered 报告本流是否以 finish="content_filter" 审核终止（OG-16）。
// 外层在 Feed 正常收尾后读取一次，用于网关层 content_filter 独立计数。
func (d *SSEStreamDecoder) ContentFiltered() bool {
	return d.contentFilter
}

// Completed 报告流是否**完整结束**（isLastChunk 终态校验全部通过并已正常终止；P1-6 M2.1）。
// 用于 TTFT 候选样本的唯一提交判定：失败/截断/乱序流均为 false，候选自然丢弃。
func (d *SSEStreamDecoder) Completed() bool {
	return d.completed
}

// SawLabel 报告上游流是否已携带强标标识 label meta（B1 去重语义）：
// 上游 tee-infer 已注入标识时，本插件不得重复注入（单一注入点规则的可执行兜底）。
func (d *SSEStreamDecoder) SawLabel() bool {
	return d.labelSeen
}

// Feed 喂入一个响应 body 分帧（后续末尾帧的 isLastChunk=true），经 cb 交付本帧拼合后
// 可外发的明文字节。cb 收到非 nil err 表示整流拒绝，此后任何 Feed 均返回该 err。
//
// CPS：每个 data: 行需经 cryptop sidecar 解密（异步），故循环改写为 drain 递归。
func (d *SSEStreamDecoder) Feed(chunk []byte, isLastChunk bool, cb func(out []byte, err error)) {
	if d.err != nil {
		cb(nil, d.err)
		return
	}
	d.pending = append(d.pending, chunk...)
	d.drain(nil, isLastChunk, cb)
}

// drain 从 pending 逐行消费：
//   - 非 data:/[DONE] 行忽略
//   - data: 行：逐帧模式（batchSize<=1）即时解密（走 decryptSSEChunk）；
//     批量模式攒到 batched[]，满 batchSize 触发 flushBatch 批量解密
//   - pending 无完整行时进入 finish 收尾判定
//
// emitQueue：批量模式下，已解密的明文 SSE 字节先进入 emitQueue 排队，
// 下次 drain 开头优先输出，输出完再继续攒新帧。
func (d *SSEStreamDecoder) drain(out []byte, isLastChunk bool, cb func(out []byte, err error)) {
	// 第一步：优先输出 emitQueue 里已解密的内容（批量模式用）
	if len(d.emitQueue) > 0 {
		out = append(out, d.emitQueue...)
		d.emitQueue = nil
	}

	idx := bytes.IndexByte(d.pending, '\n')
	if idx < 0 {
		// pending 无完整行：批量模式且有剩余待解密帧 + isLastChunk → 冲刷尾批
		if d.batchSize > 1 && len(d.batched) > 0 && isLastChunk {
			d.flushBatch(out, isLastChunk, cb)
			return
		}
		d.finish(out, isLastChunk, cb)
		return
	}
	line := strings.TrimRight(string(d.pending[:idx]), "\r")
	d.pending = d.pending[idx+1:]
	dataLine, ok := strings.CutPrefix(line, "data:")
	if !ok {
		d.drain(out, isLastChunk, cb)
		return
	}
	if strings.TrimSpace(dataLine) == "[DONE]" {
		d.drain(out, isLastChunk, cb)
		return
	}

	if d.batchSize <= 1 {
		// ---- 逐帧模式（原逻辑）----
		d.dec.decryptSSEChunk(dataLine, func(sc *streamChunk, err error) {
			if err != nil {
				d.err = err
				cb(nil, err)
				return
			}
			d.first = true
			if sc.Label != nil {
				d.labelSeen = true // B1：上游已带标识（head/repeat/tail 任一）
			}
			bs, err := sseLine(d.reqID, d.model, sc)
			if err != nil {
				d.err = err
				cb(nil, err)
				return
			}
			out = append(out, bs...)
			if sc.Finish != "" {
				// stop=正常结束；content_filter=内容安全审核终止（OG-16，正常收尾可提示）；
				// 其他值（error/未知码）整流拒绝。
				if sc.Finish != "stop" && sc.Finish != "content_filter" {
					d.err = fmt.Errorf("envelope: SSE 流异常终止（finish=%q）", sc.Finish)
					cb(nil, d.err)
					return
				}
				if sc.Finish == "content_filter" {
					d.contentFilter = true
				}
				out = append(out, "data: [DONE]\n\n"...)
				d.done = true
				cb(out, nil)
				return
			}
			d.drain(out, isLastChunk, cb)
		})
		return
	}

	// ---- 批量模式 ----
	d.batched = append(d.batched, []byte(strings.TrimSpace(dataLine)))

	if len(d.batched) >= d.batchSize {
		d.flushBatch(out, isLastChunk, cb)
		return
	}

	// 继续攒下一行
	d.drain(out, isLastChunk, cb)
}

// flushBatch 批量解密当前 batched 中的所有帧。
// 成功后结果按顺序追加到 emitQueue，清空 batched，继续 drain。
// 任一帧失败 → 整流拒绝（fail-closed）。
func (d *SSEStreamDecoder) flushBatch(out []byte, isLastChunk bool, cb func(out []byte, err error)) {
	n := len(d.batched)
	if n == 0 {
		d.drain(out, isLastChunk, cb)
		return
	}
	// hex 解码每帧
	wires := make([][]byte, n)
	for i, line := range d.batched {
		wire, err := hex.DecodeString(string(line))
		if err != nil {
			d.err = fmt.Errorf("envelope batch[%d]: SSE 分片非 hex: %w", i, err)
			cb(nil, d.err)
			return
		}
		wires[i] = wire
	}
	// 清空 batched（复用底层数组）
	d.batched = d.batched[:0]

	d.inBatch = true
	Session.batchOpenPayloads(protocol.EndpointInfer, wires, func(results []batchOpenResult, berr error) {
		d.inBatch = false
		if berr != nil {
			d.err = berr
			cb(nil, berr)
			return
		}
		// 逐帧处理结果（按顺序）
		for i, r := range results {
			if r.Err != nil {
				d.err = fmt.Errorf("envelope batch[%d]: %w", i, r.Err)
				cb(nil, d.err)
				return
			}
			var chunk streamChunk
			if err := json.Unmarshal(r.Pt, &chunk); err != nil {
				d.err = fmt.Errorf("envelope batch[%d]: SSE 分片 JSON 无效: %w", i, err)
				cb(nil, d.err)
				return
			}
			// seq 严格递增校验
			if err := protocol.CheckStreamSequence(d.dec.lastSeq, chunk.Seq); err != nil {
				d.err = err
				cb(nil, d.err)
				return
			}
			d.dec.lastSeq = chunk.Seq
			d.first = true
			if chunk.Label != nil {
				d.labelSeen = true
			}
			bs, err := sseLine(d.reqID, d.model, &chunk)
			if err != nil {
				d.err = err
				cb(nil, d.err)
				return
			}
			d.emitQueue = append(d.emitQueue, bs...)
			if chunk.Finish != "" {
				if chunk.Finish != "stop" && chunk.Finish != "content_filter" {
					d.err = fmt.Errorf("envelope: SSE 流异常终止（finish=%q）", chunk.Finish)
					cb(nil, d.err)
					return
				}
				if chunk.Finish == "content_filter" {
					d.contentFilter = true
				}
				d.emitQueue = append(d.emitQueue, "data: [DONE]\n\n"...)
				d.done = true
			}
		}
		// 本批全部处理完，继续 drain（emitQueue 有内容 → 输出 → 再攒新帧）
		d.drain(out, isLastChunk, cb)
	})
}

// finish pending 无完整行时的收尾：isLastChunk 强制校验（非空流/无残留/已正常终止）。
func (d *SSEStreamDecoder) finish(out []byte, isLastChunk bool, cb func(out []byte, err error)) {
	if isLastChunk {
		if !d.first {
			d.err = errors.New("envelope: SSE 流无有效加密分片")
			cb(nil, d.err)
			return
		}
		if len(d.pending) != 0 {
			d.err = errors.New("envelope: SSE 流被截断（残留未完成帧）")
			cb(nil, d.err)
			return
		}
		if !d.done {
			d.err = errors.New("envelope: SSE 流未正常终止（缺 finish 分片）")
			cb(nil, d.err)
			return
		}
		d.completed = true // P1-6 M2.1：终态校验全部通过——流完整结束
	}
	cb(out, nil)
}

// sseLine 将单个解密分片编译为标准 OpenAI SSE data 行（含行尾 \n\n）。
// 正常块：choices[].delta.content = delta；finish=="stop"/"content_filter" 块：delta 置空
// + 同名 finish_reason（OpenAI 标准）；content_filter 块同时在顶层透传 guard 注解。
// 其他 finish 值（error/未知码）返回错误，由外层整流 fail-closed。
func sseLine(reqID, model string, chunk *streamChunk) ([]byte, error) {
	choice := sseChoice{Index: 0}
	switch chunk.Finish {
	case "":
		delta := chunk.Delta
		// OG-16 扩展：插件侧 PII mask 改写（两形态第二形态）。
		// 仅对正常 delta 块改写；finish 块 delta 为空，跳过。
		// 默认 off（piiMaskEnabled=false），零行为变化。
		if piiMaskEnabled && delta != "" {
			masked, hits := maskTextPII(delta)
			if hits > 0 {
				delta = masked
				metricMasked.incr()
			}
		}
		choice.Delta.Content = delta
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
		Label:   chunk.Label, // B1：label meta 按 wire 原样透传（sseLine 透传义务）
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
