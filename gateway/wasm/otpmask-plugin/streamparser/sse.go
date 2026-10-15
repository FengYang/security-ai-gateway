// Package streamparser — SSE 流解析器（流式重试 PoC 核心组件）。
//
// 用途：判断流式响应是否已经输出了第一个 token。
// 首 token 前失败 = 可安全重试（不会产生重复内容/重复计费）。
// 首 token 后失败 = 不可重试（已产生实际 token，按实际消耗计费）。
//
// 纯逻辑包，无 proxy-wasm hostcall 依赖，可独立单测。
//
// SSE 格式参考：
//
//	event: message\n
//	data: {\"choices\":[{\"delta\":{\"content\":\"hello\"}}]}\n
//	\n
//
// 关键判断：收到第一个非空的 data: 行 = 首 token 已输出。
// event: 行、注释行（:前缀）、空 data 不算首 token。
package streamparser

import (
	"bytes"
	"strings"

	"github.com/tidwall/gjson"
)

// SSEParser SSE 流解析器（增量式，跨帧维护状态）。
//
// 用法：
//
//	p := NewSSEParser()
//	p.Feed(chunk1)
//	p.Feed(chunk2)
//	if p.FirstTokenSent() { ... }
type SSEParser struct {
	firstTokenSent   bool   // 是否已输出第一个 token
	buf              []byte // 跨帧缓冲（不完整行；≤ maxSSELineBytes 定长封顶，R2-05）
	eventName        string // 当前 event 名（最近一个 event: 行的值）
	inData           bool   // 是否正在处理 data 行
	contentDelta     bool   // R2-04：true = 判定「choices[].delta.content 非空」；false = 原「非空 data 行」口径
	skippingOverlong bool   // R2-05：超长行丢弃中（消费到下一行边界后恢复解析）
}

// maxSSELineBytes SSE 单行上限（64KB）。超过即视为异常流：丢弃该行、缓冲不保留，
// 防止 buf 无界 append（R2-05/C-3）。正常 SSE 内容行远小于该上限。
const maxSSELineBytes = 64 * 1024

// NewSSEParser 创建新的 SSE 解析器（默认口径：首个非空 data: 行 = 首 token，重试语义）。
func NewSSEParser() *SSEParser {
	return &SSEParser{}
}

// NewContentDeltaSSEParser 创建「delta.content 非空」判定模式的解析器（R2-04，P1-6 M2.1）：
// data 行 JSON 的 choices[].delta.content 非空才算首 token——role 帧（无 content）、
// finish 帧、心跳/[DONE] 均不触发，与 tee-infer 侧「首个 delta.content 非空分片」口径对齐。
func NewContentDeltaSSEParser() *SSEParser {
	return &SSEParser{contentDelta: true}
}

// FirstTokenSent 返回是否已经输出了第一个 token。
// 判定标准：默认模式 = 收到第一个非空的 data: 行；contentDelta 模式 = 首个
// choices[].delta.content 非空的 data 行（R2-04）。
func (p *SSEParser) FirstTokenSent() bool {
	return p.firstTokenSent
}

// Reset 重置解析器状态（用于重试时重新开始；缓冲容量保留、跨请求复用，R2-05）。
func (p *SSEParser) Reset() {
	p.firstTokenSent = false
	p.buf = p.buf[:0]
	p.eventName = ""
	p.inData = false
	p.skippingOverlong = false
}

// Feed 喂入新的数据块（chunk），增量解析。
// 可分多次调用（跨帧），内部维护缓冲；已完成首 token 判定后立即返回、不再喂入（R2-05）。
// 缓冲定长封顶：无换行残留超过 maxSSELineBytes 即丢弃该行并进入跳过模式（防无界 append）。
func (p *SSEParser) Feed(data []byte) {
	if p.firstTokenSent {
		return // 已经输出了首 token，不再解析
	}
	if p.skippingOverlong {
		// 超长行丢弃中：消费到下一行边界后恢复
		i := bytes.IndexByte(data, '\n')
		if i < 0 {
			return
		}
		p.skippingOverlong = false
		data = data[i+1:]
	}

	// 逐行处理
	for len(data) > 0 {
		idx := bytes.IndexByte(data, '\n')
		if idx < 0 {
			// 无完整行：仅保留 ≤ 行上限 的尾部（禁止无界 append，R2-05）
			if len(p.buf)+len(data) > maxSSELineBytes {
				p.buf = p.buf[:0]
				p.skippingOverlong = true
				return
			}
			p.buf = append(p.buf, data...)
			return // 等下一个 chunk
		}

		// 拼合跨帧残留，得到完整行（buf 仅承载单行；行处理后立即复用容量）
		line := append(p.buf, data[:idx]...)
		p.buf = p.buf[:0]
		data = data[idx+1:]

		// 去掉 \r（如果有）
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		// 超长完整行（> 行上限）同样丢弃（与拆分跨帧的超长行口径一致）
		if len(line) <= maxSSELineBytes {
			p.processLine(string(line))
		}

		if p.firstTokenSent {
			return // 找到首 token 了，直接返回
		}
	}
}

// processLine 处理单行 SSE 数据。
//
// SSE 行格式：
//   - 空行 = 事件结束分隔符
//   - :开头 = 注释，忽略
//   - field: value = 字段 + 值
//   - field: = 字段 + 空值（区别于没有该字段）
func (p *SSEParser) processLine(line string) {
	// 空行 = 事件分隔符，重置 event 名
	if line == "" {
		p.eventName = ""
		p.inData = false
		return
	}

	// 注释行，忽略
	if strings.HasPrefix(line, ":") {
		return
	}

	// 解析字段
	field, value, _ := strings.Cut(line, ":")

	// 去掉 value 开头的单个空格（如果有）
	if strings.HasPrefix(value, " ") {
		value = value[1:]
	}

	switch field {
	case "event":
		p.eventName = value
	case "data":
		if p.contentDelta {
			// R2-04 口径：仅 choices[].delta.content 非空的 data 行触发（role/finish/[DONE] 不触发）
			if contentDeltaNonEmpty(value) {
				p.firstTokenSent = true
			}
		} else if value != "" {
			// 非空 data 行 = 有内容输出（原口径，重试语义）
			// 注意：data: （空值）不算
			// 检查是否是真正的 token 内容（而不是 ping/心跳）
			// 标准 SSE 心跳通常是 ": ping" 注释行或 event: ping
			// 只要有非空 data，就认为首 token 已输出
			p.firstTokenSent = true
		}
		p.inData = true
	case "id", "retry":
		// 其他标准字段，忽略但不影响首 token 判断
	default:
		// 未知字段，忽略
	}
}

// contentDeltaNonEmpty 判定 SSE data 行 JSON 的 choices[].delta.content 是否非空（R2-04，P1-6 M2.1）。
// 多 choices（n>1）时任一 delta.content 非空即视为内容帧；JSON 无效/无该字段 → false。
func contentDeltaNonEmpty(data string) bool {
	if data == "" || data[0] != '{' {
		return false // [DONE]/非 JSON 载荷不触发（快路径，避免无谓解析）
	}
	choices := gjson.Get(data, "choices")
	if !choices.IsArray() {
		return false
	}
	for _, c := range choices.Array() {
		if s := c.Get("delta.content"); s.Type == gjson.String && s.String() != "" {
			return true
		}
	}
	return false
}

// EventName 返回当前（最近一个）event 的名称。
// 仅供调试/日志使用。
func (p *SSEParser) EventName() string {
	return p.eventName
}

// ============================================================
// 工具函数：首 token 快速检测
// ============================================================

// FirstTokenInChunk 快速检测一个数据块中是否包含首 token。
// 适用于一次性检测（不需要跨帧维护状态）。
func FirstTokenInChunk(data []byte) bool {
	p := NewSSEParser()
	p.Feed(data)
	return p.FirstTokenSent()
}

// IsPingEvent 检测一个数据块是否是 SSE ping/心跳事件（无实际 token 内容）。
// 返回 true 表示这是心跳，不算首 token。
func IsPingEvent(data []byte) bool {
	// 纯注释行（: 开头）= 心跳
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return true // 空数据 = 心跳
	}
	// 检查是否只有注释行
	lines := bytes.Split(trimmed, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if !bytes.HasPrefix(line, []byte(":")) {
			return false // 有非注释行，不是纯心跳
		}
	}
	return true
}
