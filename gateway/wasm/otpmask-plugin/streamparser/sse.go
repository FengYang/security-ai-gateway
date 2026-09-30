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
	firstTokenSent bool   // 是否已输出第一个 token
	buf            []byte // 跨帧缓冲（不完整行）
	eventName      string // 当前 event 名（最近一个 event: 行的值）
	inData         bool   // 是否正在处理 data 行
}

// NewSSEParser 创建新的 SSE 解析器。
func NewSSEParser() *SSEParser {
	return &SSEParser{}
}

// FirstTokenSent 返回是否已经输出了第一个 token。
// 判定标准：收到了第一个非空的 data: 行的内容。
func (p *SSEParser) FirstTokenSent() bool {
	return p.firstTokenSent
}

// Reset 重置解析器状态（用于重试时重新开始）。
func (p *SSEParser) Reset() {
	p.firstTokenSent = false
	p.buf = p.buf[:0]
	p.eventName = ""
	p.inData = false
}

// Feed 喂入新的数据块（chunk），增量解析。
// 可分多次调用（跨帧），内部维护缓冲。
func (p *SSEParser) Feed(data []byte) {
	if p.firstTokenSent {
		return // 已经输出了首 token，不再解析
	}

	// 把新数据追加到缓冲
	p.buf = append(p.buf, data...)

	// 逐行处理
	for {
		idx := bytes.IndexByte(p.buf, '\n')
		if idx < 0 {
			break // 没有完整行，等下一个 chunk
		}
		line := p.buf[:idx]
		p.buf = p.buf[idx+1:]

		// 去掉 \r（如果有）
		if len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}

		p.processLine(string(line))

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
		// 非空 data 行 = 有内容输出
		// 注意：data: （空值）不算
		if value != "" {
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
