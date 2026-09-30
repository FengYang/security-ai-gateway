package streamparser

import (
	"testing"
)

// 基本场景：标准 SSE data 行触发首 token
func TestFirstTokenBasicData(t *testing.T) {
	p := NewSSEParser()
	p.Feed([]byte("data: hello world\n\n"))
	if !p.FirstTokenSent() {
		t.Fatal("data 行应触发首 token")
	}
}

// 空 data 行不算首 token（data: 后面没内容）
func TestEmptyDataNotFirstToken(t *testing.T) {
	p := NewSSEParser()
	p.Feed([]byte("data: \n\n"))
	if p.FirstTokenSent() {
		t.Fatal("空 data 行不应触发首 token")
	}
}

// event: 行不算首 token
func TestEventLineNotFirstToken(t *testing.T) {
	p := NewSSEParser()
	p.Feed([]byte("event: message\n\n"))
	if p.FirstTokenSent() {
		t.Fatal("event 行不应触发首 token")
	}
}

// 注释行（:开头）不算首 token
func TestCommentLineNotFirstToken(t *testing.T) {
	p := NewSSEParser()
	p.Feed([]byte(": ping\n\n"))
	if p.FirstTokenSent() {
		t.Fatal("注释行不应触发首 token")
	}
}

// 标准 OpenAI 格式 SSE：event + data 组合
func TestOpenAIFormat(t *testing.T) {
	p := NewSSEParser()
	// 先收到 event 行，还没首 token
	p.Feed([]byte("event: message\n"))
	if p.FirstTokenSent() {
		t.Fatal("只有 event 行不应触发首 token")
	}
	// 再收到 data 行，首 token
	p.Feed([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n"))
	if !p.FirstTokenSent() {
		t.Fatal("data 行应触发首 token")
	}
	if p.EventName() != "message" {
		t.Fatalf("event name 应为 message，got %s", p.EventName())
	}
}

// 跨帧（chunk 跨数据块）：data 行被分成两部分
func TestCrossChunkDataLine(t *testing.T) {
	p := NewSSEParser()
	// 第一块：只有部分行
	p.Feed([]byte("data: hel"))
	if p.FirstTokenSent() {
		t.Fatal("不完整行不应触发首 token")
	}
	// 第二块：行的剩余部分 + 换行
	p.Feed([]byte("lo world\n\n"))
	if !p.FirstTokenSent() {
		t.Fatal("完整 data 行应触发首 token")
	}
}

// 跨帧（chunk 在行中间断开）：一整行被切成多段
func TestCrossChunkMultiplePieces(t *testing.T) {
	p := NewSSEParser()
	p.Feed([]byte("d"))
	p.Feed([]byte("at"))
	p.Feed([]byte("a:"))
	p.Feed([]byte(" hello"))
	p.Feed([]byte("\n"))
	if !p.FirstTokenSent() {
		t.Fatal("拼接后的 data 行应触发首 token")
	}
}

// Reset 后重新使用
func TestReset(t *testing.T) {
	p := NewSSEParser()
	p.Feed([]byte("data: test\n\n"))
	if !p.FirstTokenSent() {
		t.Fatal("第一次应触发首 token")
	}
	p.Reset()
	if p.FirstTokenSent() {
		t.Fatal("Reset 后不应再有首 token")
	}
	// 重新喂数据
	p.Feed([]byte("data: new\n\n"))
	if !p.FirstTokenSent() {
		t.Fatal("Reset 后重新喂数据应再次触发")
	}
}

// CRLF 换行符
func TestCRLFLineEnding(t *testing.T) {
	p := NewSSEParser()
	p.Feed([]byte("data: hello\r\n\r\n"))
	if !p.FirstTokenSent() {
		t.Fatal("CRLF 格式也应触发首 token")
	}
}

// 纯心跳（全是注释行）不算首 token
func TestPurePingNotFirstToken(t *testing.T) {
	p := NewSSEParser()
	p.Feed([]byte(": ping\n: still alive\n\n"))
	if p.FirstTokenSent() {
		t.Fatal("纯心跳不应触发首 token")
	}
}

// FirstTokenInChunk 快速检测函数
func TestFirstTokenInChunkHelper(t *testing.T) {
	if !FirstTokenInChunk([]byte("data: hello\n\n")) {
		t.Fatal("FirstTokenInChunk 应返回 true")
	}
	if FirstTokenInChunk([]byte(": ping\n\n")) {
		t.Fatal("FirstTokenInChunk 心跳应返回 false")
	}
	if FirstTokenInChunk([]byte("")) {
		t.Fatal("FirstTokenInChunk 空数据应返回 false")
	}
}

// IsPingEvent 检测函数
func TestIsPingEvent(t *testing.T) {
	tests := []struct {
		name     string
		data     string
		expected bool
	}{
		{"纯注释", ": ping\n", true},
		{"多行注释", ": ping\n: hello\n", true},
		{"空数据", "", true},
		{"空行", "\n\n", true},
		{"data 行", "data: hi\n", false},
		{"混合注释和数据", ": ping\ndata: hi\n", false},
		{"event 行", "event: message\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if IsPingEvent([]byte(tt.data)) != tt.expected {
				t.Fatalf("IsPingEvent 应为 %v", tt.expected)
			}
		})
	}
}

// 真实 OpenAI SSE 响应的渐进式场景
func TestRealisticOpenAIStream(t *testing.T) {
	p := NewSSEParser()

	// 帧1：注释行（心跳）
	p.Feed([]byte(": OPENROUTER PROCESSING\n\n"))
	if p.FirstTokenSent() {
		t.Fatal("心跳帧不应触发首 token")
	}

	// 帧2：event 行
	p.Feed([]byte("event: message\n"))
	if p.FirstTokenSent() {
		t.Fatal("只有 event 不应触发首 token")
	}

	// 帧3：data 行 + 空行 = 完整事件
	p.Feed([]byte("data: {\"id\":\"chatcmdl23456\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"},\"finish_reason\":null}]}\n\n"))
	// 注意：content 是空字符串 ""，这个 data 行有内容（JSON），算首 token
	if !p.FirstTokenSent() {
		t.Fatal("非空 data 应触发首 token（即使 content 为空）")
	}
}

// 多 data 行事件（SSE 允许多个 data 行拼接）
func TestMultipleDataLines(t *testing.T) {
	p := NewSSEParser()
	// 一个事件里有 2 个 data 行
	p.Feed([]byte("data: line1\ndata: line2\n\n"))
	if !p.FirstTokenSent() {
		t.Fatal("多 data 行事件应在第一个 data 行就触发首 token")
	}
}

// 已经 FirstTokenSent 后，Feed 不再解析（直接返回）
func TestNoParseAfterFirstToken(t *testing.T) {
	p := NewSSEParser()
	p.Feed([]byte("data: first\n\n"))
	if !p.FirstTokenSent() {
		t.Fatal("应有首 token")
	}
	// 喂入更多数据，FirstTokenSent 仍为 true（且不再解析，只是快速返回）
	p.Feed([]byte("more data here"))
	if !p.FirstTokenSent() {
		t.Fatal("首 token 状态不应被清除")
	}
}
