package main

// P1b SSE 加密流解密测试：合法流重组、乱序/重放/截断/篡改拒绝、isSSEBody 判定。
// 服务端等价物 = protocol.SealEnvelope（跨语言一致性已由 protocol 包测试与
// cross_test.py 覆盖），此处只测插件侧流状态机。

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"security-ai-gateway/protocol/go"
)

// buildSSEStream 服务端等价：构造加密 SSE 响应体（hex 信封分片 + [DONE]）。
func buildSSEStream(t *testing.T, kenc []byte, sessionID string, chunks []streamChunk, counters []uint64) []byte {
	t.Helper()
	var sb strings.Builder
	for i, c := range chunks {
		plain, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		wire, err := protocol.SealEnvelope(kenc, sessionID, protocol.EndpointInfer, protocol.DirectionS2C, counters[i], plain)
		if err != nil {
			t.Fatal(err)
		}
		sb.WriteString("data: " + hex.EncodeToString(wire) + "\n\n")
	}
	sb.WriteString("data: [DONE]\n\n")
	return []byte(sb.String())
}

// TestDecryptSSEBodyValid 合法流解密重组：标准 OpenAI SSE 分片（delta.content）+ finish_reason + [DONE] 终止。
func TestDecryptSSEBodyValid(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "Hello"},
		{Seq: 2, Delta: " 世界"},
		{Seq: 3, Delta: "", Finish: "stop"},
	}, []uint64{1, 2, 3})
	if !isSSEBody(body) {
		t.Fatal("isSSEBody 未识别加密 SSE 流")
	}
	out, err := decryptSSEBody(body, "req123", "mock")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{
		`"object":"chat.completion.chunk"`,
		`"delta":{"content":"Hello"`,
		`"delta":{"content":" 世界"`,
		`"finish_reason":"stop"`,
		"data: [DONE]",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("重组结果缺 %q: %q", want, s)
		}
	}
	if !strings.HasSuffix(s, "data: [DONE]\n\n") {
		t.Fatal("流未以 [DONE] 终止")
	}
}

// TestDecryptSSEBodyReorder 流内序号乱序（1→3）→ 整流拒绝。
func TestDecryptSSEBodyReorder(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 3, Delta: "c"},
	}, []uint64{1, 2})
	if _, err := decryptSSEBody(body, "req123", "mock"); err == nil {
		t.Fatal("流内序号乱序未被拒绝")
	}
}

// TestDecryptSSEBodyReplay 外层计数器重放（同 counter 两个分片）→ 整流拒绝。
func TestDecryptSSEBodyReplay(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 2, Delta: "b", Finish: "stop"},
	}, []uint64{1, 1}) // 第二分片重放 counter=1
	if _, err := decryptSSEBody(body, "req123", "mock"); err == nil {
		t.Fatal("外层计数器重放未被拒绝")
	}
}

// TestDecryptSSEBodyTruncated 无 finish 分片（流被截断）→ 拒绝（防截断攻击静默丢尾）。
func TestDecryptSSEBodyTruncated(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 2, Delta: "b"},
	}, []uint64{1, 2})
	if _, err := decryptSSEBody(body, "req123", "mock"); err == nil {
		t.Fatal("截断流（缺 finish）未被拒绝")
	}
}

// TestDecryptSSEBodyTamper 篡改任一分片密文 → 整流拒绝（不输出半截明文）。
func TestDecryptSSEBodyTamper(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "a", Finish: "stop"},
	}, []uint64{1})
	// 篡改密文 hex（信封 wire 中部）
	s := string(body)
	idx := strings.Index(s, "data: ") + len("data: ") + 20
	b := []byte(s)
	b[idx] = b[idx] ^ 0x01
	if _, err := decryptSSEBody(b, "req123", "mock"); err == nil {
		t.Fatal("篡改分片未被拒绝")
	}
}

// TestDecryptSSEBodyEmpty 空流（仅 [DONE]，无加密分片）→ 拒绝。
func TestDecryptSSEBodyEmpty(t *testing.T) {
	newSessionForTest(t)
	if _, err := decryptSSEBody([]byte("data: [DONE]\n\n"), "req123", "mock"); err == nil {
		t.Fatal("无加密分片的 [DONE] 流未被拒绝")
	}
}

// TestDecryptSSEBodyFinishError 错误终止（finish="error"）应 fail-closed，不输出半截明文。
func TestDecryptSSEBodyFinishError(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "partial"},
		{Seq: 2, Delta: "", Finish: "error"},
	}, []uint64{1, 2})
	if out, err := decryptSSEBody(body, "req123", "mock"); err == nil {
		t.Fatalf("finish=error 应拒绝，但返回明文: %q", string(out))
	}
}

// TestDecryptSSEFinishReasonPrecise finish=stop 时 delta 为空对象 + finish_reason="stop"。
func TestDecryptSSEFinishReasonPrecise(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "hi", Finish: "stop"},
	}, []uint64{1})
	out, err := decryptSSEBody(body, "req789", "test-model")
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	// 终止块应包含 finish_reason=stop
	if !strings.Contains(s, `"finish_reason":"stop"`) {
		t.Fatalf("终止块缺 finish_reason=stop: %q", s)
	}
	// 终止块的 delta 应是空对象 {}（content omitempty，且 finish 块 Content 为空）
	// 即同一 choice 内 "delta":{}  或 delta 完全不出现
	if strings.Contains(s, `"delta":{"content":"hi"}`) && strings.Contains(s, `"finish_reason":"stop"`) {
		t.Fatalf("终止块不应包含 content=hi: %q", s)
	}
	// id/model 透传
	if !strings.Contains(s, `"id":"req789"`) {
		t.Fatalf("缺 id: %q", s)
	}
	if !strings.Contains(s, `"model":"test-model"`) {
		t.Fatalf("缺 model: %q", s)
	}
}

// TestDecryptSSEBodyWrongKey 错误会话（密钥不同步）→ 拒绝。
func TestDecryptSSEBodyWrongKey(t *testing.T) {
	_, kenc := newSessionForTest(t)
	// 用另一会话密钥构造的流（模拟服务端重启换了密钥）
	otherKey := make([]byte, 32)
	for i := range otherKey {
		otherKey[i] = 0x99
	}
	body := buildSSEStream(t, otherKey, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "a", Finish: "stop"},
	}, []uint64{1})
	_ = kenc
	if _, err := decryptSSEBody(body, "req123", "mock"); err == nil {
		t.Fatal("错误密钥的流未被拒绝")
	}
}

// TestIsSSEBody 判定：data: 行 → true；二进制协议响应 → false。
func TestIsSSEBody(t *testing.T) {
	if !isSSEBody([]byte("data: abc\n\n")) {
		t.Fatal("data: 行应识别为 SSE")
	}
	if isSSEBody([]byte{0x01, 0x02, 0x1f, 0x8b, 0x00}) {
		t.Fatal("二进制响应不应识别为 SSE")
	}
	if isSSEBody([]byte("")) {
		t.Fatal("空体不应识别为 SSE")
	}
}
