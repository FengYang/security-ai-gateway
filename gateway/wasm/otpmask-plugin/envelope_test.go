package main

// P1b SSE 加密流解密测试：合法流重组、乱序/重放/截断/篡改拒绝、isSSEBody 判定。
// 服务端等价物 = cryptoops.SealEnvelope（跨语言一致性已由 protocol 包测试与
// cross_test.py 覆盖），此处只测插件侧流状态机。

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
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
		wire, err := cryptoops.SealEnvelope(kenc, sessionID, protocol.EndpointInfer, protocol.DirectionS2C, counters[i], plain)
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

// TestDecryptSSEBodyContentFilter OG-16：finish="content_filter" 为内容安全审核终止，
// 插件须正常收尾（finish_reason=content_filter + [DONE]），已外发合法前缀保留，
// guard 注解顶层透传；不得伪装 stop，终止帧不带 delta 内容。
func TestDecryptSSEBodyContentFilter(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "安全前缀"},
		{Seq: 2, Finish: "content_filter", Guard: &chunkGuard{
			Detected:      true,
			Filtered:      true,
			Action:        "block",
			Category:      "A1-06",
			PolicyVersion: "pol-v1",
			Mode:          "enforcing",
		}},
	}, []uint64{1, 2})
	out, err := decryptSSEBody(body, "reqCF", "mock")
	if err != nil {
		t.Fatalf("finish=content_filter 应正常收尾，实际拒绝: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`"delta":{"content":"安全前缀"}`,
		`"finish_reason":"content_filter"`,
		`"guard":{"detected":true,"filtered":true,"action":"block","category":"A1-06","policy_version":"pol-v1","mode":"enforcing"}`,
		"data: [DONE]",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("content_filter 重组结果缺 %q: %q", want, s)
		}
	}
	if strings.Contains(s, `"finish_reason":"stop"`) {
		t.Fatalf("审核终止不得伪装成 stop: %q", s)
	}
	// 终止帧 delta 必须为空对象（不得携带任何文本）
	if strings.Contains(s, `"delta":{"content":`) && strings.LastIndex(s, `"delta":{"content":`) > strings.LastIndex(s, `"finish_reason"`) {
		t.Fatalf("终止帧不应携带 delta 内容: %q", s)
	}
	if !strings.HasSuffix(s, "data: [DONE]\n\n") {
		t.Fatal("content_filter 流未以 [DONE] 正常终止")
	}
}

// TestDecryptSSEBodyUnknownFinish OG-16：除 stop/content_filter 外的终止码
// （如旧拼写 "filter"）仍 fail-closed，防止未知终止语义被静默放行。
func TestDecryptSSEBodyUnknownFinish(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "partial"},
		{Seq: 2, Delta: "", Finish: "filter"},
	}, []uint64{1, 2})
	if out, err := decryptSSEBody(body, "req123", "mock"); err == nil {
		t.Fatalf("未知 finish 码应拒绝，但返回明文: %q", string(out))
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

// ---------------- P1b 增量状态机测试 ----------------
// SSEStreamDecoder.Feed：跨帧拼合、乱序/重放/截断/篡改拒绝，安全语义与整包解密等价。
// 注：sseChunk.Created = time.Now()，故不对比两次运行的完整字节，改用结构包含判定。

// feedAll 逐字节喂入（frame=1，最细粒度跨帧边界），末尾帧置 isLastChunk=true。
func feedAll(dec *SSEStreamDecoder, data []byte) ([]byte, error) {
	var out []byte
	for i := 0; i < len(data); i++ {
		last := i == len(data)-1
		chunk, err := dec.Feed(data[i:i+1], last)
		if err != nil {
			return out, err
		}
		out = append(out, chunk...)
	}
	return out, nil
}

// TestSSEDecoderIncrementalValid 合法流跨帧重组：逐字节喂入，重组结果与整包版结构一致。
func TestSSEDecoderIncrementalValid(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "Hello"},
		{Seq: 2, Delta: " 世界"},
		{Seq: 3, Delta: "", Finish: "stop"},
	}, []uint64{1, 2, 3})
	out, err := feedAll(NewSSEStreamDecoder("reqInc", "modelInc"), body)
	if err != nil {
		t.Fatalf("增量解密失败: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`"object":"chat.completion.chunk"`,
		`"id":"reqInc"`,
		`"model":"modelInc"`,
		`"delta":{"content":"Hello"`,
		`"delta":{"content":" 世界"`,
		`"finish_reason":"stop"`,
		"data: [DONE]",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("增量重组缺 %q: %q", want, s)
		}
	}
	if !strings.HasSuffix(s, "data: [DONE]\n\n") {
		t.Fatal("增量流未以 [DONE] 终止")
	}
}

// TestSSEDecoderIncrementalCoarseFrame 粗粒度跨帧（frame=5）同样正确重组。
func TestSSEDecoderIncrementalCoarseFrame(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 2, Delta: "b", Finish: "stop"},
	}, []uint64{1, 2})
	dec := NewSSEStreamDecoder("reqC", "modelC")
	var out []byte
	frame := 5
	for i := 0; i < len(body); i += frame {
		end := i + frame
		if end > len(body) {
			end = len(body)
		}
		chunk, err := dec.Feed(body[i:end], end == len(body))
		if err != nil {
			t.Fatalf("Feed: %v", err)
		}
		out = append(out, chunk...)
	}
	s := string(out)
	if !strings.Contains(s, `"delta":{"content":"a"`) || !strings.Contains(s, "data: [DONE]") {
		t.Fatalf("粗粒度跨帧重组异常: %q", s)
	}
}

// TestSSEDecoderIncrementalReorder 流内序号乱序（1→3）→ 整流拒绝。
func TestSSEDecoderIncrementalReorder(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 3, Delta: "c"},
	}, []uint64{1, 2})
	if _, err := feedAll(NewSSEStreamDecoder("reqR", "modelR"), body); err == nil {
		t.Fatal("流内序号乱序未被拒绝")
	}
}

// TestSSEDecoderIncrementalReplay 外层计数器重放 → 整流拒绝。
func TestSSEDecoderIncrementalReplay(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 2, Delta: "b", Finish: "stop"},
	}, []uint64{1, 1}) // 第二分片重放 counter=1
	if _, err := feedAll(NewSSEStreamDecoder("reqP", "modelP"), body); err == nil {
		t.Fatal("外层计数器重放未被拒绝")
	}
}

// TestSSEDecoderIncrementalTruncated 流被截断（缺 finish，无 [DONE] 亦然）→ 整流拒绝。
func TestSSEDecoderIncrementalTruncated(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 2, Delta: "b"},
	}, []uint64{1, 2})
	// 去掉末尾 [DONE] 行与空行，模拟流被硬截断
	trim := bytes.TrimSuffix(body, []byte("data: [DONE]\n\n"))
	if _, err := feedAll(NewSSEStreamDecoder("reqT", "modelT"), trim); err == nil {
		t.Fatal("截断流（缺 finish）未被拒绝")
	}
}

// TestSSEDecoderIncrementalFinishError finish="error" → fail-closed 整流拒绝。
func TestSSEDecoderIncrementalFinishError(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "partial"},
		{Seq: 2, Delta: "", Finish: "error"},
	}, []uint64{1, 2})
	if _, err := feedAll(NewSSEStreamDecoder("reqF", "modelF"), body); err == nil {
		t.Fatal("finish=error 未被拒绝")
	}
}

// TestSSEDecoderIncrementalContentFilter OG-16：增量路径 content_filter 正常收尾，
// guard 顶层透传，ContentFiltered() 标志置位；stop 流标志须保持 false。
func TestSSEDecoderIncrementalContentFilter(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "安全前缀"},
		{Seq: 2, Finish: "content_filter", Guard: &chunkGuard{
			Detected:      true,
			Filtered:      true,
			Action:        "block",
			Category:      "A1-06",
			PolicyVersion: "pol-v1",
			Mode:          "enforcing",
		}},
	}, []uint64{1, 2})
	dec := NewSSEStreamDecoder("reqICF", "modelICF")
	if dec.ContentFiltered() {
		t.Fatal("新建解码器 ContentFiltered 应为 false")
	}
	out, err := feedAll(dec, body)
	if err != nil {
		t.Fatalf("增量 content_filter 应正常收尾，实际拒绝: %v", err)
	}
	s := string(out)
	for _, want := range []string{
		`"delta":{"content":"安全前缀"}`,
		`"finish_reason":"content_filter"`,
		`"category":"A1-06"`,
		`"mode":"enforcing"`,
		"data: [DONE]",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("增量 content_filter 重组缺 %q: %q", want, s)
		}
	}
	if !strings.HasSuffix(s, "data: [DONE]\n\n") {
		t.Fatal("增量 content_filter 流未以 [DONE] 终止")
	}
	if !dec.ContentFiltered() {
		t.Fatal("content_filter 收尾后 ContentFiltered() 应为 true")
	}
	// 对照：stop 正常结束的流标志保持 false
	stopBody := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "ok", Finish: "stop"},
	}, []uint64{3})
	stopDec := NewSSEStreamDecoder("reqS", "modelS")
	if _, err := feedAll(stopDec, stopBody); err != nil {
		t.Fatalf("stop 对照流解密失败: %v", err)
	}
	if stopDec.ContentFiltered() {
		t.Fatal("stop 流 ContentFiltered 不应为 true")
	}
}

// TestSSEDecoderIncrementalUnknownFinish OG-16：增量路径未知终止码（"filter"）仍整流拒绝。
func TestSSEDecoderIncrementalUnknownFinish(t *testing.T) {
	_, kenc := newSessionForTest(t)
	body := buildSSEStream(t, kenc, Session.SessionID, []streamChunk{
		{Seq: 1, Delta: "partial"},
		{Seq: 2, Delta: "", Finish: "filter"},
	}, []uint64{1, 2})
	if _, err := feedAll(NewSSEStreamDecoder("reqUF", "modelUF"), body); err == nil {
		t.Fatal("增量路径未知 finish 码未被拒绝")
	}
}

// TestSSEDecoderIncrementalEmpty 仅 [DONE] 空流 → 拒绝（判空流）。
func TestSSEDecoderIncrementalEmpty(t *testing.T) {
	newSessionForTest(t)
	if _, err := feedAll(NewSSEStreamDecoder("reqE", "modelE"), []byte("data: [DONE]\n\n")); err == nil {
		t.Fatal("无加密分片的 [DONE] 空流未被拒绝")
	}
}

// TestSSEDecoderIncrementalLatch 首次 error 后状态机闭锁：后续帧一律返回同一错误，不透传明文。
func TestSSEDecoderIncrementalLatch(t *testing.T) {
	newSessionForTest(t)
	dec := NewSSEStreamDecoder("reqL", "modelL")
	// 直接喂入非法数据触发首错
	if _, err := dec.Feed([]byte("data: nothex!\n\n"), false); err == nil {
		t.Fatal("非法 hex 分片未被拒绝")
	}
	// 闭锁后合法数据帧也应被拒绝（不透传明文）
	if _, err := dec.Feed([]byte("data: 616263\n\n"), true); err == nil {
		t.Fatal("闭锁后新帧未被拒绝")
	}
}
