package main

// P1b SSE 加密流解密测试：合法流重组、乱序/重放/截断/篡改拒绝、isSSEBody 判定。
//
// P0-4 接线后：s2c 信封经会话方向子密钥（cryptoseam_test.go 的 in-process sidecar 接缝）加解密，
// 状态机 `SSEStreamDecoder.Feed` 为 CPS。seam Transport 同步回调 ⇒ 测试可同步驱动。

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"security-ai-gateway/protocol/go"
)

// buildSSEStream 服务端等价：构造加密 SSE 响应体（hex s2c 信封分片 + [DONE]）。
func buildSSEStream(t *testing.T, chunks []streamChunk, counters []uint64) []byte {
	t.Helper()
	var sb strings.Builder
	for i, c := range chunks {
		plain, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		wire := sealS2CForTest(t, protocol.EndpointInfer, counters[i], plain)
		sb.WriteString("data: " + hex.EncodeToString(wire) + "\n\n")
	}
	sb.WriteString("data: [DONE]\n\n")
	return []byte(sb.String())
}

// ---------------- P1b 增量状态机测试 ----------------
// SSEStreamDecoder.Feed：跨帧拼合、乱序/重放/截断/篡改拒绝，安全语义与整流一致。
// 注：sseChunk.Created = time.Now()，故不对比两次运行的完整字节，改用结构包含判定。

// feedAll 逐字节喂入（frame=1，最细粒度跨帧边界），末尾帧置 isLastChunk=true。
// seam Transport 同步回调 ⇒ 每次 Feed 立即回调一次。
func feedAll(dec *SSEStreamDecoder, data []byte) ([]byte, error) {
	var out []byte
	for i := 0; i < len(data); i++ {
		last := i == len(data)-1
		var chunk []byte
		var ferr error
		called := false
		dec.Feed(data[i:i+1], last, func(o []byte, e error) { chunk, ferr, called = o, e, true })
		if !called {
			return out, errors.New("seam 未同步回调")
		}
		if ferr != nil {
			return out, ferr
		}
		out = append(out, chunk...)
	}
	return out, nil
}

// TestSSEDecoderIncrementalValid 合法流跨帧重组：逐字节喂入，重组结果结构一致。
func TestSSEDecoderIncrementalValid(t *testing.T) {
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
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
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
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
		var chunk []byte
		var ferr error
		dec.Feed(body[i:end], end == len(body), func(o []byte, e error) { chunk, ferr = o, e })
		if ferr != nil {
			t.Fatalf("Feed: %v", ferr)
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
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 3, Delta: "c"},
	}, []uint64{1, 2})
	if _, err := feedAll(NewSSEStreamDecoder("reqR", "modelR"), body); err == nil {
		t.Fatal("流内序号乱序未被拒绝")
	}
}

// TestSSEDecoderIncrementalReplay 外层计数器重放 → 整流拒绝。
func TestSSEDecoderIncrementalReplay(t *testing.T) {
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 2, Delta: "b", Finish: "stop"},
	}, []uint64{1, 1}) // 第二分片重放 counter=1
	if _, err := feedAll(NewSSEStreamDecoder("reqP", "modelP"), body); err == nil {
		t.Fatal("外层计数器重放未被拒绝")
	}
}

// TestSSEDecoderIncrementalTruncated 流被截断（缺 finish，无 [DONE] 亦然）→ 整流拒绝。
func TestSSEDecoderIncrementalTruncated(t *testing.T) {
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
		{Seq: 1, Delta: "a"},
		{Seq: 2, Delta: "b"},
	}, []uint64{1, 2})
	// 去掉末尾 [DONE] 行与空行，模拟流被硬截断
	trim := bytes.TrimSuffix(body, []byte("data: [DONE]\n\n"))
	if _, err := feedAll(NewSSEStreamDecoder("reqT", "modelT"), trim); err == nil {
		t.Fatal("截断流（缺 finish）未被拒绝")
	}
}

// TestSSEDecoderIncrementalTamper 篡改任一分片密文 → 整流拒绝（不输出半截明文）。
func TestSSEDecoderIncrementalTamper(t *testing.T) {
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
		{Seq: 1, Delta: "a", Finish: "stop"},
	}, []uint64{1})
	// 篡改密文 hex（信封 wire 中部）
	idx := strings.Index(string(body), "data: ") + len("data: ") + 20
	b := append([]byte(nil), body...)
	b[idx] ^= 0x01
	if _, err := feedAll(NewSSEStreamDecoder("reqTM", "modelTM"), b); err == nil {
		t.Fatal("篡改分片未被拒绝")
	}
}

// TestSSEDecoderIncrementalFinishError finish="error" → fail-closed 整流拒绝。
func TestSSEDecoderIncrementalFinishError(t *testing.T) {
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
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
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
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
	stopBody := buildSSEStream(t, []streamChunk{
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
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
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
	var firstErr error
	dec.Feed([]byte("data: nothex!\n\n"), false, func(_ []byte, err error) { firstErr = err })
	if firstErr == nil {
		t.Fatal("非法 hex 分片未被拒绝")
	}
	// 闭锁后合法数据帧也应被拒绝（不透传明文）
	var latchErr error
	dec.Feed([]byte("data: 616263\n\n"), true, func(_ []byte, err error) { latchErr = err })
	if latchErr == nil {
		t.Fatal("闭锁后新帧未被拒绝")
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
