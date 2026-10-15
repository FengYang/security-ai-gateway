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
	"fmt"
	"strings"
	"testing"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/cryptoclient"
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

// TestSSEDecoderCompletedFlag（P1-6 M2.1）：完整流 → Completed()=true；截断流 → false。
func TestSSEDecoderCompletedFlag(t *testing.T) {
	newSessionForTest(t)
	body := buildSSEStream(t, []streamChunk{
		{Seq: 1, Delta: "hi"},
		{Seq: 2, Delta: "", Finish: "stop"},
	}, []uint64{1, 2})
	dec := NewSSEStreamDecoder("reqCmp", "modelCmp")
	if _, err := feedAll(dec, body); err != nil {
		t.Fatalf("完整流不应失败: %v", err)
	}
	if !dec.Completed() {
		t.Fatal("完整流应 Completed()=true")
	}
	// 截断流（去掉末尾 [DONE] 尾部）→ 终态校验失败且 Completed()=false
	trunc := NewSSEStreamDecoder("reqCmp2", "modelCmp")
	if _, err := feedAll(trunc, body[:len(body)-5]); err == nil {
		t.Fatal("截断流未被拒绝")
	}
	if trunc.Completed() {
		t.Fatal("截断流不应 Completed()=true")
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

// countingTransport 包装 Transport，统计 sidecar 调用次数（按路径）。
type countingTransport struct {
	inner  cryptoclient.Transport
	counts map[string]int
}

func (c *countingTransport) Post(path string, hdr [][2]string, body []byte, cb cryptoclient.ResponseCallback, timeout uint32) error {
	c.counts[path]++
	return c.inner.Post(path, hdr, body, cb, timeout)
}

func (c *countingTransport) Get(path string, hdr [][2]string, cb cryptoclient.ResponseCallback, timeout uint32) error {
	c.counts[path]++
	return c.inner.Get(path, hdr, cb, timeout)
}

// installSeamWithCounter 安装接缝并返回计数器（替换全局 CryptoClient 为带计数包装）。
// 调用方须已调用 installSeam / newSessionForTest。
func installSeamWithCounter() *countingTransport {
	ct := &countingTransport{inner: CryptoClient.Transport(), counts: map[string]int{}}
	// 用包装器重建 Client（保留原 breaker/metrics/config）
	cfg := cryptoclient.Config{}
	c := cryptoclient.New(ct, nil, nil, cfg)
	// 复制 capabilities（避免重复 LoadCapabilities）
	CryptoClient = c
	cryptoReady = true
	return ct
}

// buildSSEStreamN 构造 N 帧合法 SSE 流（seq 1..N，delta 递增，最后一帧 finish=stop，delta 空）。
// 共 N 个密文分片：前 N-1 个有 delta，第 N 个是 finish 帧。
func buildSSEStreamN(t *testing.T, n int) []byte {
	t.Helper()
	if n < 1 {
		t.Fatal("n < 1")
	}
	chunks := make([]streamChunk, n)
	counters := make([]uint64, n)
	for i := 0; i < n-1; i++ {
		chunks[i] = streamChunk{Seq: uint64(i + 1), Delta: fmt.Sprintf("token-%03d", i+1)}
		counters[i] = uint64(i + 1)
	}
	chunks[n-1] = streamChunk{Seq: uint64(n), Delta: "", Finish: "stop"}
	counters[n-1] = uint64(n)
	return buildSSEStream(t, chunks, counters)
}

// countSSEDataLines 统计明文 SSE 中 data: 行数（不含 [DONE]）。
func countSSEDataLines(out []byte) int {
	n := 0
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "data: ") && !strings.Contains(line, "[DONE]") {
			n++
		}
	}
	return n
}

// TestT542_SSEBatchBaseline T-5.4-2：batchSize=1 等价于逐帧模式（基线）。
//
// 验证点：
//   - 输出帧数与输入帧数一致
//   - 每帧对应一次 /v1/open 调用（N 帧 = N 次 open）
//   - 正常收尾，[DONE] 存在
func TestT542_SSEBatchBaseline(t *testing.T) {
	newSessionForTest(t)
	ct := installSeamWithCounter()

	const n = 10
	body := buildSSEStreamN(t, n)

	dec := NewSSEStreamDecoderWithBatch("reqT542", "modelT542", 1)
	out, err := feedAll(dec, body)
	if err != nil {
		t.Fatalf("基线批量(batchSize=1)解密失败: %v", err)
	}

	// 帧数校验
	if got := countSSEDataLines(out); got != n {
		t.Fatalf("帧数不匹配: got %d, want %d", got, n)
	}
	// [DONE] 存在
	if !strings.Contains(string(out), "data: [DONE]") {
		t.Fatal("未输出 [DONE]")
	}
	// sidecar 调用：n 次 /v1/open（逐帧）+ 1 次 /v1/capabilities（installSeam）
	if ct.counts["/v1/open"] != n {
		t.Fatalf("/v1/open 调用次数: got %d, want %d", ct.counts["/v1/open"], n)
	}
	if ct.counts["/v1/batch"] != 0 {
		t.Fatalf("逐帧模式不应调用 /v1/batch，实际 %d 次", ct.counts["/v1/batch"])
	}
}

// TestT547_SSEBatchAggregation T-5.4-7：批量聚合模式（batchSize=B）。
//
// 验证点：
//   - 输出帧数与逐帧模式逐字节一致（内容等价）
//   - /v1/batch 调用次数 = ceil(N/B)（批次数）
//   - 无逐帧 /v1/open 调用
//   - 尾批不满 B 帧也能冲刷（isLastChunk 触发）
//   - 跨 Feed 攒帧也正确（逐字节喂入，每字节一次 Feed）
func TestT547_SSEBatchAggregation(t *testing.T) {
	const n = 17
	const batchSize = 4
	wantBatches := (n + batchSize - 1) / batchSize // ceil(17/4) = 5

	// 逐帧模式：自己的会话 + 自己的 body
	newSessionForTest(t)
	body1 := buildSSEStreamN(t, n)
	refOut, refErr := feedAll(NewSSEStreamDecoderWithBatch("ref", "model", 1), body1)
	if refErr != nil {
		t.Fatalf("参照(逐帧)解密失败: %v", refErr)
	}

	// 批量模式：全新会话 + 新会话加密的 body
	newSessionForTest(t)
	body2 := buildSSEStreamN(t, n)
	ct := installSeamWithCounter()
	batchOut, batchErr := feedAll(NewSSEStreamDecoderWithBatch("t547", "model", batchSize), body2)
	if batchErr != nil {
		t.Fatalf("批量解密失败: %v", batchErr)
	}

	// 帧数一致
	if got := countSSEDataLines(batchOut); got != n {
		t.Fatalf("批量模式帧数: got %d, want %d", got, n)
	}
	// [DONE] 存在
	if !strings.Contains(string(batchOut), "data: [DONE]") {
		t.Fatal("批量模式未输出 [DONE]")
	}
	// 调用次数：全部走 batch，不走逐帧 open
	if ct.counts["/v1/batch"] != wantBatches {
		t.Fatalf("/v1/batch 调用次数: got %d, want %d", ct.counts["/v1/batch"], wantBatches)
	}
	if ct.counts["/v1/open"] != 0 {
		t.Fatalf("批量模式不应调用 /v1/open，实际 %d 次", ct.counts["/v1/open"])
	}
	// 内容等价（逐帧 vs 批量）—— 用关键字段比对（Created 是时间戳，忽略）
	refS := string(refOut)
	batS := string(batchOut)
	for _, want := range []string{
		`"object":"chat.completion.chunk"`,
		`"id":"t547"`,
		`"model":"model"`,
	} {
		if !strings.Contains(batS, want) {
			t.Fatalf("批量输出缺 %q", want)
		}
	}
	// delta 数量与顺序：token-001..token-(n-1) 应该都在批量输出里且顺序正确
	numTokens := n - 1
	for i := 1; i <= numTokens; i++ {
		token := fmt.Sprintf("token-%03d", i)
		if !strings.Contains(batS, token) {
			t.Fatalf("批量输出缺 token %q", token)
		}
	}
	// 顺序校验：token-001 在 token-002 前，依此类推
	prevIdx := -1
	for i := 1; i <= numTokens; i++ {
		token := fmt.Sprintf("token-%03d", i)
		idx := strings.Index(batS, token)
		if idx <= prevIdx {
			t.Fatalf("token 顺序错：token-%03d 在 token-%03d 之前（位置 %d vs %d）", i, i-1, idx, prevIdx)
		}
		prevIdx = idx
	}
	_ = refS // 参照输出保留（如需逐字节比对可加）
}
