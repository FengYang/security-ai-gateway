package main

// P2/P5 text 载荷路径集成测试：
// - token 模式无信封的 text 载荷 → 400（fail-closed，text 仅限证明会话）
// - quote 会话 + tee_gpu 本地引擎 → 200 SSE 信封流（seq 递增 + finish stop）
// - cmaas 引擎未配置 → 503（fail-closed）
// - Guardrail 拦截（PII / 提示注入）→ 403

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

// buildTextInferRequest 构造 text 载荷推理请求（会话签名 + c2s 信封）。
// counter 为 c2s 信封计数器（同会话内须单调唯一，避免反重放窗口拒绝）。
func buildTextInferRequest(t *testing.T, fullURL, sessionID string, ksig, kenc []byte,
	text string, engineType string, stream bool, counter uint64) *http.Request {
	t.Helper()
	req := &protocol.InferenceRequest{
		RequestID:    nextTestRequestID("text"),
		TimestampNS:  time.Now().UnixNano(),
		Model:        "mock",
		MaxNewTokens: 32,
		Nonce:        make([]byte, 16),
		EngineType:   engineType,
		AttestType:   protocol.AttestTypeQuote,
		TextPayload:  []byte(`[{"role":"user","content":` + strconvQuote(text) + `}]`),
		Stream:       stream,
	}
	cryptoops.SignRequest(ksig, req)
	enc, err := protocol.EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := cryptoops.SealEnvelope(kenc, sessionID, protocol.EndpointInfer, protocol.DirectionC2S, counter, enc)
	if err != nil {
		t.Fatal(err)
	}
	hr, _ := http.NewRequest("POST", fullURL, bytes.NewReader(sealed))
	hr.Header.Set("X-Session-ID", sessionID)
	hr.Header.Set("Content-Type", "application/octet-stream")
	return hr
}

// strconvQuote 简单 JSON 字符串转义（测试用；内容为 ASCII/中文无特殊字符）。
func strconvQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// decodeTextSSE 解密 SSE 信封流 → 明文增量 + 终止状态。
func decodeTextSSE(t *testing.T, body []byte, sessionID string, kenc []byte) (string, string) {
	t.Helper()
	var sb strings.Builder
	finish := ""
	lastSeq := uint64(0)
	sawDone := false
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimRight(line, "\r")
		data, ok := strings.CutPrefix(line, "data:")
		if !ok {
			continue
		}
		if strings.TrimSpace(data) == "[DONE]" {
			sawDone = true
			continue
		}
		wire, err := hex.DecodeString(strings.TrimSpace(data))
		if err != nil {
			t.Fatalf("SSE 分片非 hex: %v", err)
		}
		pt, counter, err := cryptoops.OpenEnvelope(kenc, sessionID, protocol.EndpointInfer, protocol.DirectionS2C, wire)
		if err != nil {
			t.Fatalf("SSE 分片解密失败: %v", err)
		}
		if counter != lastSeq+1 {
			t.Fatalf("s2c 计数器乱序: got=%d last=%d", counter, lastSeq)
		}
		lastSeq = counter
		var chunk textStreamChunk
		if err := json.Unmarshal(pt, &chunk); err != nil {
			t.Fatalf("分片 JSON 无效: %v", err)
		}
		sb.WriteString(chunk.Delta)
		if chunk.Finish != "" {
			finish = chunk.Finish
		}
	}
	if !sawDone {
		t.Fatal("SSE 流缺 [DONE]")
	}
	return sb.String(), finish
}

// TestTextInferRequiresSession token 模式（无会话）text 载荷 → 400 fail-closed。
func TestTextInferRequiresSession(t *testing.T) {
	_, ts := newM9Server(t)
	req := &protocol.InferenceRequest{
		RequestID:   nextTestRequestID("text"),
		TimestampNS: time.Now().UnixNano(),
		Model:       "mock",
		EngineType:  protocol.EngineTypeTEEGPU,
		AttestType:  protocol.AttestTypeToken, // token 模式：无会话
		TextPayload: []byte(`[{"role":"user","content":"hi"}]`),
	}
	cryptoops.SignRequest(bytes.Repeat([]byte{0x42}, 32), req) // 全局 K_sig（newM9Server 固定）
	enc, _ := protocol.EncodeRequest(req)
	hr, _ := http.NewRequest("POST", ts.URL+"/v1/infer", bytes.NewReader(enc))
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("token 模式 text 载荷应 400（fail-closed），got %d", resp.StatusCode)
	}
}

// TestTextInferSSE quote 会话 + tee_gpu（本地引擎）：SSE 信封流解密 → 明文回显 + finish=stop。
func TestTextInferSSE(t *testing.T) {
	srv, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc, "你好", protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("text 推理应 200，got %d", resp.StatusCode)
	}
	body := mustReadAll(t, resp.Body)
	text, finish := decodeTextSSE(t, body, sessionID, kenc)
	if text != "你好" {
		t.Fatalf("明文不符: %q", text)
	}
	if finish != "stop" {
		t.Fatalf("finish 应为 stop，got %q", finish)
	}
	// 审计已记录 infer 事件
	if srv.audit.countByAction("infer") < 1 {
		t.Fatal("审计未记录 infer 事件")
	}
}

// TestTextInferCmaasUnconfigured cmaas 引擎未配置 → 503（fail-closed）。
func TestTextInferCmaasUnconfigured(t *testing.T) {
	_, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc, "hi", protocol.EngineTypeCMAAS, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("cmaas 未配置应 503（fail-closed），got %d", resp.StatusCode)
	}
}

// TestTextInferGuardrail text 载荷 Guardrail（PII）→ 403 拦截（C-MaaS 无内容安全，本网关补位）。
func TestTextInferGuardrail(t *testing.T) {
	_, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	// 身份证号（PII 命中）
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc, "我的身份证是 110101199003078516", protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PII 文本应 403，got %d", resp.StatusCode)
	}
}

// TestTextInferCacheHit GF.4.1 精确缓存（演示）：相同输入第二次请求命中缓存，
// 跳过真实引擎以缓存文本回放；审计 infer 事件带 cache_hit 标记。
func TestTextInferCacheHit(t *testing.T) {
	srv, ts := newM9Server(t)
	const text = "缓存命中测试内容"

	// 第一次（会话1）：缓存未命中 → 本地引擎回显 → 回填缓存
	sessionID1, ksig1, kenc1 := setupTestSession(t, ts)
	hr1 := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID1, ksig1, kenc1, text, protocol.EngineTypeTEEGPU, true, 1)
	resp1, err := http.DefaultClient.Do(hr1)
	if err != nil {
		t.Fatal(err)
	}
	body1 := mustReadAll(t, resp1.Body)
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("首次推理应 200，got %d", resp1.StatusCode)
	}
	if out, finish := decodeTextSSE(t, body1, sessionID1, kenc1); out != text || finish != "stop" {
		t.Fatalf("首次明文不符: %q finish=%q", out, finish)
	}

	// 第二次（会话2，同租户）：相同输入 → 缓存命中（回放缓存文本，不再走引擎）
	sessionID2, ksig2, kenc2 := setupTestSession(t, ts)
	hr2 := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID2, ksig2, kenc2, text, protocol.EngineTypeTEEGPU, true, 1)
	resp2, err := http.DefaultClient.Do(hr2)
	if err != nil {
		t.Fatal(err)
	}
	body2 := mustReadAll(t, resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("缓存命中推理应 200，got %d", resp2.StatusCode)
	}
	if out, finish := decodeTextSSE(t, body2, sessionID2, kenc2); out != text || finish != "stop" {
		t.Fatalf("命中明文不符: %q finish=%q", out, finish)
	}

	// 审计：两次 infer，第一次 cache_hit=false，第二次 cache_hit=true
	var inferEvents []AuditEvent
	for _, e := range srv.audit.query("") {
		if e.Action == "infer" {
			inferEvents = append(inferEvents, e)
		}
	}
	if len(inferEvents) < 2 {
		t.Fatalf("应有至少 2 次 infer 审计，got %d", len(inferEvents))
	}
	first, second := inferEvents[len(inferEvents)-2], inferEvents[len(inferEvents)-1]
	if first.CacheHit {
		t.Fatal("首次 infer 不应 cache_hit")
	}
	if !second.CacheHit {
		t.Fatal("第二次 infer 应 cache_hit（精确缓存命中）")
	}
}

// TestTextInferCacheIsolation 缓存键租户/参数隔离：不同输入不命中缓存。
func TestTextInferCacheIsolation(t *testing.T) {
	srv, ts := newM9Server(t)

	sessionID1, ksig1, kenc1 := setupTestSession(t, ts)
	first := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID1, ksig1, kenc1, "输入A", protocol.EngineTypeTEEGPU, true, 1)
	resp1, err := http.DefaultClient.Do(first)
	if err != nil {
		t.Fatal(err)
	}
	body1 := mustReadAll(t, resp1.Body)
	resp1.Body.Close()
	if out, _ := decodeTextSSE(t, body1, sessionID1, kenc1); out != "输入A" {
		t.Fatalf("输入A 明文不符: %q", out)
	}

	sessionID2, ksig2, kenc2 := setupTestSession(t, ts)
	second := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID2, ksig2, kenc2, "输入B", protocol.EngineTypeTEEGPU, true, 1)
	resp2, err := http.DefaultClient.Do(second)
	if err != nil {
		t.Fatal(err)
	}
	body2 := mustReadAll(t, resp2.Body)
	resp2.Body.Close()
	if out, _ := decodeTextSSE(t, body2, sessionID2, kenc2); out != "输入B" {
		t.Fatalf("输入B 明文不符: %q（不同输入不应命中缓存）", out)
	}

	// 输入B 未命中，不应出现 cache_hit
	var hit bool
	for _, e := range srv.audit.query("") {
		if e.Action == "infer" && e.CacheHit {
			hit = true
		}
	}
	if hit {
		t.Fatal("不同输入不应触发 cache_hit")
	}
}
