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
	protocol.SignRequest(ksig, req)
	enc, err := protocol.EncodeRequest(req)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := protocol.SealEnvelope(kenc, sessionID, protocol.EndpointInfer, protocol.DirectionC2S, counter, enc)
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
		pt, counter, err := protocol.OpenEnvelope(kenc, sessionID, protocol.EndpointInfer, protocol.DirectionS2C, wire)
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
	protocol.SignRequest(bytes.Repeat([]byte{0x42}, 32), req) // 全局 K_sig（newM9Server 固定）
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
