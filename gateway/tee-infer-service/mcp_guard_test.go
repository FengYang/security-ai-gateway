package main

// P1-1 G-8（T-5 步 5 / M8-2）场景 A：统一 text 载荷内 assistant.tool_calls 经 TEE 内 mcpguard 裁决。
// 验证 mcpguard 已接入主流程（闭 GP-8）：未就绪 fail-closed、RBAC 拒绝 → 403 且审计留痕、放行 → 200。

import (
	"bytes"
	"net/http"
	"testing"
	"time"

	"security-ai-gateway/gateway/mcpsec"
	"security-ai-gateway/gateway/tee-infer-service/mcpguard"
	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

// buildToolCallInferRequest 构造含 assistant.tool_calls 的 text 载荷推理请求（会话签名 + c2s 信封）。
func buildToolCallInferRequest(t *testing.T, fullURL, sessionID string, ksig, kenc []byte,
	payload []byte, tenant string, counter uint64) *http.Request {
	t.Helper()
	req := &protocol.InferenceRequest{
		RequestID:    nextTestRequestID("mcp"),
		TimestampNS:  time.Now().UnixNano(),
		Model:        "mock",
		MaxNewTokens: 32,
		Nonce:        make([]byte, 16),
		EngineType:   protocol.EngineTypeTEEGPU,
		AttestType:   protocol.AttestTypeQuote,
		TextPayload:  payload,
		Stream:       true,
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
	if tenant != "" {
		hr.Header.Set("X-Tenant-ID", tenant)
	}
	return hr
}

// toolCallPayload 构造统一 text 载荷（单条 assistant.tool_calls）。
func toolCallPayload(tool, args string) []byte {
	return []byte(`[{"role":"assistant","content":"","tool_calls":[{"id":"call_1","type":"function",` +
		`"function":{"name":` + strconvQuote(tool) + `,"arguments":` + strconvQuote(args) + `}}]}]`)
}

// testMCPCache 构造已就绪的 mcpguard 缓存（目录含 secure_ok[secure]；策略仅授权 tenant）。
func testMCPCache(t *testing.T, tenant string) *mcpguard.PolicyCache {
	t.Helper()
	key := bytes.Repeat([]byte{0x5A}, 32)
	sig, err := mcpsec.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := mcpguard.NewCache(key)
	if err != nil {
		t.Fatal(err)
	}
	cat := mcpsec.NewToolCatalog(1, 1000)
	cat.Tools = []mcpsec.TableTool{{Name: "secure_ok", CatalogOwner: "o", Track: mcpsec.TrackSecure}}
	if err := sig.SignCatalog(cat); err != nil {
		t.Fatal(err)
	}
	if !cache.UpdateCatalog(cat) {
		t.Fatal("UpdateCatalog 应成功")
	}
	pol := mcpsec.NewRBACPolicy(1, 1000)
	pol.TenantRules = map[string]map[string]*mcpsec.PolicyBinding{tenant: {"secure_ok": {}}}
	if err := sig.SignPolicy(pol); err != nil {
		t.Fatal(err)
	}
	if !cache.UpdatePolicy(pol) {
		t.Fatal("UpdatePolicy 应成功")
	}
	return cache
}

// lastDenyReason 返回审计链中最后一条 deny 事件的 result（无则空串）。
func lastDenyReason(srv *teeServer) string {
	out := ""
	for _, e := range srv.audit.query("") {
		if e.Action == "deny" {
			out = e.Result
		}
	}
	return out
}

// TestMCPToolCallsFailClosedWhenNotReady 治理未启用（mcpEngine/cache 为 nil）→ 含 tool_calls 请求 403 + 审计。
func TestMCPToolCallsFailClosedWhenNotReady(t *testing.T) {
	srv, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildToolCallInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc,
		toolCallPayload("secure_ok", `{}`), "", 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("治理未就绪应 403（fail-closed），got %d", resp.StatusCode)
	}
	if got := lastDenyReason(srv); got != "mcp_guard_not_ready" {
		t.Fatalf("审计 result 应为 mcp_guard_not_ready，got %q", got)
	}
}

// TestMCPToolCallsDeniedByRBAC 治理就绪但租户未授权 → 403 + 审计 mcp_tool_deny。
func TestMCPToolCallsDeniedByRBAC(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.mcpCache = testMCPCache(t, "other") // 仅授权 other，请求租户 ta 未授权
	srv.mcpEngine = mcpguard.NewEngine(srv.mcpCache)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildToolCallInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc,
		toolCallPayload("secure_ok", `{}`), "ta", 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("越权工具应 403，got %d", resp.StatusCode)
	}
	if got := lastDenyReason(srv); got != "mcp_tool_deny" {
		t.Fatalf("审计 result 应为 mcp_tool_deny，got %q", got)
	}
}

// TestMCPToolCallsAllowed 治理就绪且租户已授权 → 放行（200，主流程继续）。
func TestMCPToolCallsAllowed(t *testing.T) {
	srv, ts := newM9Server(t)
	srv.mcpCache = testMCPCache(t, "ta")
	srv.mcpEngine = mcpguard.NewEngine(srv.mcpCache)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildToolCallInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc,
		toolCallPayload("secure_ok", `{"q":"x"}`), "ta", 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("授权工具应放行（200），got %d", resp.StatusCode)
	}
	if got := lastDenyReason(srv); got == "mcp_tool_deny" || got == "mcp_guard_not_ready" {
		t.Fatalf("放行请求不应产生 MCP 拒绝审计，got %q", got)
	}
}

// TestMCPNoToolCallsUnaffected 无 tool_calls 的载荷零行为变化（向后兼容）。
func TestMCPNoToolCallsUnaffected(t *testing.T) {
	srv, ts := newM9Server(t) // 治理未启用也不影响
	sessionID, ksig, kenc := setupTestSession(t, ts)
	hr := buildTextInferRequest(t, ts.URL+"/v1/infer", sessionID, ksig, kenc, "hi", protocol.EngineTypeTEEGPU, true, 1)
	resp, err := http.DefaultClient.Do(hr)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("无 tool_calls 应 200（治理未启用不影响），got %d", resp.StatusCode)
	}
	if got := lastDenyReason(srv); got == "mcp_tool_deny" || got == "mcp_guard_not_ready" {
		t.Fatalf("无 tool_calls 不应触发 MCP 门控，got %q", got)
	}
}
