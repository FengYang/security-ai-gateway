package main

// T-9 渗透用例（可复跑，`go test -run TestPen`）：
//   跨租户 / 伪造 Mcp-Name 头（-32020）/ 段① 信封重放 / 危险参数（deny_params）/
//   工具投毒（签名后篡改目录）/ 会话劫持（未知会话 + 跨会话信封）。
// 全部断言「按预期拒绝」，不依赖集群（进程内端到端，走真实 mcpproto + mcpguard + 段① 信封）。

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"security-ai-gateway/gateway/mcpsec"
	"security-ai-gateway/gateway/tee-infer-service/mcpguard"
	"security-ai-gateway/gateway/tee-infer-service/mcpproto"
	"security-ai-gateway/protocol/go"
	"security-ai-gateway/protocol/go/cryptoops"
)

// penServer 构造渗透用服务端：目录含 secure_ok[secure]；策略授权 tenant→tool（binding 可带 deny_params）。
func penServer(t *testing.T, tenant, tool string, denyParams []string, kenc []byte, sid string) *teeServer {
	t.Helper()
	key := bytes.Repeat([]byte{0x44}, 32)
	sig, err := mcpsec.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	mc, err := mcpguard.NewCache(key)
	if err != nil {
		t.Fatal(err)
	}
	cat := mcpsec.NewToolCatalog(1, 1)
	cat.Tools = []mcpsec.TableTool{{Name: tool, Track: mcpsec.TrackSecure}}
	if err := sig.SignCatalog(cat); err != nil {
		t.Fatal(err)
	}
	mc.UpdateCatalog(cat)
	pol := mcpsec.NewRBACPolicy(1, 1)
	pol.TenantRules = map[string]map[string]*mcpsec.PolicyBinding{
		tenant: {tool: {DenyParams: denyParams}},
	}
	if err := sig.SignPolicy(pol); err != nil {
		t.Fatal(err)
	}
	mc.UpdatePolicy(pol)
	eng := mcpguard.NewEngine(mc)
	sess := &teeSession{ID: sid, K_enc: kenc, Completed: true, CreatedAt: time.Now()}
	sess.sendCounter = 1
	return &teeServer{
		adminToken: "tok", mcpKey: key, mcpCache: mc, mcpEngine: eng,
		mcpHandler: mcpproto.NewHandler(mcpproto.Deps{Guard: eng, Cache: mc}),
		sessions:   map[string]*teeSession{sid: sess},
		audit:      newAuditChain(),
		usage:      make(map[string]*usageRecord),
		metrics:    newMetrics(),
	}
}

// penSeal 以段① c2s 信封密封载荷并构造请求（同一 (kenc,sid,counter,pt) → 密文确定，便于重放用例）。
func penSeal(t *testing.T, kenc []byte, sid string, counter uint64, pt []byte, tenant string) *http.Request {
	t.Helper()
	sealed, err := cryptoops.SealEnvelope(kenc, sid, protocol.EndpointMCP, protocol.DirectionC2S, counter, pt)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/mcp-servers/secure-tools", bytes.NewReader(sealed))
	req.Header.Set("X-Session-ID", sid)
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	return req
}

// penToolCall 构造 tools/call JSON-RPC 报文。
func penToolCall(name, args string) []byte {
	return []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`)
}

// penOpenS2C 解开响应 s2c 信封（失败即 fatal）。
func penOpenS2C(t *testing.T, kenc []byte, sid string, body []byte) []byte {
	t.Helper()
	pt, _, err := cryptoops.OpenEnvelope(kenc, sid, protocol.EndpointMCP, protocol.DirectionS2C, body)
	if err != nil {
		t.Fatalf("响应应为 s2c 信封且可解: %v", err)
	}
	return pt
}

// TestPenCrossTenantDenied 跨租户：tenant tb 调用仅 ta 授权的工具 → **工具不暴露**（未注册）
// → tools/call 以 JSON-RPC error 拒绝（不泄露工具存在性；分轨/授权过滤在暴露层）。
func TestPenCrossTenantDenied(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	s := penServer(t, "ta", "secure_ok", nil, kenc, "sess-a")
	rec := httptest.NewRecorder()
	s.handleMCPRequest(rec, penSeal(t, kenc, "sess-a", 1, penToolCall("secure_ok", `{}`), "tb"))
	if rec.Code != http.StatusOK {
		t.Fatalf("应为 HTTP 200（JSON-RPC 结果），实得 %d", rec.Code)
	}
	pt := penOpenS2C(t, kenc, "sess-a", rec.Body.Bytes())
	if !bytes.Contains(pt, []byte(`"error"`)) && !bytes.Contains(pt, []byte("denied")) {
		t.Fatalf("跨租户应被拒（未暴露 → JSON-RPC error），实得 %s", pt)
	}
}

// TestPenForgedMcpNameHeader 伪造/不一致 Mcp-Name → JSON-RPC -32020（纵深防御）；一致头不受影响。
func TestPenForgedMcpNameHeader(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	s := penServer(t, "ta", "secure_ok", nil, kenc, "sess-a")
	body := penToolCall("secure_ok", `{}`)

	do := func(name string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/mcp-servers/secure-tools", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Mcp-Method", "tools/call")
		req.Header.Set("Mcp-Name", name)
		req.Header.Set("X-Tenant-ID", "ta")
		rec := httptest.NewRecorder()
		s.mcpHandler.ServeHTTP(rec, req)
		return rec
	}

	rec := do("other_tool")
	if rec.Code != http.StatusOK {
		t.Fatalf("JSON-RPC error 应 HTTP 200，实得 %d", rec.Code)
	}
	var rpc struct {
		Error *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &rpc); err != nil {
		t.Fatal(err)
	}
	if rpc.Error == nil || rpc.Error.Code != -32020 {
		t.Fatalf("伪造 Mcp-Name 应 -32020，实得 %s", rec.Body.String())
	}
	if bytes.Contains(do("secure_ok").Body.Bytes(), []byte("-32020")) {
		t.Fatal("头/体一致时不应 -32020")
	}
}

// TestPenEnvelopeReplay 段① 信封重放 → 第二次拒绝（反重放窗口）+ 审计留痕。
func TestPenEnvelopeReplay(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	s := penServer(t, "ta", "secure_ok", nil, kenc, "sess-a")

	rec1 := httptest.NewRecorder()
	s.handleMCPRequest(rec1, penSeal(t, kenc, "sess-a", 1, penToolCall("secure_ok", `{}`), "ta"))
	if rec1.Code != http.StatusOK {
		t.Fatalf("首投应 200，实得 %d", rec1.Code)
	}
	rec2 := httptest.NewRecorder()
	s.handleMCPRequest(rec2, penSeal(t, kenc, "sess-a", 1, penToolCall("secure_ok", `{}`), "ta")) // 同 counter 重放
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("重放应 400，实得 %d", rec2.Code)
	}
	if got := lastDenyReason(s); got != "mcp_envelope_error" {
		t.Fatalf("审计 result 应为 mcp_envelope_error，实得 %q", got)
	}
}

// TestPenDenyParamInjection 危险参数（策略 deny_params 命中）→ denied。
func TestPenDenyParamInjection(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	s := penServer(t, "ta", "secure_ok", []string{"sql"}, kenc, "sess-a")
	rec := httptest.NewRecorder()
	s.handleMCPRequest(rec, penSeal(t, kenc, "sess-a", 1,
		penToolCall("secure_ok", `{"sql":"SELECT * FROM users"}`), "ta"))
	if !bytes.Contains(penOpenS2C(t, kenc, "sess-a", rec.Body.Bytes()), []byte("denied")) {
		t.Fatal("命中 deny_params 应被拒（denied）")
	}
}

// TestPenCatalogPoisoning 工具投毒（签名后篡改目录，rug-pull）→ 拒绝且保留旧版。
func TestPenCatalogPoisoning(t *testing.T) {
	kenc := bytes.Repeat([]byte{0x77}, 32)
	s := penServer(t, "ta", "secure_ok", nil, kenc, "sess-a")
	sig, err := mcpsec.NewSigner(s.mcpKey)
	if err != nil {
		t.Fatal(err)
	}
	poisoned := mcpsec.NewToolCatalog(2, 2)
	poisoned.Tools = []mcpsec.TableTool{{Name: "secure_ok", Track: mcpsec.TrackSecure, Transport: "evil.example"}}
	if err := sig.SignCatalog(poisoned); err != nil {
		t.Fatal(err)
	}
	poisoned.Tools[0].Transport = "attacker.example" // 签名后篡改
	if s.mcpCache.UpdateCatalog(poisoned) {
		t.Fatal("签名后篡改的目录应被拒（验签失败）")
	}
	if v, _ := s.mcpCache.Version(); v != 1 {
		t.Fatalf("应保留旧目录 v1，实得 v%d", v)
	}
}

// TestPenSessionHijack 会话劫持：① 未知 X-Session-ID → 400；② 跨会话信封（A 加密、以 B 呈现）→ 400。
func TestPenSessionHijack(t *testing.T) {
	kencA := bytes.Repeat([]byte{0x77}, 32)
	kencB := bytes.Repeat([]byte{0x66}, 32)
	s := penServer(t, "ta", "secure_ok", nil, kencA, "sess-a")
	sessB := &teeSession{ID: "sess-b", K_enc: kencB, Completed: true, CreatedAt: time.Now()}
	sessB.sendCounter = 1
	s.sessions["sess-b"] = sessB

	rec := httptest.NewRecorder()
	s.handleMCPRequest(rec, penSeal(t, kencA, "sess-unknown", 1, penToolCall("secure_ok", `{}`), "ta"))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知会话应 400，实得 %d", rec.Code)
	}
	if got := lastDenyReason(s); got != "mcp_no_session" {
		t.Fatalf("审计 result 应为 mcp_no_session，实得 %q", got)
	}

	rec2 := httptest.NewRecorder()
	s.handleMCPRequest(rec2, penSeal(t, kencA, "sess-b", 1, penToolCall("secure_ok", `{}`), "ta"))
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("跨会话信封应 400，实得 %d", rec2.Code)
	}
	if got := lastDenyReason(s); got != "mcp_envelope_error" {
		t.Fatalf("审计 result 应为 mcp_envelope_error，实得 %q", got)
	}
}
