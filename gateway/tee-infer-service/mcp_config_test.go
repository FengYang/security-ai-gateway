package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"security-ai-gateway/gateway/mcpsec"
	"security-ai-gateway/gateway/tee-infer-service/mcpguard"
)

func mcpTestServer(t *testing.T) (*teeServer, *mcpsec.Signer, []byte) {
	t.Helper()
	key := bytes.Repeat([]byte{0x33}, 32)
	sig, err := mcpsec.NewSigner(key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	mc, err := mcpguard.NewCache(key)
	if err != nil {
		t.Fatalf("NewCache: %v", err)
	}
	return &teeServer{adminToken: "tok", mcpKey: key, mcpCache: mc, mcpEngine: mcpguard.NewEngine(mc)}, sig, key
}

func signedCatalog(t *testing.T, sig *mcpsec.Signer, version int) *mcpsec.ToolCatalog {
	t.Helper()
	c := mcpsec.NewToolCatalog(version, 1)
	c.Tools = []mcpsec.TableTool{{Name: "secure_ok", Track: mcpsec.TrackSecure}}
	if err := sig.SignCatalog(c); err != nil {
		t.Fatalf("SignCatalog: %v", err)
	}
	return c
}

func signedPolicy(t *testing.T, sig *mcpsec.Signer, version int) *mcpsec.RBACPolicy {
	t.Helper()
	p := mcpsec.NewRBACPolicy(version, 1)
	p.TenantRules = map[string]map[string]*mcpsec.PolicyBinding{"ta": {"secure_ok": {}}}
	if err := sig.SignPolicy(p); err != nil {
		t.Fatalf("SignPolicy: %v", err)
	}
	return p
}

func TestMCPConfigSnapshotUnauthorized(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	rec := httptest.NewRecorder()
	s.handleMCPConfig(rec, httptest.NewRequest(http.MethodGet, "/config/mcp", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，实得 %d", rec.Code)
	}
}

func TestMCPConfigSnapshot(t *testing.T) {
	s, sig, _ := mcpTestServer(t)
	s.mcpCache.UpdateCatalog(signedCatalog(t, sig, 1))
	s.mcpCache.UpdatePolicy(signedPolicy(t, sig, 1))

	req := httptest.NewRequest(http.MethodGet, "/config/mcp", nil)
	req.Header.Set(adminHeader, "tok")
	rec := httptest.NewRecorder()
	s.handleMCPConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，实得 %d", rec.Code)
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("解析快照失败: %v", err)
	}
	if got["ready"] != true || got["tools"].(float64) != 1 {
		t.Fatalf("快照不符: %v", got)
	}
}

func TestMCPConfigMethodNotAllowed(t *testing.T) {
	s, _, _ := mcpTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/config/mcp", nil)
	req.Header.Set(adminHeader, "tok")
	rec := httptest.NewRecorder()
	s.handleMCPConfig(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET 应 405，实得 %d", rec.Code)
	}
}

func TestMCPPolicyAppliesSignedObjects(t *testing.T) {
	s, sig, _ := mcpTestServer(t)
	body, _ := json.Marshal(mcpPolicyRequest{Catalog: signedCatalog(t, sig, 5), Policy: signedPolicy(t, sig, 5)})
	req := httptest.NewRequest(http.MethodPost, "/config/mcp/policy", bytes.NewReader(body))
	req.Header.Set(adminHeader, "tok")
	rec := httptest.NewRecorder()
	s.handleMCPPolicy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("应 200，实得 %d（%s）", rec.Code, rec.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["catalog_applied"] != true || got["policy_applied"] != true {
		t.Fatalf("合法签名应 applied=true: %v", got)
	}
	if !s.mcpCache.Ready() {
		t.Fatal("更新后缓存应就绪")
	}
}

func TestMCPPolicyKeepsOldOnBadSignature(t *testing.T) {
	s, sig, _ := mcpTestServer(t)
	// 先装入合法 v5
	s.mcpCache.UpdateCatalog(signedCatalog(t, sig, 5))
	// 再投递被篡改（签名失效）的 v6
	bad := signedCatalog(t, sig, 6)
	bad.Tools[0].Name = "tampered"
	body, _ := json.Marshal(mcpPolicyRequest{Catalog: bad})
	req := httptest.NewRequest(http.MethodPost, "/config/mcp/policy", bytes.NewReader(body))
	req.Header.Set(adminHeader, "tok")
	rec := httptest.NewRecorder()
	s.handleMCPPolicy(rec, req)

	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["catalog_applied"] != false {
		t.Fatalf("篡改应被拒: %v", got)
	}
	if v, _ := s.mcpCache.Version(); v != 5 {
		t.Fatalf("应保留旧目录 v5，实得 v%d", v)
	}
}

// TestMCPPolicyRejectsBadRequests T-9：handleMCPPolicy 边界（405 / 401 / 400 非法 JSON / 400 空对象）。
func TestMCPPolicyRejectsBadRequests(t *testing.T) {
	s, _, _ := mcpTestServer(t)

	// 非 POST → 405
	rec := httptest.NewRecorder()
	s.handleMCPPolicy(rec, httptest.NewRequest(http.MethodGet, "/config/mcp/policy", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 POST 应 405，实得 %d", rec.Code)
	}
	// 无令牌 → 401
	rec = httptest.NewRecorder()
	s.handleMCPPolicy(rec, httptest.NewRequest(http.MethodPost, "/config/mcp/policy", bytes.NewReader([]byte(`{}`))))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，实得 %d", rec.Code)
	}
	// 令牌正确但 body 非法 JSON → 400
	rec = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/mcp/policy", bytes.NewReader([]byte(`{oops`)))
	req.Header.Set(adminHeader, "tok")
	s.handleMCPPolicy(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 JSON 应 400，实得 %d", rec.Code)
	}
	// catalog/policy 皆缺 → 400
	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/config/mcp/policy", bytes.NewReader([]byte(`{}`)))
	req.Header.Set(adminHeader, "tok")
	s.handleMCPPolicy(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("catalog/policy 皆缺应 400，实得 %d", rec.Code)
	}
}

// TestMCPPolicySingleSide T-9：单边下发（仅 catalog / 仅 policy）各自生效。
func TestMCPPolicySingleSide(t *testing.T) {
	s, sig, _ := mcpTestServer(t)
	body, _ := json.Marshal(mcpPolicyRequest{Catalog: signedCatalog(t, sig, 1)})
	req := httptest.NewRequest(http.MethodPost, "/config/mcp/policy", bytes.NewReader(body))
	req.Header.Set(adminHeader, "tok")
	rec := httptest.NewRecorder()
	s.handleMCPPolicy(rec, req)
	var got map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got["catalog_applied"] != true {
		t.Fatalf("仅 catalog 应 applied=true: %v", got)
	}
	if _, ok := got["policy_applied"]; ok {
		t.Fatalf("仅 catalog 时不应出现 policy_applied: %v", got)
	}

	s2, sig2, _ := mcpTestServer(t)
	body2, _ := json.Marshal(mcpPolicyRequest{Policy: signedPolicy(t, sig2, 1)})
	req2 := httptest.NewRequest(http.MethodPost, "/config/mcp/policy", bytes.NewReader(body2))
	req2.Header.Set(adminHeader, "tok")
	rec2 := httptest.NewRecorder()
	s2.handleMCPPolicy(rec2, req2)
	var got2 map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &got2)
	if got2["policy_applied"] != true {
		t.Fatalf("仅 policy 应 applied=true: %v", got2)
	}
}
