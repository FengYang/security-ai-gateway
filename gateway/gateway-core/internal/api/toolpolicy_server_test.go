package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/mcpsec"
)

func doToolPolicy(s *Server, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/tools/policy", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func doGetToolPolicy(s *Server, kind, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/tools/policy?kind="+kind, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestToolPolicyUnauthorized(t *testing.T) {
	s := testServer()
	if rec := doToolPolicy(s, `{"kind":"catalog","data":{}}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 token 应 401，got %d", rec.Code)
	}
	if rec := doGetToolPolicy(s, "catalog", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET 无 token 应 401，got %d", rec.Code)
	}
}

func TestToolPolicyBadKind(t *testing.T) {
	s := testServer()
	if rec := doToolPolicy(s, `{"kind":"bogus","data":{}}`, "tok"); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 kind 应 400，got %d", rec.Code)
	}
	if rec := doGetToolPolicy(s, "bogus", "tok"); rec.Code != http.StatusBadRequest {
		t.Fatalf("GET 非法 kind 应 400，got %d", rec.Code)
	}
}

func TestToolPolicyCatalogRoundtripAndVersion(t *testing.T) {
	s := testServer()
	body := `{"kind":"catalog","data":{"tools":[{"name":"db_query","catalog_owner":"tenant-a","schema":{"table":{"type":"string"}},"required":["table"]}]}}`
	rec := doToolPolicy(s, body, "tok")
	if rec.Code != http.StatusCreated {
		t.Fatalf("签发 catalog 应 201，got %d body=%s", rec.Code, rec.Body.String())
	}
	var c mcpsec.ToolCatalog
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 {
		t.Fatalf("首个目录版本应为 1，got %d", c.Version)
	}
	if !s.msigner.ValidCatalog(&c) {
		t.Fatal("服务端签发目录应验签通过")
	}
	// 再签发一次 → 版本单调自增到 2
	rec2 := doToolPolicy(s, body, "tok")
	if rec2.Code != http.StatusCreated {
		t.Fatalf("二次签发应 201，got %d", rec2.Code)
	}
	var c2 mcpsec.ToolCatalog
	_ = json.Unmarshal(rec2.Body.Bytes(), &c2)
	if c2.Version != 2 {
		t.Fatalf("版本应单调自增到 2，got %d", c2.Version)
	}
	// GET 往返校验
	g := doGetToolPolicy(s, "catalog", "tok")
	if g.Code != http.StatusOK {
		t.Fatalf("GET catalog 应 200，got %d", g.Code)
	}
	var got mcpsec.ToolCatalog
	if err := json.Unmarshal(g.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !s.msigner.ValidCatalog(&got) || got.Version != 2 || len(got.Tools) != 1 {
		t.Fatalf("GET 往返校验失败: version=%d tools=%d", got.Version, len(got.Tools))
	}
}

func TestToolPolicyRBACRoundtrip(t *testing.T) {
	s := testServer()
	body := `{"kind":"policy","data":{"tenant_rules":{"tenant-a":{"db_query":{"deny_params":["sql"]}}}}}`
	rec := doToolPolicy(s, body, "tok")
	if rec.Code != http.StatusCreated {
		t.Fatalf("签发 policy 应 201，got %d body=%s", rec.Code, rec.Body.String())
	}
	var p mcpsec.RBACPolicy
	if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	if !s.msigner.ValidPolicy(&p) {
		t.Fatal("服务端签发策略应验签通过")
	}
	if b := p.TenantRules["tenant-a"]["db_query"]; b == nil || len(b.DenyParams) != 1 {
		t.Fatalf("deny_params 往返缺失: %+v", b)
	}
	// 客户端提交的 version/signature 不得被采信：此时应被服务端重写
	g := doGetToolPolicy(s, "policy", "tok")
	var got mcpsec.RBACPolicy
	_ = json.Unmarshal(g.Body.Bytes(), &got)
	if !s.msigner.ValidPolicy(&got) || got.Version != p.Version {
		t.Fatalf("GET policy 校验失败: version=%d", got.Version)
	}
}