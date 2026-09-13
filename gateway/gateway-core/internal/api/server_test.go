package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
	"security-ai-gateway/gateway/mcpsec"
)

func testServer() *Server {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sig, err := route.NewSigner(key)
	if err != nil {
		panic(err)
	}
	msig, err := mcpsec.NewSigner(key)
	if err != nil {
		panic(err)
	}
	rlsig, err := ratelimit.NewSigner(key)
	if err != nil {
		panic(err)
	}
	return New(sig, msig, rlsig, store.NewMemory(), "tok",
		route.NewRouteTable(1, 1725500000), ratelimit.NewTable(1, time.Unix(1725500000, 0)))
}

func doIssue(s *Server, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/prescriptions", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

func TestIssueMissingModel(t *testing.T) {
	s := testServer()
	rec := doIssue(s, `{"tenant":"tenant-a"}`, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 model 应 400，got %d", rec.Code)
	}
}

func TestIssueUnauthorized(t *testing.T) {
	s := testServer()
	rec := doIssue(s, `{"tenant":"tenant-a","model":"m"}`, "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无 token 应 401，got %d", rec.Code)
	}
}

func TestIssueOK(t *testing.T) {
	s := testServer()
	rec := doIssue(s, `{"tenant":"tenant-a","model":"qwen-plus","preferred_engine":"cmaas"}`, "tok")
	if rec.Code != http.StatusCreated {
		t.Fatalf("正常签发应 201，got %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		PrescriptionID string `json:"prescription_id"`
		SignedToken    string `json:"signed_token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.PrescriptionID == "" || resp.SignedToken == "" {
		t.Fatalf("字段不应为空: %+v", resp)
	}
}

func TestGetRoutes(t *testing.T) {
	s := testServer()
	req := httptest.NewRequest(http.MethodGet, "/routes", nil)
	req.Header.Set("Authorization", "Bearer tok")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/routes 应 200，got %d", rec.Code)
	}
	var tbl route.RouteTable
	if err := json.Unmarshal(rec.Body.Bytes(), &tbl); err != nil {
		t.Fatal(err)
	}
	_ = tbl
}
