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
	return New(sig, msig, rlsig, nil, store.NewMemory(), "tok",
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

// P1-6 M4.3：PUT /routes 非法 latency 组合 → 400 invalid_route（用户可见契约）；
// 合法组合对照 → 200。
func TestUpsertRouteLatencyValidation(t *testing.T) {
	s := testServer()
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/routes/t1/m1", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}
	// 非法：latency 策略缺 latency 段
	rec := put(`{"default_engine":"cmaas","strategy":"hybrid","endpoints":[{"name":"a","url":"https://a/v1","weight":1,"priority":1,"enabled":true}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("latency 策略缺段应 400，got %d body=%s", rec.Code, rec.Body.String())
	}
	var e struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	if e.Code != "invalid_route" {
		t.Fatalf("错误码应 invalid_route，got %q（body=%s）", e.Code, rec.Body.String())
	}
	// 非法：gamma 越界（0–5）
	rec = put(`{"default_engine":"cmaas","strategy":"latency-aware","latency":{"gamma":6},"endpoints":[{"name":"a","url":"https://a/v1","weight":1,"priority":1,"enabled":true}]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("gamma 越界应 400，got %d body=%s", rec.Code, rec.Body.String())
	}
	// 对照：合法组合（§6.1 示例字段）应 200
	rec = put(`{"default_engine":"cmaas","strategy":"latency-aware","latency":{"window_sec":300,"quantile":"p95","gamma":1,"min_weight":0.05,"explore_ratio":0.05,"min_samples":20,"stale_sec":75,"cache_partition":true,"max_ttft_ms":30000},"endpoints":[{"name":"a","url":"https://a/v1","weight":1,"priority":1,"enabled":true}]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("合法组合应 200，got %d body=%s", rec.Code, rec.Body.String())
	}
}
