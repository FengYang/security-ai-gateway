package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
)

// doRateLimits 发起带鉴权的限流表请求。
func doRateLimits(s *Server, method, body, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, "/ratelimits", strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// validTableJSON 合法策略表（version 2 高于测试种子表 version 1）。
const validTableJSON = `{"version":2,"issued_at":"2026-09-13T10:00:00Z","rules":[
{"id":"t-a-rate","kind":"rate","scope":"tenant","target":"t-a","rpm":600,"action":"reject","enabled":true}]}`

// TestPutRateLimits_ok PUT 合法表：200 + 编译产物（600rpm → 10 QPS）。
func TestPutRateLimits_ok(t *testing.T) {
	s := testServer()
	rec := doRateLimits(s, http.MethodPut, validTableJSON, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Version           int             `json:"version"`
		Rules             int             `json:"rules"`
		DataPlaneCompiled bool            `json:"data_plane_compiled"`
		DataPlaneConfig   json.RawMessage `json:"data_plane_config"`
		Notes             []string        `json:"notes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Version != 2 || resp.Rules != 1 || !resp.DataPlaneCompiled {
		t.Fatalf("响应不符: %+v", resp)
	}
	var cfg ratelimit.DataPlaneConfig
	if err := json.Unmarshal(resp.DataPlaneConfig, &cfg); err != nil {
		t.Fatalf("编译产物解析失败: %v", err)
	}
	if len(cfg.RuleItems) != 1 || cfg.RuleItems[0].LimitByPerHeader != "x-tenant-id" ||
		cfg.RuleItems[0].LimitKeys[0].QueryPerSecond != 10 {
		t.Fatalf("编译产物不符: %+v", cfg)
	}
}

// TestGetRateLimits_signedAndVersioned GET 返回已签名的新版本表（插件侧可验签）。
func TestGetRateLimits_signedAndVersioned(t *testing.T) {
	s := testServer()
	if rec := doRateLimits(s, http.MethodPut, validTableJSON, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("前置 PUT 失败: %d", rec.Code)
	}
	rec := doRateLimits(s, http.MethodGet, "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rec.Code)
	}
	var tbl ratelimit.Table
	if err := json.Unmarshal(rec.Body.Bytes(), &tbl); err != nil {
		t.Fatalf("限流表解析失败: %v", err)
	}
	if tbl.Version != 2 || len(tbl.Rules) != 1 {
		t.Fatalf("下发内容不符: %+v", tbl)
	}
	// 用同一测试密钥验签（与 main.go 同源用法：控制面签、插件验）
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	signer, err := ratelimit.NewSigner(key)
	if err != nil {
		t.Fatalf("构造签名器失败: %v", err)
	}
	if !signer.VerifyTable(&tbl) {
		t.Fatal("下发表的签名应可验证")
	}
}

// TestPutRateLimits_versionGuards 防回滚：同版本与低版本一律 409。
func TestPutRateLimits_versionGuards(t *testing.T) {
	s := testServer() // 种子表 version=1
	same := strings.Replace(validTableJSON, `"version":2`, `"version":1`, 1)
	if rec := doRateLimits(s, http.MethodPut, same, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("同版本期望 409，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	if rec := doRateLimits(s, http.MethodPut, validTableJSON, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("前置 PUT(version=2) 失败: %d", rec.Code)
	}
	if rec := doRateLimits(s, http.MethodPut, same, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("回滚版本期望 409，实际 %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestPutRateLimits_rejectsUnknownField 策略通道不得携带认证类配置（未知字段即拒）。
func TestPutRateLimits_rejectsUnknownField(t *testing.T) {
	s := testServer()
	body := `{"version":3,"issued_at":"2026-09-13T10:00:00Z","rules":[],"consumers":[{"name":"x"}]}`
	rec := doRateLimits(s, http.MethodPut, body, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("未知字段期望 400，实际 %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestPutRateLimits_rejectsInvalidRule 非法规则（rate 未设 rpm/tpm）即 400。
func TestPutRateLimits_rejectsInvalidRule(t *testing.T) {
	s := testServer()
	body := `{"version":3,"issued_at":"2026-09-13T10:00:00Z","rules":[
{"id":"bad","kind":"rate","scope":"tenant","target":"t-a","action":"reject","enabled":true}]}`
	rec := doRateLimits(s, http.MethodPut, body, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法规则期望 400，实际 %d body=%s", rec.Code, rec.Body.String())
	}
}

// TestRateLimits_authRequired 两个端点均须内网令牌。
func TestRateLimits_authRequired(t *testing.T) {
	s := testServer()
	if rec := doRateLimits(s, http.MethodGet, "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("无令牌 GET 期望 401，实际 %d", rec.Code)
	}
	if rec := doRateLimits(s, http.MethodPut, validTableJSON, "wrong"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("坏令牌 PUT 期望 401，实际 %d", rec.Code)
	}
}
