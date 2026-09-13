package api

import (
	"context"
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

// stubTeeApplier 记录下发的配额更新，可注入失败（验证"失败保留现有配额"的回报语义）。
type stubTeeApplier struct {
	got  []ratelimit.QuotaUpdate
	fail bool
}

func (s *stubTeeApplier) ApplyQuota(_ context.Context, updates []ratelimit.QuotaUpdate) error {
	if s.fail {
		return errStubTeeFail
	}
	s.got = append(s.got, updates...)
	return nil
}

// errStubTeeFail 模拟 tee-infer 不可达/拒绝。
var errStubTeeFail = errTee("tee: 下发被拒 status=500（tee-infer 保留现有配额）")

type errTee string

func (e errTee) Error() string { return string(e) }

// testServerWithTee 构造带 TEE 下发器的测试 Server（密钥与 testServer 一致）。
func testServerWithTee(applier TeeQuotaApplier) *Server {
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
	return New(sig, msig, rlsig, applier, store.NewMemory(), "tok",
		route.NewRouteTable(1, 1725500000), ratelimit.NewTable(1, time.Unix(1725500000, 0)))
}

// budgetTableJSON 含预算规则的表（version 2 > 种子 1）。
const budgetTableJSON = `{"version":2,"issued_at":"2026-09-13T10:00:00Z","rules":[
{"id":"t-a-budget","kind":"budget","scope":"tenant","target":"t-a","daily_budget_tokens":50000000,"action":"reject","enabled":true}]}`

type putResp struct {
	Version           int      `json:"version"`
	Notes             []string `json:"notes"`
	DataPlaneCompiled bool     `json:"data_plane_compiled"`
	TeeApplied        bool     `json:"tee_applied"`
	TeeUpdates        int      `json:"tee_updates"`
	TeeError          string   `json:"tee_error"`
}

func decodePutResp(t *testing.T, body []byte) putResp {
	t.Helper()
	var r putResp
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatalf("响应解析失败: %v body=%s", err, string(body))
	}
	return r
}

// TestPutRateLimits_teeApplied 预算规则应下发 tee-infer（stub 成功）。
func TestPutRateLimits_teeApplied(t *testing.T) {
	stub := &stubTeeApplier{}
	s := testServerWithTee(stub)
	rec := doRateLimits(s, http.MethodPut, budgetTableJSON, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	r := decodePutResp(t, rec.Body.Bytes())
	if !r.TeeApplied || r.TeeUpdates != 1 {
		t.Fatalf("应成功下发 1 条配额: %+v", r)
	}
	if len(stub.got) != 1 || stub.got[0].Tenant != "t-a" || len(stub.got[0].Limits) != 1 ||
		stub.got[0].Limits[0] != (ratelimit.QuotaLimit{Window: "day", MaxTokens: 50_000_000}) {
		t.Fatalf("下发内容不符（应为 limits[day]）: %+v", stub.got)
	}
	// 预算规则在数据面无内容（不下发），并须带窗口语义与内存态说明
	if r.DataPlaneCompiled {
		t.Fatalf("仅预算规则时数据面不应编译成功: %+v", r)
	}
	if len(r.Notes) == 0 || !strings.Contains(strings.Join(r.Notes, "|"), "UTC+8 自然日窗口") {
		t.Fatalf("应带窗口语义 Note: %+v", r.Notes)
	}
}

// TestPutRateLimits_teeFailKeepsQuota 下发失败：如实回报 tee_applied=false，且不发送清除指令。
func TestPutRateLimits_teeFailKeepsQuota(t *testing.T) {
	stub := &stubTeeApplier{fail: true}
	s := testServerWithTee(stub)
	rec := doRateLimits(s, http.MethodPut, budgetTableJSON, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("策略表应已落库（200），实际 %d", rec.Code)
	}
	r := decodePutResp(t, rec.Body.Bytes())
	if r.TeeApplied || !strings.Contains(r.TeeError, "保留现有配额") {
		t.Fatalf("失败语义不符: %+v", r)
	}
	if len(stub.got) != 0 {
		t.Fatalf("失败时不应记录成功下发: %+v", stub.got)
	}
	// 表已落库（GET 可读到新版本）
	if rec := doRateLimits(s, http.MethodGet, "", "tok"); rec.Code != http.StatusOK {
		t.Fatalf("GET 应 200，实际 %d", rec.Code)
	}
}

// TestPutRateLimits_teeNotConfigured 未配置下发器：明确说明未下发（不静默）。
func TestPutRateLimits_teeNotConfigured(t *testing.T) {
	s := testServerWithTee(nil)
	rec := doRateLimits(s, http.MethodPut, budgetTableJSON, "tok")
	r := decodePutResp(t, rec.Body.Bytes())
	if r.TeeApplied || !strings.Contains(r.TeeError, "未配置 tee-infer 下发器") {
		t.Fatalf("未配置时应明确说明: %+v", r)
	}
}

// TestNewHTTPTeeQuotaApplier_applies 真实 HTTP 下发路径（httptest 替身 tee-infer）：
// 断言路径、管理头与负载形态与 tee-infer 既有契约一致。
func TestNewHTTPTeeQuotaApplier_applies(t *testing.T) {
	var gotPath, gotToken string
	var gotBody map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotToken = r.Header.Get("X-Admin-Token")
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"tenant":"t-a","quota":50000000}`))
	}))
	defer ts.Close()

	applier := NewHTTPTeeQuotaApplier(ts.URL+"/", "admin-token-1")
	if applier == nil {
		t.Fatal("URL 非空时应返回下发器")
	}
	if err := applier.ApplyQuota(context.Background(), []ratelimit.QuotaUpdate{{
		Tenant: "t-a",
		Limits: []ratelimit.QuotaLimit{{Window: "day", MaxTokens: 50_000_000}},
	}}); err != nil {
		t.Fatalf("下发失败: %v", err)
	}
	if gotPath != "/usage/quota" {
		t.Fatalf("路径应为 /usage/quota，实际 %s", gotPath)
	}
	if gotToken != "admin-token-1" {
		t.Fatalf("管理头不符: %s", gotToken)
	}
	// B 项契约：只发 limits[]（扁平 max_tokens/window 不再使用）
	if _, has := gotBody["max_tokens"]; has {
		t.Fatalf("不应再发扁平 max_tokens: %+v", gotBody)
	}
	limits, _ := gotBody["limits"].([]any)
	if gotBody["tenant"] != "t-a" || len(limits) != 1 {
		t.Fatalf("负载形态不符（须含 limits[]）: %+v", gotBody)
	}
	first, _ := limits[0].(map[string]any)
	if first["window"] != "day" || first["max_tokens"] != float64(50_000_000) {
		t.Fatalf("limits 维度不符: %+v", limits[0])
	}
}

// TestNewHTTPTeeQuotaApplier_rejects 非 200 视为失败（调用方保留现有配额）。
func TestNewHTTPTeeQuotaApplier_rejects(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "管理认证失败", http.StatusUnauthorized)
	}))
	defer ts.Close()

	applier := NewHTTPTeeQuotaApplier(ts.URL, "")
	err := applier.ApplyQuota(context.Background(), []ratelimit.QuotaUpdate{{Tenant: "t-a", Limits: []ratelimit.QuotaLimit{{MaxTokens: 1}}}})
	if err == nil || !strings.Contains(err.Error(), "保留现有配额") {
		t.Fatalf("非 200 应报失败且说明保留配额，实际 %v", err)
	}
	// 空 URL = 未配置（nil）
	if NewHTTPTeeQuotaApplier("", "t") != nil {
		t.Fatal("空 URL 应返回 nil")
	}
}
