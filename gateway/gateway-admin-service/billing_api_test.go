// billing_api_test.go — GA-计费 P0-3（§7.4）：/billing/* 跨租户强隔离测试。
//
// 隔离口径：admin 可跨租户；非 admin 仅限令牌 `tenant` 声明所指租户；
// 声明缺失或不符 → 403（fail-closed）；tenant 为空的全量列举仅 admin 可用。
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/gateway-admin-service/billing"
)

// newBillingTestHandler 构造启用状态的计费 handler（临时价格表 + 临时 SQLite）。
func newBillingTestHandler(t *testing.T) *billingHandler {
	t.Helper()
	dir := t.TempDir()
	pricing := filepath.Join(dir, "pricing.json")
	if err := os.WriteFile(pricing, []byte(`{"version":"v1","currency":"CNY",
		"models":{"m1":{"in_coef":1,"out_coef":1,
		"tiers":[{"up_to_tokens":0,"in_per_1k":1,"out_per_1k":2}]}}}`), 0o644); err != nil {
		t.Fatalf("写价格表失败: %v", err)
	}
	cfg := &billing.BillingConfig{
		Enabled: true,
		Store:   billing.StoreConfig{Driver: "sqlite", DSN: filepath.Join(dir, "billing.db")},
		Rating:  billing.RatingConfig{Rounding: "half_up", PriceTable: pricing},
		Source:  billing.SourceConfig{SyncMode: billing.SyncModePull},
	}
	h, err := newBillingHandler(cfg, nil)
	if err != nil {
		t.Fatalf("构造计费 handler 失败: %v", err)
	}
	t.Cleanup(func() { _ = h.store.Close() })
	return h
}

// billingTestEnv 测试环境：handler + 服务端。
type billingTestEnv struct {
	h   *billingHandler
	srv *httptest.Server
}

// newBillingTestEnv 组装管理面 mux（仅计费特性启用）+ httptest 服务端。
func newBillingTestEnv(t *testing.T) *billingTestEnv {
	t.Helper()
	h := newBillingTestHandler(t)
	mux := buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, h, false)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &billingTestEnv{h: h, srv: srv}
}

// billingGet 以指定令牌发起 GET。
func billingGet(t *testing.T, env *billingTestEnv, token, path string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, env.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestBillingCrossTenantIsolation(t *testing.T) {
	env := newBillingTestEnv(t)

	// 预置 t2 的账单（供跨租户读取断言）
	if err := env.h.store.Bills().Put(&billing.Bill{
		ID: "monthly-t2-2026-10", TenantID: "t2", Kind: billing.BillKindMonthly,
		Period: "2026-10", Status: billing.BillStatusIssued, Currency: "CNY",
	}); err != nil {
		t.Fatalf("预置账单失败: %v", err)
	}

	adminTok := testSignToken(t, testSecret, claims{
		Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
	})
	// 带租户声明的 auditor（t1）
	auditorT1 := testSignToken(t, testSecret, claims{
		Sub: "bob", Role: roleAuditor, Iss: defaultIssuer, Aud: defaultAudience, Tenant: "t1",
	})
	// 无租户声明的 auditor（旧令牌形态）
	auditorNoTenant := testSignToken(t, testSecret, claims{
		Sub: "carol", Role: roleAuditor, Iss: defaultIssuer, Aud: defaultAudience,
	})

	bills := billingAPIBase + "/bills"
	ledger := billingAPIBase + "/ledger"

	t.Run("admin 可全量列举", func(t *testing.T) {
		if code := billingGet(t, env, adminTok, bills); code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", code)
		}
	})
	t.Run("admin 可读任意租户", func(t *testing.T) {
		if code := billingGet(t, env, adminTok, bills+"?tenant=t2"); code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", code)
		}
	})
	t.Run("auditor 读自身租户 200", func(t *testing.T) {
		if code := billingGet(t, env, auditorT1, bills+"?tenant=t1"); code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", code)
		}
	})
	t.Run("auditor 跨租户 403", func(t *testing.T) {
		if code := billingGet(t, env, auditorT1, bills+"?tenant=t2"); code != http.StatusForbidden {
			t.Fatalf("期望 403，实际 %d", code)
		}
	})
	t.Run("auditor 全量列举 403", func(t *testing.T) {
		if code := billingGet(t, env, auditorT1, bills); code != http.StatusForbidden {
			t.Fatalf("期望 403（禁止越权全量），实际 %d", code)
		}
	})
	t.Run("auditor 缺租户声明 403", func(t *testing.T) {
		if code := billingGet(t, env, auditorNoTenant, bills+"?tenant=t1"); code != http.StatusForbidden {
			t.Fatalf("期望 403（fail-closed），实际 %d", code)
		}
	})
	t.Run("账单详情跨租户 403 / 同租户与 admin 200", func(t *testing.T) {
		if code := billingGet(t, env, auditorT1, bills+"/monthly-t2-2026-10"); code != http.StatusForbidden {
			t.Fatalf("详情跨租户期望 403，实际 %d", code)
		}
		if code := billingGet(t, env, adminTok, bills+"/monthly-t2-2026-10"); code != http.StatusOK {
			t.Fatalf("详情 admin 期望 200，实际 %d", code)
		}
	})
	t.Run("账本查询隔离", func(t *testing.T) {
		if code := billingGet(t, env, auditorT1, ledger+"?tenant=t1"); code != http.StatusOK {
			t.Fatalf("账本同租户期望 200，实际 %d", code)
		}
		if code := billingGet(t, env, auditorT1, ledger+"?tenant=t2"); code != http.StatusForbidden {
			t.Fatalf("账本跨租户期望 403，实际 %d", code)
		}
		if code := billingGet(t, env, auditorT1, ledger); code != http.StatusForbidden {
			t.Fatalf("账本全量期望 403，实际 %d", code)
		}
	})
}

// TestBillingSchedulerWiring 后台调度接线：schedule.enabled 决定是否构造调度器（S-8）。
func TestBillingSchedulerWiring(t *testing.T) {
	dir := t.TempDir()
	pricing := filepath.Join(dir, "pricing.json")
	if err := os.WriteFile(pricing, []byte(`{"version":"v1","currency":"CNY","models":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	base := func(enabled bool) *billing.BillingConfig {
		return &billing.BillingConfig{
			Enabled: true,
			Store:   billing.StoreConfig{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "b.db")},
			Rating:  billing.RatingConfig{Rounding: "half_up", PriceTable: pricing},
			Source:  billing.SourceConfig{SyncMode: billing.SyncModePull},
			Schedule: billing.ScheduleConfig{
				Enabled: enabled, BackfillLookbackDays: 7,
			},
		}
	}
	hOn, err := newBillingHandler(base(true), nil)
	if err != nil {
		t.Fatalf("handler(enabled) err: %v", err)
	}
	defer hOn.store.Close()
	if hOn.sched == nil {
		t.Error("schedule.enabled=true 应构造调度器（S-8）")
	}
	if hOn.backfillDays != 7 {
		t.Errorf("backfillDays = %d, want 7", hOn.backfillDays)
	}
	hOn.Close() // 幂等停止（未启动时也安全）

	hOff, err := newBillingHandler(base(false), nil)
	if err != nil {
		t.Fatalf("handler(disabled) err: %v", err)
	}
	defer hOff.store.Close()
	if hOff.sched != nil {
		t.Error("schedule.enabled=false 不应构造调度器")
	}
}

// TestBillingIsolationDisabledWhenFeatureOff 计费关闭时不注册端点（R-1/M10）。
func TestBillingIsolationDisabledWhenFeatureOff(t *testing.T) {
	mux := buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, nil, false)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+billingAPIBase+"/bills", nil)
	req.Header.Set("Authorization", bearerToken(t))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("计费关闭时期望 404，实际 %d", resp.StatusCode)
	}
}

// ---------- 推送消费 webhook（§6.3.1；S-4/B-6.3-1/2） ----------

const testPushSecretEnv = "TEST_BILLING_PUSH_SECRET"

// testEventsSecretEnv 独立 events 密钥的环境变量名（BUG-002：events_secret_ref 优先域）。
const testEventsSecretEnv = "TEST_BILLING_EVENTS_SECRET"

// newBillingPushTestHandler 构造推送消费 handler（sync_mode=push + HMAC 密钥引用）。
// pushSecret 为空 = 不配置 push_secret_ref；eventsSecret 为空 = 不配置 events_secret_ref（触发回退）。
func newBillingPushTestHandler(t *testing.T, pushSecret, eventsSecret string) *billingHandler {
	t.Helper()
	dir := t.TempDir()
	pricing := filepath.Join(dir, "pricing.json")
	if err := os.WriteFile(pricing, []byte(`{"version":"v1","currency":"CNY",
		"models":{"m1":{"in_coef":1,"out_coef":1,
		"tiers":[{"up_to_tokens":0,"in_per_1k":1,"out_per_1k":2}]}}}`), 0o644); err != nil {
		t.Fatalf("写价格表失败: %v", err)
	}
	cfg := &billing.BillingConfig{
		Enabled: true,
		Store:   billing.StoreConfig{Driver: "sqlite", DSN: filepath.Join(dir, "billing.db")},
		Rating:  billing.RatingConfig{Rounding: "half_up", PriceTable: pricing},
		Source: billing.SourceConfig{
			SyncMode:      billing.SyncModePush,
			PushSecretRef: "env:" + testPushSecretEnv,
		},
	}
	if pushSecret != "" {
		t.Setenv(testPushSecretEnv, pushSecret)
	} else {
		cfg.Source.PushSecretRef = ""
	}
	if eventsSecret != "" {
		t.Setenv(testEventsSecretEnv, eventsSecret)
		cfg.Secrets = billing.SecretsConfig{EventsSecretRef: "env:" + testEventsSecretEnv}
	}
	h, err := newBillingHandler(cfg, nil)
	if err != nil {
		t.Fatalf("构造计费 handler 失败: %v", err)
	}
	t.Cleanup(func() { _ = h.store.Close() })
	return h
}

// signEventsBody 生成推送签名（与 tee-infer `X-Signature: sha256=<hex>` 同构）。
func signEventsBody(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func TestBillingEventsWebhook(t *testing.T) {
	const secret = "test-hook-secret"
	h := newBillingPushTestHandler(t, secret, "")
	mux := buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, h, false)
	srv := httptest.NewServer(mux)
	defer srv.Close()
	url := srv.URL + billingAPIBase + "/events"

	body := []byte(`{"event_id":"e1","tenant":"t1","model":"m1","tokens_in":100,"tokens_out":50,` +
		`"result":"ok","ts":"` + time.Now().UTC().Format(time.RFC3339Nano) + `"}`)

	// 1) 正确签名 → 200 accepted + 入账
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("X-Signature", signEventsBody(secret, body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("正确签名 status = %d, want 200", resp.StatusCode)
	}
	entries, _ := h.store.Ledger().Range(billing.LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Errorf("ledger entries = %d, want 1", len(entries))
	}

	// 2) 错误签名 → 401（B-6.3-1）
	req2, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	req2.Header.Set("X-Signature", "sha256=deadbeef")
	resp2, _ := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("错误签名 status = %d, want 401", resp2.StatusCode)
	}

	// 3) 无签名 → 401
	req3, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	resp3, _ := http.DefaultClient.Do(req3)
	resp3.Body.Close()
	if resp3.StatusCode != http.StatusUnauthorized {
		t.Errorf("无签名 status = %d, want 401", resp3.StatusCode)
	}

	// 4) 签名正确但 JSON 非法 → 400
	bad := []byte(`{not json`)
	req4, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(bad))
	req4.Header.Set("X-Signature", signEventsBody(secret, bad))
	resp4, _ := http.DefaultClient.Do(req4)
	resp4.Body.Close()
	if resp4.StatusCode != http.StatusBadRequest {
		t.Errorf("非法 JSON status = %d, want 400", resp4.StatusCode)
	}

	// 5) GET → 405
	req5, _ := http.NewRequest(http.MethodGet, url, nil)
	resp5, _ := http.DefaultClient.Do(req5)
	resp5.Body.Close()
	if resp5.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET status = %d, want 405", resp5.StatusCode)
	}
}

// 未配置推送密钥 → 端点 fail-closed（一律 401）
func TestBillingEventsWebhook_NoSecretFailClosed(t *testing.T) {
	h := newBillingTestHandler(t) // 未配置 PushSecretRef
	mux := buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, h, false)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := []byte(`{"event_id":"e1","tenant":"t1","model":"m1","tokens_in":100,"ts":"2026-10-01T00:00:00Z"}`)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+billingAPIBase+"/events", bytes.NewReader(body))
	req.Header.Set("X-Signature", signEventsBody("anything", body))
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("未配置密钥 status = %d, want 401 (fail-closed)", resp.StatusCode)
	}
}

// BUG-002：events_secret_ref 优先；未配置时回退 push_secret_ref（向后兼容）。
func TestBillingEventsWebhook_EventsSecretPreferredAndFallback(t *testing.T) {
	const pushSecret = "push-secret"
	const eventsSecret = "events-secret"
	body := []byte(`{"event_id":"e1","tenant":"t1","model":"m1","tokens_in":100,"ts":"2026-10-01T00:00:00Z"}`)
	post := func(url, sig string) int {
		req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		req.Header.Set("X-Signature", sig)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	// 1) 配置 events_secret → events 密钥签名通过；push 密钥签名被拒（401）
	h1 := newBillingPushTestHandler(t, pushSecret, eventsSecret)
	srv1 := httptest.NewServer(buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, h1, false))
	defer srv1.Close()
	url1 := srv1.URL + billingAPIBase + "/events"
	if code := post(url1, signEventsBody(eventsSecret, body)); code != http.StatusOK {
		t.Errorf("events 密钥签名 status = %d, want 200", code)
	}
	if code := post(url1, signEventsBody(pushSecret, body)); code != http.StatusUnauthorized {
		t.Errorf("push 密钥签名 status = %d, want 401（events 域优先）", code)
	}

	// 2) 未配置 events_secret → 回退 push 密钥（向后兼容）
	h2 := newBillingPushTestHandler(t, pushSecret, "")
	srv2 := httptest.NewServer(buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, h2, false))
	defer srv2.Close()
	url2 := srv2.URL + billingAPIBase + "/events"
	if code := post(url2, signEventsBody(pushSecret, body)); code != http.StatusOK {
		t.Errorf("回退 push 密钥签名 status = %d, want 200", code)
	}
}

// SEC-001：对端 CRYPTO_PROFILE=sm 时以 HMAC-SM3 签名（头前缀仍 sha256=），
// 本端（intl）应仍可通过 —— 双算法兼容，消除 profile 不一致导致的推送全 401。
func TestBillingEventsWebhook_HMACAlgCompat(t *testing.T) {
	const secret = "shared-secret"
	h := newBillingPushTestHandler(t, secret, "")
	mux := buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, h, false)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := []byte(`{"event_id":"e1","tenant":"t1","model":"m1","tokens_in":10,"ts":"2026-10-01T00:00:00Z"}`)
	smProv, err := cryptop.New(cryptop.ProfileSMSW)
	if err != nil {
		t.Fatalf("cryptop sm provider: %v", err)
	}
	sig := "sha256=" + hex.EncodeToString(smProv.HMAC([]byte(secret), body))

	req, _ := http.NewRequest(http.MethodPost, srv.URL+billingAPIBase+"/events", bytes.NewReader(body))
	req.Header.Set("X-Signature", sig)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("SM3 签名（对端 sm profile）status = %d, want 200（双算法兼容）", resp.StatusCode)
	}
}

// ---------- 套餐热下发 M6（§6.4.1 2c；P-1 回读确认） ----------

// renderAdminMetrics 渲染进程指标文本（断言 #13 用）。
func renderAdminMetrics() string {
	var buf bytes.Buffer
	billing.DefaultMetrics.Render(&buf)
	return buf.String()
}

// quotaStub 伪 tee-infer：POST /usage/quota 记录下发；GET /usage/quota 回读已生效限额。
type quotaStub struct {
	mu      sync.Mutex
	applied map[string][]billing.QuotaLimit
	gets    int  // 回读次数（断言 M6 判据确实走了回读）
	drop    bool // true = 回读恒为空（模拟"POST 2xx 但未生效"）
}

func newQuotaStub() *quotaStub { return &quotaStub{applied: map[string][]billing.QuotaLimit{}} }

func (s *quotaStub) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/usage/quota" {
			http.NotFound(w, r)
			return
		}
		switch r.Method {
		case http.MethodPost:
			var u billing.QuotaUpdate
			if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			s.mu.Lock()
			s.applied[u.Tenant] = u.Limits
			s.mu.Unlock()
			w.WriteHeader(http.StatusOK)
		case http.MethodGet:
			tenant := r.URL.Query().Get("tenant")
			s.mu.Lock()
			s.gets++
			lims := s.applied[tenant]
			if s.drop {
				lims = nil
			}
			s.mu.Unlock()
			if lims == nil {
				lims = []billing.QuotaLimit{}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"tenant": tenant, "limits": lims})
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	})
}

const testM6TokenEnv = "TEST_BILLING_M6_TOKEN"

// newBillingM6TestHandler 构造带配额下发/回读链路的 handler（TEEURL → 伪 tee-infer）。
func newBillingM6TestHandler(t *testing.T, teeURL string, budget time.Duration) *billingHandler {
	t.Helper()
	t.Setenv(testM6TokenEnv, "m6-token")
	dir := t.TempDir()
	pricing := filepath.Join(dir, "pricing.json")
	if err := os.WriteFile(pricing, []byte(`{"version":"v1","currency":"CNY",
		"models":{"m1":{"in_coef":1,"out_coef":1,
		"tiers":[{"up_to_tokens":0,"in_per_1k":1,"out_per_1k":2}]}}}`), 0o644); err != nil {
		t.Fatalf("写价格表失败: %v", err)
	}
	cfg := &billing.BillingConfig{
		Enabled: true,
		Store:   billing.StoreConfig{Driver: "sqlite", DSN: filepath.Join(dir, "billing.db")},
		Rating:  billing.RatingConfig{Rounding: "half_up", PriceTable: pricing},
		Source: billing.SourceConfig{
			SyncMode:      billing.SyncModePull,
			TEEURL:        teeURL,
			AdminTokenRef: "env:" + testM6TokenEnv,
		},
	}
	h, err := newBillingHandler(cfg, nil)
	if err != nil {
		t.Fatalf("构造计费 handler 失败: %v", err)
	}
	h.quotaApplyBudget = budget
	t.Cleanup(func() { _ = h.store.Close() })
	return h
}

// postSubscription 经管理面绑定套餐，返回状态码。
func postSubscription(t *testing.T, srvURL string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, srvURL+billingAPIBase+"/subscription",
		bytes.NewReader([]byte(`{"tenant":"acme","plan_id":"p1"}`)))
	req.Header.Set("Authorization", bearerToken(t))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// 回读命中 → 200；下发限额正确；M6 指标 #13 有样本
func TestBillingSubscription_M6Confirmed(t *testing.T) {
	stub := newQuotaStub()
	tee := httptest.NewServer(stub.handler())
	defer tee.Close()

	h := newBillingM6TestHandler(t, tee.URL, 2*time.Second)
	if err := h.store.Plans().PutPlan(&billing.Plan{ID: "p1", Name: "基础", MonthlyTokens: 1000}); err != nil {
		t.Fatalf("PutPlan: %v", err)
	}
	srv := httptest.NewServer(buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, h, false))
	defer srv.Close()

	if code := postSubscription(t, srv.URL); code != http.StatusOK {
		t.Fatalf("绑定套餐 status = %d, want 200", code)
	}

	stub.mu.Lock()
	got, gets := stub.applied["acme"], stub.gets
	stub.mu.Unlock()
	if len(got) != 1 || got[0].Window != "month" || got[0].MaxTokens != 1000 {
		t.Fatalf("下发限额 = %+v, want [{month 1000}]", got)
	}
	if gets < 1 {
		t.Error("未发生回读（M6 判据须以 GET /usage/quota 构造）")
	}
	if !strings.Contains(renderAdminMetrics(), "gateway_admin_billing_quota_apply_duration_seconds_count") {
		t.Error("M6 指标 #13 未观测")
	}
}

// 回读不符（POST 2xx ≠ 生效）→ 确认超时但**仍 200 且不回滚**（§6.4.1：TEE 已生效为准）
func TestBillingSubscription_M6UnconfirmedStill200(t *testing.T) {
	stub := newQuotaStub()
	stub.drop = true // 回读恒空 → 确认必然超时
	tee := httptest.NewServer(stub.handler())
	defer tee.Close()

	h := newBillingM6TestHandler(t, tee.URL, 30*time.Millisecond) // 缩短预算（默认 60s）
	if err := h.store.Plans().PutPlan(&billing.Plan{ID: "p1", Name: "基础", MonthlyTokens: 1000}); err != nil {
		t.Fatalf("PutPlan: %v", err)
	}
	srv := httptest.NewServer(buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, h, false))
	defer srv.Close()

	if code := postSubscription(t, srv.URL); code != http.StatusOK {
		t.Fatalf("确认失败不应改变响应（不回滚），status = %d, want 200", code)
	}
	subs, err := h.store.Plans().ListSubscriptions(time.Now().UnixNano())
	if err != nil {
		t.Fatalf("ListSubscriptions: %v", err)
	}
	if len(subs) != 1 || subs[0].TenantID != "acme" {
		t.Fatalf("订阅应仍绑定（不回滚），got %+v", subs)
	}
	if !strings.Contains(renderAdminMetrics(), "gateway_admin_billing_quota_apply_duration_seconds_count") {
		t.Error("确认失败路径也应观测 M6 时延（便于暴露 60s 违约）")
	}
}

// TestBillingPlanUpsert_R29：套餐 upsert 的 R-29 交叉约束（charge 须非免费档 + 单价非全 0）。
func TestBillingPlanUpsert_R29(t *testing.T) {
	env := newBillingTestEnv(t)
	adminTok := testSignToken(t, testSecret, claims{
		Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
	})
	postPlan := func(body string) int {
		req, _ := http.NewRequest(http.MethodPost, env.srv.URL+billingAPIBase+"/plans", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+adminTok)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	// charge + 免费档（monthly_tokens=0）→ 400（R-29）
	if code := postPlan(`{"id":"free","name":"免费版","over_quota":"charge","pay_mode":"postpaid","cache_tier":"none","monthly_tokens":0}`); code != http.StatusBadRequest {
		t.Fatalf("R-29 免费档 charge 期望 400，实际 %d", code)
	}
	// charge + 付费档 + 非 0 单价表 → 200
	if code := postPlan(`{"id":"pro","name":"专业版","over_quota":"charge","pay_mode":"postpaid","cache_tier":"none","monthly_tokens":1000}`); code != http.StatusOK {
		t.Fatalf("合法 charge 期望 200，实际 %d", code)
	}
}

// TestBillingVerifyChain：手动完整性校验端点（S-6 账本链 + REC-6 审计链）。
func TestBillingVerifyChain(t *testing.T) {
	env := newBillingTestEnv(t)
	adminTok := testSignToken(t, testSecret, claims{
		Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
	})
	auditorTok := testSignToken(t, testSecret, claims{
		Sub: "bob", Role: roleAuditor, Iss: defaultIssuer, Aud: defaultAudience,
	})
	call := func(method, token string) (int, []byte) {
		req, _ := http.NewRequest(method, env.srv.URL+billingAPIBase+"/verify-chain", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, body
	}

	if code, _ := call(http.MethodGet, adminTok); code != http.StatusMethodNotAllowed {
		t.Fatalf("GET 期望 405，实际 %d", code)
	}
	if code, _ := call(http.MethodPost, auditorTok); code != http.StatusForbidden {
		t.Fatalf("auditor 期望 403，实际 %d", code)
	}
	code, body := call(http.MethodPost, adminTok)
	if code != http.StatusOK {
		t.Fatalf("admin 期望 200，实际 %d body=%s", code, body)
	}
	var out struct {
		LedgerBrokenAt int64 `json:"ledger_broken_at"`
		LedgerBroken   bool  `json:"ledger_broken"`
		AuditChainOK   bool  `json:"audit_chain_ok"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if out.LedgerBrokenAt != -1 || out.LedgerBroken {
		t.Fatalf("空账本应链完好（-1/false），got %+v", out)
	}
}
