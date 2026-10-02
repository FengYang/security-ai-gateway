// billing_api_test.go — GA-计费 P0-3（§7.4）：/billing/* 跨租户强隔离测试。
//
// 隔离口径：admin 可跨租户；非 admin 仅限令牌 `tenant` 声明所指租户；
// 声明缺失或不符 → 403（fail-closed）；tenant 为空的全量列举仅 admin 可用。
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

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
