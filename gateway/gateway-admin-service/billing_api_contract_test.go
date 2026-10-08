// billing_api_contract_test.go — P0-3 T9 页面契约测试（§4.3.4 T-4.3-1..3）。
//
// 归属：T-4.3-1 页面级 RBAC 矩阵 / T-4.3-2 enabled=false 端点 404 / T-4.3-3 写动作落审计链。
// T-4.3-4（金额列仅账单页）为前端源扫描，见 scripts/check-billing-amount-scope.ps1 + admin-portal.yml。
package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
)

// newBillingAuditTestHandler 构造**带审计链**的计费 handler（T-4.3-3 用）。
func newBillingAuditTestHandler(t *testing.T) (*billingHandler, *adminAuditChain) {
	t.Helper()
	dir := t.TempDir()
	pricing := filepath.Join(dir, "pricing.json")
	if err := os.WriteFile(pricing, []byte(`{"version":"v1","currency":"CNY",
		"models":{"m1":{"in_coef":1,"out_coef":1,
		"tiers":[{"up_to_tokens":0,"in_per_1k":1,"out_per_1k":2}]}}}`), 0o644); err != nil {
		t.Fatalf("写价格表失败: %v", err)
	}
	audit, err := newAdminAuditChain(filepath.Join(dir, "audit.log"), "")
	if err != nil {
		t.Fatalf("构造审计链失败: %v", err)
	}
	t.Cleanup(func() { _ = audit.Close() })
	cfg := &billing.BillingConfig{
		Enabled: true,
		Store:   billing.StoreConfig{Driver: "sqlite", DSN: filepath.Join(dir, "billing.db")},
		Rating:  billing.RatingConfig{Rounding: "half_up", PriceTable: pricing},
		Source:  billing.SourceConfig{SyncMode: billing.SyncModePull},
	}
	h, err := newBillingHandler(cfg, audit)
	if err != nil {
		t.Fatalf("构造计费 handler 失败: %v", err)
	}
	t.Cleanup(func() { _ = h.store.Close() })
	return h, audit
}

func auditActions(c *adminAuditChain) map[string]int {
	out := map[string]int{}
	events, _ := c.list(1000, 0)
	for _, e := range events {
		out[e.Action]++
	}
	return out
}

// T-4.3-1：页面级 RBAC 矩阵——读端点按角色放行；写端点仅 admin；未认证 401。
func TestBillingContractT4_3_1_RBACMatrix(t *testing.T) {
	env := newBillingTestEnv(t)

	tokAdmin := testSignToken(t, testSecret, claims{Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience})
	tokAuditor := testSignToken(t, testSecret, claims{Sub: "aud", Role: roleAuditor, Iss: defaultIssuer, Aud: defaultAudience, Tenant: "t1"})
	tokReader := testSignToken(t, testSecret, claims{Sub: "fin", Role: roleBillingReader, Iss: defaultIssuer, Aud: defaultAudience, Tenant: "t1"})

	readPaths := []string{"/plans", "/bills?tenant=t1", "/ledger?tenant=t1", "/subscription?tenant=t1"}
	writePaths := []string{"/freeze", "/close-daily"}

	// 读：三角色（admin/auditor/billing_reader）均 200
	for _, p := range readPaths {
		for name, tok := range map[string]string{"admin": tokAdmin, "auditor": tokAuditor, "billing_reader": tokReader} {
			if code := billingGet(t, env, tok, billingAPIBase+p); code != http.StatusOK {
				t.Errorf("读矩阵：%s 读 %s 期望 200，实际 %d", name, p, code)
			}
		}
	}
	// 读：未认证 → 401（缺 Bearer）
	if code := billingGet(t, env, "", billingAPIBase+"/plans"); code != http.StatusUnauthorized {
		t.Errorf("未认证读期望 401，实际 %d", code)
	}

	// 写：admin 通过（非 401/403）；auditor/billing_reader → 403；未认证 → 401
	for _, p := range writePaths {
		body := `{"tenant":"t1","day":"2026-09-01"}`
		if p == "/freeze" {
			body = `{"tenant":"t1"}`
		}
		if code := billingPost(t, env, tokAdmin, billingAPIBase+p, body); code == http.StatusUnauthorized || code == http.StatusForbidden {
			t.Errorf("写矩阵：admin 写 %s 不应被拒，实际 %d", p, code)
		}
		if code := billingPost(t, env, tokAuditor, billingAPIBase+p, body); code != http.StatusForbidden {
			t.Errorf("写矩阵：auditor 写 %s 期望 403，实际 %d", p, code)
		}
		if code := billingPost(t, env, tokReader, billingAPIBase+p, body); code != http.StatusForbidden {
			t.Errorf("写矩阵：billing_reader 写 %s 期望 403，实际 %d", p, code)
		}
		if code := billingPost(t, env, "", billingAPIBase+p, body); code != http.StatusUnauthorized {
			t.Errorf("写矩阵：未认证写 %s 期望 401，实际 %d", p, code)
		}
	}
}

// T-4.3-2：enabled=false → 计费端点全部 404（不注册；页面/端点级隔离，R-1/M10）。
func TestBillingContractT4_3_2_DisabledAllEndpoints404(t *testing.T) {
	mux := buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, nil, false) // bih=nil
	srv := httptest.NewServer(mux)
	defer srv.Close()
	tok := testSignToken(t, testSecret, claims{Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience})

	gets := []string{"/plans", "/bills", "/ledger", "/subscription", "/bills/daily-t1-2026-09-01", "/bills/x/verify", "/bills/x/export"}
	posts := []string{"/plans", "/subscription", "/freeze", "/unfreeze", "/close-daily", "/close-monthly", "/verify-chain", "/events"}

	for _, p := range gets {
		if code := billingGet(t, &billingTestEnv{h: nil, srv: srv}, tok, billingAPIBase+p); code != http.StatusNotFound {
			t.Errorf("enabled=false：GET %s 期望 404，实际 %d", p, code)
		}
	}
	for _, p := range posts {
		if code := billingPost(t, &billingTestEnv{h: nil, srv: srv}, tok, billingAPIBase+p, `{}`); code != http.StatusNotFound {
			t.Errorf("enabled=false：POST %s 期望 404，实际 %d", p, code)
		}
	}
}

// T-4.3-3：写动作落审计链（plan_upsert / plan_bind / bill_freeze）。
func TestBillingContractT4_3_3_WriteAuditTrail(t *testing.T) {
	h, audit := newBillingAuditTestHandler(t)
	srv := httptest.NewServer(buildAdminMux(testCfg(), nil, nil, nil, nil, nil, nil, nil, h, false))
	defer srv.Close()
	env := &billingTestEnv{h: h, srv: srv}
	tok := testSignToken(t, testSecret, claims{Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience})

	// 1) 套餐 upsert → plan_upsert
	if code := billingPost(t, env, tok, billingAPIBase+"/plans",
		`{"id":"pro","name":"专业版","over_quota":"charge","pay_mode":"postpaid","cache_tier":"none","monthly_tokens":1000}`); code != http.StatusOK {
		t.Fatalf("POST /plans 期望 200，实际 %d", code)
	}
	// 2) 订阅绑定 → plan_bind
	if code := billingPost(t, env, tok, billingAPIBase+"/subscription", `{"tenant":"t1","plan_id":"pro"}`); code != http.StatusOK {
		t.Fatalf("POST /subscription 期望 200，实际 %d", code)
	}
	// 3) 冻结 → bill_freeze
	if code := billingPost(t, env, tok, billingAPIBase+"/freeze", `{"tenant":"t1"}`); code != http.StatusOK {
		t.Fatalf("POST /freeze 期望 200，实际 %d", code)
	}

	actions := auditActions(audit)
	for _, want := range []string{auditActionPlanUpsert, auditActionPlanBind, auditActionBillFreeze} {
		if actions[want] == 0 {
			t.Errorf("审计链缺少写动作 %q（实际动作：%v）", want, actions)
		}
	}
}
