package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// adminTakeoverRequest 构造 admin 接管请求（scope: tenant=target, isAdmin=true）。
func adminTakeoverRequest(method, target, body, targetTenant, sub string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, bytes.NewBufferString(body))
	}
	req.RemoteAddr = "10.0.0.1:1234"
	ctx := withTenantScope(req.Context(), tenantScope{TenantID: targetTenant, IsAdmin: true, AdminSub: sub})
	return req.WithContext(ctx)
}

// ---------- 开通配置读写 ----------

func TestProvisioningGet_NotProvisioned(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "p1@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	w := httptest.NewRecorder()
	h.handleTenantProvisioningGet(w, tenantRequest("GET", tenantProvisioningPath, "", tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var v provisioningView
	json.NewDecoder(w.Body).Decode(&v)
	if v.Provisioned {
		t.Error("未开通时 provisioned 应为 false")
	}
	if v.AccessMode != accessModeASegmented || v.Segment2Mode != segment2None {
		t.Errorf("默认视图不对: %+v", v)
	}
	if v.PluginSet == nil {
		t.Error("plugin_set 应为非 nil 空数组")
	}
}

func TestProvisioningPut_SelfServe_S1(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "p2@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	body := `{"scenario":"s1","trust_tier":"trusted"}`
	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, body, tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var v provisioningView
	json.NewDecoder(w.Body).Decode(&v)
	if !v.Provisioned || v.Scenario != scenarioS1 {
		t.Errorf("视图不对: %+v", v)
	}
	if v.Segment1Enabled != 0 || v.Segment2Mode != segment2None {
		t.Errorf("S1 段①/段② 不对: %+v", v)
	}
	if v.TemplateVersion != pluginTemplateVersion {
		t.Errorf("模板版本=%q，期望 %q", v.TemplateVersion, pluginTemplateVersion)
	}
	if !pluginChainHas(v.PluginSet, "ai-proxy") || pluginChainHas(v.PluginSet, "otpmask") {
		t.Errorf("S1 插件集不对: %+v", v.PluginSet)
	}
	// 回读一致
	w2 := httptest.NewRecorder()
	h.handleTenantProvisioningGet(w2, tenantRequest("GET", tenantProvisioningPath, "", tid, "u1"))
	var v2 provisioningView
	json.NewDecoder(w2.Body).Decode(&v2)
	if v2.Scenario != scenarioS1 || !v2.Provisioned {
		t.Errorf("回读不对: %+v", v2)
	}
}

func TestProvisioningPut_S2_Segment1(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "p3@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	body := `{"scenario":"s2","trust_tier":"trusted"}`
	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, body, tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var v provisioningView
	json.NewDecoder(w.Body).Decode(&v)
	if v.Segment1Enabled != 1 || v.Segment2Mode != segment2VendorSDK {
		t.Errorf("S2 段①/段② 不对: %+v", v)
	}
	if !pluginChainHas(v.PluginSet, "otpmask") {
		t.Errorf("S2 应含 otpmask: %+v", v.PluginSet)
	}
}

func TestProvisioningPut_S5_Rejected(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "p4@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, `{"scenario":"s5","trust_tier":"trusted"}`, tid, "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("S5 应 400, got=%d", w.Code)
	}
}

func TestProvisioningPut_InvalidTrustTier(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "p5@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, `{"scenario":"s1","trust_tier":"weird"}`, tid, "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法 trust_tier 应 400, got=%d", w.Code)
	}
}

// TestProvisioningPut_ActiveTenantRequiresAdmin active 租户自助变更 → 403；admin+确认 → 200。
func TestProvisioningPut_ActiveTenantRequiresAdmin(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "p6@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	// 租户自助 → 403
	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, `{"scenario":"s2","trust_tier":"trusted"}`, tid, "u1"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("active 租户自助变更应 403, got=%d body=%s", w.Code, w.Body.String())
	}

	// admin 接管但未二次确认 → 400
	w2 := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w2, adminTakeoverRequest("PUT", tenantProvisioningPath, `{"scenario":"s2","trust_tier":"trusted"}`, tid, "alice"))
	if w2.Code != http.StatusBadRequest {
		t.Errorf("admin 缺二次确认应 400, got=%d body=%s", w2.Code, w2.Body.String())
	}

	// admin 接管 + 二次确认 → 200
	w3 := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w3, adminTakeoverRequest("PUT", tenantProvisioningPath,
		`{"scenario":"s2","trust_tier":"trusted","confirm":true}`, tid, "alice"))
	if w3.Code != http.StatusOK {
		t.Fatalf("admin 二次确认应 200, got=%d body=%s", w3.Code, w3.Body.String())
	}
	var v provisioningView
	json.NewDecoder(w3.Body).Decode(&v)
	if v.Scenario != scenarioS2 {
		t.Errorf("场景未更新: %+v", v)
	}
}

// TestProvisioningPut_PreservesProvisionedAt 多次变更保留首次开通时间。
func TestProvisioningPut_PreservesProvisionedAt(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "p7@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, `{"scenario":"s1","trust_tier":"trusted"}`, tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("首次开通应 200, got=%d", w.Code)
	}
	first, _ := h.store.GetProvisioning(tid)
	if first == nil {
		t.Fatal("开通配置未落库")
	}

	w2 := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w2, tenantRequest("PUT", tenantProvisioningPath, `{"scenario":"s3a","trust_tier":"trusted"}`, tid, "u1"))
	if w2.Code != http.StatusOK {
		t.Fatalf("变更应 200, got=%d", w2.Code)
	}
	second, _ := h.store.GetProvisioning(tid)
	if second == nil {
		t.Fatal("开通配置丢失")
	}
	if second.ProvisionedAt != first.ProvisionedAt {
		t.Errorf("provisioned_at 应保留: %d -> %d", first.ProvisionedAt, second.ProvisionedAt)
	}
	if second.Scenario != scenarioS3a {
		t.Errorf("场景应更新为 s3a, got=%s", second.Scenario)
	}
}

// TestProvisioningPut_TriggersEffects 断言 N4/N5 联动钩子被调用（同事务 version+1 + 声明重签）。
func TestProvisioningPut_TriggersEffects(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "p8@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	bumped, reissued := false, false
	h.effects.bumpDispatchVersion = func(tx TenantTx, tenantID string) error {
		if tenantID != tid {
			t.Errorf("dispatch 租户不对: %s", tenantID)
		}
		bumped = true
		return nil
	}
	h.effects.reissueStatement = func(tenantID string) error {
		reissued = true
		return nil
	}

	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, `{"scenario":"s2","trust_tier":"trusted"}`, tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	if !bumped {
		t.Error("N5 bumpDispatchVersion 应被调用")
	}
	if !reissued {
		t.Error("N4 reissueStatement 应被调用")
	}
}

// ---------- C-16 双策略 ----------

func TestTenantAuthMiddleware_AdminTakeover(t *testing.T) {
	cfg := testCfg()
	token := testSignToken(t, cfg.jwtSecret, claims{Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience})
	handler := tenantAuthMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		id, err := requireTenantScope(r)
		if err != nil || id != "t_target" {
			t.Errorf("接管租户不对: id=%s err=%v", id, err)
		}
		if sub, isAdmin := tenantTakeoverFromCtx(r); !isAdmin || sub != testAdminUser {
			t.Errorf("接管留痕不对: sub=%s isAdmin=%v", sub, isAdmin)
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/v1/adminext/tenant/provisioning?target_tenant=t_target", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("admin 接管应 200, got=%d", w.Code)
	}
}

func TestTenantAuthMiddleware_AdminNoTarget_403(t *testing.T) {
	cfg := testCfg()
	token := testSignToken(t, cfg.jwtSecret, claims{Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience})
	handler := tenantAuthMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler 不应被调用")
	})
	req := httptest.NewRequest("GET", "/v1/adminext/tenant/provisioning", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("admin 缺 target_tenant 应 403, got=%d", w.Code)
	}
}

func TestTenantAuthMiddleware_NonAdminInternal_401(t *testing.T) {
	cfg := testCfg()
	token := testSignToken(t, cfg.jwtSecret, claims{Sub: "aud1", Role: roleAuditor, Iss: defaultIssuer, Aud: defaultAudience})
	handler := tenantAuthMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		t.Error("非 admin 内部令牌不应通过")
	})
	req := httptest.NewRequest("GET", "/v1/adminext/tenant/provisioning?target_tenant=t_x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("非 admin 内部令牌应 401, got=%d", w.Code)
	}
}

// pluginChainHas 判断插件链是否含指定插件名。
func pluginChainHas(chain []pluginEntry, name string) bool {
	for _, p := range chain {
		if p.Name == name {
			return true
		}
	}
	return false
}
