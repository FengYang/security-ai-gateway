// Package main — N7 · 多租户隔离增强单测（§4.3.7，V-S7）。
//
// 覆盖：
//   - tenant 解析一致性（自声明头被令牌真值覆盖，防伪造 X-Tenant-ID）；
//   - consumer→tenant 绑定 RBAC（篡改拒绝）；
//   - 哨兵租户噪声抑制与告警；
//   - 下发隔离参数（缓存命名空间 / 配额隔离 / tenant 解析一致性 / 密态轨解密绑定）。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------- tenant 解析一致性 / consumer→tenant 绑定 ----------

func TestResolveTenantBinding(t *testing.T) {
	cases := []struct {
		name           string
		authoritative  string
		declared       string
		wantTenant     string
		wantConsumer   string
		wantOverridden bool
		wantSentinel   bool
	}{
		{"一致", "t_1", "t_1", "t_1", "t_1", false, false},
		{"无自声明", "t_1", "", "t_1", "t_1", false, false},
		{"自声明被覆盖", "t_1", "t_9", "t_1", "t_1", true, false},
		{"缺失权威→哨兵", "", "", "", sentinelTenant, false, true},
		{"缺失权威但有自声明", "", "t_9", "", sentinelTenant, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := resolveTenantBinding(c.authoritative, c.declared)
			if b.TenantID != c.wantTenant || b.Consumer != c.wantConsumer ||
				b.Overridden != c.wantOverridden || b.Sentinel != c.wantSentinel {
				t.Errorf("binding 不符: %+v", b)
			}
		})
	}
}

func TestConsumerForTenant(t *testing.T) {
	if consumerForTenant("") != sentinelTenant || consumerForTenant("  ") != sentinelTenant {
		t.Error("空租户应落哨兵")
	}
	if consumerForTenant("t_1") != "t_1" {
		t.Error("consumer 应等于租户")
	}
}

func TestDeclaredTenantFromRequest(t *testing.T) {
	r := httptest.NewRequest("GET", "/x", nil)
	r.Header.Set("X-Tenant-ID", "t_hdr")
	if got := declaredTenantFromRequest(r); got != "t_hdr" {
		t.Errorf("头优先解析失败: %q", got)
	}

	r2 := httptest.NewRequest("GET", "/x", nil)
	r2.Header.Set("X-Mse-Consumer", "t_mse")
	if got := declaredTenantFromRequest(r2); got != "t_mse" {
		t.Errorf("X-Mse-Consumer 解析失败: %q", got)
	}

	r3 := httptest.NewRequest("GET", "/x?tenant=t_q", nil)
	if got := declaredTenantFromRequest(r3); got != "t_q" {
		t.Errorf("query tenant 解析失败: %q", got)
	}

	if got := declaredTenantFromRequest(httptest.NewRequest("GET", "/x", nil)); got != "" {
		t.Errorf("无自声明应为空: %q", got)
	}
}

func TestAuthorizeConsumerBindingWrite(t *testing.T) {
	// 租户自助（无越权）
	tid, admin, err := authorizeConsumerBindingWrite(tenantRequest("PUT", "/x", "", "t_1", "u1"))
	if err != nil || tid != "t_1" || admin {
		t.Errorf("租户自助写应放行: id=%s admin=%v err=%v", tid, admin, err)
	}

	// admin 接管（C-6 留痕）
	tid2, admin2, err2 := authorizeConsumerBindingWrite(adminTakeoverRequest("PUT", "/x", "", "t_2", "alice"))
	if err2 != nil || tid2 != "t_2" || !admin2 {
		t.Errorf("admin 接管写应放行且留痕: id=%s admin=%v err=%v", tid2, admin2, err2)
	}

	// 篡改：自声明租户与权威不一致
	req := tenantRequest("PUT", "/x", "", "t_1", "u1")
	req.Header.Set("X-Tenant-ID", "t_9")
	if _, _, err := authorizeConsumerBindingWrite(req); err != errTenantMappingTamper {
		t.Errorf("篡改应拒（errTenantMappingTamper）: %v", err)
	}

	// 哨兵：无租户上下文
	if _, _, err := authorizeConsumerBindingWrite(httptest.NewRequest("PUT", "/x", nil)); err == nil {
		t.Error("无租户上下文应拒")
	}
}

func TestTenantSentinelNoise(t *testing.T) {
	n := &tenantSentinelNoise{window: 100}
	if !n.observe(1000) {
		t.Error("首事件应放行告警")
	}
	if n.observe(1001) || n.observe(1099) {
		t.Error("同窗口应抑制")
	}
	if !n.observe(1100) {
		t.Error("跨窗口应再告警")
	}
	if n.total() != 4 {
		t.Errorf("累计应为 4, got=%d", n.total())
	}
}

func TestNoteSentinelFailure(t *testing.T) {
	before := tenantSentinel.total()
	noteSentinelFailure(http.StatusTeapot) // 非 401/403/429 → 忽略
	if tenantSentinel.total() != before {
		t.Error("非哨兵状态码不应计数")
	}
	noteSentinelFailure(http.StatusUnauthorized)
	noteSentinelFailure(http.StatusForbidden)
	noteSentinelFailure(http.StatusTooManyRequests)
	if tenantSentinel.total() != before+3 {
		t.Errorf("哨兵计数应 +3, got=%d", tenantSentinel.total()-before)
	}
}

// 中间件：伪造 X-Tenant-ID 被令牌真值覆盖，绑定入上下文。
func TestTenantAuthMiddleware_OverridesForgedTenantHeader(t *testing.T) {
	secret := []byte("shared-secret-16chars-minimum")
	token := newTenantJWT(secret, "1", "t_true", "u@e.com", 3600)

	var got tenantBinding
	handler := tenantAuthMiddleware(tenantTestCfg(secret), func(w http.ResponseWriter, r *http.Request) {
		got = tenantBindingFromCtx(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Tenant-ID", "t_forged")
	handler(httptest.NewRecorder(), req)

	if got.TenantID != "t_true" || got.Consumer != "t_true" || !got.Overridden {
		t.Errorf("伪造头应被覆盖且标记 overridden: %+v", got)
	}
}

// 中间件 admin 接管分支：target_tenant 作为权威租户写入绑定。
func TestTenantAuthMiddleware_AdminTakeoverBinding(t *testing.T) {
	cfg := testCfg()
	token := testSignToken(t, cfg.jwtSecret, claims{
		Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
	})

	var got tenantBinding
	handler := tenantAuthMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		got = tenantBindingFromCtx(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/?target_tenant=t_take", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	handler(httptest.NewRecorder(), req)

	if got.TenantID != "t_take" || got.Sentinel {
		t.Errorf("admin 接管绑定应以 target_tenant 为准: %+v", got)
	}
}

// ---------- N7 · 下发隔离参数 ----------

// dispatchTargetsByKind 按目标类型索引下发计划。
func dispatchTargetsByKind(plan *DispatchPlan) map[string]DispatchTarget {
	out := map[string]DispatchTarget{}
	for _, tg := range plan.Targets {
		out[tg.Kind] = tg
	}
	return out
}

func TestBuildDispatch_IncludesIsolationParams(t *testing.T) {
	chain, _ := marshalPluginSet([]pluginEntry{{Name: "ai-proxy", Order: 1}})
	plan, err := BuildDispatch(DispatchInput{
		TenantID:      "t_iso",
		ConfigVersion: 1,
		Provisioning: &TenantProvisioning{
			TenantID: "t_iso", Scenario: scenarioS2, TrustTier: trustTierTrusted,
			AccessMode: accessModeASegmented, PluginSetJSON: chain,
			Segment1Enabled: true, Segment2Mode: segment2VendorSDK,
		},
		Quota: &dispatchQuota{PlanID: "pro", MonthlyTokens: 100, Concurrency: 5, CacheTier: "semantic"},
	})
	if err != nil {
		t.Fatal(err)
	}
	byKind := dispatchTargetsByKind(plan)

	wasm := byKind[dispatchTargetWasmPlugin].Spec
	if wasm["cache_namespace"] != "tenant:t_iso" || wasm["cache_key_prefix"] != dispatchCacheKeyPrefix {
		t.Errorf("缓存命名空间隔离参数缺失: %+v", wasm)
	}
	if _, ok := wasm["tenant_resolution"]; !ok {
		t.Error("WasmPlugin 应含 tenant_resolution")
	}

	iso, ok := byKind[dispatchTargetConsumerQuota].Spec["isolation"].(map[string]any)
	if !ok || iso["consumer"] != "t_iso" || iso["isolate"] != true ||
		iso["reject_self_declared_tenant_header"] != true {
		t.Errorf("配额隔离参数缺失: %+v", byKind[dispatchTargetConsumerQuota].Spec["isolation"])
	}

	presc := byKind[dispatchTargetPrescription].Spec
	if _, ok := presc["tenant_resolution"]; !ok {
		t.Error("处方应含 tenant_resolution")
	}
	if _, ok := presc["decrypt_tenant_binding"]; !ok {
		t.Error("密态轨应含 decrypt_tenant_binding")
	}
}

func TestBuildDispatch_NoDenseTrackBinding(t *testing.T) {
	chain, _ := marshalPluginSet([]pluginEntry{{Name: "ai-proxy", Order: 1}})
	plan, err := BuildDispatch(DispatchInput{
		TenantID:      "t_s1",
		ConfigVersion: 1,
		Provisioning: &TenantProvisioning{
			TenantID: "t_s1", Scenario: scenarioS1, TrustTier: trustTierTrusted,
			AccessMode: accessModeASegmented, PluginSetJSON: chain, Segment1Enabled: false,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tg := range plan.Targets {
		if tg.Kind == dispatchTargetPrescription {
			if _, ok := tg.Spec["decrypt_tenant_binding"]; ok {
				t.Error("非密态轨（段① 未启用）不应含 decrypt_tenant_binding")
			}
		}
	}
	if requiresDecryptTenantBinding(nil) {
		t.Error("nil provisioning 不应要求解密绑定")
	}
}

func TestTenantResolutionSpec(t *testing.T) {
	spec := tenantResolutionSpec("t_1")
	if spec["sentinel_tenant"] != sentinelTenant || spec["mode"] != "jwt_override" ||
		spec["header"] != "X-Tenant-ID" || spec["audit_field"] != "tenant_id_resolution" {
		t.Errorf("tenant_resolution 处方不符: %+v", spec)
	}
	if spec["consumer"] != "t_1" {
		t.Errorf("consumer 应为租户: %+v", spec["consumer"])
	}
	// 哨兵租户不可被序列化泄露为任何密钥材料
	raw, _ := json.Marshal(spec)
	if strings.Contains(string(raw), "secret") {
		t.Errorf("tenant_resolution 不应含密钥字段: %s", raw)
	}
}
