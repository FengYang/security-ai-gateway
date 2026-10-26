// Package main — P2-4 T-3.1 策略作用域 scope{global|cluster[]} 单测（§6.2）。
//
// 覆盖：
//   - 纯函数：解析/序列化（存量兼容）、写请求解析（互斥/空数组/缺省）、
//     计划级作用域交集聚合、集群注册表校验（未注册/状态不可用/注册表未启用）；
//   - 存储层：三张表 scope 读写往返、存量库（无 scope 列）补列后仍按 global 解释；
//   - 写路径：集群作用域生效与回显、非法作用域拒绝（未注册/空数组/互斥）、
//     注册表未启用只允许 global、存量数据照旧、scope 变更推进 config_version、
//     跨租户隔离（同租户不同集群互不串味）；
//   - 下发层：DispatchPlan 顶层携带作用域、空交集不下发（fail-closed）。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// fakeScopeChecker 集群注册表校验器替身（可控集群集合 / 状态 / 故障）。
type fakeScopeChecker struct {
	recs []*ClusterRecord
	err  error
}

func (f *fakeScopeChecker) List(context.Context) ([]*ClusterRecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.recs, nil
}

// scopeClusters 构造一组处于指定状态的集群记录。
func scopeClusters(ids []string, status ClusterStatus) []*ClusterRecord {
	out := make([]*ClusterRecord, 0, len(ids))
	for _, id := range ids {
		out = append(out, &ClusterRecord{ID: id, Status: status})
	}
	return out
}

// ---------- 纯函数：解析与序列化 ----------

func TestScope_ParseDispatchScope_存量与非法(t *testing.T) {
	// 存量兼容：空/NULL/"{}" 一律视作 global（决策点②，不回填）。
	for _, raw := range []string{"", "   ", "null", "{}"} {
		sc, err := parseDispatchScope(raw)
		if err != nil {
			t.Fatalf("存量值 %q 应解析为 global: %v", raw, err)
		}
		if !sc.Global {
			t.Errorf("存量值 %q 应视作 global, got=%+v", raw, sc)
		}
	}
	// 非法 JSON → fail-closed（不得当 global 放行）。
	if _, err := parseDispatchScope("{oops"); err == nil {
		t.Error("非法 JSON 应报错")
	}
	// global 与 clusters 并存 → 拒绝。
	if _, err := parseDispatchScope(`{"global":true,"clusters":["c1"]}`); !errors.Is(err, errScopeGlobalAndClusters) {
		t.Errorf("global+clusters 应报互斥, got=%v", err)
	}
	// 正常 cluster 作用域 → 规范化（去重 + 排序）。
	sc, err := parseDispatchScope(`{"global":false,"clusters":["c2","c1","c2"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if sc.Global || len(sc.Clusters) != 2 || sc.Clusters[0] != "c1" || sc.Clusters[1] != "c2" {
		t.Errorf("应规范化为 [c1 c2], got=%+v", sc)
	}
}

func TestScope_MarshalRoundTrip(t *testing.T) {
	if got := marshalDispatchScope(DispatchScope{Global: true}); got != dispatchScopeGlobalJSON {
		t.Errorf("global 序列化不对: %q", got)
	}
	raw := marshalDispatchScope(DispatchScope{Global: false, Clusters: []string{"c1"}})
	sc, err := parseDispatchScope(raw)
	if err != nil || sc.Global || len(sc.Clusters) != 1 || sc.Clusters[0] != "c1" {
		t.Errorf("往返失败: raw=%q sc=%+v err=%v", raw, sc, err)
	}
}

func TestScope_WriteRequest_Resolve(t *testing.T) {
	// 缺省（字段未出现）→ 不变更。
	var absent scopeWriteRequest
	if absent.specified() {
		t.Error("零值不应算作已指定")
	}
	if got, err := absent.resolve(); err != nil || got != nil {
		t.Errorf("缺省应返回 (nil,nil), got=%v err=%v", got, err)
	}
	// 显式 global。
	g := scopeWriteRequest{Global: true}
	sc, err := g.resolve()
	if err != nil || sc == nil || !sc.Global {
		t.Errorf("显式 global 应解析为 global, got=%v err=%v", sc, err)
	}
	// 显式 cluster[] → 规范化。
	c := scopeWriteRequest{Clusters: []string{"c2", "c1", "c2"}}
	sc, err = c.resolve()
	if err != nil || sc == nil || sc.Global || len(sc.Clusters) != 2 || sc.Clusters[0] != "c1" {
		t.Errorf("cluster[] 应规范化为 [c1 c2], got=%v err=%v", sc, err)
	}
	// global 与 clusters 并存 → 拒绝（互斥，决策点④）。
	both := scopeWriteRequest{Global: true, Clusters: []string{"c1"}}
	if _, err := both.resolve(); !errors.Is(err, errScopeGlobalAndClusters) {
		t.Errorf("global+clusters 应报互斥, got=%v", err)
	}
	// 显式空数组 → 拒绝（空集合按不下发，写入 fail-closed）。
	empty := scopeWriteRequest{Clusters: []string{}}
	if _, err := empty.resolve(); !errors.Is(err, errScopeEmptyClusters) {
		t.Errorf("显式空数组应拒绝, got=%v", err)
	}
	// 空集群 ID → 拒绝。
	bad := scopeWriteRequest{Clusters: []string{"  "}}
	if _, err := bad.resolve(); err == nil {
		t.Error("空集群 ID 应拒绝")
	}
}

func TestScope_EffectiveDispatchScope_交集(t *testing.T) {
	// 全部 global → global（默认零变化）。
	sc, err := effectiveDispatchScope("", dispatchScopeGlobalJSON, "")
	if err != nil || !sc.Global {
		t.Errorf("全 global 应得 global, got=%+v err=%v", sc, err)
	}
	// 任一 cluster 作用域收窄目标集合。
	sc, err = effectiveDispatchScope("", `{"global":false,"clusters":["c1","c2"]}`, "")
	if err != nil || sc.Global || len(sc.Clusters) != 2 {
		t.Errorf("应收窄为 [c1 c2], got=%+v err=%v", sc, err)
	}
	// 交集。
	sc, err = effectiveDispatchScope(`{"global":false,"clusters":["c1","c2"]}`, `{"global":false,"clusters":["c2"]}`, "")
	if err != nil || sc.Global || len(sc.Clusters) != 1 || sc.Clusters[0] != "c2" {
		t.Errorf("交集应为 [c2], got=%+v err=%v", sc, err)
	}
	// 交集为空 → 不下发（不退化为 global）。
	sc, err = effectiveDispatchScope(`{"global":false,"clusters":["c1"]}`, `{"global":false,"clusters":["c2"]}`, "")
	if err != nil {
		t.Fatal(err)
	}
	if sc.Global {
		t.Error("交集为空不得退化为 global")
	}
	if _, ok := scopeTargetClusters(sc); ok {
		t.Error("空交集应判为不下发")
	}
	// 非法存量值 → 报错（fail-closed）。
	if _, err := effectiveDispatchScope("{oops"); err == nil {
		t.Error("非法 scope 应报错")
	}
}

func TestScope_ValidateDispatchScope_集群状态与注册表未启用(t *testing.T) {
	ctx := context.Background()
	// 未注册 → 拒绝。
	checker := &fakeScopeChecker{recs: scopeClusters([]string{"c1"}, ClusterStatusActive)}
	err := validateDispatchScope(ctx, checker, DispatchScope{Clusters: []string{"cX"}})
	if err == nil || !strings.Contains(err.Error(), "未注册") {
		t.Errorf("未注册集群应拒绝, got=%v", err)
	}
	// active / degraded → 放行。
	for _, st := range []ClusterStatus{ClusterStatusActive, ClusterStatusDegraded} {
		if err := validateDispatchScope(ctx, checker, DispatchScope{Clusters: []string{"c1"}}); err != nil {
			t.Errorf("状态 %s 应放行: %v", st, err)
		}
	}
	// removed / quarantined / unreachable → 拒绝（不可用于下发）。
	for _, st := range []ClusterStatus{ClusterStatusRemoved, ClusterStatusQuarantined, ClusterStatusUnreachable} {
		bad := &fakeScopeChecker{recs: scopeClusters([]string{"c1"}, st)}
		if err := validateDispatchScope(ctx, bad, DispatchScope{Clusters: []string{"c1"}}); err == nil {
			t.Errorf("状态 %s 应拒绝", st)
		}
	}
	// 注册表未启用（checker = nil）→ 只允许 global。
	if err := validateDispatchScope(ctx, nil, DispatchScope{Clusters: []string{"c1"}}); !errors.Is(err, errScopeNoRegistry) {
		t.Errorf("注册表未启用应报 errScopeNoRegistry, got=%v", err)
	}
	if err := validateDispatchScope(ctx, nil, DispatchScope{Global: true}); err != nil {
		t.Errorf("global 应无条件放行: %v", err)
	}
	// 注册表查询失败 → fail-closed。
	failing := &fakeScopeChecker{err: errors.New("db down")}
	if err := validateDispatchScope(ctx, failing, DispatchScope{Clusters: []string{"c1"}}); err == nil {
		t.Error("注册表查询失败应拒绝")
	}
}

// ---------- 存储层 ----------

func TestScope_StoreRoundTrip_三张表(t *testing.T) {
	s := newTestStore(t)
	// tenant_provisionings 对 tenants(id) 有外键 ⇒ 须先有租户行。
	tid, _ := seedTenantUser(t, s, "scope-store@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	scopeJSON := `{"global":false,"clusters":["c1"]}`

	tx, err := s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertPolicyOverlay(tx, &PolicyOverlay{
		TenantID: tid, Version: 0, WhitelistJSON: `{"entries":[]}`, BlacklistJSON: `{"entries":[]}`,
		CategoryActionsJSON: `{}`, UpdatedAt: 1, ScopeJSON: scopeJSON,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertModelConfig(tx, &ModelConfig{
		TenantID: tid, AllowedModelsJSON: `[]`, DefaultModel: "", Version: 0, UpdatedAt: 1, ScopeJSON: scopeJSON,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertProvisioning(tx, &TenantProvisioning{
		TenantID: tid, Scenario: scenarioS1, TrustTier: trustTierTrusted, AccessMode: accessModeASegmented,
		PluginSetJSON: `[]`, Segment1Enabled: true, Segment2Mode: segment2None, TemplateVersion: "v1",
		ProviderCredRefsJSON: `[]`, ProvisionedAt: 1, UpdatedAt: 1, ScopeJSON: scopeJSON,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	po, err := s.GetPolicyOverlay(tid)
	if err != nil || po == nil || po.ScopeJSON != scopeJSON {
		t.Fatalf("policy scope 往返失败: %+v err=%v", po, err)
	}
	mc, err := s.GetModelConfig(tid)
	if err != nil || mc == nil || mc.ScopeJSON != scopeJSON {
		t.Fatalf("model scope 往返失败: %+v err=%v", mc, err)
	}
	pv, err := s.GetProvisioning(tid)
	if err != nil || pv == nil || pv.ScopeJSON != scopeJSON {
		t.Fatalf("provisioning scope 往返失败: %+v err=%v", pv, err)
	}

	// 落库值应解析为 cluster 作用域（非 global）。
	sc, err := parseDispatchScope(po.ScopeJSON)
	if err != nil || sc.Global || len(sc.Clusters) != 1 || sc.Clusters[0] != "c1" {
		t.Errorf("scope 应解析为 cluster 作用域, got=%+v err=%v", sc, err)
	}
}

func TestScope_Store_存量库补列后仍按global解释(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	// 造一个"T-3.1 之前"的旧结构库：三张表均无 scope 列。
	db, err := sqlutil.Open(sqlutil.SQLite, path, 1)
	if err != nil {
		t.Fatalf("打开旧库失败: %v", err)
	}
	legacyDDL := `
CREATE TABLE IF NOT EXISTS policy_overlays (
  tenant_id        TEXT PRIMARY KEY,
  version          INTEGER NOT NULL DEFAULT 1,
  whitelist        TEXT    NOT NULL DEFAULT '{"entries":[]}',
  blacklist        TEXT    NOT NULL DEFAULT '{"entries":[]}',
  category_actions TEXT    NOT NULL DEFAULT '{}',
  updated_at       INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS model_configs (
  tenant_id      TEXT PRIMARY KEY,
  allowed_models TEXT    NOT NULL DEFAULT '[]',
  default_model  TEXT    NOT NULL DEFAULT '',
  version        INTEGER NOT NULL DEFAULT 1,
  updated_at     INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS tenant_provisionings (
  tenant_id          TEXT PRIMARY KEY,
  scenario           TEXT    NOT NULL,
  trust_tier         TEXT    NOT NULL,
  access_mode        TEXT    NOT NULL DEFAULT 'a_segmented',
  plugin_set         TEXT    NOT NULL DEFAULT '[]',
  segment1_enabled   INTEGER NOT NULL,
  segment2_mode      TEXT    NOT NULL,
  template_version   TEXT    NOT NULL,
  provider_cred_refs TEXT    NOT NULL DEFAULT '[]',
  provisioned_at     INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
);
INSERT INTO policy_overlays (tenant_id, version, whitelist, blacklist, category_actions, updated_at)
VALUES ('t_legacy', 3, '{"entries":[]}', '{"entries":[]}', '{}', 111);
`
	if _, err := db.Exec(legacyDDL); err != nil {
		t.Fatalf("建旧结构失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	ts, err := OpenTenantStore(path, false, []byte("test-pepper-12345678"))
	if err != nil {
		t.Fatalf("打开存量库失败: %v", err)
	}
	defer func() { _ = ts.Close() }()
	s, ok := ts.(*sqliteTenantStore)
	if !ok {
		t.Fatal("类型断言失败")
	}

	// 存量行不得丢失，且 scope 按 global 解释（NULL 视作 global，不回填）。
	po, err := s.GetPolicyOverlay("t_legacy")
	if err != nil || po == nil {
		t.Fatalf("存量行应保留: %+v err=%v", po, err)
	}
	if po.Version != 3 {
		t.Errorf("存量 version 应保留 3, got=%d", po.Version)
	}
	if po.ScopeJSON != "" {
		t.Errorf("存量 scope 应为空（视作 global）, got=%q", po.ScopeJSON)
	}
	sc, err := parseDispatchScope(po.ScopeJSON)
	if err != nil || !sc.Global {
		t.Errorf("存量应视作 global, got=%+v err=%v", sc, err)
	}

	// 补列后可写入 scope（存量行不被回填、仅新写入生效）。
	tx, err := s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertPolicyOverlay(tx, &PolicyOverlay{
		TenantID: "t_legacy", Version: po.Version, WhitelistJSON: `{"entries":[]}`,
		BlacklistJSON: `{"entries":[]}`, CategoryActionsJSON: `{}`, UpdatedAt: 222,
		ScopeJSON: `{"global":false,"clusters":["c1"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	po2, err := s.GetPolicyOverlay("t_legacy")
	if err != nil || po2.ScopeJSON != `{"global":false,"clusters":["c1"]}` {
		t.Errorf("补列后应可写 scope, got=%q err=%v", po2.ScopeJSON, err)
	}
}

// ---------- 写路径：策略 overlay ----------

// scopePolicyPut 调用策略 PUT（带 If-Match），返回响应记录器。
func scopePolicyPut(t *testing.T, h *tenantHandler, tid, body, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := tenantRequest("PUT", tenantPolicyPath, body, tid, "u1")
	req.Header.Set("If-Match", ifMatch)
	h.handleTenantPolicyPut(w, req)
	return w
}

// scopePolicyPutAdmin 调用策略 PUT（**管理面接管**会话），返回响应记录器。
//
// 用途：cluster[] 作用域**仅管理面可写**（P2-4 主理人裁定），故写 cluster 作用域
// 的用例必须走管理面会话；租户自助面的拒绝用例见 TestScope_租户面写集群作用域被拒。
func scopePolicyPutAdmin(t *testing.T, h *tenantHandler, tid, body, ifMatch string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	req := adminTakeoverRequest("PUT", tenantPolicyPath, body, tid, "admin1")
	req.Header.Set("If-Match", ifMatch)
	h.handleTenantPolicyPut(w, req)
	return w
}

func TestScope_PolicyPut_集群作用域生效并回显(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.setScopeResolver(&fakeScopeChecker{recs: scopeClusters([]string{"c1", "c2"}, ClusterStatusActive)})
	tid, _ := seedTenantUser(t, store, "scope-a@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	w := scopePolicyPutAdmin(t, h, tid,
		`{"whitelist":{"entries":[]},"blacklist":{"entries":[]},"category_actions":{},"scope":{"global":false,"clusters":["c2","c1"]}}`,
		"0")
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var resp policyView
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Scope == nil || resp.Scope.Global || len(resp.Scope.Clusters) != 2 {
		t.Fatalf("响应应回显集群作用域, got=%+v", resp.Scope)
	}
	if resp.Scope.Clusters[0] != "c1" || resp.Scope.Clusters[1] != "c2" {
		t.Errorf("作用域应规范化排序, got=%v", resp.Scope.Clusters)
	}
	// 落库值正确。
	po, err := store.GetPolicyOverlay(tid)
	if err != nil || po == nil || po.ScopeJSON != `{"global":false,"clusters":["c1","c2"]}` {
		t.Fatalf("落库 scope 不对: %q err=%v", po.ScopeJSON, err)
	}
	// GET 回显一致。
	w2 := httptest.NewRecorder()
	h.handleTenantPolicyGet(w2, tenantRequest("GET", tenantPolicyPath, "", tid, "u1"))
	if w2.Code != http.StatusOK {
		t.Fatalf("GET 应 200, got=%d", w2.Code)
	}
	var got policyView
	if err := json.Unmarshal(w2.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.Scope == nil || got.Scope.Global || len(got.Scope.Clusters) != 2 {
		t.Errorf("GET 应回显集群作用域, got=%+v", got.Scope)
	}
}

func TestScope_PolicyPut_拒绝非法作用域(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"显式空数组", `{"scope":{"global":false,"clusters":[]}}`},
		{"global与clusters并存", `{"scope":{"global":true,"clusters":["c1"]}}`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
			h.setScopeResolver(&fakeScopeChecker{recs: scopeClusters([]string{"c1"}, ClusterStatusActive)})
			tid, _ := seedTenantUser(t, store, "scope-b@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

			w := scopePolicyPut(t, h, tid, c.body, "0")
			if w.Code != http.StatusBadRequest {
				t.Fatalf("应 400, got=%d body=%s", w.Code, w.Body.String())
			}
			// 拒绝后不得落库（fail-closed）。
			po, err := store.GetPolicyOverlay(tid)
			if err != nil {
				t.Fatal(err)
			}
			if po != nil {
				t.Errorf("拒绝写入后不应有落库行: %+v", po)
			}
		})
	}
}

// TestScope_管理面写集群作用域_未注册集群被拒 注册表校验（管理面路径）。
func TestScope_管理面写集群作用域_未注册集群被拒(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.setScopeResolver(&fakeScopeChecker{recs: scopeClusters([]string{"c1"}, ClusterStatusActive)})
	tid, _ := seedTenantUser(t, store, "scope-b2@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	w := scopePolicyPutAdmin(t, h, tid, `{"scope":{"global":false,"clusters":["cX"]}}`, "0")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未注册集群应 400, got=%d body=%s", w.Code, w.Body.String())
	}
	po, err := store.GetPolicyOverlay(tid)
	if err != nil {
		t.Fatal(err)
	}
	if po != nil {
		t.Errorf("拒绝写入后不应有落库行: %+v", po)
	}
}

// TestScope_租户面写集群作用域被拒 P2-4 主理人裁定：cluster[] 作用域**仅管理面可写**。
//
// 理由：scope 决定"配置投递到哪些集群"，影响其它集群的数据面；租户自助面写
// cluster[] = 越权。故租户面写 cluster[] ⇒ 403，且**不落库**；global 两侧皆可写。
func TestScope_租户面写集群作用域被拒(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.setScopeResolver(&fakeScopeChecker{recs: scopeClusters([]string{"c1", "c2"}, ClusterStatusActive)})
	tid, _ := seedTenantUser(t, store, "scope-b3@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	// 租户自助面写 cluster[] ⇒ 403。
	w := scopePolicyPut(t, h, tid, `{"scope":{"global":false,"clusters":["c1"]}}`, "0")
	if w.Code != http.StatusForbidden {
		t.Fatalf("租户面写 cluster[] 应 403, got=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "仅管理面") {
		t.Errorf("403 文案应可诊断（含「仅管理面」）, got=%s", w.Body.String())
	}
	// 不得落库（fail-closed）。
	po, err := store.GetPolicyOverlay(tid)
	if err != nil {
		t.Fatal(err)
	}
	if po != nil {
		t.Errorf("拒绝写入后不应有落库行: %+v", po)
	}

	// 租户自助面写 global ⇒ 放行。
	w2 := scopePolicyPut(t, h, tid, `{"scope":{"global":true}}`, "0")
	if w2.Code != http.StatusOK {
		t.Fatalf("租户面写 global 应 200, got=%d body=%s", w2.Code, w2.Body.String())
	}
	po2, err := store.GetPolicyOverlay(tid)
	if err != nil || po2 == nil {
		t.Fatalf("应有落库行: %+v err=%v", po2, err)
	}
	sc, err := parseDispatchScope(po2.ScopeJSON)
	if err != nil || !sc.Global {
		t.Errorf("应落 global, got=%+v err=%v", sc, err)
	}

	// 管理面写 cluster[] ⇒ 成功（与租户面同一端点，走 admin 接管会话）。
	w3 := scopePolicyPutAdmin(t, h, tid, `{"scope":{"global":false,"clusters":["c1"]}}`, "1")
	if w3.Code != http.StatusOK {
		t.Fatalf("管理面写 cluster[] 应 200, got=%d body=%s", w3.Code, w3.Body.String())
	}
	po3, err := store.GetPolicyOverlay(tid)
	if err != nil || po3 == nil {
		t.Fatalf("应有落库行: %+v err=%v", po3, err)
	}
	sc3, err := parseDispatchScope(po3.ScopeJSON)
	if err != nil || sc3.Global || len(sc3.Clusters) != 1 || sc3.Clusters[0] != "c1" {
		t.Errorf("管理面应写落 [c1], got=%+v err=%v", sc3, err)
	}
}

func TestScope_注册表未启用只允许global(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	// 未注入校验器且配置里无注册表路径 ⇒ 注册表未启用。
	tid, _ := seedTenantUser(t, store, "scope-c@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	// 管理面写 cluster[]：注册表未启用 ⇒ 无法校验 ⇒ 400（fail-closed，只允许 global）。
	wAdmin := scopePolicyPutAdmin(t, h, tid, `{"scope":{"global":false,"clusters":["c1"]}}`, "0")
	if wAdmin.Code != http.StatusBadRequest {
		t.Fatalf("注册表未启用时集群作用域应 400, got=%d body=%s", wAdmin.Code, wAdmin.Body.String())
	}
	// 租户面写 cluster[] ⇒ 403（管理面专属闸门先于注册表校验）。
	w := scopePolicyPut(t, h, tid, `{"scope":{"global":false,"clusters":["c1"]}}`, "0")
	if w.Code != http.StatusForbidden {
		t.Fatalf("租户面写集群作用域应 403, got=%d body=%s", w.Code, w.Body.String())
	}
	// global 放行。
	w2 := scopePolicyPut(t, h, tid, `{"scope":{"global":true}}`, "0")
	if w2.Code != http.StatusOK {
		t.Fatalf("global 应放行, got=%d body=%s", w2.Code, w2.Body.String())
	}
	po, err := store.GetPolicyOverlay(tid)
	if err != nil || po == nil {
		t.Fatalf("应有落库行: %+v err=%v", po, err)
	}
	sc, err := parseDispatchScope(po.ScopeJSON)
	if err != nil || !sc.Global {
		t.Errorf("应落 global, got=%+v err=%v", sc, err)
	}
}

func TestScope_存量数据照旧_PUT不带scope不变更(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.setScopeResolver(&fakeScopeChecker{recs: scopeClusters([]string{"c1"}, ClusterStatusActive)})
	tid, _ := seedTenantUser(t, store, "scope-d@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	// 先写入集群作用域（管理面）。
	w := scopePolicyPutAdmin(t, h, tid, `{"scope":{"global":false,"clusters":["c1"]}}`, "0")
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	// 再以"不带 scope"的请求全量替换（老客户端行为）⇒ scope 保持不变。
	w2 := scopePolicyPut(t, h, tid, `{"whitelist":{"entries":[]},"blacklist":{"entries":[]},"category_actions":{}}`, "1")
	if w2.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w2.Code, w2.Body.String())
	}
	po, err := store.GetPolicyOverlay(tid)
	if err != nil || po == nil {
		t.Fatalf("应有落库行: %+v err=%v", po, err)
	}
	if po.ScopeJSON != `{"global":false,"clusters":["c1"]}` {
		t.Errorf("不带 scope 的写入不得改变既有作用域, got=%q", po.ScopeJSON)
	}
}

func TestScope_变更推进config_version(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.setScopeResolver(&fakeScopeChecker{recs: scopeClusters([]string{"c1"}, ClusterStatusActive)})
	tid, _ := seedTenantUser(t, store, "scope-e@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	h.dispatch = d
	h.effects.bumpDispatchVersion = d.BumpInTx
	h.effects.enqueueDispatch = d.Enqueue

	// 首次写入（scope = global）。
	w := scopePolicyPut(t, h, tid, `{"scope":{"global":true}}`, "0")
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	d.Wait()
	st, err := store.GetDispatchState(tid)
	if err != nil || st == nil {
		t.Fatalf("应有下发状态: %+v err=%v", st, err)
	}
	if st.ConfigVersion != 1 {
		t.Fatalf("首次写入 config_version 应=1, got=%d", st.ConfigVersion)
	}

	// 仅改 scope（内容不变）⇒ config_version 必须推进（决策点⑤）。
	w2 := scopePolicyPutAdmin(t, h, tid, `{"scope":{"global":false,"clusters":["c1"]}}`, "1")
	if w2.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w2.Code, w2.Body.String())
	}
	d.Wait()
	st2, err := store.GetDispatchState(tid)
	if err != nil || st2 == nil {
		t.Fatalf("应有下发状态: %+v err=%v", st2, err)
	}
	if st2.ConfigVersion != 2 {
		t.Errorf("scope 变更应推进 config_version 到 2, got=%d", st2.ConfigVersion)
	}
}

func TestScope_跨租户隔离_同租户不同集群(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.setScopeResolver(&fakeScopeChecker{recs: scopeClusters([]string{"c1", "c2"}, ClusterStatusActive)})
	tidA, _ := seedTenantUser(t, store, "scope-a1@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	tidB, _ := seedTenantUser(t, store, "scope-b1@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	// 租户 A 定向 c1（管理面写 cluster[]：仅管理面可写）。
	if w := scopePolicyPutAdmin(t, h, tidA, `{"scope":{"global":false,"clusters":["c1"]}}`, "0"); w.Code != http.StatusOK {
		t.Fatalf("租户 A 写入应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	// 租户 B 未写 scope ⇒ 仍为 global（A 的作用域不得串到 B）。
	if w := scopePolicyPut(t, h, tidB, `{"scope":{"global":true}}`, "0"); w.Code != http.StatusOK {
		t.Fatalf("租户 B 写入应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	poB, err := store.GetPolicyOverlay(tidB)
	if err != nil || poB == nil {
		t.Fatalf("租户 B 应有落库行: %+v err=%v", poB, err)
	}
	scB, err := parseDispatchScope(poB.ScopeJSON)
	if err != nil || !scB.Global {
		t.Errorf("租户 B 应为 global, got=%+v err=%v", scB, err)
	}

	// 同租户换集群：作用域**替换**而非并集（互斥语义）。
	if w := scopePolicyPutAdmin(t, h, tidA, `{"scope":{"global":false,"clusters":["c2"]}}`, "1"); w.Code != http.StatusOK {
		t.Fatalf("租户 A 改作用域应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	poA, err := store.GetPolicyOverlay(tidA)
	if err != nil || poA == nil {
		t.Fatalf("租户 A 应有落库行: %+v err=%v", poA, err)
	}
	scA, err := parseDispatchScope(poA.ScopeJSON)
	if err != nil {
		t.Fatal(err)
	}
	if scA.Global || len(scA.Clusters) != 1 || scA.Clusters[0] != "c2" {
		t.Errorf("同租户改集群应替换为 [c2], got=%+v", scA)
	}
}

// ---------- 写路径：开通配置 ----------

func TestScope_ProvisioningPut_作用域(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.setScopeResolver(&fakeScopeChecker{recs: scopeClusters([]string{"c1"}, ClusterStatusActive)})
	// 非 active 租户：场景变更不触发"仅管理员"闸门（本用例只验作用域链路）。
	tid, _ := seedTenantUser(t, store, "scope-f@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	// 租户自助面写 cluster[] ⇒ 403（cluster[] 仅管理面可写）。
	wTenant := httptest.NewRecorder()
	h.handleTenantProvisioningPut(wTenant, tenantRequest("PUT", tenantProvisioningPath,
		`{"scenario":"s1","trust_tier":"trusted","scope":{"global":false,"clusters":["c1"]}}`, tid, "u1"))
	if wTenant.Code != http.StatusForbidden {
		t.Fatalf("租户面写集群作用域应 403, got=%d body=%s", wTenant.Code, wTenant.Body.String())
	}
	if pv, _ := store.GetProvisioning(tid); pv != nil {
		t.Fatalf("拒绝写入后不应有落库行: %+v", pv)
	}

	// 管理面写 cluster[] ⇒ 成功。
	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, adminTakeoverRequest("PUT", tenantProvisioningPath,
		`{"scenario":"s1","trust_tier":"trusted","scope":{"global":false,"clusters":["c1"]}}`, tid, "admin1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	pv, err := store.GetProvisioning(tid)
	if err != nil || pv == nil {
		t.Fatalf("应有落库行: %+v err=%v", pv, err)
	}
	if pv.ScopeJSON != `{"global":false,"clusters":["c1"]}` {
		t.Errorf("开通配置 scope 不对: %q", pv.ScopeJSON)
	}
	// GET 回显。
	w2 := httptest.NewRecorder()
	h.handleTenantProvisioningGet(w2, tenantRequest("GET", tenantProvisioningPath, "", tid, "u1"))
	if w2.Code != http.StatusOK {
		t.Fatalf("GET 应 200, got=%d", w2.Code)
	}
	var view provisioningView
	if err := json.Unmarshal(w2.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Scope == nil || view.Scope.Global || len(view.Scope.Clusters) != 1 || view.Scope.Clusters[0] != "c1" {
		t.Errorf("GET 应回显集群作用域, got=%+v", view.Scope)
	}
	// 未注册集群 → 拒绝（管理面路径）。
	w3 := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w3, adminTakeoverRequest("PUT", tenantProvisioningPath,
		`{"scenario":"s1","trust_tier":"trusted","scope":{"global":false,"clusters":["cX"]}}`, tid, "admin1"))
	if w3.Code != http.StatusBadRequest {
		t.Errorf("未注册集群应 400, got=%d body=%s", w3.Code, w3.Body.String())
	}
}

// ---------- 下发层 ----------

func TestScope_BuildDispatch_计划携带作用域(t *testing.T) {
	// 默认（无 scope）⇒ global（零变化）。
	plan, err := BuildDispatch(DispatchInput{TenantID: "t_1", ConfigVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Scope.Global {
		t.Errorf("默认应为 global, got=%+v", plan.Scope)
	}
	if _, ok := plan.TargetClusters(); !ok {
		t.Error("global 应判为可下发")
	}
	// 策略定向 c1 ⇒ 计划级作用域收窄。
	plan2, err := BuildDispatch(DispatchInput{
		TenantID: "t_1", ConfigVersion: 1,
		Policy: &PolicyOverlay{TenantID: "t_1", ScopeJSON: `{"global":false,"clusters":["c1"]}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan2.Scope.Global || len(plan2.Scope.Clusters) != 1 || plan2.Scope.Clusters[0] != "c1" {
		t.Errorf("计划作用域应收窄为 [c1], got=%+v", plan2.Scope)
	}
	clusters, ok := plan2.TargetClusters()
	if !ok || len(clusters) != 1 || clusters[0] != "c1" {
		t.Errorf("目标集群应为 [c1], got=%v ok=%v", clusters, ok)
	}
	// 交集为空 ⇒ 不下发。
	plan3, err := BuildDispatch(DispatchInput{
		TenantID: "t_1", ConfigVersion: 1,
		Policy: &PolicyOverlay{TenantID: "t_1", ScopeJSON: `{"global":false,"clusters":["c1"]}`},
		Models: &ModelConfig{TenantID: "t_1", ScopeJSON: `{"global":false,"clusters":["c2"]}`},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := plan3.TargetClusters(); ok {
		t.Errorf("空交集应判为不下发, got=%+v", plan3.Scope)
	}
}

func TestScope_空交集不下发(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.setScopeResolver(&fakeScopeChecker{recs: scopeClusters([]string{"c1", "c2"}, ClusterStatusActive)})
	tid, _ := seedTenantUser(t, store, "scope-g@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	// 策略定向 c1，模型配置定向 c2 ⇒ 交集为空。
	if w := scopePolicyPutAdmin(t, h, tid, `{"scope":{"global":false,"clusters":["c1"]}}`, "0"); w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertModelConfig(tx, &ModelConfig{
		TenantID: tid, AllowedModelsJSON: `[]`, DefaultModel: "", Version: 0, UpdatedAt: 1,
		ScopeJSON: `{"global":false,"clusters":["c2"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	h.dispatch = d
	h.effects.bumpDispatchVersion = d.BumpInTx
	h.effects.enqueueDispatch = d.Enqueue

	// 触发一次下发（scope 交集为空）。
	tx2, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BumpDispatchVersion(tx2, tid, 1); err != nil {
		t.Fatal(err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatal(err)
	}
	d.Enqueue(tid)
	d.Wait()

	if applier.callCount() != 0 {
		t.Errorf("作用域交集为空时不得下发, calls=%d", applier.callCount())
	}
	st, err := store.GetDispatchState(tid)
	if err != nil || st == nil {
		t.Fatalf("应有下发状态: %+v err=%v", st, err)
	}
	if st.Status != dispatchStatusFailed {
		t.Errorf("交集为空应置 failed（可观测）, got=%q", st.Status)
	}
}
