// Package main — P2-4 T-3.3 收敛核对 API 单测（§6.2 T-3④）。
//
// 覆盖：
//   - 注册表未启用 ⇒ 所有集群 actual=unknown、alert=true（fail-closed，禁止默认收敛）；
//   - 集群上报版本 == 期望 ⇒ converged；
//   - 集群上报版本 != 期望 ⇒ diverged、alert=true；
//   - 集群已注册但未上报（Applied 空）⇒ unknown、alert=true；
//   - 全局作用域扇出到多集群（混合收敛/发散）；
//   - 定向（cluster[]）行 + 孤儿目标（不在注册表）⇒ unknown；
//   - 鉴权：非 admin 令牌 403、缺 Bearer 401。
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// doSyncStatus 经 authMiddleware 发一次 GET /v1/adminext/clusters/sync-status 并解码响应。
func doSyncStatus(t *testing.T, h *tenantHandler, cfg *config) (*syncStatusResponse, int) {
	t.Helper()
	mux := http.NewServeMux()
	h.registerSyncStatus(mux, cfg)
	token := testSignToken(t, testSecret, claims{Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience})
	req := httptest.NewRequest(http.MethodGet, syncStatusPath, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		return nil, rr.Code
	}
	var resp syncStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解码响应失败: %v body=%s", err, rr.Body.String())
	}
	return &resp, rr.Code
}

// syncSeedClusterRow 在租户下建一条具体集群下发行（config_version=1）。
func syncSeedClusterRow(t *testing.T, store *sqliteTenantStore, tid, cid string) {
	t.Helper()
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BumpDispatchVersionForCluster(tx, tid, cid, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func newSyncHandler(t *testing.T, store *sqliteTenantStore, cs ClusterStore) *tenantHandler {
	t.Helper()
	h := newTenantHandler(store, testCfg(), nil, nil, nil, nil, nil)
	h.setClusterStore(cs)
	return h
}

func TestSyncStatus_RegistryDisabled_AllUnknown(t *testing.T) {
	store := newTestStore(t)
	dispatchSeedTenant(t, store, "sync-rd@example.com") // 全局行 config_version=1

	h := newSyncHandler(t, store, nil) // 注册表未注入
	resp, code := doSyncStatus(t, h, testCfg())
	if code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", code)
	}
	if resp.ClusterRegistryEnabled {
		t.Errorf("注册表未启用却标记 enabled=true")
	}
	if resp.Total != 1 || resp.Unknown != 1 || resp.Converged != 0 || resp.Diverged != 0 {
		t.Errorf("期望 total=1 unknown=1 converged=0 diverged=0, got total=%d unknown=%d converged=%d diverged=%d",
			resp.Total, resp.Unknown, resp.Converged, resp.Diverged)
	}
	if !resp.Alert {
		t.Errorf("全部 unknown 应触发 alert")
	}
	if len(resp.Entries) != 1 || resp.Entries[0].ActualVersion != "unknown" {
		t.Errorf("条目应为 1 条且 actual=unknown, got=%+v", resp.Entries)
	}
}

func TestSyncStatus_Converged(t *testing.T) {
	store := newTestStore(t)
	dispatchSeedTenant(t, store, "sync-cv@example.com") // 全局行 config_version=1
	cs := openTestClusterStore(t)
	ctx := context.Background()
	if err := cs.Register(ctx, sampleCluster("c1")); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Heartbeat(ctx, "c1", "1", time.Now()); err != nil {
		t.Fatal(err)
	}

	h := newSyncHandler(t, store, cs)
	resp, code := doSyncStatus(t, h, testCfg())
	if code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", code)
	}
	if !resp.ClusterRegistryEnabled {
		t.Errorf("注册表已启用却标记 enabled=false")
	}
	if resp.Total != 1 || resp.Converged != 1 || resp.Diverged != 0 || resp.Unknown != 0 {
		t.Errorf("期望 total=1 converged=1, got total=%d converged=%d diverged=%d unknown=%d",
			resp.Total, resp.Converged, resp.Diverged, resp.Unknown)
	}
	if resp.Alert {
		t.Errorf("全部收敛不应 alert")
	}
	if e := resp.Entries[0]; e.ActualVersion != "1" || !e.Converged {
		t.Errorf("条目应 actual=1 converged, got=%+v", e)
	}
}

func TestSyncStatus_Diverged(t *testing.T) {
	store := newTestStore(t)
	dispatchSeedTenant(t, store, "sync-dv@example.com") // 全局行 config_version=1
	cs := openTestClusterStore(t)
	ctx := context.Background()
	if err := cs.Register(ctx, sampleCluster("c1")); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Heartbeat(ctx, "c1", "2", time.Now()); err != nil { // 上报 2 != 期望 1
		t.Fatal(err)
	}

	h := newSyncHandler(t, store, cs)
	resp, code := doSyncStatus(t, h, testCfg())
	if code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", code)
	}
	if resp.Diverged != 1 || resp.Converged != 0 || !resp.Alert {
		t.Errorf("期望 diverged=1 alert=true, got diverged=%d converged=%d alert=%v",
			resp.Diverged, resp.Converged, resp.Alert)
	}
	if e := resp.Entries[0]; e.ActualVersion != "2" || e.Converged {
		t.Errorf("条目应 actual=2 不收敛, got=%+v", e)
	}
}

func TestSyncStatus_RegisteredButNotReported(t *testing.T) {
	store := newTestStore(t)
	dispatchSeedTenant(t, store, "sync-nr@example.com") // 全局行 config_version=1
	cs := openTestClusterStore(t)
	ctx := context.Background()
	if err := cs.Register(ctx, sampleCluster("c1")); err != nil { // 注册但从不心跳
		t.Fatal(err)
	}

	h := newSyncHandler(t, store, cs)
	resp, code := doSyncStatus(t, h, testCfg())
	if code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", code)
	}
	if resp.Unknown != 1 || resp.Diverged != 0 || !resp.Alert {
		t.Errorf("期望 unknown=1 alert=true（未上报）, got unknown=%d diverged=%d alert=%v",
			resp.Unknown, resp.Diverged, resp.Alert)
	}
	if e := resp.Entries[0]; e.ActualVersion != "unknown" {
		t.Errorf("未上报应标记 unknown, got=%q", e.ActualVersion)
	}
}

func TestSyncStatus_GlobalFanoutMixed(t *testing.T) {
	store := newTestStore(t)
	dispatchSeedTenant(t, store, "sync-fo@example.com") // 全局行 config_version=1
	cs := openTestClusterStore(t)
	ctx := context.Background()
	if err := cs.Register(ctx, sampleCluster("c1")); err != nil {
		t.Fatal(err)
	}
	if err := cs.Register(ctx, sampleCluster("c2")); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Heartbeat(ctx, "c1", "1", time.Now()); err != nil { // 收敛
		t.Fatal(err)
	}
	if _, err := cs.Heartbeat(ctx, "c2", "3", time.Now()); err != nil { // 发散
		t.Fatal(err)
	}

	h := newSyncHandler(t, store, cs)
	resp, code := doSyncStatus(t, h, testCfg())
	if code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", code)
	}
	if resp.Total != 2 {
		t.Fatalf("全局扇出应得 2 条, got=%d entries=%+v", resp.Total, resp.Entries)
	}
	if resp.Converged != 1 || resp.Diverged != 1 || !resp.Alert {
		t.Errorf("期望 converged=1 diverged=1 alert=true, got converged=%d diverged=%d alert=%v",
			resp.Converged, resp.Diverged, resp.Alert)
	}
}

func TestSyncStatus_DirectedOrphanTarget(t *testing.T) {
	store := newTestStore(t)
	// 仅定向行（无全局行）：c1 已注册且收敛，c2 不在注册表（孤儿目标 ⇒ unknown）。
	tid, _ := seedTenantUser(t, store, "sync-dr@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	syncSeedClusterRow(t, store, tid, "c1")
	syncSeedClusterRow(t, store, tid, "c2")
	cs := openTestClusterStore(t)
	ctx := context.Background()
	if err := cs.Register(ctx, sampleCluster("c1")); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Heartbeat(ctx, "c1", "1", time.Now()); err != nil {
		t.Fatal(err)
	}

	h := newSyncHandler(t, store, cs)
	resp, code := doSyncStatus(t, h, testCfg())
	if code != http.StatusOK {
		t.Fatalf("期望 200, 实际 %d", code)
	}
	if resp.Total != 2 {
		t.Fatalf("定向两行应得 2 条, got=%d entries=%+v", resp.Total, resp.Entries)
	}
	if resp.Converged != 1 || resp.Unknown != 1 || !resp.Alert {
		t.Errorf("期望 converged=1(已注册) unknown=1(孤儿) alert=true, got converged=%d unknown=%d alert=%v",
			resp.Converged, resp.Unknown, resp.Alert)
	}
	// 孤儿目标 c2 必须出现在条目中（actual=unknown），不得被静默丢弃。
	foundOrphan := false
	for _, e := range resp.Entries {
		if e.ClusterID == "c2" && e.ActualVersion == "unknown" {
			foundOrphan = true
		}
	}
	if !foundOrphan {
		t.Errorf("孤儿目标 c2 应出现在条目中（actual=unknown）, entries=%+v", resp.Entries)
	}
}

func TestSyncStatus_Auth(t *testing.T) {
	store := newTestStore(t)
	dispatchSeedTenant(t, store, "sync-auth@example.com")
	h := newSyncHandler(t, store, nil)

	// 非 admin 令牌 ⇒ 403。
	mux := http.NewServeMux()
	h.registerSyncStatus(mux, testCfg())
	auditorTok := testSignToken(t, testSecret, claims{Sub: "bob", Role: roleAuditor, Iss: defaultIssuer, Aud: defaultAudience})
	req := httptest.NewRequest(http.MethodGet, syncStatusPath, nil)
	req.Header.Set("Authorization", "Bearer "+auditorTok)
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("非 admin 应 403, got=%d", rr.Code)
	}

	// 缺 Bearer ⇒ 401（authMiddleware 前置）。
	req2 := httptest.NewRequest(http.MethodGet, syncStatusPath, nil)
	rr2 := httptest.NewRecorder()
	mux.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusUnauthorized {
		t.Errorf("缺 Bearer 应 401, got=%d", rr2.Code)
	}
}
