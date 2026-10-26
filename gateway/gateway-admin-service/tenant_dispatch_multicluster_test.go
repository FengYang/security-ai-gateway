// Package main — P2-4 T-3.2b 下发语义「每租户×每集群单飞」单测。
//
// 覆盖：
//   - global 作用域 → 注册表中所有可用集群各下发一次（V-3「global 策略全集群生效」）；
//   - 定向作用域（cluster[]）→ 只下发到目标集群，其余集群无行、无副作用；
//   - 定向目标不可用 → fail-closed **不下发**（不投到不该收的集群）；
//   - 注册表不可用/为空 → 回退本地默认端点（单集群行为不变，V-7）；
//   - 集群行承载"期望版本"投影（T-3.3 收敛核对的数据基础）；
//   - 重启重放按租户×集群精确重放。
package main

import (
	"context"
	"sort"
	"testing"
	"time"
)

// fakeTargetResolver 目标集群解析器替身。
type fakeTargetResolver struct {
	tgts []dispatchTarget
	err  error
}

func (f *fakeTargetResolver) ListTargets(context.Context) ([]dispatchTarget, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.tgts, nil
}

// dispatchClusters 返回两个可用集群（active）。
func dispatchClusters() []dispatchTarget {
	return []dispatchTarget{
		{ClusterID: "c1", Endpoint: "http://core-c1:8080"},
		{ClusterID: "c2", Endpoint: "http://core-c2:8080"},
	}
}

// dispatchSeedTenant 建租户并把期望版本推进到 1（模拟写路径 bump）。
func dispatchSeedTenant(t *testing.T, store *sqliteTenantStore, email string) string {
	t.Helper()
	tid, _ := seedTenantUser(t, store, email, "Password123!", tenantUserStatusActive, tenantStatusActive)
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.BumpDispatchVersion(tx, tid, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return tid
}

// appliedClusters 返回已下发（applied）的**集群行**集合（不含租户级全局行）。
//
// 说明：全部集群收敛后，租户级全局行（cluster_id=”）也会被聚合置 applied；
// 本助手只关心"哪些集群收到了配置"，故排除全局行。
func appliedClusters(t *testing.T, store *sqliteTenantStore, tid string) []string {
	t.Helper()
	rows, err := store.ListDispatchStatesByStatus(dispatchStatusApplied)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		if r.TenantID == tid && r.ClusterID != dispatchClusterGlobal {
			out = append(out, r.ClusterID)
		}
	}
	sort.Strings(out)
	return out
}

func TestDispatch_MultiCluster_GlobalScope_DispatchesToAllClusters(t *testing.T) {
	store := newTestStore(t)
	tid := dispatchSeedTenant(t, store, "t32b-a@example.com")
	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	d.SetTargetResolver(&fakeTargetResolver{tgts: dispatchClusters()})

	d.Enqueue(tid)
	d.Wait()

	if applier.callCount() != 2 {
		t.Fatalf("global 作用域应向 2 个集群各下发一次, calls=%d", applier.callCount())
	}
	// 每个集群一行，且状态 applied。
	got := appliedClusters(t, store, tid)
	if len(got) != 2 || got[0] != "c1" || got[1] != "c2" {
		t.Fatalf("应有 c1/c2 两个集群行, got=%v", got)
	}
	// 计划的路由信息正确（端点随集群，不随载荷下发）。
	eps := map[string]string{}
	for _, p := range applier.plans {
		eps[p.TargetClusterID] = p.TargetEndpoint
	}
	if eps["c1"] != "http://core-c1:8080" || eps["c2"] != "http://core-c2:8080" {
		t.Errorf("目标端点不对: %v", eps)
	}
	// 全部集群收敛后，租户级全局行才 applied（聚合语义）。
	global, err := store.GetDispatchState(tid)
	if err != nil || global == nil {
		t.Fatalf("应有全局行: %+v err=%v", global, err)
	}
	if global.Status != dispatchStatusApplied {
		t.Errorf("全部集群收敛后全局行应 applied, got=%q", global.Status)
	}
	// 集群行承载"期望版本"投影（T-3.3 的期望版本来源）。
	for _, cid := range []string{"c1", "c2"} {
		row, err := store.GetDispatchStateForCluster(tid, cid)
		if err != nil || row == nil {
			t.Fatalf("缺集群行 %s: %+v err=%v", cid, row, err)
		}
		if row.ConfigVersion != global.ConfigVersion {
			t.Errorf("集群行 %s 期望版本应为 %d, got=%d", cid, global.ConfigVersion, row.ConfigVersion)
		}
		if row.AppliedVersion != global.ConfigVersion {
			t.Errorf("集群行 %s 实际版本应为 %d, got=%d", cid, global.ConfigVersion, row.AppliedVersion)
		}
	}
}

func TestDispatch_ClusterScope_OnlyTargetCluster(t *testing.T) {
	store := newTestStore(t)
	tid := dispatchSeedTenant(t, store, "t32b-b@example.com")
	// 策略定向 c2。
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPolicyOverlay(tx, &PolicyOverlay{
		TenantID: tid, Version: 0, WhitelistJSON: `{"entries":[]}`, BlacklistJSON: `{"entries":[]}`,
		CategoryActionsJSON: `{}`, UpdatedAt: 1, ScopeJSON: `{"global":false,"clusters":["c2"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	d.SetTargetResolver(&fakeTargetResolver{tgts: dispatchClusters()})

	d.Enqueue(tid)
	d.Wait()

	if applier.callCount() != 1 {
		t.Fatalf("定向作用域应只下发 1 次, calls=%d", applier.callCount())
	}
	if len(applier.plans) != 1 || applier.plans[0].TargetClusterID != "c2" {
		t.Fatalf("应下发到 c2, got=%+v", applier.plans)
	}
	// c1 不得有任何行（无副作用）。
	if row, _ := store.GetDispatchStateForCluster(tid, "c1"); row != nil {
		t.Errorf("非目标集群不应有行: %+v", row)
	}
	// c2 行 applied。
	row, err := store.GetDispatchStateForCluster(tid, "c2")
	if err != nil || row == nil || row.Status != dispatchStatusApplied {
		t.Fatalf("c2 行应 applied: %+v err=%v", row, err)
	}
}

func TestDispatch_ClusterScope_UnavailableTarget_FailClosed(t *testing.T) {
	store := newTestStore(t)
	tid := dispatchSeedTenant(t, store, "t32b-c@example.com")
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPolicyOverlay(tx, &PolicyOverlay{
		TenantID: tid, Version: 0, WhitelistJSON: `{"entries":[]}`, BlacklistJSON: `{"entries":[]}`,
		CategoryActionsJSON: `{}`, UpdatedAt: 1, ScopeJSON: `{"global":false,"clusters":["cX"]}`,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	d.SetTargetResolver(&fakeTargetResolver{tgts: dispatchClusters()})
	alarms := 0
	d.alarm = func(tenantID, kind, detail string) { alarms++ }

	d.Enqueue(tid)
	d.Wait()

	if applier.callCount() != 0 {
		t.Fatalf("目标不可用时不得下发, calls=%d", applier.callCount())
	}
	if alarms == 0 {
		t.Error("目标不可用应产生告警")
	}
	// 全局行保持 pending（未收敛），不得被误判为已生效。
	global, err := store.GetDispatchState(tid)
	if err != nil || global == nil {
		t.Fatalf("应有全局行: %+v err=%v", global, err)
	}
	if global.Status == dispatchStatusApplied {
		t.Error("未下发不得置 applied")
	}
}

func TestDispatch_NoRegistry_LegacySingleTargetUnchanged(t *testing.T) {
	store := newTestStore(t)
	tid := dispatchSeedTenant(t, store, "t32b-d@example.com")
	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	// 目标解析器不可用（注册表未启用）⇒ 回退本地默认端点。
	d.SetTargetResolver(&fakeTargetResolver{err: context.DeadlineExceeded})

	d.Enqueue(tid)
	d.Wait()

	if applier.callCount() != 1 {
		t.Fatalf("单集群行为应下发 1 次, calls=%d", applier.callCount())
	}
	if len(applier.plans) != 1 || applier.plans[0].TargetClusterID != dispatchClusterGlobal {
		t.Fatalf("应走本地默认端点（cluster_id=''）, got=%+v", applier.plans)
	}
	global, err := store.GetDispatchState(tid)
	if err != nil || global == nil {
		t.Fatalf("应有全局行: %+v err=%v", global, err)
	}
	if global.Status != dispatchStatusApplied {
		t.Errorf("全局行应 applied, got=%q", global.Status)
	}
	if global.AppliedVersion != global.ConfigVersion {
		t.Errorf("全局行应已收敛, applied=%d config=%d", global.AppliedVersion, global.ConfigVersion)
	}
}

func TestDispatch_ReplayPending_PerCluster(t *testing.T) {
	store := newTestStore(t)
	tid := dispatchSeedTenant(t, store, "t32b-e@example.com")
	// 手工造一个"某集群待下发"的行（模拟上次进程崩溃在 applying 之前）。
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.MarkDispatchPendingForCluster(tx, tid, "c1", 1, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	d.SetTargetResolver(&fakeTargetResolver{tgts: dispatchClusters()})

	n, err := d.ReplayPending()
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Error("重放应扫描到待下发行")
	}
	d.Wait()

	// c1：集群行精确重放；全局行扇出也命中 c1 ⇒ **去重后只下发 1 次**（单飞）。
	if got := targetCallCount(applier, "c1"); got != 1 {
		t.Errorf("c1 应只下发 1 次（全局行扇出与集群行精确重放须去重）, got=%d", got)
	}
	// c2：此前**无行**（从未收到过配置）⇒ 全局行扇出必须补发 1 次，
	// 否则一次崩溃会让 c2 静默缺配置（全局行 pending 语义）。
	if got := targetCallCount(applier, "c2"); got != 1 {
		t.Errorf("c2 此前无行，全局行扇出应补发 1 次, got=%d", got)
	}
	// 重放后 c1 收敛（applied）。
	row, err := store.GetDispatchStateForCluster(tid, "c1")
	if err != nil || row == nil || row.Status != dispatchStatusApplied {
		t.Fatalf("c1 行应 applied: %+v err=%v", row, err)
	}
}

// targetCallCount 统计下发到指定集群的次数（按计划的目标集群归集）。
func targetCallCount(applier *fakeDispatchApplier, clusterID string) int {
	applier.mu.Lock()
	defer applier.mu.Unlock()
	n := 0
	for _, p := range applier.plans {
		if p.TargetClusterID == clusterID {
			n++
		}
	}
	return n
}
