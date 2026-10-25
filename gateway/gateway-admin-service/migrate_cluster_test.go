// migrate_cluster_test.go — P2-4 T-1.6 补：迁移工具覆盖集群注册表（T-2.1/T-2.3）
// + rollback -purge 精确清除语义。
//
// 背景：sqlite 部署下集群注册表在**独立文件**（<TENANT_STORE_PATH>.clusters），
// 不在租户库文件内；若迁移工具只搬租户库，切库后目标库 ensureSchema 会建出
// **空注册表** → 已注册集群全部消失、集群身份凭证失效（心跳被 fail-closed 拒绝）
// → 注册表状态机直接 degraded/unreachable。本文件锁定该场景不回归。
//
// 同时锁定：rollback -purge 只清除**本次导入的行**，不得误删目标库既有数据
// （早前实现是清空整表，与文档口径不符，已修正）。
package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// newMigrateClusterSource 构造集群注册表源（sqlite 独立文件），写入
// 1 个集群 + 1 条心跳明细 + 1 条集群身份凭证。
func newMigrateClusterSource(t *testing.T, clusterPath string) {
	t.Helper()
	cs, err := OpenClusterStore(sqlutil.SQLite, clusterPath)
	if err != nil {
		t.Fatalf("open cluster store: %v", err)
	}
	defer cs.Close()
	ctx := context.Background()
	now := time.Now()
	if err := cs.Register(ctx, &ClusterRecord{
		ID:       "c-mig-1",
		Name:     "迁移集群",
		Endpoint: "http://cluster-a.example.com:8080",
		Form:     ClusterFormSameCity,
		Capacity: ClusterCapacity{RPS: 100, Concurrency: 50},
	}); err != nil {
		t.Fatalf("register cluster: %v", err)
	}
	if _, err := cs.Heartbeat(ctx, "c-mig-1", "cfg-v1", now); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if _, _, err := cs.Credentials().Issue(ctx, "c-mig-1", time.Hour, now); err != nil {
		t.Fatalf("issue cluster credential: %v", err)
	}
}

// newMigrateTargetWithCluster 在目标库建集群注册表（PG 部署下与租户库同库）。
func newMigrateTargetWithCluster(t *testing.T, targetPath string) {
	t.Helper()
	cs, err := OpenClusterStore(sqlutil.SQLite, targetPath)
	if err != nil {
		t.Fatalf("init target cluster schema: %v", err)
	}
	cs.Close()
}

// countRows 统计目标库某表行数。
func countRows(t *testing.T, dsn, table string) int {
	t.Helper()
	db, err := sqlutil.Open(sqlutil.SQLite, "file:"+dsn+"?_pragma=query_only(1)", 0)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return n
}

// TestMigrate_ClusterRegistry_Migrated 集群注册表必须随迁：
// 源 clusters/cluster_heartbeats/cluster_credentials（独立文件）→ 导入目标 → 对账一致。
func TestMigrate_ClusterRegistry_Migrated(t *testing.T) {
	src := newMigrateSource(t)
	clusterSrc := src + ".clusters"
	newMigrateClusterSource(t, clusterSrc)

	dir := t.TempDir()
	dst := newMigrateTarget(t, sqlutil.SQLite, filepath.Join(dir, "target.db"))
	newMigrateTargetWithCluster(t, dst)
	dump := filepath.Join(dir, "dump.json")

	if code := runMigrate([]string{"-action", "export", "-from", src, "-out", dump}); code != 0 {
		t.Fatalf("export 退出码 %d", code)
	}
	if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", dump, "-apply"}); code != 0 {
		t.Fatalf("import 退出码 %d", code)
	}
	if code := runMigrate([]string{"-action", "verify", "-from", src, "-to", dst, "-driver", "sqlite"}); code != 0 {
		t.Fatalf("verify 应通过（集群注册表随迁），实际 %d", code)
	}
	for table, want := range map[string]int{
		"clusters":            1,
		"cluster_heartbeats":  1,
		"cluster_credentials": 1,
	} {
		if got := countRows(t, dst, table); got != want {
			t.Errorf("目标 %s 行数 = %d，期望 %d（集群注册表未随迁 → 切库即丢集群拓扑/凭证）", table, got, want)
		}
	}
}

// TestMigrate_ClusterRegistry_SourceMissing 源无集群注册表文件时该组表跳过
// （未启用集群注册表的部署）；显式 -from-cluster 指向不存在路径 → fail-closed。
func TestMigrate_ClusterRegistry_SourceMissing(t *testing.T) {
	src := newMigrateSource(t)
	dir := t.TempDir()
	dst := newMigrateTarget(t, sqlutil.SQLite, filepath.Join(dir, "target.db"))
	newMigrateTargetWithCluster(t, dst)
	dump := filepath.Join(dir, "dump.json")

	// 缺省推导 <from>.clusters 不存在 → 导出跳过该组表，退出码 0。
	if code := runMigrate([]string{"-action", "export", "-from", src, "-out", dump}); code != 0 {
		t.Fatalf("export 应跳过集群组表并成功，实际 %d", code)
	}
	if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", dump, "-apply"}); code != 0 {
		t.Fatalf("import 退出码 %d", code)
	}
	if got := countRows(t, dst, "clusters"); got != 0 {
		t.Errorf("源无集群注册表时目标不应有集群行: got=%d", got)
	}
	// 显式指定不存在的集群源 → fail-closed（退出码 2，不得静默跳过整组表）。
	missing := filepath.Join(dir, "no-such.clusters")
	if code := runMigrate([]string{"-action", "export", "-from", src, "-from-cluster", missing, "-out", dump}); code != 2 {
		t.Fatalf("显式集群源不存在应退出码 2（fail-closed），实际 %d", code)
	}
}

// TestMigrate_PurgeOnlyImportedRows rollback -purge 只清除本次导入的行，
// 目标库**既有数据不得被误删**。
func TestMigrate_PurgeOnlyImportedRows(t *testing.T) {
	src := newMigrateSource(t)
	clusterSrc := src + ".clusters"
	newMigrateClusterSource(t, clusterSrc)
	dir := t.TempDir()
	dst := newMigrateTarget(t, sqlutil.SQLite, filepath.Join(dir, "target.db"))
	newMigrateTargetWithCluster(t, dst)
	dump := filepath.Join(dir, "dump.json")

	// 目标库预置"既有数据"（不是本次导入的行）。
	cs, err := OpenClusterStore(sqlutil.SQLite, dst)
	if err != nil {
		t.Fatalf("open target cluster store: %v", err)
	}
	if err := cs.Register(context.Background(), &ClusterRecord{
		ID: "c-existing", Name: "既有集群", Endpoint: "http://cluster-b.example.com:8080",
		Form: ClusterFormRemote,
	}); err != nil {
		t.Fatalf("register existing cluster: %v", err)
	}
	cs.Close()

	if code := runMigrate([]string{"-action", "export", "-from", src, "-out", dump}); code != 0 {
		t.Fatalf("export: %d", code)
	}
	if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", dump, "-apply"}); code != 0 {
		t.Fatalf("import: %d", code)
	}
	if got := countRows(t, dst, "clusters"); got != 2 {
		t.Fatalf("导入后 clusters 行数 = %d，期望 2（既有 1 + 导入 1）", got)
	}

	if code := runMigrate([]string{"-action", "rollback", "-to", dst, "-driver", "sqlite", "-purge", "-out", dump}); code != 0 {
		t.Fatalf("rollback -purge 退出码 %d", code)
	}
	// 导入的集群行被清除；既有集群行保留。
	if got := countRows(t, dst, "clusters"); got != 1 {
		t.Errorf("purge 后 clusters 行数 = %d，期望 1（只清除本次导入的行）", got)
	}
	db, err := sqlutil.Open(sqlutil.SQLite, "file:"+dst+"?_pragma=query_only(1)", 0)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	defer db.Close()
	var id string
	if err := db.QueryRow(`SELECT id FROM clusters`).Scan(&id); err != nil {
		t.Fatalf("读 clusters: %v", err)
	}
	if id != "c-existing" {
		t.Errorf("保留下来的应是既有集群 c-existing，实际 %q", id)
	}
	// 租户侧既有行同样只清导入行。
	if got := countRows(t, dst, "tenants"); got != 0 {
		t.Errorf("purge 后 tenants 行数 = %d，期望 0（导入行应被清除）", got)
	}
}

// TestMigrate_PurgeRequiresDump rollback -purge 缺 dump 时 fail-closed：
// 不得在无凭据的情况下清库。
func TestMigrate_PurgeRequiresDump(t *testing.T) {
	dir := t.TempDir()
	dst := newMigrateTarget(t, sqlutil.SQLite, filepath.Join(dir, "target.db"))
	if code := runMigrate([]string{"-action", "rollback", "-to", dst, "-driver", "sqlite", "-purge", "-out", filepath.Join(dir, "missing.json")}); code != 2 {
		t.Fatalf("缺 dump 时 purge 应退出码 2（fail-closed），实际 %d", code)
	}
}
