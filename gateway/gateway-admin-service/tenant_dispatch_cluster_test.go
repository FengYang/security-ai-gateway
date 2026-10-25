// Package main — P2-4 T-3.2a tenant_dispatch_state 复合主键 (tenant_id, cluster_id) 迁移单测。
//
// 覆盖：
//   - sqlite 存量库**整表重建**（旧结构 → 复合主键，存量行保留且 cluster_id=”）；
//   - 幂等可重入（重复打开不重复重建、不报错、行数不变）；
//   - 新旧并存可读写（全局行 cluster_id=” 与定向集群行互不覆盖）；
//   - 集群维度索引齐备（T-1.9 交接清单：(cluster_id,status)、(tenant_id,cluster_id)）；
//   - 并发互斥（同一租户×集群版本单调不丢更新；不同集群互不干扰）；
//   - 迁移工具复合主键路径（导出/导入/对账/purge 按复合键定位）；
//   - PG 门控变体（真机 PG 上验证 DROP PK + ADD 复合 PK 与双方言等价）。
package main

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// legacyDispatchDDL 迁移前的旧结构（tenant_id 单列主键、无 cluster_id 列）。
const legacyDispatchDDL = `
CREATE TABLE tenant_dispatch_state (
  tenant_id       TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  config_version  INTEGER NOT NULL DEFAULT 0,
  status          TEXT    NOT NULL DEFAULT 'idle' CHECK (status IN ('idle','pending','applying','applied','failed')),
  applied_version INTEGER NOT NULL DEFAULT 0,
  last_error      TEXT,
  retry_count     INTEGER NOT NULL DEFAULT 0,
  updated_at      INTEGER NOT NULL
);
`

// dispatchIndexNames 返回 tenant_dispatch_state 上的索引名集合（sqlite）。
func dispatchIndexNames(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query(`PRAGMA index_list(tenant_dispatch_state)`)
	if err != nil {
		t.Fatalf("index_list: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]bool{}
	for rows.Next() {
		var seq, unique, partial int
		var name, origin string
		if err := rows.Scan(&seq, &name, &unique, &origin, &partial); err != nil {
			t.Fatalf("scan index_list: %v", err)
		}
		out[name] = true
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("index_list rows: %v", err)
	}
	return out
}

// ---------- 存量库迁移（sqlite 整表重建） ----------

func TestDispatchState_LegacyMigration_KeepsRowsAndIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy-dispatch.db")
	pepper := []byte("t32a-test-pepper-12345678")

	// 1) 先按新版本建库并写入租户与一条下发状态行。
	ts, err := OpenTenantStore(path, false, pepper)
	if err != nil {
		t.Fatalf("初始化库失败: %v", err)
	}
	tx, err := ts.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := ts.CreateTenant(tx, &Tenant{ID: "t_legacy", Name: "存量租户", Status: tenantStatusActive, PlanID: "free", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := ts.BumpDispatchVersion(tx, "t_legacy", now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = ts.Close()

	// 2) 把下发状态表改回**旧结构**（模拟迁移前的部署）。
	db, err := sqlutil.Open(sqlutil.SQLite, path, 1)
	if err != nil {
		t.Fatalf("打开库失败: %v", err)
	}
	if _, err := db.Exec(`DROP TABLE tenant_dispatch_state`); err != nil {
		t.Fatalf("删旧表失败: %v", err)
	}
	if _, err := db.Exec(legacyDispatchDDL); err != nil {
		t.Fatalf("建旧结构失败: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_dispatch_state
		(tenant_id, config_version, status, applied_version, last_error, retry_count, updated_at)
		VALUES ('t_legacy', 7, 'pending', 3, NULL, 0, 111)`); err != nil {
		t.Fatalf("写存量行失败: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// 3) 重新打开（新版本启动）⇒ 触发整表重建。
	ts2, err := OpenTenantStore(path, false, pepper)
	if err != nil {
		t.Fatalf("存量库打开失败（迁移未生效）: %v", err)
	}
	s, ok := ts2.(*sqliteTenantStore)
	if !ok {
		t.Fatal("类型断言失败")
	}
	// 存量行保留，且落在全局行（cluster_id=''）。
	st, err := s.GetDispatchState("t_legacy")
	if err != nil || st == nil {
		t.Fatalf("存量行应保留: %+v err=%v", st, err)
	}
	if st.ClusterID != dispatchClusterGlobal {
		t.Errorf("存量行 cluster_id 应为空（全局行）, got=%q", st.ClusterID)
	}
	if st.ConfigVersion != 7 || st.AppliedVersion != 3 || st.Status != dispatchStatusPending {
		t.Errorf("存量行内容应原样保留, got=%+v", st)
	}
	// 结构已迁移为复合主键。
	hasCluster, need, err := dispatchStateSchemaState(s.db.DB)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCluster || need {
		t.Errorf("应已迁移为复合主键, hasCluster=%v need=%v", hasCluster, need)
	}
	_ = ts2.Close()

	// 4) 幂等可重入：再次打开不报错、不重复重建、行数不变。
	ts3, err := OpenTenantStore(path, false, pepper)
	if err != nil {
		t.Fatalf("重复打开失败（幂等可重入被破坏）: %v", err)
	}
	s3 := ts3.(*sqliteTenantStore)
	hasCluster2, need2, err := dispatchStateSchemaState(s3.db.DB)
	if err != nil {
		t.Fatal(err)
	}
	if !hasCluster2 || need2 {
		t.Errorf("重复打开后结构应保持目标态, hasCluster=%v need=%v", hasCluster2, need2)
	}
	var n int
	if err := s3.db.QueryRow(`SELECT COUNT(*) FROM tenant_dispatch_state`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("行数应仍为 1, got=%d", n)
	}
	_ = ts3.Close()
}

// ---------- 新旧并存可读写 ----------

func TestDispatchState_GlobalAndClusterRowsCoexist(t *testing.T) {
	s := newTestStore(t)
	tid, _ := seedTenantUser(t, s, "t32a-a@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	now := time.Now().Unix()

	tx, err := s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s.BumpDispatchVersionForCluster(tx, tid, dispatchClusterGlobal, now); err != nil || v != 1 {
		t.Fatalf("全局行 bump 应得 1, got=%d err=%v", v, err)
	}
	if v, err := s.BumpDispatchVersionForCluster(tx, tid, "c1", now); err != nil || v != 1 {
		t.Fatalf("集群行 bump 应得 1, got=%d err=%v", v, err)
	}
	if v, err := s.BumpDispatchVersionForCluster(tx, tid, "c2", now); err != nil || v != 1 {
		t.Fatalf("集群行 bump 应得 1, got=%d err=%v", v, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	// 三行并存，互不覆盖。
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tenant_dispatch_state WHERE tenant_id = ?`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("应有 3 行（全局 + c1 + c2）, got=%d", n)
	}
	g, err := s.GetDispatchState(tid)
	if err != nil || g == nil || g.ClusterID != dispatchClusterGlobal {
		t.Fatalf("全局行读取失败: %+v err=%v", g, err)
	}
	for _, cid := range []string{"c1", "c2"} {
		row, err := s.GetDispatchStateForCluster(tid, cid)
		if err != nil || row == nil || row.ClusterID != cid {
			t.Fatalf("集群行 %s 读取失败: %+v err=%v", cid, row, err)
		}
		if row.ConfigVersion != 1 {
			t.Errorf("集群行 %s 版本应为 1, got=%d", cid, row.ConfigVersion)
		}
	}
	// 集群行的 bump 不影响全局行。
	tx2, err := s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BumpDispatchVersionForCluster(tx2, tid, "c1", now); err != nil {
		t.Fatal(err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatal(err)
	}
	g2, _ := s.GetDispatchState(tid)
	c1, _ := s.GetDispatchStateForCluster(tid, "c1")
	if g2.ConfigVersion != 1 {
		t.Errorf("全局行版本不应被集群行影响, got=%d", g2.ConfigVersion)
	}
	if c1.ConfigVersion != 2 {
		t.Errorf("集群行版本应推进到 2, got=%d", c1.ConfigVersion)
	}
	// 跨租户隔离：另一租户看不到这些行。
	other, _ := seedTenantUser(t, s, "t32a-b@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	if row, _ := s.GetDispatchStateForCluster(other, "c1"); row != nil {
		t.Errorf("跨租户读取应为空, got=%+v", row)
	}
}

// ---------- 索引齐备 ----------

func TestDispatchState_ClusterIndexesRegistered(t *testing.T) {
	s := newTestStore(t)
	names := dispatchIndexNames(t, s.db.DB)
	want := []string{
		"idx_dispatch_status",         // 既有：按状态扫描
		"idx_dispatch_status_updated", // 既有（T-1.9）：状态 + 更新时间排序
		"idx_dispatch_cluster_status", // T-3.2a：T-1.9 交接清单（cluster_id, status）
		"idx_dispatch_tenant_cluster", // T-3.2a：T-1.9 交接清单（tenant_id, cluster_id）
	}
	for _, w := range want {
		if !names[w] {
			t.Errorf("缺索引 %s（现有: %v）", w, names)
		}
	}
}

// ---------- 并发互斥 ----------

func TestDispatchState_ConcurrentBumpPerCluster(t *testing.T) {
	s := newTestStore(t)
	tid, _ := seedTenantUser(t, s, "t32a-c@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	now := time.Now().Unix()

	const workers = 4
	const rounds = 5
	var wg sync.WaitGroup
	errCh := make(chan error, workers*rounds)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < rounds; j++ {
				tx, err := s.Begin()
				if err != nil {
					errCh <- err
					return
				}
				if _, err := s.BumpDispatchVersionForCluster(tx, tid, "c1", now); err != nil {
					_ = tx.Rollback()
					errCh <- err
					return
				}
				if err := tx.Commit(); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatalf("并发 bump 失败: %v", err)
	}

	row, err := s.GetDispatchStateForCluster(tid, "c1")
	if err != nil || row == nil {
		t.Fatalf("应有一行: %+v err=%v", row, err)
	}
	if row.ConfigVersion != workers*rounds {
		t.Errorf("版本应单调到 %d（不丢更新）, got=%d", workers*rounds, row.ConfigVersion)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tenant_dispatch_state WHERE tenant_id = ? AND cluster_id = 'c1'`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("同一租户×集群应只有 1 行, got=%d", n)
	}
	// 不同集群互不干扰。
	tx, err := s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.BumpDispatchVersionForCluster(tx, tid, "c2", now); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	row2, _ := s.GetDispatchStateForCluster(tid, "c2")
	if row2.ConfigVersion != 1 {
		t.Errorf("另一集群行版本应为 1, got=%d", row2.ConfigVersion)
	}
}

// ---------- 迁移工具：复合主键路径 ----------

func TestMigrate_CompositePK_ExportImportVerifyPurge(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "source.db")
	dst := filepath.Join(dir, "target.db")
	dump := filepath.Join(dir, "dump.json")
	pepper := []byte("t32a-migrate-pepper-123456")

	// 源库：全局行 + 两个集群行（同一租户）。
	ts, err := OpenTenantStore(src, false, pepper)
	if err != nil {
		t.Fatalf("建源库失败: %v", err)
	}
	tx, err := ts.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := ts.CreateTenant(tx, &Tenant{ID: "t-mig-c", Name: "复合主键租户", Status: tenantStatusActive, PlanID: "free", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, cid := range []string{dispatchClusterGlobal, "c1", "c2"} {
		if _, err := ts.BumpDispatchVersionForCluster(tx, "t-mig-c", cid, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	_ = ts.Close()

	// 目标库：空表（同一 schema）。
	tgt, err := OpenTenantStore(dst, false, pepper)
	if err != nil {
		t.Fatalf("建目标库失败: %v", err)
	}
	_ = tgt.Close()

	if code := runMigrate([]string{"-action", "export", "-from", src, "-out", dump}); code != 0 {
		t.Fatalf("export 退出码 %d", code)
	}
	if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", dump, "-apply"}); code != 0 {
		t.Fatalf("import 退出码 %d", code)
	}
	if code := runMigrate([]string{"-action", "verify", "-from", src, "-to", dst, "-driver", "sqlite"}); code != 0 {
		t.Fatalf("复合主键导入后 verify 应通过, 退出码 %d", code)
	}

	db, err := sqlutil.Open(sqlutil.SQLite, dst, 1)
	if err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenant_dispatch_state WHERE tenant_id = 't-mig-c'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("导入后应有 3 行（复合主键各一行）, got=%d", n)
	}
	// 幂等：重复导入不新增行。
	if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", dump, "-apply"}); code != 0 {
		t.Fatalf("二次 import 退出码 %d", code)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenant_dispatch_state WHERE tenant_id = 't-mig-c'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("重复导入后行数不应变化, got=%d", n)
	}
	// purge 按复合主键清除本次导入的行。
	if code := runMigrate([]string{"-action", "rollback", "-to", dst, "-driver", "sqlite", "-purge", "-out", dump}); code != 0 {
		t.Fatalf("rollback -purge 退出码 %d", code)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenant_dispatch_state WHERE tenant_id = 't-mig-c'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("purge 后应清空导入行, got=%d", n)
	}
	_ = db.Close()
}

// ---------- PG 门控（真机复验） ----------

func TestDispatchState_PGGate_CompositePK(t *testing.T) {
	dsn := os.Getenv("ADMIN_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("ADMIN_TEST_PG_DSN 未设置，跳过 PG 门控用例")
	}
	ts, err := OpenTenantStoreWithDialect(sqlutil.Postgres, dsn, false, []byte("pg-test-pepper-1234"))
	if err != nil {
		t.Fatalf("open pg tenant store: %v", err)
	}
	s, ok := ts.(*sqliteTenantStore)
	if !ok {
		t.Fatalf("unexpected store type %T", ts)
	}
	defer s.Close()

	// 主键必须是 (tenant_id, cluster_id)。
	conName, cols, err := pgPrimaryKeyInfo(s.db, "tenant_dispatch_state")
	if err != nil {
		t.Fatalf("读主键失败: %v", err)
	}
	if len(cols) != 2 || cols[0] != "tenant_id" || cols[1] != "cluster_id" {
		t.Fatalf("PG 主键应为 (tenant_id, cluster_id), got=%v (约束 %q)", cols, conName)
	}
	// 幂等可重入：重复执行迁移不报错、主键不变。
	if err := ensureDispatchSchemaPG(s.db); err != nil {
		t.Fatalf("重复迁移失败（幂等可重入被破坏）: %v", err)
	}
	_, cols2, err := pgPrimaryKeyInfo(s.db, "tenant_dispatch_state")
	if err != nil {
		t.Fatal(err)
	}
	if len(cols2) != 2 || cols2[0] != "tenant_id" || cols2[1] != "cluster_id" {
		t.Errorf("重复迁移后主键应不变, got=%v", cols2)
	}
	// 新旧并存可读写（真实共享库）。
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tid := "pg-d32a-" + suffix
	tx, err := s.Begin()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if err := s.CreateTenant(tx, &Tenant{ID: tid, Name: "PG 复合主键租户", Status: tenantStatusActive, PlanID: "free", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	for _, cid := range []string{dispatchClusterGlobal, "c1"} {
		if _, err := s.BumpDispatchVersionForCluster(tx, tid, cid, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	g, err := s.GetDispatchState(tid)
	if err != nil || g == nil {
		t.Fatalf("PG 全局行读取失败: %+v err=%v", g, err)
	}
	c1, err := s.GetDispatchStateForCluster(tid, "c1")
	if err != nil || c1 == nil {
		t.Fatalf("PG 集群行读取失败: %+v err=%v", c1, err)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM tenant_dispatch_state WHERE tenant_id = ?`, tid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Errorf("PG 应有 2 行（全局 + c1）, got=%d", n)
	}
}
