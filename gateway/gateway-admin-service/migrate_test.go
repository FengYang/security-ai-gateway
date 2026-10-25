// migrate_test.go — P2-4 T-1.6 存储迁移工具测试。
//
// 主线用例以 sqlite 影子库（源 → 目标）完整演练导出/导入/校验和/回滚（不 skip）；
// 真 PG 门控用例（ADMIN_TEST_PG_DSN 未设置时跳过，不伪装通过）。
package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// newMigrateSource 构造源 sqlite 库（租户表 + 安全计数器表），并写入样本数据。
func newMigrateSource(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "source.db")
	ts, err := OpenTenantStore(path, false, []byte("migrate-test-pepper-123456"))
	if err != nil {
		t.Fatalf("open tenant store: %v", err)
	}
	// 安全计数器表与租户表同库（单 sqlite 文件部署形态）。
	sec, err := openSecurityStore(sqlutil.SQLite, path)
	if err != nil {
		t.Fatalf("open security store: %v", err)
	}
	now := time.Now().Unix()
	tx, err := ts.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := ts.CreateTenant(tx, &Tenant{ID: "t-mig-1", Name: "迁移租户", Status: tenantStatusActive, PlanID: "free", CreatedAt: now}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	uid, err := ts.CreateUser(tx, &TenantUser{TenantID: "t-mig-1", Email: "Migrate@Example.COM", PasswordHash: "$2a$12$fakefakefakefakefakefakefakefakefakefakefakefakefakef", Status: tenantUserStatusActive, CreatedAt: now})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := ts.CreateToken(tx, &MailActionToken{TokenHash: "hash-mig-1", TenantUserID: uid, Action: mailActionVerify, ExpiresAt: now + 3600, ConsumedAt: 0}); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := ts.UpsertProvisioning(tx, &TenantProvisioning{TenantID: "t-mig-1", Scenario: "s3a", TrustTier: "trusted", AccessMode: "a_segmented", PluginSetJSON: `[]`, Segment1Enabled: true, Segment2Mode: "cross_node_mtls", TemplateVersion: "tpl-1", ProviderCredRefsJSON: `[]`, ProvisionedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("upsert provisioning: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	// 安全计数器样本。
	if _, err := sec.Exec(`INSERT INTO login_attempts (identity, failed_count, locked_until, updated_at) VALUES (?, ?, 0, ?)`, "attacker@example.com", 3, now); err != nil {
		t.Fatalf("seed login_attempts: %v", err)
	}
	if _, err := sec.Exec(`INSERT INTO operation_intervals (op_key, last_at) VALUES (?, ?)`, "reset@example.com", now); err != nil {
		t.Fatalf("seed operation_intervals: %v", err)
	}
	ts.Close()
	sec.Close()
	return path
}

// newMigrateTarget 构造目标库（默认 sqlite 影子库；PG 由门控用例指定）。
func newMigrateTarget(t *testing.T, d sqlutil.Dialect, dsn string) string {
	t.Helper()
	if d.IsPostgres() {
		return dsn
	}
	ts, err := OpenTenantStore(dsn, false, []byte("migrate-test-pepper-123456"))
	if err != nil {
		t.Fatalf("init target tenant schema: %v", err)
	}
	ts.Close() // 仅建表；迁移工具自己打开（避免句柄未释放阻碍 TempDir 清理）
	sec, err := openSecurityStore(sqlutil.SQLite, dsn)
	if err != nil {
		t.Fatalf("init target security schema: %v", err)
	}
	sec.Close()
	return dsn
}

// TestMigrate_ExportImportVerify 完整演练：导出 → 导入 → 校验和一致。
func TestMigrate_ExportImportVerify(t *testing.T) {
	src := newMigrateSource(t)
	dir := t.TempDir()
	dst := newMigrateTarget(t, sqlutil.SQLite, filepath.Join(dir, "target.db"))
	dump := filepath.Join(dir, "dump.json")

	if code := runMigrate([]string{"-action", "export", "-from", src, "-out", dump}); code != 0 {
		t.Fatalf("export 退出码 %d", code)
	}
	// 导入前：校验和不通过（目标为空）。
	if code := runMigrate([]string{"-action", "verify", "-from", src, "-to", dst, "-driver", "sqlite"}); code != 1 {
		t.Fatalf("空目标 verify 应返回 1（禁止切换），实际 %d", code)
	}
	if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", dump, "-apply"}); code != 0 {
		t.Fatalf("import 退出码 %d", code)
	}
	if code := runMigrate([]string{"-action", "verify", "-from", src, "-to", dst, "-driver", "sqlite"}); code != 0 {
		t.Fatalf("导入后 verify 应通过，实际 %d", code)
	}
}

// TestMigrate_Idempotent 幂等可重入：连跑两次 import，结果一致、无重复行。
func TestMigrate_Idempotent(t *testing.T) {
	src := newMigrateSource(t)
	dir := t.TempDir()
	dst := newMigrateTarget(t, sqlutil.SQLite, filepath.Join(dir, "target.db"))
	dump := filepath.Join(dir, "dump.json")
	if code := runMigrate([]string{"-action", "export", "-from", src, "-out", dump}); code != 0 {
		t.Fatalf("export: %d", code)
	}
	for i := 0; i < 2; i++ {
		if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", dump, "-apply"}); code != 0 {
			t.Fatalf("第 %d 次 import 退出码 %d", i+1, code)
		}
	}
	if code := runMigrate([]string{"-action", "verify", "-from", src, "-to", dst, "-driver", "sqlite"}); code != 0 {
		t.Fatalf("二次导入后 verify 应通过（幂等），实际 %d", code)
	}
	// 行数不翻倍。
	db, err := sqlutil.Open(sqlutil.SQLite, "file:"+dst+"?_pragma=query_only(1)", 0)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenants`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("tenants 行数 = %d err=%v，重复导入应不翻倍", n, err)
	}
}

// TestMigrate_DryRunNoWrite 默认 dry-run：import 不得写目标库。
func TestMigrate_DryRunNoWrite(t *testing.T) {
	src := newMigrateSource(t)
	dir := t.TempDir()
	dst := newMigrateTarget(t, sqlutil.SQLite, filepath.Join(dir, "target.db"))
	dump := filepath.Join(dir, "dump.json")
	if code := runMigrate([]string{"-action", "export", "-from", src, "-out", dump}); code != 0 {
		t.Fatalf("export: %d", code)
	}
	if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", dump}); code != 0 {
		t.Fatalf("dry-run import 退出码 %d", code)
	}
	db, err := sqlutil.Open(sqlutil.SQLite, "file:"+dst+"?_pragma=query_only(1)", 0)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenants`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("dry-run 不应写入：tenants 行数 = %d err=%v", n, err)
	}
}

// TestMigrate_FailurePaths 失败路径：dump 损坏、源库缺表、未知表名。
func TestMigrate_FailurePaths(t *testing.T) {
	dir := t.TempDir()
	dst := newMigrateTarget(t, sqlutil.SQLite, filepath.Join(dir, "target.db"))
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", bad, "-apply"}); code != 2 {
		t.Fatalf("损坏 dump 应退出码 2，实际 %d", code)
	}
	// 空库（无表）导出 tenant_statements → 失败。
	empty := filepath.Join(dir, "empty.db")
	if code := runMigrate([]string{"-action", "export", "-from", empty, "-out", filepath.Join(dir, "d2.json"), "-tables", "tenants"}); code != 1 {
		t.Fatalf("源缺表应退出码 1，实际 %d", code)
	}
	// 未知表名。
	if code := runMigrate([]string{"-action", "plan", "-from", empty, "-tables", "no_such_table"}); code != 2 {
		t.Fatalf("未知表名应退出码 2，实际 %d", code)
	}
}

// TestMigrate_RollbackPurge 回滚：默认仅打印 SOP；-purge 清除目标库导入行。
func TestMigrate_RollbackPurge(t *testing.T) {
	src := newMigrateSource(t)
	dir := t.TempDir()
	dst := newMigrateTarget(t, sqlutil.SQLite, filepath.Join(dir, "target.db"))
	dump := filepath.Join(dir, "dump.json")
	if code := runMigrate([]string{"-action", "export", "-from", src, "-out", dump}); code != 0 {
		t.Fatalf("export: %d", code)
	}
	if code := runMigrate([]string{"-action", "import", "-to", dst, "-driver", "sqlite", "-out", dump, "-apply"}); code != 0 {
		t.Fatalf("import: %d", code)
	}
	if code := runMigrate([]string{"-action", "rollback", "-to", dst, "-driver", "sqlite"}); code != 0 {
		t.Fatalf("rollback（仅 SOP）退出码 %d", code)
	}
	// -purge 需带 dump（按主键精确清除本次导入的行；缺 dump → fail-closed）。
	if code := runMigrate([]string{"-action", "rollback", "-to", dst, "-driver", "sqlite", "-purge"}); code != 2 {
		t.Fatalf("缺 dump 的 purge 应退出码 2（fail-closed），实际 %d", code)
	}
	if code := runMigrate([]string{"-action", "rollback", "-to", dst, "-driver", "sqlite", "-purge", "-out", dump}); code != 0 {
		t.Fatalf("rollback -purge 退出码 %d", code)
	}
	db, err := sqlutil.Open(sqlutil.SQLite, "file:"+dst+"?_pragma=query_only(1)", 0)
	if err != nil {
		t.Fatalf("open target: %v", err)
	}
	defer db.Close()
	for _, table := range []string{"tenants", "tenant_users", "login_attempts"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s 清除后应为空: n=%d err=%v", table, n, err)
		}
	}
}

// TestMigrate_PGPGate 真 PG 门控用例（导出 → 导入 → 校验和一致）。
func TestMigrate_PGPGate(t *testing.T) {
	dsn := pgTestDSN()
	if dsn == "" {
		t.Skip("ADMIN_TEST_PG_DSN 未设置，跳过 PG 门控用例")
	}
	src := newMigrateSource(t)
	dir := t.TempDir()
	dump := filepath.Join(dir, "dump.json")
	// 目标 PG 侧先建表（复用应用侧 DDL）。
	if ts, err := OpenTenantStoreWithDialect(sqlutil.Postgres, dsn, false, []byte("migrate-test-pepper-123456")); err != nil {
		t.Fatalf("init pg tenant schema: %v", err)
	} else {
		ts.Close()
	}
	if sec, err := openSecurityStore(sqlutil.Postgres, dsn); err != nil {
		t.Fatalf("init pg security schema: %v", err)
	} else {
		sec.Close()
	}
	if code := runMigrate([]string{"-action", "export", "-from", src, "-out", dump}); code != 0 {
		t.Fatalf("export: %d", code)
	}
	if code := runMigrate([]string{"-action", "import", "-to", dsn, "-driver", "pgx", "-out", dump, "-apply"}); code != 0 {
		t.Fatalf("import: %d", code)
	}
	if code := runMigrate([]string{"-action", "verify", "-from", src, "-to", dsn, "-driver", "pgx"}); code != 0 {
		t.Fatalf("PG verify 应通过，实际 %d", code)
	}
	// 幂等：二次导入后仍一致。
	if code := runMigrate([]string{"-action", "import", "-to", dsn, "-driver", "pgx", "-out", dump, "-apply"}); code != 0 {
		t.Fatalf("二次 import: %d", code)
	}
	if code := runMigrate([]string{"-action", "verify", "-from", src, "-to", dsn, "-driver", "pgx"}); code != 0 {
		t.Fatalf("PG 二次导入后 verify 应通过（幂等），实际 %d", code)
	}
}
