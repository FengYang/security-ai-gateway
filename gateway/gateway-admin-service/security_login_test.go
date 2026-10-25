// security_login_test.go — P2-4 T-1.4 登录失败锁定共享库后端测试。
//
// 主体用例以内存 sqlite 驱动同一套 SQL（双方言逻辑全覆盖，不 skip）；
// 另含真 PG 门控用例（ADMIN_TEST_PG_DSN 未设置时跳过，不伪装通过）。
package main

import (
	"sync"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// newSQLLoginTestGuard 构造基于内存 sqlite 的共享库登录锁定门禁。
func newSQLLoginTestGuard(t *testing.T, maxFail, lockMin int) (*loginGuard, *sqlutil.DB) {
	t.Helper()
	db, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open security store: %v", err)
	}
	db.SetMaxOpenConns(1) // 内存库单连接；并发原子性由真 PG 门控用例覆盖
	t.Cleanup(func() {
		db.Close()
	})
	return newSQLLoginGuard(db, maxFail, lockMin), db
}

// failedCount 读回当前失败计数（直查库，验证原子累计结果）。
func failedCount(t *testing.T, db *sqlutil.DB, identity string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT failed_count FROM login_attempts WHERE identity = ?`, identity).Scan(&n); err != nil {
		t.Fatalf("read failed_count: %v", err)
	}
	return n
}

func TestSQLLoginGuard_LockAndExpiryReset(t *testing.T) {
	g, db := newSQLLoginTestGuard(t, 3, 15)
	const id = "attacker@example.com"
	g.onFail(id)
	g.onFail(id)
	if g.isLocked(id) {
		t.Fatal("未达阈值不应锁定")
	}
	g.onFail(id) // 第 3 次 → 锁定
	if !g.isLocked(id) {
		t.Fatal("达阈值应锁定")
	}
	// 锁定窗口内继续失败：语义与内存实现对齐（计数累加、窗口顺延）。
	g.onFail(id)
	if n := failedCount(t, db, id); n != 4 {
		t.Fatalf("锁定期内失败应继续计数: %d", n)
	}
	if !g.isLocked(id) {
		t.Fatal("锁定期内应持续拒绝")
	}
	// 锁定过期 → 记录删除、计数清零、重新累计。
	if _, err := db.Exec(`UPDATE login_attempts SET locked_until = ? WHERE identity = ?`, time.Now().Unix()-1, id); err != nil {
		t.Fatalf("rewind lock: %v", err)
	}
	if g.isLocked(id) {
		t.Fatal("锁定过期应解锁")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_attempts WHERE identity = ?`, id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("过期锁定记录应被清理: n=%d err=%v", n, err)
	}
	g.onFail(id)
	if c := failedCount(t, db, id); c != 1 {
		t.Fatalf("解锁后应重新从 1 计数: %d", c)
	}
}

func TestSQLLoginGuard_SuccessReset(t *testing.T) {
	g, db := newSQLLoginTestGuard(t, 3, 15)
	const id = "user@example.com"
	g.onFail(id)
	g.onFail(id)
	g.onSuccess(id)
	if g.isLocked(id) {
		t.Fatal("成功后不应锁定")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_attempts WHERE identity = ?`, id).Scan(&n); err != nil || n != 0 {
		t.Fatalf("成功后记录应删除: n=%d err=%v", n, err)
	}
	// 清零后重新累计：2 次不锁定。
	g.onFail(id)
	g.onFail(id)
	if g.isLocked(id) {
		t.Fatal("清零后 2 次失败不应锁定")
	}
	if c := failedCount(t, db, id); c != 2 {
		t.Fatalf("清零后重新计数应为 2: %d", c)
	}
}

func TestSQLLoginGuard_UnknownIdentity(t *testing.T) {
	g, _ := newSQLLoginTestGuard(t, 3, 15)
	if g.isLocked("nobody@example.com") {
		t.Fatal("无记录不应锁定")
	}
	g.onSuccess("nobody@example.com") // 无记录删除为空操作，不应报错
}

// TestSQLLoginGuard_ConcurrentFailCount 并发失败计数：原子 upsert 无丢失，
// 达阈值即锁定（跨副本不按副本放大）。
func TestSQLLoginGuard_ConcurrentFailCount(t *testing.T) {
	g, db := newSQLLoginTestGuard(t, 5, 15)
	const id = "race@example.com"
	const workers = 20
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			g.onFail(id)
		}()
	}
	wg.Wait()
	if c := failedCount(t, db, id); c != workers {
		t.Fatalf("并发失败计数 = %d, want %d（原子累计无丢失）", c, workers)
	}
	if !g.isLocked(id) {
		t.Fatal("计数远超阈值应处于锁定")
	}
}

// TestLoginGuardPGGate 真 PG 门控用例（建表/失败累计/锁定/解锁/成功清零/并发）。
func TestLoginGuardPGGate(t *testing.T) {
	dsn := pgTestDSN()
	if dsn == "" {
		t.Skip("ADMIN_TEST_PG_DSN 未设置，跳过 PG 门控用例")
	}
	db, err := openSecurityStore(sqlutil.Postgres, dsn)
	if err != nil {
		t.Fatalf("open pg security store: %v", err)
	}
	defer db.Close()
	g := newSQLLoginGuard(db, 3, 15)

	const id = "pg-lock@example.com"
	if _, err := db.Exec(`DELETE FROM login_attempts WHERE identity = ?`, id); err != nil {
		t.Fatalf("clean: %v", err)
	}
	g.onFail(id)
	g.onFail(id)
	if g.isLocked(id) {
		t.Fatal("PG 下未达阈值不应锁定")
	}
	g.onFail(id)
	if !g.isLocked(id) {
		t.Fatal("PG 下达阈值应锁定")
	}
	g.onSuccess(id)
	if g.isLocked(id) {
		t.Fatal("PG 下成功后应解锁")
	}
	// 并发计数无丢失。
	const workers = 10
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			g.onFail(id)
		}()
	}
	wg.Wait()
	var c int
	if err := db.QueryRow(`SELECT failed_count FROM login_attempts WHERE identity = ?`, id).Scan(&c); err != nil || c != workers {
		t.Fatalf("PG 并发失败计数 = %d err=%v, want %d", c, err, workers)
	}
}
