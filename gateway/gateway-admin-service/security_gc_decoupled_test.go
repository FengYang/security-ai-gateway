// security_gc_decoupled_test.go — P2-4 T-1.5 共享库健壮性修复回归用例
// （QA P3-1 GC 与 captcha 解耦 / P3-2 显式传参无包级全局 / P3-3 locked 口径统一）。
package main

import (
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// TestSecurityGC_DecoupledFromCaptcha QA P3-1：不启动 captcha 后端的情况下，
// 共享库层 GC 仍会清理 operation_intervals / login_attempts / captcha 过期行。
func TestSecurityGC_DecoupledFromCaptcha(t *testing.T) {
	db, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	stale := time.Now().Add(-48 * time.Hour).Unix()
	if _, err := db.Exec(`INSERT INTO operation_intervals (op_key, last_at) VALUES (?, ?)`, "old@example.com", stale); err != nil {
		t.Fatalf("seed interval: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO login_attempts (identity, failed_count, locked_until, updated_at) VALUES (?, 1, 0, ?)`, "old@example.com", stale); err != nil {
		t.Fatalf("seed login: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO captcha_challenges (id, code_hash, expires_at, consumed) VALUES (?, ?, ?, 0)`, "old-1", "deadbeef", stale); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
	// 只启动共享库层 GC（无任何 captcha 后端参与）。
	stop := startSecurityGC(db, 20*time.Millisecond)
	defer stop()
	deadline := time.Now().Add(3 * time.Second)
	for {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM operation_intervals`).Scan(&n); err != nil {
			t.Fatalf("count: %v", err)
		}
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("共享库层 GC 未清理 operation_intervals（P3-1 回归失败）")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for table := range map[string]string{"login_attempts": "", "captcha_challenges": ""} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Fatalf("%s 陈旧行应被清理: n=%d", table, n)
		}
	}
}

// TestMFAStore_ExplicitSharedDB QA P3-2：共享库后端由显式参数注入，
// 不存在包级全局（多 handler/测试并发无污染）。
func TestMFAStore_ExplicitSharedDB(t *testing.T) {
	db, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	// 未传 db → 文件后端（db 字段为空）。
	fileStore, err := loadMFAStore(t.TempDir()+"/mfa.json", mfaTestSecret)
	if err != nil {
		t.Fatalf("loadMFAStore: %v", err)
	}
	if fileStore.db != nil {
		t.Fatal("未传共享库句柄时应为文件后端")
	}
	// 显式传 db → 共享库后端。
	shared, err := loadMFAStoreShared(t.TempDir()+"/mfa.json", mfaTestSecret, db)
	if err != nil {
		t.Fatalf("loadMFAStoreShared: %v", err)
	}
	if shared.db != db {
		t.Fatal("显式传参应得到共享库后端")
	}
	// 两个共享库实例互不影响文件后端（无全局串扰）。
	other, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	defer other.Close()
	other.SetMaxOpenConns(1)
	b2 := newSQLMFAStore(other, mfaTestSecret)
	tx, err := shared.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tx.put("sub-a", &mfaRecord{SecretSealed: "00aa", KeyVersion: 1}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := tx.commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if b2.enrolled("sub-a") {
		t.Fatal("另一共享库实例不应看到 sub-a（无全局串扰）")
	}
}

// TestMFAStore_LockedFailClosed QA P3-3：状态记录不可解析时 locked() 取
// fail-closed（视为锁定），与 enrolled() 的 fail-closed 取向一致。
func TestMFAStore_LockedFailClosed(t *testing.T) {
	db, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	s := newSQLMFAStore(db, mfaTestSecret)
	if _, err := db.Exec(`INSERT INTO mfa_states (sub, record, updated_at) VALUES (?, ?, ?)`,
		"bad-record", "{not-json", time.Now().Unix()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if !s.locked("bad-record") {
		t.Fatal("记录不可解析时应 fail-closed 判为锁定（QA P3-3）")
	}
	if !s.enrolled("bad-record") {
		t.Fatal("已存在记录应判为已绑定")
	}
}
