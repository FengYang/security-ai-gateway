// security_mfa_interval_test.go — P2-4 T-1.5 MFA 存储与发信限频共享库后端测试。
//
// 主体用例以内存 sqlite 驱动同一套 SQL（双方言逻辑全覆盖，不 skip）；
// 另含真 PG 门控用例（ADMIN_TEST_PG_DSN 未设置时跳过，不伪装通过）。
package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// newSQLSecurityTestDB 打开内存 sqlite 安全计数器库（多实例共用同一句柄模拟同库多副本）。
func newSQLSecurityTestDB(t *testing.T) *sqlutil.DB {
	t.Helper()
	db, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open security store: %v", err)
	}
	db.SetMaxOpenConns(1) // 内存库单连接；真跨副本原子性由 PG 门控用例覆盖
	t.Cleanup(func() { db.Close() })
	return db
}

// ---------- 发信限频（operation_intervals）----------

func TestSQLIntervalGuard_Window(t *testing.T) {
	db := newSQLSecurityTestDB(t)
	g := newSQLIntervalGuard(db, 10) // 最小间隔 10 分钟
	if !g.allow("a@example.com") {
		t.Fatal("首次应放行")
	}
	if g.allow("a@example.com") {
		t.Fatal("间隔未到应拒发（跨副本共享计数）")
	}
	if !g.allow("b@example.com") {
		t.Fatal("不同 key 互不影响")
	}
	// 间隔过期后重新放行（回退 last_at 模拟时间推移）。
	if _, err := db.Exec(`UPDATE operation_intervals SET last_at = ? WHERE op_key = ?`,
		time.Now().Add(-11*time.Minute).Unix(), "a@example.com"); err != nil {
		t.Fatalf("rewind: %v", err)
	}
	if !g.allow("a@example.com") {
		t.Fatal("间隔已过应放行")
	}
}

// TestSQLIntervalGuard_MultiReplica 两副本一致性：B 副本（另一 store 实例）立即可见
// A 副本的记录，无按副本放大。
func TestSQLIntervalGuard_MultiReplica(t *testing.T) {
	db := newSQLSecurityTestDB(t)
	a := newSQLIntervalGuard(db, 10)
	b := newSQLIntervalGuard(db, 10) // 模拟第二个副本
	if !a.allow("shared@example.com") {
		t.Fatal("A 副本首次应放行")
	}
	if b.allow("shared@example.com") {
		t.Fatal("B 副本应看到 A 的记录（共库共享，非各副本各记一次）")
	}
}

// TestSQLIntervalGuard_Concurrent 并发同 key：原子 check-and-set 恰一个放行。
func TestSQLIntervalGuard_Concurrent(t *testing.T) {
	db := newSQLSecurityTestDB(t)
	g := newSQLIntervalGuard(db, 10)
	const workers = 20
	var okCount int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if g.allow("race@example.com") {
				atomic.AddInt64(&okCount, 1)
			}
		}()
	}
	wg.Wait()
	if okCount != 1 {
		t.Fatalf("并发放行数 = %d, want 1（原子 check-and-set）", okCount)
	}
}

// TestIntervalGuard_SemanticsAligned memory 与 sql 后端语义比对。
func TestIntervalGuard_SemanticsAligned(t *testing.T) {
	db := newSQLSecurityTestDB(t)
	mem := newIntervalGuard(10)
	sqlGuard := newSQLIntervalGuard(db, 10)
	for _, key := range []string{"x@example.com", "y@example.com"} {
		if !mem.allow(key) || !sqlGuard.allow(key) {
			t.Fatalf("两后端首次均应放行: key=%s", key)
		}
		if mem.allow(key) || sqlGuard.allow(key) {
			t.Fatalf("两后端间隔内均应拒发: key=%s", key)
		}
	}
}

// ---------- MFA 状态（mfa_states）----------

func newSQLMFATestStore(t *testing.T, db *sqlutil.DB) *mfaStore {
	t.Helper()
	return newSQLMFAStore(db, mfaTestSecret)
}

// mfaTestSecret 测试用 JWT 共享密钥（主密钥派生源；与 mfa_test.go 的 testSecret 同用途）。
var mfaTestSecret = []byte("mfa-test-jwt-secret-0123456789abcdef")

func TestSQLMFAStore_RoundTripAndJSONEquivalence(t *testing.T) {
	db := newSQLSecurityTestDB(t)
	s := newSQLMFATestStore(t, db)
	const sub = "admin@example.com"

	mtx, err := s.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	rec := &mfaRecord{
		SecretSealed: "00aabb",
		KeyVersion:   1,
		EnrolledAt:   time.Now().Unix(),
		LastTimestep: 12345,
		FailCount:    2,
		LockedUntil:  time.Now().Add(time.Hour).Unix(),
		Emergency: []mfaEmergencyCode{
			{Hash: strings.Repeat("ab", 32)},
			{Hash: strings.Repeat("cd", 32), UsedAt: 1700000000},
		},
	}
	if err := mtx.put(sub, rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := mtx.commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	mtx2, err := s.begin()
	if err != nil {
		t.Fatalf("begin2: %v", err)
	}
	got, ok, err := mtx2.get(sub)
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	mtx2.rollback()
	// 字段逐项等价（JSON 往返无损）。
	want, _ := json.Marshal(rec)
	gotBytes, _ := json.Marshal(got)
	if string(want) != string(gotBytes) {
		t.Fatalf("JSON 往返不等价:\n want=%s\n got=%s", want, gotBytes)
	}
	if !s.enrolled(sub) {
		t.Error("已写入应判为已绑定")
	}
	if !s.locked(sub) {
		t.Error("LockedUntil 未过期应判为锁定")
	}
	if s.enrolled("nobody@example.com") {
		t.Error("未知账号不应判为已绑定")
	}
}

// TestSQLMFAStore_MultiReplica 两副本一致性：A 副本写入，B 副本（另一 mfaStore
// 实例指向同库）立即可见。
func TestSQLMFAStore_MultiReplica(t *testing.T) {
	db := newSQLSecurityTestDB(t)
	a := newSQLMFATestStore(t, db)
	b := newSQLMFATestStore(t, db) // 模拟第二个副本
	const sub = "shared-admin@example.com"

	tx, err := a.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tx.put(sub, &mfaRecord{SecretSealed: "00ff", KeyVersion: 1, LockedUntil: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := tx.commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !b.enrolled(sub) {
		t.Fatal("B 副本应立即可见 A 副本的绑定状态")
	}
	if !b.locked(sub) {
		t.Fatal("B 副本应立即可见 A 副本的锁定状态")
	}
	// B 副本改状态（解绑式清理）→ A 副本亦可见。
	tx2, err := b.begin()
	if err != nil {
		t.Fatalf("begin b: %v", err)
	}
	if err := tx2.put(sub, &mfaRecord{SecretSealed: "00ff", KeyVersion: 1, LockedUntil: 0}); err != nil {
		t.Fatalf("put b: %v", err)
	}
	if err := tx2.commit(); err != nil {
		t.Fatalf("commit b: %v", err)
	}
	if a.locked(sub) {
		t.Fatal("A 副本应看到 B 副本解除的锁定")
	}
}

// TestSQLMFAStore_Rollback 回滚：未提交的写入对其它实例不可见。
func TestSQLMFAStore_Rollback(t *testing.T) {
	db := newSQLSecurityTestDB(t)
	a := newSQLMFATestStore(t, db)
	b := newSQLMFATestStore(t, db)
	const sub = "rollback-admin@example.com"
	tx, err := a.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tx.put(sub, &mfaRecord{SecretSealed: "00ee", KeyVersion: 1}); err != nil {
		t.Fatalf("put: %v", err)
	}
	tx.rollback()
	if b.enrolled(sub) {
		t.Fatal("回滚后不应可见（事务边界等价文件实现的原子 rename）")
	}
}

// TestMFAStore_FileVsSQLSemantics 文件后端与共享库后端语义对齐比对。
func TestMFAStore_FileVsSQLSemantics(t *testing.T) {
	db := newSQLSecurityTestDB(t)
	fileStore, err := loadMFAStore(filepath.Join(t.TempDir(), "mfa-state.json"), mfaTestSecret)
	if err != nil {
		t.Fatalf("loadMFAStore: %v", err)
	}
	sqlStore := newSQLMFATestStore(t, db)
	const sub = "both@example.com"

	put := func(s *mfaStore, rec *mfaRecord) {
		t.Helper()
		tx, err := s.begin()
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		if err := tx.put(sub, rec); err != nil {
			t.Fatalf("put: %v", err)
		}
		if err := tx.commit(); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}
	rec := &mfaRecord{SecretSealed: "00ab", KeyVersion: 1, LockedUntil: time.Now().Add(time.Hour).Unix()}
	put(fileStore, rec)
	put(sqlStore, rec)

	for name, s := range map[string]*mfaStore{"file": fileStore, "sql": sqlStore} {
		if !s.enrolled(sub) {
			t.Errorf("%s 后端应判为已绑定", name)
		}
		if !s.locked(sub) {
			t.Errorf("%s 后端应判为锁定", name)
		}
		if s.enrolled("absent@example.com") || s.locked("absent@example.com") {
			t.Errorf("%s 后端对未知账号应 false", name)
		}
	}
}

// ---------- PG 门控 ----------

// TestMFAIntervalPGGate 真 PG 门控用例（建表/发信限频/MFA 状态双副本一致）。
func TestMFAIntervalPGGate(t *testing.T) {
	dsn := pgTestDSN()
	if dsn == "" {
		t.Skip("ADMIN_TEST_PG_DSN 未设置，跳过 PG 门控用例")
	}
	db, err := openSecurityStore(sqlutil.Postgres, dsn)
	if err != nil {
		t.Fatalf("open pg security store: %v", err)
	}
	defer db.Close()

	// 发信限频：两实例共库。
	a := newSQLIntervalGuard(db, 10)
	b := newSQLIntervalGuard(db, 10)
	if _, err := db.Exec(`DELETE FROM operation_intervals WHERE op_key = ?`, "pg-interval@example.com"); err != nil {
		t.Fatalf("clean: %v", err)
	}
	if !a.allow("pg-interval@example.com") {
		t.Fatal("PG 首次应放行")
	}
	if b.allow("pg-interval@example.com") {
		t.Fatal("PG 下第二副本应看到共享计数（拒发）")
	}

	// MFA 状态：两实例共库。
	const sub = "pg-mfa@example.com"
	if _, err := db.Exec(`DELETE FROM mfa_states WHERE sub = ?`, sub); err != nil {
		t.Fatalf("clean mfa: %v", err)
	}
	sa := newSQLMFAStore(db, mfaTestSecret)
	sb := newSQLMFAStore(db, mfaTestSecret)
	tx, err := sa.begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if err := tx.put(sub, &mfaRecord{SecretSealed: "00aa", KeyVersion: 1, LockedUntil: time.Now().Add(time.Hour).Unix()}); err != nil {
		t.Fatalf("put: %v", err)
	}
	if err := tx.commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if !sb.enrolled(sub) {
		t.Fatal("PG 下第二副本应可见绑定状态")
	}
	if !sb.locked(sub) {
		t.Fatal("PG 下第二副本应可见锁定状态")
	}
}
