// security_captcha_test.go — P2-4 T-1.3 captcha 共享库后端测试。
//
// 主体用例以内存 sqlite 驱动同一套 SQL（双方言逻辑全覆盖，不 skip）；
// 另含真 PG 门控用例（ADMIN_TEST_PG_DSN 未设置时跳过，不伪装通过）。
package main

import (
	"errors"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// pgTestDSN 返回 PG 门控测试 DSN（ADMIN_TEST_PG_DSN，未设置返回空串）。
// T-1.3/T-1.4 的 PG 门控用例共用。
func pgTestDSN() string {
	return strings.TrimSpace(os.Getenv("ADMIN_TEST_PG_DSN"))
}

// newSQLCaptchaTestBackend 构造基于内存 sqlite 的共享库 captcha 后端。
func newSQLCaptchaTestBackend(t *testing.T, ttlMin, ipLimit int) (*sqlCaptchaBackend, *sqlutil.DB) {
	t.Helper()
	db, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open security store: %v", err)
	}
	db.SetMaxOpenConns(1) // 内存库单连接；并发原子性由真 PG 门控用例覆盖
	t.Cleanup(func() {
		db.Close()
	})
	b := newSQLCaptchaBackend(db, ttlMin, ipLimit)
	return b, db
}

// seedChallenge 直接插入已知明文的挑战（后端只存哈希，测试须经此取得可控答案）。
func seedChallenge(t *testing.T, db *sqlutil.DB, id, code string, expiresAt int64) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO captcha_challenges (id, code_hash, expires_at, consumed)
		VALUES (?, ?, ?, 0)`, id, captchaCodeHash(code), expiresAt); err != nil {
		t.Fatalf("seed challenge: %v", err)
	}
}

func TestSQLCaptcha_IssueAndOneShotVerify(t *testing.T) {
	b, db := newSQLCaptchaTestBackend(t, 5, 30)
	id, img, err := b.Issue("10.1.1.1")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if id == "" || len(img) == 0 {
		t.Fatal("Issue 应返回 id 与图片")
	}
	// 答案哈希入库、未消费（库内不落明文）。
	var consumed int
	if err := db.QueryRow(`SELECT consumed FROM captcha_challenges WHERE id = ?`, id).Scan(&consumed); err != nil || consumed != 0 {
		t.Fatalf("challenge 应入库且未消费: consumed=%d err=%v", consumed, err)
	}

	// 已知明文的完整一次性消费链路。
	seedChallenge(t, db, "seed-1", "AB23", time.Now().Add(time.Minute).Unix())
	if !b.Verify("seed-1", "ab23") {
		t.Error("正确验证码应通过（大小写不敏感）")
	}
	if b.Verify("seed-1", "AB23") {
		t.Error("验证码应一次性（已消费）")
	}
	// 错误码同样被消费（防爆破）。
	seedChallenge(t, db, "seed-2", "XY89", time.Now().Add(time.Minute).Unix())
	if b.Verify("seed-2", "ZZZZ") {
		t.Error("错误验证码应失败")
	}
	if b.Verify("seed-2", "XY89") {
		t.Error("错误尝试也应消费答案（一次性语义）")
	}
	// 空 id / 空码直接拒绝。
	if b.Verify("", "AB23") || b.Verify("seed-1", "") {
		t.Error("空 id/空码应失败")
	}
}

func TestSQLCaptcha_Expired(t *testing.T) {
	b, db := newSQLCaptchaTestBackend(t, 5, 30)
	seedChallenge(t, db, "exp-1", "AB23", time.Now().Add(-time.Second).Unix())
	if b.Verify("exp-1", "AB23") {
		t.Error("过期挑战应失败")
	}
	// GC 清理过期行。
	if _, err := db.Exec(`DELETE FROM captcha_challenges WHERE expires_at <= ?`, time.Now().Unix()); err != nil {
		t.Fatalf("gc: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM captcha_challenges WHERE id = ?`, "exp-1").Scan(&n); err != nil || n != 0 {
		t.Fatalf("过期行应被 GC: n=%d err=%v", n, err)
	}
}

func TestSQLCaptcha_IPRateLimit(t *testing.T) {
	b, _ := newSQLCaptchaTestBackend(t, 5, 2)
	if _, _, err := b.Issue("10.2.2.2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Issue("10.2.2.2"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Issue("10.2.2.2"); !errors.Is(err, errCaptchaRateLimited) {
		t.Errorf("第 3 次签发应限流: %v", err)
	}
	// 不同客户端（IP）互不影响。
	if _, _, err := b.Issue("10.2.2.3"); err != nil {
		t.Errorf("不同 IP 不应受限: %v", err)
	}
}

func TestSQLCaptcha_WindowRollover(t *testing.T) {
	b, db := newSQLCaptchaTestBackend(t, 5, 1)
	if _, _, err := b.Issue("10.3.3.3"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Issue("10.3.3.3"); !errors.Is(err, errCaptchaRateLimited) {
		t.Fatal("同窗口第 2 次应限流")
	}
	// 窗口翻转（模拟上一小时）后计数重置。
	if _, err := db.Exec(`UPDATE captcha_rate_limits SET window_hour = window_hour - 1 WHERE ip = ?`, "10.3.3.3"); err != nil {
		t.Fatalf("rewind window: %v", err)
	}
	if _, _, err := b.Issue("10.3.3.3"); err != nil {
		t.Errorf("新窗口应重新计数: %v", err)
	}
}

// TestSQLCaptcha_ConcurrentIssueRateLimit 并发签发：多 goroutine 冲刺上限，
// 原子 upsert 自增保证成功数恰为 ipLimit（跨副本不放大、不丢失计数）。
func TestSQLCaptcha_ConcurrentIssueRateLimit(t *testing.T) {
	b, _ := newSQLCaptchaTestBackend(t, 5, 30)
	const workers = 60
	var okCount int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := b.Issue("10.4.4.4"); err == nil {
				atomic.AddInt64(&okCount, 1)
			}
		}()
	}
	wg.Wait()
	if okCount != 30 {
		t.Errorf("并发签发成功数 = %d, want 30（原子限流）", okCount)
	}
}

// TestSQLCaptcha_ConcurrentVerifyOneShot 并发消费同一挑战：恰一个成功。
func TestSQLCaptcha_ConcurrentVerifyOneShot(t *testing.T) {
	b, db := newSQLCaptchaTestBackend(t, 5, 30)
	seedChallenge(t, db, "race-1", "AB23", time.Now().Add(time.Minute).Unix())
	const workers = 20
	var okCount int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.Verify("race-1", "ab23") {
				atomic.AddInt64(&okCount, 1)
			}
		}()
	}
	wg.Wait()
	if okCount != 1 {
		t.Errorf("并发校验成功数 = %d, want 1（原子一次性消费）", okCount)
	}
}

// TestSQLCaptcha_CrossClientIsolation 客户端 id 隔离：未知 id 不消费真实挑战。
func TestSQLCaptcha_CrossClientIsolation(t *testing.T) {
	b, db := newSQLCaptchaTestBackend(t, 5, 30)
	seedChallenge(t, db, "iso-1", "AB23", time.Now().Add(time.Minute).Unix())
	if b.Verify("someone-else", "AB23") {
		t.Error("未知 id 应失败")
	}
	var consumed int
	if err := db.QueryRow(`SELECT consumed FROM captcha_challenges WHERE id = ?`, "iso-1").Scan(&consumed); err != nil || consumed != 0 {
		t.Fatalf("他人 id 的失败尝试不应消费真实挑战: consumed=%d err=%v", consumed, err)
	}
	if !b.Verify("iso-1", "AB23") {
		t.Error("真实挑战仍应可用")
	}
}

// TestCaptchaPGGate 真 PG 门控用例（建表/签发/限流/一次性消费/并发）。
func TestCaptchaPGGate(t *testing.T) {
	dsn := pgTestDSN()
	if dsn == "" {
		t.Skip("ADMIN_TEST_PG_DSN 未设置，跳过 PG 门控用例")
	}
	db, err := openSecurityStore(sqlutil.Postgres, dsn)
	if err != nil {
		t.Fatalf("open pg security store: %v", err)
	}
	defer db.Close()
	b := newSQLCaptchaBackend(db, 5, 2)
	stop := startSecurityGC(db, securityGCInterval) // 共享库层 GC（QA P3-1：与 captcha 解耦）
	defer stop()

	// 限流 + 跨副本语义同 sqlite 用例。
	if _, _, err := b.Issue("192.0.2.1"); err != nil {
		t.Fatalf("issue: %v", err)
	}
	if _, _, err := b.Issue("192.0.2.1"); err != nil {
		t.Fatalf("issue 2: %v", err)
	}
	if _, _, err := b.Issue("192.0.2.1"); !errors.Is(err, errCaptchaRateLimited) {
		t.Fatalf("应限流: %v", err)
	}
	// 一次性消费。
	if _, err := db.Exec(`DELETE FROM captcha_challenges WHERE id = ?`, "pg-seed-1"); err != nil {
		t.Fatalf("clean: %v", err)
	}
	seedChallenge(t, db, "pg-seed-1", "AB23", time.Now().Add(time.Minute).Unix())
	if !b.Verify("pg-seed-1", "AB23") {
		t.Fatal("PG 下正确验证码应通过")
	}
	if b.Verify("pg-seed-1", "AB23") {
		t.Fatal("PG 下应一次性消费")
	}
	// 并发一次性。
	const workers = 10
	var okCount int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if b.Verify("pg-seed-1", "AB23") {
				atomic.AddInt64(&okCount, 1)
			}
		}()
	}
	wg.Wait()
	if okCount != 0 {
		t.Fatalf("已消费挑战并发校验应全失败, got %d", okCount)
	}
}
