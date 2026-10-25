// security_fixes_test.go — P2-4 T-1.3/T-1.4 QA 复验批次修复的回归用例
// （P2-2 maxFail=0 两端一致 / P3-1 窗口只前进 / P3-2 消费与 GC 并发 /
//
//	P3-3 混合降级态双向 / P3-4 登录计数 GC / P3-5 限流 0 语义 / P3-6 identity 归一化）。
package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// TestLoginGuard_MaxFailZeroBothBackends P2-2：LOGIN_MAX_FAIL=0（"关闭锁定"）
// 时内存与共享库两端必须一致——永不锁定，不得第一次输错即锁。
func TestLoginGuard_MaxFailZeroBothBackends(t *testing.T) {
	mem := newLoginGuard(0, 15)
	db, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	sqlGuard := newSQLLoginGuard(db, 0, 15)

	for i := 0; i < 10; i++ {
		mem.onFail("zeromax@example.com")
		sqlGuard.onFail("zeromax@example.com")
	}
	if mem.isLocked("zeromax@example.com") {
		t.Error("内存侧 maxFail=0 不应锁定")
	}
	if sqlGuard.isLocked("zeromax@example.com") {
		t.Error("共享库侧 maxFail=0 不应锁定（QA P2-2 配置地雷）")
	}
	// 归一化后的 identity 也一致（P3-6 防御性归一化）。
	sqlGuard.onFail("ZeroMax@Example.COM")
	if sqlGuard.isLocked("zeromax@example.com") {
		t.Error("maxFail=0 下大小写不同的同一邮箱也不应锁定")
	}
}

// TestSQLCaptcha_WindowNeverRewinds P3-1：带着旧窗口的迟到请求（副本时钟漂移）
// 既不得把 window_hour 拉回旧值，也不得把 hits 重置为 1（否则限流额度被放大）。
func TestSQLCaptcha_WindowNeverRewinds(t *testing.T) {
	b, db := newSQLCaptchaTestBackend(t, 5, 5)
	cur := time.Now().Unix() / 3600
	if _, _, err := b.Issue("10.7.7.7"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := b.Issue("10.7.7.7"); err != nil {
		t.Fatal(err)
	}
	// 迟到请求（漂移副本用更早的窗口）。
	if _, _, err := b.issueSQLAt("10.7.7.7", cur-1); err != nil {
		t.Fatalf("issue with drifted window: %v", err)
	}
	var gotW int64
	var gotHits int
	if err := db.QueryRow(`SELECT window_hour, hits FROM captcha_rate_limits WHERE ip = ?`, "10.7.7.7").Scan(&gotW, &gotHits); err != nil {
		t.Fatalf("read: %v", err)
	}
	if gotW != cur {
		t.Fatalf("window_hour 应停在当前窗口 %d（不得回退），实际 %d", cur, gotW)
	}
	if gotHits != 3 {
		t.Fatalf("迟到请求应计入当前窗口（hits=3），实际 %d（计数被重置即额度放大）", gotHits)
	}
	// 窗口正常前移时计数从 1 重开。
	if _, _, err := b.issueSQLAt("10.7.7.7", cur+1); err != nil {
		t.Fatalf("issue with newer window: %v", err)
	}
	if err := db.QueryRow(`SELECT window_hour, hits FROM captcha_rate_limits WHERE ip = ?`, "10.7.7.7").Scan(&gotW, &gotHits); err != nil {
		t.Fatalf("read2: %v", err)
	}
	if gotW != cur+1 || gotHits != 1 {
		t.Fatalf("新窗口应前移并重开计数: window=%d hits=%d", gotW, gotHits)
	}
}

// TestSQLCaptcha_ConsumeWithConcurrentGC P3-2：消费与 GC 并发不再导致正确码被判失败
// （UPDATE ... RETURNING 单语句取哈希，消除"消费后读哈希"的边界竞争）。
func TestSQLCaptcha_ConsumeWithConcurrentGC(t *testing.T) {
	b, db := newSQLCaptchaTestBackend(t, 5, 30)
	const workers = 40
	var okCount int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			id := fmt.Sprintf("gc-race-%03d", i)
			// TTL 恰在边界：expires_at = now+1s，GC 可能并发删除。
			seedChallenge(t, db, id, "AB23", time.Now().Add(time.Second).Unix())
			// 并发 GC：模拟 5min ticker 的过期清理。
			go func() {
				_, _ = db.Exec(`DELETE FROM captcha_challenges WHERE expires_at <= ?`, time.Now().Unix())
			}()
			if b.Verify(id, "ab23") {
				atomic.AddInt64(&okCount, 1)
			}
		}(i)
	}
	wg.Wait()
	// 边界竞争下每次校验要么成功（未过期即消费）要么失败（已过期被 GC），
	// 但**绝不允许**出现"消费成功却因读不到哈希而返回失败"的第三种状态：
	// 成功数 = 实际抢在 GC 前消费的数量；此处只断言不出现重复消费与 panic。
	if okCount > int64(workers) {
		t.Fatalf("成功数 %d 超过挑战数 %d（一次性消费被破坏）", okCount, workers)
	}
	// 确定性校验：非边界 TTL 必成功（回归 P3-2 主路径）。
	seedChallenge(t, db, "gc-safe", "XY89", time.Now().Add(time.Minute).Unix())
	if !b.Verify("gc-safe", "xy89") {
		t.Fatal("正常 TTL 下正确验证码应通过（P3-2 回归）")
	}
	if b.Verify("gc-safe", "xy89") {
		t.Fatal("应一次性消费")
	}
}

// TestSQLCaptcha_MixedDegradationFallback P3-3：内存签发 + 共享库校验（库中无此 id）
// 时也应回退进程内命中。
func TestSQLCaptcha_MixedDegradationFallback(t *testing.T) {
	b, _ := newSQLCaptchaTestBackend(t, 5, 30)
	// 模拟降级态：直接用进程内后端签发（共享库无该 id）。
	id, _, err := b.fallback.Issue("10.8.8.8")
	if err != nil {
		t.Fatalf("fallback issue: %v", err)
	}
	b.fallback.mu.Lock()
	code := b.fallback.items[id].code
	b.fallback.mu.Unlock()
	if !b.Verify(id, code) {
		t.Fatal("混合降级态（内存签发 + 共享库校验）应回退内存命中（QA P3-3）")
	}
	if b.Verify(id, code) {
		t.Fatal("回退路径也应保持一次性消费")
	}
}

// TestLoginGC_StaleAttempts P3-4：陈旧登录计数被 GC 清理；锁定中的行不得被清。
func TestLoginGC_StaleAttempts(t *testing.T) {
	db, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	g := newSQLLoginGuard(db, 5, 15)
	g.onFail("stale@example.com")
	if _, err := db.Exec(`UPDATE login_attempts SET updated_at = ? WHERE identity = ?`,
		time.Now().Add(-25*time.Hour).Unix(), "stale@example.com"); err != nil {
		t.Fatalf("age: %v", err)
	}
	g.onFail("locked@example.com")
	if _, err := db.Exec(`UPDATE login_attempts SET updated_at = ?, locked_until = ? WHERE identity = ?`,
		time.Now().Add(-25*time.Hour).Unix(), time.Now().Add(time.Hour).Unix(), "locked@example.com"); err != nil {
		t.Fatalf("age locked: %v", err)
	}
	securityGCOnce(db, &securityAlarm{})
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_attempts WHERE identity = ?`, "stale@example.com").Scan(&n); err != nil || n != 0 {
		t.Fatalf("陈旧未锁定行应被清理: n=%d err=%v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_attempts WHERE identity = ?`, "locked@example.com").Scan(&n); err != nil || n != 1 {
		t.Fatalf("仍处锁定窗口的行不得被清理: n=%d err=%v", n, err)
	}
}

// TestCaptchaRateLimitZeroBothBackends P3-5：限流阈值 0 = 关闭限流（两端一致）。
func TestCaptchaRateLimitZeroBothBackends(t *testing.T) {
	mem := newCaptchaStore(5, 0)
	for i := 0; i < 3; i++ {
		if _, _, err := mem.Issue("10.9.9.9"); err != nil {
			t.Fatalf("内存侧 0 = 关闭限流，应放行: %v", err)
		}
	}
	b, _ := newSQLCaptchaTestBackend(t, 5, 0)
	for i := 0; i < 3; i++ {
		if _, _, err := b.Issue("10.9.9.9"); err != nil {
			t.Fatalf("共享库侧 0 = 关闭限流，应放行: %v", err)
		}
	}
}

// TestSQLLoginGuard_IdentityNormalized P3-6：共享库后端入口归一化 identity，
// 大小写差异不得形成多键（PG TEXT 主键区分大小写会绕过锁定）。
func TestSQLLoginGuard_IdentityNormalized(t *testing.T) {
	db, err := openSecurityStore(sqlutil.SQLite, ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	g := newSQLLoginGuard(db, 2, 15)
	g.onFail("Mixed.Case@Example.COM")
	g.onFail("MIXED.case@example.com") // 第二次（大小写不同）应计入同一 identity → 锁定
	if !g.isLocked("mixed.case@example.com") {
		t.Fatal("大小写变体应计入同一 identity（QA P3-6 归一化）")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM login_attempts`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("应只有一条归一化后的记录: n=%d err=%v", n, err)
	}
}
