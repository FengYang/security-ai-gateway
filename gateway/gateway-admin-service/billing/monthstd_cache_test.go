package billing

import (
	"context"
	"sort"
	"testing"
	"time"
)

// ---------- A-37 月累计缓存单测 ----------

// countingStdSrc 计数替身：记录全量回源与区间求和调用次数（验证增量推进）。
type countingStdSrc struct {
	stds  map[string][2]int64 // day -> {stdIn, stdOut}
	full  int                 // MonthStdBefore 调用次数
	rng   int                 // SumStdRange 调用次数
	days  []string            // 有序日列表
}

func newCountingStdSrc(stds map[string][2]int64) *countingStdSrc {
	days := make([]string, 0, len(stds))
	for d := range stds {
		days = append(days, d)
	}
	sort.Strings(days)
	return &countingStdSrc{stds: stds, days: days}
}

func (s *countingStdSrc) sum(from, to string) (int64, int64) {
	var in, out int64
	for _, d := range s.days {
		if d >= from && (to == "" || d < to) {
			in += s.stds[d][0]
			out += s.stds[d][1]
		}
	}
	return in, out
}

func (s *countingStdSrc) MonthStdBefore(tenant, modelKey, period string) (int64, int64) {
	s.full++
	month := period[:7]
	return s.sum(month+"-01", period)
}

func (s *countingStdSrc) SumStdRange(tenant, modelKey, fromDay, toDay string) (int64, int64, error) {
	s.rng++
	in, out := s.sum(fromDay, toDay)
	return in, out, nil
}

// ---------- 命中与增量推进 ----------

func TestCachedMonthStd_HitAndIncrementalAdvance(t *testing.T) {
	src := newCountingStdSrc(map[string][2]int64{
		"2026-10-01": {10, 5},
		"2026-10-02": {20, 10},
		"2026-10-03": {30, 15},
	})
	c := NewCachedMonthStd(src)

	// D2 查询（起点 10-02 → 累计 [10-01,10-02) = D1）→ 首次未命中，全量回源
	if in, out := c.MonthStdBefore("t1", "m1", "2026-10-02"); in != 10 || out != 5 {
		t.Fatalf("D2 = (%d,%d), want (10,5)", in, out)
	}
	// 重复查询 → 命中（不新增回源）
	if in, _ := c.MonthStdBefore("t1", "m1", "2026-10-02"); in != 10 {
		t.Errorf("D2 repeat = %d, want 10", in)
	}
	fullAfterHit, rngAfterHit := src.full, src.rng
	if fullAfterHit != 1 {
		t.Errorf("full calls = %d, want 1 (second query should hit)", fullAfterHit)
	}

	// D3 查询 → 游标推进为增量 [10-02,10-03)，累加到已有 10
	if in, out := c.MonthStdBefore("t1", "m1", "2026-10-03"); in != 30 || out != 15 {
		t.Fatalf("D3 = (%d,%d), want (30,15)", in, out)
	}
	if src.full != fullAfterHit {
		t.Errorf("advance should not trigger full re-read (full=%d)", src.full)
	}
	if src.rng != rngAfterHit+1 {
		t.Errorf("advance should issue exactly 1 range query (rng=%d)", src.rng)
	}

	// D4 查询 → 再增量
	if in, _ := c.MonthStdBefore("t1", "m1", "2026-10-04"); in != 60 {
		t.Errorf("D4 = %d, want 60", in)
	}
	hits, misses := c.Stats()
	if hits < 1 || misses < 1 {
		t.Errorf("stats (hits=%d, misses=%d) unexpected", hits, misses)
	}
}

func TestCachedMonthStd_MonthlyPeriodReturnsZero(t *testing.T) {
	src := newCountingStdSrc(map[string][2]int64{"2026-10-01": {10, 5}})
	c := NewCachedMonthStd(src)
	// 月结（"YYYY-MM"）→ 起点即月初 → 0，且不触发任何回源
	if in, out := c.MonthStdBefore("t1", "m1", "2026-10"); in != 0 || out != 0 {
		t.Errorf("monthly period = (%d,%d), want (0,0)", in, out)
	}
	if src.full != 0 || src.rng != 0 {
		t.Errorf("monthly period must not query source (full=%d rng=%d)", src.full, src.rng)
	}
}

// ---------- 单调防回退 ----------

func TestCachedMonthStd_RegressQueryDoesNotPollute(t *testing.T) {
	src := newCountingStdSrc(map[string][2]int64{
		"2026-10-01": {10, 1},
		"2026-10-02": {20, 2},
		"2026-10-03": {30, 3},
	})
	c := NewCachedMonthStd(src)

	// 推进到 D4（累计 D1..D3 = 60）
	if in, _ := c.MonthStdBefore("t1", "m1", "2026-10-04"); in != 60 {
		t.Fatalf("prime D4 = %d, want 60", in)
	}
	// 回退查询 D3（应得 D1+D2 = 30）——全量回源，但不回写（游标仍为 D3=10-03）
	if in, _ := c.MonthStdBefore("t1", "m1", "2026-10-03"); in != 30 {
		t.Fatalf("regress D3 = %d, want 30", in)
	}
	// 再查 D4 → 必须仍命中（游标未被回退污染）
	rngBefore := src.rng
	if in, _ := c.MonthStdBefore("t1", "m1", "2026-10-04"); in != 60 {
		t.Errorf("D4 after regress = %d, want 60", in)
	}
	if src.rng != rngBefore {
		t.Errorf("D4 should be a cache hit after regress (rng advanced %d)", src.rng-rngBefore)
	}
}

// ---------- 补账失效（A-37/A-51） ----------

func TestCachedMonthStd_InvalidateOnBackfill(t *testing.T) {
	src := newCountingStdSrc(map[string][2]int64{
		"2026-10-01": {10, 1},
		"2026-10-02": {20, 2},
	})
	c := NewCachedMonthStd(src)

	// 推进到 D3（累计 D1+D2 = 30）
	if in, _ := c.MonthStdBefore("t1", "m1", "2026-10-03"); in != 30 {
		t.Fatalf("prime = %d, want 30", in)
	}
	// 补账：迟到数据写入 D2（≤ 游标 D2）→ 失效
	src.stds["2026-10-02"] = [2]int64{200, 20}
	c.InvalidateDayIfBackfill("t1", "2026-10-02")
	if in, out := c.MonthStdBefore("t1", "m1", "2026-10-03"); in != 210 || out != 21 {
		t.Errorf("after backfill = (%d,%d), want (210,21)", in, out)
	}
}

func TestCachedMonthStd_ForwardWriteDoesNotInvalidate(t *testing.T) {
	src := newCountingStdSrc(map[string][2]int64{
		"2026-10-01": {10, 1},
		"2026-10-02": {20, 2},
	})
	c := NewCachedMonthStd(src)
	// 推进到 D3（游标 = 10-02，累计 30）
	c.MonthStdBefore("t1", "m1", "2026-10-03")

	// 正常前进：D5 入账（晚于游标）→ 不失效
	src.stds["2026-10-05"] = [2]int64{50, 5}
	c.InvalidateDayIfBackfill("t1", "2026-10-05")

	// D3 查询仍应命中（游标未被清除）
	rngBefore := src.rng
	if in, _ := c.MonthStdBefore("t1", "m1", "2026-10-03"); in != 30 {
		t.Errorf("D3 = %d, want 30", in)
	}
	if src.rng != rngBefore {
		t.Errorf("forward write must not invalidate cache (rng advanced)")
	}
}

func TestCachedMonthStd_InvalidateOtherMonthNotAffected(t *testing.T) {
	src := newCountingStdSrc(map[string][2]int64{"2026-10-01": {10, 1}, "2026-11-01": {77, 7}})
	c := NewCachedMonthStd(src)
	c.MonthStdBefore("t1", "m1", "2026-10-02")
	c.MonthStdBefore("t1", "m1", "2026-11-02")

	// 失效 10 月，不应影响 11 月
	c.InvalidateDayIfBackfill("t1", "2026-10-01")
	rngBefore := src.rng
	if in, _ := c.MonthStdBefore("t1", "m1", "2026-11-02"); in != 77 {
		t.Errorf("Nov = %d, want 77", in)
	}
	if src.rng != rngBefore {
		t.Errorf("Nov cache should still hit after Oct invalidation")
	}
}

// ---------- 与直读一致（正确性对齐） ----------

func TestCachedMonthStd_MatchesDirectLedger(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	// 构造 3 天数据（含跨月边界）
	for _, e := range []LedgerEntry{
		{TenantID: "t1", ModelKey: "m1", Day: "2026-09-30", TokensIn: 5, StdIn: 5, EventKey: "a"},
		{TenantID: "t1", ModelKey: "m1", Day: "2026-10-01", TokensIn: 10, StdIn: 10, EventKey: "b"},
		{TenantID: "t1", ModelKey: "m1", Day: "2026-10-02", TokensIn: 20, StdIn: 20, EventKey: "c"},
		{TenantID: "t1", ModelKey: "m1", Day: "2026-10-03", TokensIn: 30, StdIn: 30, EventKey: "d"},
	} {
		seedLedger(t, s, e)
	}
	ledger := concreteLedger(s)
	c := NewCachedMonthStd(ledger)

	for _, period := range []string{"2026-10-01", "2026-10-02", "2026-10-03", "2026-10-04", "2026-10-02", "2026-10"} {
		wIn, wOut := ledger.MonthStdBefore("t1", "m1", period)
		gIn, gOut := c.MonthStdBefore("t1", "m1", period)
		if gIn != wIn || gOut != wOut {
			t.Errorf("period %s: cached = (%d,%d), direct = (%d,%d)", period, gIn, gOut, wIn, wOut)
		}
	}
}

// ---------- 预热（A-37） ----------

func TestCachedMonthStd_WarmMakesNextDayHit(t *testing.T) {
	src := newCountingStdSrc(map[string][2]int64{
		"2026-10-01": {10, 1},
		"2026-10-02": {20, 2},
	})
	c := NewCachedMonthStd(src)

	// 未预热：以 D3 为起点查询 → 全量回源（10+20=30）
	if in, _ := c.MonthStdBefore("t1", "m1", "2026-10-03"); in != 30 {
		t.Fatalf("prime = %d, want 30", in)
	}
	// 预热到 D3（含）→ 缓存游标 = D3
	c.Warm("t1", []string{"m1"}, "2026-10-03")

	// 次日（D4）查询应直接命中（不新增任何回源调用）
	fullBefore, rngBefore := src.full, src.rng
	if in, out := c.MonthStdBefore("t1", "m1", "2026-10-04"); in != 30 || out != 3 {
		t.Fatalf("next-day = (%d,%d), want (30,3)", in, out)
	}
	if src.full != fullBefore || src.rng != rngBefore {
		t.Errorf("warmed next-day query must hit (full %d→%d, rng %d→%d)",
			fullBefore, src.full, rngBefore, src.rng)
	}
}

func TestCachedMonthStd_WarmEmptyModelsNoop(t *testing.T) {
	src := newCountingStdSrc(map[string][2]int64{"2026-10-01": {5, 1}})
	c := NewCachedMonthStd(src)
	c.Warm("t1", nil, "2026-10-01")                 // 无模型 → no-op
	c.Warm("t1", []string{""}, "2026-10-01")        // 空模型键 → 跳过
	c.Warm("t1", []string{"m1"}, "bad")             // 非法日期 → no-op
	if src.full != 0 || src.rng != 0 {
		t.Errorf("warm no-op cases must not query source (full=%d rng=%d)", src.full, src.rng)
	}
}

func TestCachedMonthStd_WarmMatchesDirectLedger(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	for _, e := range []LedgerEntry{
		{TenantID: "t1", ModelKey: "m1", Day: "2026-10-01", TokensIn: 10, StdIn: 10, EventKey: "a"},
		{TenantID: "t1", ModelKey: "m2", Day: "2026-10-02", TokensIn: 20, StdIn: 20, EventKey: "b"},
	} {
		seedLedger(t, s, e)
	}
	ledger := concreteLedger(s)
	svc := newTestBillingService(s, nil)

	// 预热（经服务：枚举当月模型 → 逐个推进）
	if err := svc.WarmMonthStd("t1", "2026-10-02"); err != nil {
		t.Fatalf("WarmMonthStd err: %v", err)
	}

	cache := svc.monthStdCache
	for _, mk := range []string{"m1", "m2"} {
		wIn, wOut := ledger.MonthStdBefore("t1", mk, "2026-10-03")
		gIn, gOut := cache.MonthStdBefore("t1", mk, "2026-10-03")
		if gIn != wIn || gOut != wOut {
			t.Errorf("model %s: warmed = (%d,%d), direct = (%d,%d)", mk, gIn, gOut, wIn, wOut)
		}
	}
	// 预热后 D3 起点查询必须命中
	hitsBefore, _ := cache.Stats()
	cache.MonthStdBefore("t1", "m1", "2026-10-03")
	hitsAfter, _ := cache.Stats()
	if hitsAfter <= hitsBefore {
		t.Errorf("warmed query should hit (hits %d→%d)", hitsBefore, hitsAfter)
	}
}

// ---------- 日结后自动预热 ----------

func TestCachedMonthStd_CloseDailyWarmsNextDay(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "seed-1",
	})
	svc := newTestBillingService(s, nil)
	if _, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01"); err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}
	// 日结后缓存应已推进到当日 → 次日（D2）起点查询命中
	cache := svc.monthStdCache
	hitsBefore, _ := cache.Stats()
	if in, _ := cache.MonthStdBefore("t1", "cheap-model", "2026-10-02"); in != 1000 {
		t.Fatalf("next-day = %d, want 1000", in)
	}
	hitsAfter, _ := cache.Stats()
	if hitsAfter <= hitsBefore {
		t.Errorf("next-day query after CloseDaily should hit (hits %d→%d)", hitsBefore, hitsAfter)
	}
}

// ---------- 端到端：入账（补账）触发失效 ----------

func TestCachedMonthStd_IngestWindowInvalidatesOnBackfill(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	// D1 用量 1000（std 锁定同值）
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "seed-1",
	})
	svc := newTestBillingService(s, nil)
	cache := svc.monthStdCache
	if cache == nil {
		t.Fatal("month std cache not wired")
	}
	// 先查询 D2 起点 → 推进缓存（upTo = D1 = 1000）
	if in, _ := cache.MonthStdBefore("t1", "cheap-model", "2026-10-02"); in != 1000 {
		t.Fatalf("prime = %d, want 1000", in)
	}

	// 补账：迟到窗口落在 D1（UTC+8 自然日）→ IngestWindow 应触发失效
	toNs := time.Date(2026, 10, 1, 12, 0, 0, 0,
		time.FixedZone("UTC+8", 8*3600)).UnixNano()
	win := &UsageWindow{
		FromNs: toNs - int64(time.Hour),
		ToNs:   toNs,
		Tenants: map[string]*TenantAgg{
			"t1": {TokensIn: 1000, ByModel: map[string]*ModelAgg{"cheap-model": {TokensIn: 1000}}},
		},
		Source: "pull", EventKey: "late-1",
	}
	if _, err := svc.IngestWindow(context.Background(), win, SyncModePull); err != nil {
		t.Fatalf("IngestWindow err: %v", err)
	}

	// 补账后：D2 起点应为 D1 的新累计 2000（缓存已失效并重算）
	if in, _ := cache.MonthStdBefore("t1", "cheap-model", "2026-10-02"); in != 2000 {
		t.Errorf("after backfill = %d, want 2000", in)
	}
}
