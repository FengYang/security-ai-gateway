package billing

import (
	"testing"
)

// ---------- 测试用价格表 ----------

func testPriceTable() *PriceTable {
	return &PriceTable{
		Version:  "v1",
		Currency: "CNY",
		Models: map[string]*ModelPrice{
			"gpt-4o": {
				InCoef:  1.0,
				OutCoef: 1.0,
				Tiers: []Tier{
					{UpToTokens: 1000000, InPer1K: 30.0, OutPer1K: 60.0}, // ≤ 1M：30/60 元/千token
					{UpToTokens: 0, InPer1K: 15.0, OutPer1K: 30.0},       // > 1M：半价
				},
			},
			"cheap-model": {
				InCoef:  1.0,
				OutCoef: 1.0,
				Tiers: []Tier{
					{UpToTokens: 0, InPer1K: 1.0, OutPer1K: 2.0}, // 单档：1/2 元/千token
				},
			},
		},
	}
}

// ---------- T-6.5-1 单模型单日计价 ----------

func TestRate_SingleModel_SingleTier(t *testing.T) {
	// cheap-model：100k in，50k out，单价 1/2 元/千
	eng := NewRatingEngine("half_up", nil)
	u := &UsageAgg{
		TenantID: "t1",
		Period:   "2026-10-01",
		ByModel: map[string]*ModelStd{
			"cheap-model": {StdIn: 100000, StdOut: 50000},
		},
	}
	amt, err := eng.Rate(u, testPriceTable())
	if err != nil {
		t.Fatalf("Rate err: %v", err)
	}
	// 期望：100k×1元/千 + 50k×2元/千 = 100 + 100 = 200 元 = 20000 分
	expected := Amount(20000)
	if amt != expected {
		t.Errorf("amount = %d 分, want %d 分", amt, expected)
	}
}

// ---------- T-6.5-2 跨档累进 ----------

func TestRate_ProgressiveTiers(t *testing.T) {
	// gpt-4o：2M in（跨两档），1.5M out
	eng := NewRatingEngine("half_up", nil)
	u := &UsageAgg{
		TenantID: "t1",
		Period:   "2026-10",
		ByModel: map[string]*ModelStd{
			"gpt-4o": {StdIn: 2000000, StdOut: 1500000},
		},
	}
	amt, err := eng.Rate(u, testPriceTable())
	if err != nil {
		t.Fatalf("Rate err: %v", err)
	}
	// 输入：1M×30元/千 + 1M×15元/千 = 30000 + 15000 = 45000 元 = 4500000 分
	// 输出：1M×60元/千 + 0.5M×30元/千 = 60000 + 15000 = 75000 元 = 7500000 分
	// 合计：120000 元 = 12000000 分
	expected := Amount(12000000) // = 12万元
	if amt != expected {
		t.Errorf("amount = %d 分, want %d 分 (12万元)", amt, expected)
	}
}

// ---------- T-6.5-3 一次取整 vs 逐笔取整 ----------

func TestRate_SingleRoundVsPerItem(t *testing.T) {
	eng := NewRatingEngine("half_up", nil)
	tbl := testPriceTable()

	// 1000 笔，每笔 333 in / 0 out（cheap-model，1 元/千）
	var totalMu int64
	var perItemSum Amount
	for i := 0; i < 1000; i++ {
		u := &UsageAgg{
			TenantID: "t1",
			ByModel: map[string]*ModelStd{
				"cheap-model": {StdIn: 333, StdOut: 0},
			},
		}
		amt, _ := eng.Rate(u, tbl)
		perItemSum += amt
		mu, _ := eng.RateMu(u, tbl)
		totalMu += mu
	}
	singleRound := roundAmount(totalMu, "half_up")

	// 累计：1000 × 333 × 1元/千 = 333 元 = 33300 分
	expected := Amount(33300)
	if singleRound != expected {
		t.Errorf("single round = %d, want %d", singleRound, expected)
	}
	// 逐笔：每笔 333 × 1元/千 = 0.333 元 = 33.3 分 → 四舍五入 33 分
	// 1000 × 33 = 33000 分（差 300 分，证明 R-16 必要性）
	if perItemSum != Amount(33000) {
		t.Logf("per-item sum = %d (expected 33000 for this example)", perItemSum)
	}
	if singleRound == perItemSum {
		t.Error("single-round should differ from per-item rounding (R-16 necessity)")
	}
}

// ---------- T-6.5-4 retry 不计入用户金额（M9） ----------

func TestRate_RetryTokensExcluded(t *testing.T) {
	eng := NewRatingEngine("half_up", nil)
	tbl := testPriceTable()

	u1 := &UsageAgg{
		TenantID: "t1",
		ByModel: map[string]*ModelStd{
			"cheap-model": {StdIn: 1000, StdOut: 500, RetryToks: 999999},
		},
	}
	amt1, _ := eng.Rate(u1, tbl)

	u2 := &UsageAgg{
		TenantID: "t1",
		ByModel: map[string]*ModelStd{
			"cheap-model": {StdIn: 1000, StdOut: 500, RetryToks: 0},
		},
	}
	amt2, _ := eng.Rate(u2, tbl)

	if amt1 != amt2 {
		t.Errorf("retry tokens affect amount: amt1=%d, amt2=%d (M9 violated)", amt1, amt2)
	}
}

// ---------- T-6.5-5 缺单价拒出账 ----------

func TestRate_PricingMissing(t *testing.T) {
	eng := NewRatingEngine("half_up", nil)
	u := &UsageAgg{
		TenantID: "t1",
		ByModel: map[string]*ModelStd{
			"unknown-model": {StdIn: 1000, StdOut: 500},
		},
	}
	_, err := eng.Rate(u, testPriceTable())
	if err == nil {
		t.Error("expected ErrPricingMissing for unknown model, got nil")
	}
}

// ---------- 内存月累计提供器（测试用） ----------

type testMonthStd struct {
	data map[string]map[string][2]int64 // key: tenant -> modelKey -> [stdInBefore, stdOutBefore]
}

func (m *testMonthStd) MonthStdBefore(tenant, modelKey, period string) (int64, int64) {
	if m.data == nil {
		return 0, 0
	}
	tm, ok := m.data[tenant]
	if !ok {
		return 0, 0
	}
	v, ok := tm[modelKey]
	if !ok {
		return 0, 0
	}
	return v[0], v[1]
}

// ---------- T-6.5-7 日/月可加性（分轴 + 正确 before 值） ----------

func TestRate_DailyMonthlyAdditive(t *testing.T) {
	// 用内存 monthStd provider，D1 之后 D2 的 before = D1 的 std
	// 验证 Σ daily.Rate == RateMonthly(月聚合)
	tbl := testPriceTable()

	d1StdIn, d1StdOut := int64(600000), int64(400000)
	d2StdIn, d2StdOut := int64(600000), int64(400000)

	// D1: before=0
	eng1 := NewRatingEngine("half_up", &testMonthStd{})
	d1 := &UsageAgg{
		TenantID: "t1", Period: "2026-10-01",
		ByModel: map[string]*ModelStd{
			"gpt-4o": {StdIn: d1StdIn, StdOut: d1StdOut},
		},
	}
	amt1, _ := eng1.Rate(d1, tbl)

	// D2: before = D1 的 std
	eng2 := NewRatingEngine("half_up", &testMonthStd{
		data: map[string]map[string][2]int64{
			"t1": {"gpt-4o": {d1StdIn, d1StdOut}},
		},
	})
	d2 := &UsageAgg{
		TenantID: "t1", Period: "2026-10-02",
		ByModel: map[string]*ModelStd{
			"gpt-4o": {StdIn: d2StdIn, StdOut: d2StdOut},
		},
	}
	amt2, _ := eng2.Rate(d2, tbl)

	sumDaily := amt1 + amt2

	// 月聚合：before=0
	engM := NewRatingEngine("half_up", &testMonthStd{})
	monthly := &UsageAgg{
		TenantID: "t1", Period: "2026-10",
		ByModel: map[string]*ModelStd{
			"gpt-4o": {StdIn: d1StdIn + d2StdIn, StdOut: d1StdOut + d2StdOut},
		},
	}
	amtMonthly, _ := engM.Rate(monthly, tbl)

	if sumDaily != amtMonthly {
		t.Errorf("split-axis additivity: Σ daily = %d, monthly = %d (A-26 violated)",
			sumDaily, amtMonthly)
	}
	t.Logf("Σ daily = %d 分, monthly = %d 分 (additivity OK)", sumDaily, amtMonthly)
}

// ---------- T-6.5-9 入/出分轴可加性回归（多日跨档） ----------

func TestRate_SplitAxisAdditivity(t *testing.T) {
	tbl := testPriceTable()
	tenant := "t1"
	mk := "gpt-4o"

	type dayAgg struct{ in, out int64 }
	days := []dayAgg{
		{500000, 300000},   // D1
		{400000, 500000},   // D2
		{600000, 400000},   // D3
		{300000, 800000},   // D4
	}

	var sumDaily Amount
	var cumIn, cumOut int64

	for i, d := range days {
		ms := &testMonthStd{
			data: map[string]map[string][2]int64{
				tenant: {mk: {cumIn, cumOut}},
			},
		}
		eng := NewRatingEngine("half_up", ms)
		u := &UsageAgg{
			TenantID: tenant, Period: "2026-10-0" + string(rune('1'+i)),
			ByModel: map[string]*ModelStd{
				mk: {StdIn: d.in, StdOut: d.out},
			},
		}
		amt, _ := eng.Rate(u, tbl)
		sumDaily += amt
		cumIn += d.in
		cumOut += d.out
	}

	// 月聚合
	engM := NewRatingEngine("half_up", &testMonthStd{})
	monthly := &UsageAgg{
		TenantID: tenant, Period: "2026-10",
		ByModel: map[string]*ModelStd{
			mk: {StdIn: cumIn, StdOut: cumOut},
		},
	}
	amtMonthly, _ := engM.Rate(monthly, tbl)

	if sumDaily != amtMonthly {
		t.Errorf("split-axis additivity (4 days): Σ daily = %d, monthly = %d (A-26 violated)",
			sumDaily, amtMonthly)
	}
	t.Logf("4-day Σ daily = %d 分, monthly = %d 分 (in=%d, out=%d)",
		sumDaily, amtMonthly, cumIn, cumOut)
}

// ---------- T-6.5-10 超额段入优先占额（A-33） ----------

func TestExtraAmount_InputFirstConsumesQuota(t *testing.T) {
	eng := NewRatingEngine("half_up", nil)
	tbl := testPriceTable()
	plan := &Plan{MonthlyTokens: 1000000} // 1M 总额度（标准 token 合计）

	// 场景：in=800k, out=400k，合计 1.2M，超额 200k
	// 入先占额：in 800k 全在额度内，out 占 200k 额度，out 超额 200k
	u := &UsageAgg{
		TenantID: "t1", Period: "2026-10",
		ByModel: map[string]*ModelStd{
			"cheap-model": {StdIn: 800000, StdOut: 400000},
		},
	}
	mu, err := eng.ExtraAmount(u, plan, tbl)
	if err != nil {
		t.Fatalf("ExtraAmount err: %v", err)
	}
	amt := roundAmount(mu, "half_up")
	// 超额 out=200k × 2元/千 = 400 元 = 40000 分
	expected := Amount(40000)
	if amt != expected {
		t.Errorf("extra amount = %d 分, want %d 分 (input-first A-33)", amt, expected)
	}
}

// ---------- T-6.5-12 超额套餐级合计基数（A-44②） ----------

func TestExtraAmount_PackageLevelBase(t *testing.T) {
	// 反例验证：MonthlyTokens=1M，双模型各 800k in（合计 1.6M）
	// 旧逐模型法：每模型各 800k < 1M → 超额 0（系统性漏收）
	// 套餐级合计法：合计 1.6M > 1M → 超额 600k
	eng := NewRatingEngine("half_up", nil)
	tbl := testPriceTable()
	plan := &Plan{MonthlyTokens: 1000000}

	u := &UsageAgg{
		TenantID: "t1", Period: "2026-10",
		ByModel: map[string]*ModelStd{
			"gpt-4o":      {StdIn: 800000, StdOut: 0},
			"cheap-model": {StdIn: 800000, StdOut: 0},
		},
	}
	mu, err := eng.ExtraAmount(u, plan, tbl)
	if err != nil {
		t.Fatalf("ExtraAmount err: %v", err)
	}
	amt := roundAmount(mu, "half_up")
	if amt <= 0 {
		t.Errorf("extra amount = %d, want > 0 (A-44②: package-level base prevents systematic undercharge)", amt)
	}
	// 600k 超额：按 gpt-4o 顶档 15元/千 = 9000 元 = 900000 分
	// （瀑布归属：用量降序，gpt-4o 的 in=800k 与 cheap-model 的 in=800k 相等 → 按 modelKey 升序排，
	//   cheap-model 在前？不对，gpt-4o 的 g 字母序比 c 大 → cheap-model 先。
	//   cheap-model 用 800k 额度，剩余 200k 给 gpt-4o，gpt-4o 超额 600k。
	//   gpt-4o 顶档 in=15元/千，600k × 15元/千 = 9000 元 = 900000 分）
	expected := Amount(900000)
	if amt != expected {
		t.Errorf("extra amount = %d 分, want %d 分 (waterfall attribution)", amt, expected)
	}
	t.Logf("extra amount = %d 分 (2 models × 800k in, 1M quota)", amt)
}

// ---------- T-6.5-6 标准 token 换算唯一性（A-9） ----------

func TestStandardTokens_UniqueImpl(t *testing.T) {
	eng := NewRatingEngine("half_up", nil)
	tbl := testPriceTable()
	mp := tbl.Models["gpt-4o"]
	mp.InCoef = 2.0
	mp.OutCoef = 3.0

	stdIn, stdOut := eng.StandardTokens(1000, 500, mp)
	if stdIn != 2000 {
		t.Errorf("stdIn = %d, want 2000", stdIn)
	}
	if stdOut != 1500 {
		t.Errorf("stdOut = %d, want 1500", stdOut)
	}
}

// ---------- roundAmount 取整测试 ----------

func TestRoundAmount(t *testing.T) {
	tests := []struct {
		mu     int64
		mode   string
		expect Amount
	}{
		{1500, "half_up", 2},     // 1.5 分 → 四舍五入 2
		{1499, "half_up", 1},     // 1.499 分 → 1
		{0, "half_up", 0},        // 0
		{-1500, "half_up", -2},   // 负数对称（C-3）
		{-1499, "half_up", -1},   // 负数对称
		{1999, "floor", 1},       // floor 截断
		{-1999, "floor", -1},     // floor 负数也截断（向零）
	}
	for _, tt := range tests {
		got := roundAmount(tt.mu, tt.mode)
		if got != tt.expect {
			t.Errorf("roundAmount(%d, %q) = %d, want %d", tt.mu, tt.mode, got, tt.expect)
		}
	}
}

// ---------- overlap 测试 ----------

func TestOverlap(t *testing.T) {
	tests := []struct {
		length, start, lo, up int64
		expect                int64
	}{
		{100, 0, 0, 1000, 100},       // 完全在档内
		{500, 800, 0, 1000, 200},     // 跨档：200 在档内
		{500, 1200, 0, 1000, 0},      // 完全在档外
		{1000, 500, 0, 0, 1000},      // 顶档(up=0=∞)
		{0, 100, 0, 1000, 0},         // 空段
	}
	for _, tt := range tests {
		got := overlap(tt.length, tt.start, tt.lo, tt.up)
		if got != tt.expect {
			t.Errorf("overlap(len=%d,start=%d,lo=%d,up=%d) = %d, want %d",
				tt.length, tt.start, tt.lo, tt.up, got, tt.expect)
		}
	}
}
