package routeengine

import (
	"encoding/json"
	"fmt"
	"testing"
)

// ============================================================
// M1.1 验收（本体 v1.5 §4.1 M1.1 / §6.1 / §6.3）：
//   - 结构存在性与类型（编译期断言）
//   - JSON 标签与 §6.1 latency 字段表、§6.3 stats 条目逐字段一致
//   - normalized() 仅越界钳制：非法范围回缺省，合法显式 0 值保留
// ============================================================

// 编译期结构断言：字段名与类型逐一固定（改动字段会在此处编译失败）。
var (
	_ = TTFTStat{
		P50Ms:     int64(0),
		P95Ms:     int64(0),
		Samples:   int64(0),
		Valid:     false,
		UpdatedAt: int64(0),
		Cache:     "miss",
	}
	_ = LatencyConfig{
		WindowSec:      int(0),
		Quantile:       "",
		Gamma:          float64(0),
		MinWeight:      float64(0),
		ExploreRatio:   float64(0),
		MinSamples:     int(0),
		StaleSec:       int(0),
		CachePartition: false,
		MaxTTFTMs:      int64(0),
	}
)

// TestLatencyConfig_JSONFieldsMatchSchema：§6.1 字段表 9 字段逐一核对。
func TestLatencyConfig_JSONFieldsMatchSchema(t *testing.T) {
	raw, err := json.Marshal(LatencyConfig{
		WindowSec:      300,
		Quantile:       "p95",
		Gamma:          1.0,
		MinWeight:      0.05,
		ExploreRatio:   0.05,
		MinSamples:     20,
		StaleSec:       75,
		CachePartition: true,
		MaxTTFTMs:      30000,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{
		"window_sec", "quantile", "gamma", "min_weight", "explore_ratio",
		"min_samples", "stale_sec", "cache_partition", "max_ttft_ms",
	}
	if len(got) != len(want) {
		t.Fatalf("JSON 字段数=%d，期望 %d：%v", len(got), len(want), raw)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("缺少字段 %q（JSON 标签须与 §6.1 字段表一致）", k)
		}
	}
}

// TestTTFTStat_JSONFieldsMatchStatsContract：§6.3 stats 条目 6 字段逐一核对。
func TestTTFTStat_JSONFieldsMatchStatsContract(t *testing.T) {
	raw, err := json.Marshal(TTFTStat{
		P50Ms: 210, P95Ms: 480, Samples: 1200, Valid: true, UpdatedAt: 1760000000, Cache: "miss",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"p50_ms", "p95_ms", "samples", "valid", "updated_at", "cache"}
	if len(got) != len(want) {
		t.Fatalf("JSON 字段数=%d，期望 %d：%v", len(got), len(want), raw)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("缺少字段 %q（JSON 标签须与 §6.3 stats 条目一致）", k)
		}
	}
}

// TestLatencyConfig_Normalized：越界钳制与合法显式 0 值保留。
func TestLatencyConfig_Normalized(t *testing.T) {
	// 全零值：越界字段（window/quantile/min_samples/stale/max_ttft）回缺省；
	// gamma=0 / min_weight=0 / explore_ratio=0 为合法显式值，须保留。
	z := (LatencyConfig{}).normalized()
	if z.WindowSec != defaultLatencyWindowSec {
		t.Errorf("零值 window_sec 应为缺省 %d，got %d", defaultLatencyWindowSec, z.WindowSec)
	}
	if z.Quantile != defaultLatencyQuantile {
		t.Errorf("空 quantile 应为缺省 %q，got %q", defaultLatencyQuantile, z.Quantile)
	}
	if z.Gamma != 0 {
		t.Errorf("gamma=0 为合法显式值，不应被改写，got %v", z.Gamma)
	}
	if z.MinWeight != 0 {
		t.Errorf("min_weight=0 为合法显式值（范围 0–0.5），不应被改写，got %v", z.MinWeight)
	}
	if z.ExploreRatio != 0 {
		t.Errorf("explore_ratio=0 为合法显式值，不应被改写，got %v", z.ExploreRatio)
	}
	if z.MinSamples != defaultLatencyMinSamples {
		t.Errorf("min_samples=0 应回缺省 %d，got %d", defaultLatencyMinSamples, z.MinSamples)
	}
	if z.StaleSec != defaultLatencyStaleSec {
		t.Errorf("stale_sec=0 应回缺省 %d，got %d", defaultLatencyStaleSec, z.StaleSec)
	}
	if z.MaxTTFTMs != defaultLatencyMaxTTFTMs {
		t.Errorf("max_ttft_ms=0 应回缺省 %d，got %d", defaultLatencyMaxTTFTMs, z.MaxTTFTMs)
	}

	cases := []struct {
		name string
		in   LatencyConfig
		chk  func(LatencyConfig) bool
		desc string
	}{
		{"window-too-small", LatencyConfig{WindowSec: 10, Quantile: "p95", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.WindowSec == 300 }, "window_sec<60 → 300"},
		{"window-too-large", LatencyConfig{WindowSec: 4000, Quantile: "p95", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.WindowSec == 300 }, "window_sec>3600 → 300"},
		{"quantile-p99", LatencyConfig{WindowSec: 300, Quantile: "p99", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Quantile == "p95" }, "quantile 非 p50/p95 → p95"},
		{"gamma-negative", LatencyConfig{WindowSec: 300, Quantile: "p95", Gamma: -0.1, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Gamma == 1.0 }, "gamma<0 → 1.0"},
		{"gamma-too-large", LatencyConfig{WindowSec: 300, Quantile: "p95", Gamma: 6, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Gamma == 1.0 }, "gamma>5 → 1.0"},
		{"minweight-too-large", LatencyConfig{WindowSec: 300, Quantile: "p95", MinWeight: 0.6, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.MinWeight == 0.05 }, "min_weight>0.5 → 0.05"},
		{"explore-too-large", LatencyConfig{WindowSec: 300, Quantile: "p95", ExploreRatio: 1.5, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.ExploreRatio == 0.05 }, "explore_ratio>1 → 0.05"},
		{"stale-too-small", LatencyConfig{WindowSec: 300, Quantile: "p95", MinSamples: 20, StaleSec: 24, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.StaleSec == 75 }, "stale_sec<25 → 75"},
		{"maxttft-too-small", LatencyConfig{WindowSec: 300, Quantile: "p95", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 999},
			func(c LatencyConfig) bool { return c.MaxTTFTMs == 30000 }, "max_ttft_ms<1000 → 30000"},
		// 合法边界值原样保留
		{"legal-gamma-5", LatencyConfig{WindowSec: 300, Quantile: "p95", Gamma: 5, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Gamma == 5 }, "gamma=5 合法边界保留"},
		{"legal-explore-1", LatencyConfig{WindowSec: 300, Quantile: "p95", ExploreRatio: 1, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.ExploreRatio == 1 }, "explore_ratio=1 合法边界保留"},
		{"legal-quantile-p50", LatencyConfig{WindowSec: 300, Quantile: "p50", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Quantile == "p50" }, "quantile=p50 保留"},
		{"legal-stale-25", LatencyConfig{WindowSec: 300, Quantile: "p95", MinSamples: 20, StaleSec: 25, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.StaleSec == 25 }, "stale_sec=25 合法边界保留"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.normalized(); !tc.chk(got) {
				t.Errorf("%s：断言失败，got %+v", tc.desc, got)
			}
		})
	}
}

// ============================================================
// M1.2 验收（本体 v1.5 §3.5 / §4.1 M1.2）：权函数公式、钳制、
// 单端点扫描、归一化前下界与防饿死、不改写 EndpointState。
// ============================================================

// mkEp 构造测试端点（默认启用、权重 1、给定 TTFT 统计）。
func mkEp(name string, prio int, t95 int64, valid bool) *EndpointState {
	return &EndpointState{
		Name:       name,
		URL:        "https://" + name + ".internal/v1",
		Priority:   prio,
		Enabled:    true,
		BaseWeight: 1,
		Weight:     1,
		TTFT:       TTFTStat{P95Ms: t95, Samples: 100, Valid: valid, UpdatedAt: 1},
	}
}

func mkState(eps ...*EndpointState) map[string]*EndpointState {
	m := make(map[string]*EndpointState, len(eps))
	for _, ep := range eps {
		m[ep.Name] = ep
	}
	return m
}

func latencyTestCfg() LatencyConfig {
	return LatencyConfig{
		WindowSec: 300, Quantile: "p95", Gamma: 1.0, MinWeight: 0.05,
		ExploreRatio: 0.05, MinSamples: 20, StaleSec: 75,
		CachePartition: true, MaxTTFTMs: 30000,
	}.normalized()
}

func TestLatencyRefMs_ClampAndQuantile(t *testing.T) {
	cfg := latencyTestCfg()
	cases := []struct {
		name string
		st   TTFTStat
		want int64
	}{
		{"p95-normal", TTFTStat{P95Ms: 200}, 200},
		{"p95-zero-clamped-to-1ms", TTFTStat{P95Ms: 0}, 1},
		{"p95-negative-clamped-to-1ms", TTFTStat{P95Ms: -5}, 1},
		{"p95-over-max-clamped", TTFTStat{P95Ms: 50000}, 30000},
		{"p95-equal-max-kept", TTFTStat{P95Ms: 30000}, 30000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := latencyRefMs(tc.st, cfg); got != tc.want {
				t.Errorf("latencyRefMs=%d，want %d", got, tc.want)
			}
		})
	}
	// quantile=p50：取 P50Ms
	cfg50 := cfg
	cfg50.Quantile = "p50"
	if got := latencyRefMs(TTFTStat{P50Ms: 100, P95Ms: 900}, cfg50); got != 100 {
		t.Errorf("quantile=p50 应取 P50Ms=100，got %d", got)
	}
}

func TestLatencyBaseOf_Monotonicity(t *testing.T) {
	const tMin = int64(200)
	// γ=1：t=200→1；t=400→0.5；t=1000→0.2（严格单调递减）
	if b := latencyBaseOf(tMin, 200, 1); b != 1 {
		t.Errorf("base(t=t_min)=%v，want 1", b)
	}
	if b := latencyBaseOf(tMin, 400, 1); b != 0.5 {
		t.Errorf("base(400)=%v，want 0.5", b)
	}
	if b := latencyBaseOf(tMin, 1000, 1); b != 0.2 {
		t.Errorf("base(1000)=%v，want 0.2", b)
	}
	// 单调性：t 越大 base 越小（γ>0）
	prev := 2.0
	for _, tm := range []int64{200, 300, 500, 900, 2000, 30000} {
		b := latencyBaseOf(tMin, tm, 1)
		if b > prev {
			t.Errorf("base 非单调：t=%d base=%v > prev=%v", tm, b, prev)
		}
		prev = b
	}
	// γ=0：所有端点的 base 恒为 1（§3.5 关键性质）
	if b := latencyBaseOf(tMin, 30000, 0); b != 1 {
		t.Errorf("γ=0 时 base 应恒为 1，got %v", b)
	}
	// γ=2：平方关系
	if b := latencyBaseOf(tMin, 400, 2); b != 0.25 {
		t.Errorf("γ=2 时 base(400)=%v，want 0.25", b)
	}
}

func TestLatencyGroupScan_SingleAndEmpty(t *testing.T) {
	// 忙碌端点（权重 0）与熔断端点不参与
	broken := mkEp("broken", 1, 100, true)
	broken.Weight = 0
	open := mkEp("open", 1, 100, true)
	open.CircuitBreaker.State = CircuitOpen
	disabled := mkEp("disabled", 1, 100, true)
	disabled.Enabled = false
	solo := mkEp("solo", 2, 500, false) // 唯一可用（TTFT 无效仍是可用）

	minPrio, usable, single, ok := latencyGroupScan(mkState(broken, open, disabled, solo))
	if !ok || minPrio != 2 || usable != 1 || single == nil || single.Name != "solo" {
		t.Fatalf("单端点扫描：minPrio=%d usable=%d single=%v ok=%v", minPrio, usable, single, ok)
	}

	// 全不可用 → ok=false
	if _, _, _, ok := latencyGroupScan(mkState(broken, open, disabled)); ok {
		t.Fatal("全不可用时应 ok=false")
	}

	// 同优先级 2 个可用 → single=nil
	a, b := mkEp("a", 1, 200, true), mkEp("b", 1, 300, true)
	minPrio, usable, single, ok = latencyGroupScan(mkState(a, b))
	if !ok || minPrio != 1 || usable != 2 || single != nil {
		t.Fatalf("双端点扫描：minPrio=%d usable=%d single=%v ok=%v", minPrio, usable, single, ok)
	}
}

func TestLatencyGroupWeights_Formula(t *testing.T) {
	cfg := latencyTestCfg()
	st := mkState(mkEp("a", 1, 200, true), mkEp("b", 1, 400, true), mkEp("c", 1, 1000, true))
	minPrio, usable, _, ok := latencyGroupScan(st)
	if !ok || usable != 3 {
		t.Fatalf("scan: usable=%d ok=%v", usable, ok)
	}
	tMin, eligible := latencyGroupTMin(st, minPrio, cfg)
	if tMin != 200 || eligible != 3 {
		t.Fatalf("tMin=%d eligible=%d，want 200/3", tMin, eligible)
	}
	maxBase := latencyGroupMaxBase(st, minPrio, tMin, cfg)
	if maxBase != 1 {
		t.Fatalf("maxBase=%v，want 1", maxBase)
	}
	floor := cfg.MinWeight * maxBase // 0.05
	total := latencyGroupTotalWeight(st, minPrio, tMin, floor, cfg)
	// w = 1 + 0.5 + 0.2 = 1.7
	if diff := total - 1.7; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("totalW=%v，want 1.7", total)
	}
	for name, want := range map[string]float64{"a": 1, "b": 0.5, "c": 0.2} {
		got := latencyGroupWeightOf(st[name], tMin, floor, cfg)
		if diff := got - want; diff > 1e-12 || diff < -1e-12 {
			t.Errorf("w(%s)=%v，want %v", name, got, want)
		}
	}
}

func TestLatencyGroupWeights_FloorProtection(t *testing.T) {
	cfg := latencyTestCfg()
	// b 极慢：base=100/30000≈0.0033 < floor=0.05 → w=floor（防饿死下界，归一化前）
	st := mkState(mkEp("a", 1, 100, true), mkEp("b", 1, 30000, true))
	minPrio, _, _, _ := latencyGroupScan(st)
	tMin, eligible := latencyGroupTMin(st, minPrio, cfg)
	if tMin != 100 || eligible != 2 {
		t.Fatalf("tMin=%d eligible=%d", tMin, eligible)
	}
	maxBase := latencyGroupMaxBase(st, minPrio, tMin, cfg)
	floor := cfg.MinWeight * maxBase
	total := latencyGroupTotalWeight(st, minPrio, tMin, floor, cfg)
	// total = 1 + 0.05 = 1.05（慢端点被 floor 托底）
	if diff := total - 1.05; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("totalW=%v，want 1.05（floor 托底）", total)
	}
	wSlow := latencyGroupWeightOf(st["b"], tMin, floor, cfg)
	if diff := wSlow - 0.05; diff > 1e-12 || diff < -1e-12 {
		t.Fatalf("慢端点 w=%v，want floor=0.05", wSlow)
	}
	// 归一化后真实概率 = 0.05/1.05 = 1/21 ≈ 0.047619（文档表取 4 位 ≈0.0476；R2-01：
	// 概率下界严格小于 min_weight，防饿死由 floor 保证——此处概率 > 0）
	wantP := 0.05 / 1.05
	if p := wSlow / total; p > wantP+1e-12 || p < wantP-1e-12 {
		t.Errorf("慢端点归一化概率=%v，want %v", p, wantP)
	}
}

// TestLatencyGroupWeights_NormalizedLowerBound_Param：R2-01 参数化——
// 归一化后慢端点概率下界等于 floor / [1+(n-1)floor]（n=2/6/50），不受 min_weight
// 直接解释；防饿死由 floor 保证（概率恒 > 0）。
func TestLatencyGroupWeights_NormalizedLowerBound_Param(t *testing.T) {
	cfg := latencyTestCfg()
	for _, n := range []int{2, 6, 50} {
		eps := make([]*EndpointState, 0, n)
		eps = append(eps, mkEp("fast", 1, 100, true))
		for i := 1; i < n; i++ {
			eps = append(eps, mkEp("slow"+string(rune('a'+i)), 1, 30000, true))
		}
		st := mkState(eps...)
		minPrio, _, _, _ := latencyGroupScan(st)
		tMin, eligible := latencyGroupTMin(st, minPrio, cfg)
		if eligible != n {
			t.Fatalf("n=%d eligible=%d", n, eligible)
		}
		maxBase := latencyGroupMaxBase(st, minPrio, tMin, cfg)
		floor := cfg.MinWeight * maxBase
		total := latencyGroupTotalWeight(st, minPrio, tMin, floor, cfg)
		// 期望：total = 1 + (n-1)×floor；慢端点概率 = floor/total
		wantTotal := 1 + float64(n-1)*floor
		if diff := total - wantTotal; diff > 1e-9 || diff < -1e-9 {
			t.Fatalf("n=%d totalW=%v，want %v", n, total, wantTotal)
		}
		p := latencyGroupWeightOf(st["slowb"], tMin, floor, cfg) / total
		wantP := floor / wantTotal
		if diff := p - wantP; diff > 1e-12 || diff < -1e-12 {
			t.Errorf("n=%d 慢端点概率=%v，want %v", n, p, wantP)
		}
		if p <= 0 {
			t.Errorf("n=%d 慢端点概率=%v，防饿死被违反", n, p)
		}
	}
}

// TestLatencyWeights_NoStateMutation：请求内临时量——helper 不得改写 EndpointState。
func TestLatencyWeights_NoStateMutation(t *testing.T) {
	cfg := latencyTestCfg()
	a := mkEp("a", 1, 200, true)
	b := mkEp("b", 1, 400, true)
	b.Weight = 0.7 // 模拟失败率维度已调整的权重
	st := mkState(a, b)
	snapA, snapB := *a, *b

	minPrio, _, _, _ := latencyGroupScan(st)
	tMin, _ := latencyGroupTMin(st, minPrio, cfg)
	maxBase := latencyGroupMaxBase(st, minPrio, tMin, cfg)
	floor := cfg.MinWeight * maxBase
	_ = latencyGroupTotalWeight(st, minPrio, tMin, floor, cfg)
	_ = latencyGroupWeightOf(b, tMin, floor, cfg)

	if *a != snapA || *b != snapB {
		t.Fatal("权函数改写了 EndpointState（违反 C-3：请求内临时量、不就地改写）")
	}
}

// ============================================================
// M1.3 验收（本体 v1.5 §3.5 / §4.1 M1.3 / R2-16 / R2-10）：
// 确定性回退（两次抽样分别注入 ok=false）、探索均匀性、加权分布与
// P_min(n)（R2-01）、Strategy 回填、单端点/等价单端点、R2-19 序 1-3 归因。
// ============================================================

// ttftRandStep 脚本化随机序列元素。
type ttftRandStep struct {
	v  float64
	ok bool
}

// ttftScriptedRand 脚本化随机源：按序消费；耗尽后返回 ok=false。
type ttftScriptedRand struct {
	steps []ttftRandStep
	i     int
}

func ttftScripted(steps ...ttftRandStep) *ttftScriptedRand {
	return &ttftScriptedRand{steps: steps}
}

func (s *ttftScriptedRand) Float64() (float64, bool) {
	if s.i >= len(s.steps) {
		return 0, false
	}
	st := s.steps[s.i]
	s.i++
	return st.v, st.ok
}

// ttftLCGRand 确定性伪随机源（测试统计用；非密码学）。
type ttftLCGRand struct{ s uint64 }

func (l *ttftLCGRand) Float64() (float64, bool) {
	l.s = l.s*6364136223846793005 + 1442695040888963407
	return float64(l.s>>11) / float64(uint64(1)<<53), true
}

func ttftWithRand(t *testing.T, rs RandSource) {
	t.Helper()
	old := randSource
	SetRandSource(rs)
	t.Cleanup(func() { SetRandSource(old) })
}

func ttftWithObserver(t *testing.T) *[]string {
	t.Helper()
	recs := &[]string{}
	old := latencyFallbackObserver
	SetLatencyFallbackObserver(func(reason string) { *recs = append(*recs, reason) })
	t.Cleanup(func() { SetLatencyFallbackObserver(old) })
	return recs
}

func ttftEngine(strategy Strategy, eps ...*EndpointState) *Engine {
	e := NewEngine(Config{Strategy: strategy, Latency: latencyTestCfg()})
	e.state = mkState(eps...)
	return e
}

// TestPickByLatency_NoRandDeterministicFallback（R2-16）：两次抽样**分别**注入
// ok=false（第一抽失败 / 利用分支第二抽失败 / 探索分支第二抽失败）均触发确定性
// 回退（latency-fastest），计 _no_rand，且 Strategy 仍回填 latency-aware（R2-10）。
func TestPickByLatency_NoRandDeterministicFallback(t *testing.T) {
	cases := []struct {
		name string
		rand *ttftScriptedRand
	}{
		{"first-draw-fails", ttftScripted(ttftRandStep{0, false})},
		{"util-second-draw-fails", ttftScripted(ttftRandStep{0.9, true}, ttftRandStep{0, false})},
		{"explore-second-draw-fails", ttftScripted(ttftRandStep{0.01, true}, ttftRandStep{0, false})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs := ttftWithObserver(t)
			ttftWithRand(t, tc.rand)
			e := ttftEngine(StrategyLatencyAware, mkEp("a", 1, 200, true), mkEp("b", 1, 400, true))
			d := e.pickByLatency()
			if d.EndpointName != "a" { // 最快有效端点（t=200）
				t.Errorf("确定性回退应选最快有效端点 a，got %q", d.EndpointName)
			}
			if d.Strategy != StrategyLatencyAware {
				t.Errorf("Strategy 应回填 latency-aware（R2-10），got %q", d.Strategy)
			}
			if d.Reason != "latency_fallback_fastest" {
				t.Errorf("Reason=%q，want latency_fallback_fastest", d.Reason)
			}
			if len(*recs) != 1 || (*recs)[0] != fallbackNoRand {
				t.Errorf("回退计数=%v，want [no_rand]", *recs)
			}
		})
	}
}

// TestPickByLatency_StrategyBackfill_R2_10：正常加权路径不得被标成 weighted。
func TestPickByLatency_StrategyBackfillR2_10(t *testing.T) {
	ttftWithRand(t, ttftScripted(ttftRandStep{0.9, true}, ttftRandStep{0.5, true}))
	e := ttftEngine(StrategyLatencyAware, mkEp("a", 1, 200, true), mkEp("b", 1, 400, true))
	// r = 0.5 × 1.7 = 0.85；a 权重 1.0 → 必中 a（与 map 序无关）
	d := e.pickByLatency()
	if d.EndpointName != "a" {
		t.Fatalf("加权抽样应命中 a，got %q", d.EndpointName)
	}
	if d.Strategy != StrategyLatencyAware {
		t.Errorf("Strategy=%q，不得被标成 weighted（R2-10）", d.Strategy)
	}
	if d.Reason != "latency_weighted" {
		t.Errorf("Reason=%q，want latency_weighted", d.Reason)
	}
}

// TestPickByLatency_ExploreUniform：explore_ratio=1 时组内均匀。
func TestPickByLatency_ExploreUniform(t *testing.T) {
	cfg := latencyTestCfg()
	cfg.ExploreRatio = 1
	e := NewEngine(Config{Strategy: StrategyLatencyAware, Latency: cfg})
	e.state = mkState(mkEp("a", 1, 200, true), mkEp("b", 1, 300, true), mkEp("c", 1, 400, true))
	ttftWithRand(t, &ttftLCGRand{s: 42})

	const n = 15000
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		counts[e.pickByLatency().EndpointName]++
	}
	for _, name := range []string{"a", "b", "c"} {
		f := float64(counts[name]) / n
		if f < 1.0/3-0.02 || f > 1.0/3+0.02 {
			t.Errorf("探索分布不均匀：%s 频率=%.4f（期望≈1/3）", name, f)
		}
	}
}

// TestPickByLatency_WeightedDistributionPMin（R2-01）：1 快 + (n-1) 极慢（触底 floor）。
// 断言慢端点频率 ≥ P_min(n) 且 > 0（防饿死）、快端点占比 > 慢端点（快慢比>1）。
func TestPickByLatency_WeightedDistributionPMin(t *testing.T) {
	ttftWithRand(t, &ttftLCGRand{s: 7})
	const floor = 0.05
	const explore = 0.05
	for _, n := range []int{2, 6, 50} {
		eps := make([]*EndpointState, 0, n)
		eps = append(eps, mkEp("fast", 1, 100, true))
		for i := 1; i < n; i++ {
			eps = append(eps, mkEp(fmt.Sprintf("slow%02d", i), 1, 30000, true))
		}
		e := ttftEngine(StrategyLatencyAware, eps...)
		const total = 30000
		counts := map[string]int{}
		for i := 0; i < total; i++ {
			counts[e.pickByLatency().EndpointName]++
		}
		pMin := explore/float64(n) + (1-explore)*floor/(1+float64(n-1)*floor)
		fSlow := float64(counts["slow01"]) / total
		if fSlow < pMin-0.01 {
			t.Errorf("n=%d 慢端点频率=%.4f < P_min(%d)=%.4f（R2-01）", n, fSlow, n, pMin)
		}
		if fSlow <= 0 {
			t.Errorf("n=%d 防饿死被违反（慢端点频率=0）", n)
		}
		if counts["fast"] <= counts["slow01"] {
			t.Errorf("n=%d 快端点占比应 > 慢端点：fast=%d slow01=%d", n, counts["fast"], counts["slow01"])
		}
	}
}

// TestPickByLatency_EligibleOne：R2-19 序 4——有效端点=1 → 等价退单端点 + _low_samples。
func TestPickByLatency_EligibleOne(t *testing.T) {
	recs := ttftWithObserver(t)
	e := ttftEngine(StrategyLatencyAware,
		mkEp("valid", 1, 300, true),
		mkEp("invalid", 1, 100, false), // 更快但统计无效 → 不参与 TTFT 权
	)
	d := e.pickByLatency()
	if d.EndpointName != "valid" || d.Reason != "latency_single_eligible" {
		t.Fatalf("等价单端点：got %q/%q", d.EndpointName, d.Reason)
	}
	if d.Strategy != StrategyLatencyAware {
		t.Errorf("Strategy=%q，want latency-aware", d.Strategy)
	}
	if len(*recs) != 1 || (*recs)[0] != fallbackLowSamples {
		t.Errorf("回退计数=%v，want [low_samples]", *recs)
	}
}

// TestPickByLatency_NoStatsClassification_R2_19：E==0 时序 1-3 归因与全局回退。
func TestPickByLatency_NoStatsClassification(t *testing.T) {
	cases := []struct {
		name        string
		unreachable bool
		samplesA    int64
		samplesB    int64
		want        string
	}{
		{"unreachable-first", true, 100, 100, fallbackUnreachable},
		{"no_samples", false, 0, 0, fallbackNoSamples},
		{"low_samples", false, 5, 10, fallbackLowSamples},
		{"stale", false, 100, 60, fallbackStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recs := ttftWithObserver(t)
			a := mkEp("a", 1, 200, true)
			a.TTFT = TTFTStat{P95Ms: 200, Samples: tc.samplesA, Valid: false, UpdatedAt: 1}
			b := mkEp("b", 1, 400, true)
			b.TTFT = TTFTStat{P95Ms: 400, Samples: tc.samplesB, Valid: false, UpdatedAt: 1}
			e := ttftEngine(StrategyLatencyAware, a, b)
			e.SetTTFTStatsUnreachable(tc.unreachable)

			d := e.pickByLatency()
			if d.EndpointName == "" {
				t.Fatal("全局回退应经 failure-aware 选出端点")
			}
			if d.Strategy != StrategyLatencyAware {
				t.Errorf("Strategy=%q，回退不得改写策略标签（R2-10）", d.Strategy)
			}
			if len(*recs) != 1 || (*recs)[0] != tc.want {
				t.Errorf("回退计数=%v，want [%s]", *recs, tc.want)
			}
		})
	}
}

// TestPickByLatency_SingleAndEmpty：单端点优化（TT2-07）与空组。
func TestPickByLatency_SingleAndEmpty(t *testing.T) {
	recs := ttftWithObserver(t)
	e := ttftEngine(StrategyLatencyAware, mkEp("solo", 1, 500, false)) // 唯一可用（统计无效也直返）
	d := e.pickByLatency()
	if d.EndpointName != "solo" || d.Reason != "latency_single" {
		t.Fatalf("单端点优化：got %q/%q", d.EndpointName, d.Reason)
	}
	if d.Strategy != StrategyLatencyAware {
		t.Errorf("Strategy=%q，want latency-aware", d.Strategy)
	}
	if len(*recs) != 0 {
		t.Errorf("单端点优化不应计回退，got %v", *recs)
	}

	e2 := ttftEngine(StrategyLatencyAware)
	d2 := e2.pickByLatency()
	if d2.EndpointName != "" || d2.Reason != "no_usable_endpoints" {
		t.Fatalf("空组应返回空 Decision，got %q/%q", d2.EndpointName, d2.Reason)
	}
}

// ============================================================
// M1.4 验收（本体 v1.5 §3.5 / §4.1 M1.4 / TT2-02 / TT2-10）：
// latency-fastest 确定性选路 + tie-break（priority → name 字典序）+
// 多次调用可复现 + 空决策 + 组上浮
// ============================================================

// TestPickByLatencyFastest_TieBreakDeterministic：t 并列 → name 字典序；
// 多次调用结果一致（可复现；map 遍历序随机化下仍须稳定）。
func TestPickByLatencyFastest_TieBreakDeterministic(t *testing.T) {
	e := ttftEngine(StrategyLatencyFastest,
		mkEp("beta", 1, 200, true),
		mkEp("alpha", 1, 200, true),
		mkEp("gamma", 1, 200, true),
	)
	for i := 0; i < 200; i++ {
		d := e.pickByLatencyFastest()
		if d.EndpointName != "alpha" || d.Reason != "latency_fastest" {
			t.Fatalf("第 %d 次调用：got %q/%q，want alpha/latency_fastest（tie-break 须确定）",
				i, d.EndpointName, d.Reason)
		}
		if d.Strategy != StrategyLatencyFastest {
			t.Fatalf("Strategy 应回填 latency-fastest（R2-10），got %q", d.Strategy)
		}
	}
}

// TestPickByLatencyFastest_PicksFastestEligible：argmin 生效；无效统计端点退出 TTFT 权。
func TestPickByLatencyFastest_PicksFastestEligible(t *testing.T) {
	e := ttftEngine(StrategyLatencyFastest,
		mkEp("fast", 1, 120, true),
		mkEp("slow", 1, 900, true),
		mkEp("fast-but-invalid", 1, 50, false), // 更快但统计无效 → 不参与
	)
	d := e.pickByLatencyFastest()
	if d.EndpointName != "fast" {
		t.Fatalf("应选有效端点中最快者 fast，got %q/%q", d.EndpointName, d.Reason)
	}
}

// TestPickByLatencyFastest_EmptyAndFailover：TT2-10 空决策 + 组上浮（与 failure-aware 一致）。
func TestPickByLatencyFastest_EmptyAndFailover(t *testing.T) {
	// (a) 最高优先级组全熔断（此处即全部端点）→ 空 Decision
	open1 := mkEp("a", 1, 200, true)
	open1.CircuitBreaker.State = CircuitOpen
	open2 := mkEp("b", 1, 300, true)
	open2.CircuitBreaker.State = CircuitOpen
	e := ttftEngine(StrategyLatencyFastest, open1, open2)
	d := e.pickByLatencyFastest()
	if d.EndpointName != "" || d.Reason != "no_usable_endpoints" {
		t.Fatalf("全熔断应返回空 Decision（TT2-10），got %q/%q", d.EndpointName, d.Reason)
	}

	// (b) 最高优先级组全熔断 + 次优先组可用 → 上浮到次优先组（与 failure-aware 组语义一致）
	dead := mkEp("dead", 1, 100, true)
	dead.CircuitBreaker.State = CircuitOpen
	backup := mkEp("backup", 2, 700, true)
	e2 := ttftEngine(StrategyLatencyFastest, dead, backup)
	d2 := e2.pickByLatencyFastest()
	if d2.EndpointName != "backup" {
		t.Fatalf("次优先组可用时应上浮选取 backup，got %q/%q", d2.EndpointName, d2.Reason)
	}
}

// TestPickByLatencyFastest_SingleUsableAndEligibleOne：单端点优化（TT2-07）与 R2-19 序 4。
func TestPickByLatencyFastest_SingleUsableAndEligibleOne(t *testing.T) {
	// 单可用（统计无效）→ 直接返回（单端点优化同语义）
	recs := ttftWithObserver(t)
	e := ttftEngine(StrategyLatencyFastest, mkEp("solo", 1, 500, false))
	d := e.pickByLatencyFastest()
	if d.EndpointName != "solo" || d.Reason != "latency_single" {
		t.Fatalf("单端点：got %q/%q", d.EndpointName, d.Reason)
	}
	if len(*recs) != 0 {
		t.Fatalf("单端点不应计回退：%v", *recs)
	}

	// E==1 → 等价退单端点 + _low_samples
	e2 := ttftEngine(StrategyLatencyFastest,
		mkEp("valid", 1, 300, true),
		mkEp("invalid", 1, 100, false),
	)
	d2 := e2.pickByLatencyFastest()
	if d2.EndpointName != "valid" || d2.Reason != "latency_single_eligible" {
		t.Fatalf("E==1：got %q/%q", d2.EndpointName, d2.Reason)
	}
	if d2.Strategy != StrategyLatencyFastest {
		t.Fatalf("Strategy=%q，want latency-fastest（R2-10）", d2.Strategy)
	}
	if len(*recs) != 1 || (*recs)[0] != fallbackLowSamples {
		t.Fatalf("回退计数=%v，want [low_samples]", *recs)
	}
}
