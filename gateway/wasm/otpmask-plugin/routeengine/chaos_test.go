package routeengine

// chaos_test.go — P1-6 M6.5：模型抖动混沌测试（SC-1..SC-5；§9.1 / V-8）。
//
// 方法（如实注记）：
//   - 被测对象 = 数据面选路引擎（`routeengine`）。控制面**滑窗聚合**在本文件内以
//     忠实模拟器（`chaosSim`）实现：按刷新周期（cycle）冻结样本、滑窗淘汰、按分位
//     取下发快照——与 §3.3/M3 分片窗口语义一致（T=25s 分片为窗口实现细节，本层按
//     周期粒度建模）。控制面实现本身由 M3 单测覆盖，本层只关心「快照 → 选路」的
//     收敛 / 稳定 / 回退行为。
//   - 随机源 = **固定种子确定性 PRNG**（`math/rand`，种子固定 → 全流程可复现），
//     份额依概率收敛到理论权重；抽样数取 1e4，使 10% 相对偏差判据的余量 > 3σ，
//     避免统计噪声引起断言抖动。
//   - 「窗口」= `window_sec`；「周期」= 统计刷新周期（`ttft_poll_interval_seconds`）。
//   - 理论份额用本包**同源**权函数（`latencyGroupScan/TMin/MaxBase/WeightOf/TotalWeight`）
//     计算，避免测试内重复实现公式而漂移。
//
// 覆盖：SC-1 单端点劣化 / SC-2 周期性抖动 / SC-3 全体劣化 / SC-4 统计中断 / SC-5 单端点变快。

import (
	"math"
	"math/rand"
	"sort"
	"testing"
)

// ============================================================
// 基础设施：确定性随机源 + 滑窗聚合/下发模拟器
// ============================================================

// chaosRand 固定种子确定性 PRNG 随机源（见文件头；种子固定 → 可复现）。
type chaosRand struct{ r *rand.Rand }

func newChaosRand(seed int64) *chaosRand { return &chaosRand{r: rand.New(rand.NewSource(seed))} }

func (r *chaosRand) Float64() (float64, bool) { return r.r.Float64(), true }

// chaosSetRand 注入随机源并在用例结束复位（`randSource` 为进程级接缝）。
func chaosSetRand(t *testing.T, rs RandSource) {
	t.Helper()
	old := randSource
	SetRandSource(rs)
	t.Cleanup(func() { SetRandSource(old) })
}

// chaosQuantile 最近秩分位（升序副本；len<1 返回 0）。
func chaosQuantile(samples []int64, q float64) int64 {
	if len(samples) == 0 {
		return 0
	}
	cp := make([]int64, len(samples))
	copy(cp, samples)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := int(math.Ceil(q*float64(len(cp)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

// chaosSim 控制面滑窗聚合 + 下发模拟器（每周期向引擎写入一份快照）。
type chaosSim struct {
	t               *testing.T
	e               *Engine
	cfg             LatencyConfig
	names           []string
	winCyc          int // 窗口 = winCyc 个刷新周期
	perCycle        int // 每周期每端点样本数
	hist            map[string][]int64
	now             int64
	valid           bool // 下发快照的 Valid 位（SC-4 置 false 模拟中断/陈旧）
	samplesOverride int  // >=0 时覆盖下发 Samples（SC-4）；<0 用窗口样本数
}

func newChaosSim(t *testing.T, names []string, cfg LatencyConfig, winCyc, perCycle int) *chaosSim {
	t.Helper()
	cfg = cfg.normalized()
	eps := make([]EndpointConfig, len(names))
	for i, n := range names {
		eps[i] = EndpointConfig{Name: n, Weight: 1.0 / float64(len(names)), Priority: 1, Enabled: true}
	}
	return &chaosSim{
		t: t, e: NewEngine(Config{Strategy: StrategyLatencyAware, Endpoints: eps, Latency: cfg}),
		cfg: cfg, names: names, winCyc: winCyc, perCycle: perCycle,
		hist: make(map[string][]int64, len(names)), now: 1700000000,
		valid: true, samplesOverride: -1,
	}
}

// step 推进一个刷新周期：各端点按 lat 产出样本 → 入滑窗、淘汰旧样本 → 计算分位并经
// `SetEndpointTTFT` 下发（`now` 按周期递增，保证快照新鲜）。
func (s *chaosSim) step(lat map[string]int64) {
	s.now += 10
	for _, n := range s.names {
		h := s.hist[n]
		for i := 0; i < s.perCycle; i++ {
			h = append(h, lat[n])
		}
		if max := s.winCyc * s.perCycle; len(h) > max {
			h = h[len(h)-max:]
		}
		s.hist[n] = h
		samples := int64(len(h))
		if s.samplesOverride >= 0 {
			samples = int64(s.samplesOverride)
		}
		s.e.SetEndpointTTFT(n, TTFTStat{
			P50Ms:     chaosQuantile(h, 0.50),
			P95Ms:     chaosQuantile(h, 0.95),
			Samples:   samples,
			Valid:     s.valid,
			UpdatedAt: s.now,
			Cache:     "miss",
		})
	}
}

// shares 在当前快照下执行 k 次选路，返回各端点命中次数（空端点立即失败）。
func (s *chaosSim) shares(k int) map[string]int {
	out := make(map[string]int, len(s.names))
	for i := 0; i < k; i++ {
		d := s.e.PickEndpoint()
		if d.EndpointName == "" {
			s.t.Fatalf("SC 选路返回空端点（请求成功率不应下降）")
		}
		out[d.EndpointName]++
	}
	return out
}

func chaosShareOf(counts map[string]int, name string, k int) float64 {
	return float64(counts[name]) / float64(k)
}

// chaosAnalyticShares 用本包同源权函数计算给定快照下的稳态理论份额（含探索占比）。
func chaosAnalyticShares(t *testing.T, cfg LatencyConfig, lat map[string]int64) map[string]float64 {
	t.Helper()
	names := make([]string, 0, len(lat))
	for n := range lat {
		names = append(names, n)
	}
	sort.Strings(names)
	eps := make([]EndpointConfig, len(names))
	for i, n := range names {
		eps[i] = EndpointConfig{Name: n, Weight: 1.0 / float64(len(names)), Priority: 1, Enabled: true}
	}
	e := NewEngine(Config{Strategy: StrategyLatencyAware, Endpoints: eps, Latency: cfg})
	for _, n := range names {
		e.SetEndpointTTFT(n, TTFTStat{P50Ms: lat[n], P95Ms: lat[n], Samples: 1000, Valid: true, UpdatedAt: 1700000000})
	}
	cfgN := cfg.normalized()
	minPrio, usable, _, _ := latencyGroupScan(e.state)
	tMin, _ := latencyGroupTMin(e.state, minPrio, cfgN)
	floor := cfgN.MinWeight * latencyGroupMaxBase(e.state, minPrio, tMin, cfgN)
	total := latencyGroupTotalWeight(e.state, minPrio, tMin, floor, cfgN)
	out := map[string]float64{}
	for _, n := range names {
		for _, ep := range e.state {
			if ep.Name == n && ep.Priority == minPrio && latencyEligible(ep) {
				w := latencyGroupWeightOf(ep, tMin, floor, cfgN)
				out[n] = (1-cfgN.ExploreRatio)*w/total + cfgN.ExploreRatio/float64(usable)
			}
		}
	}
	return out
}

// ============================================================
// SC-1 单端点劣化：A 200ms → 2000ms（阶梯）
// ============================================================

func TestChaos_SC1_SingleEndpointDegradation(t *testing.T) {
	chaosSetRand(t, newChaosRand(20261016))
	cfg := DefaultLatencyConfig()
	cfg.WindowSec = 60 // 1 窗口 = 6 周期（周期 = 10s）
	const winCyc = 6
	sim := newChaosSim(t, []string{"A", "B"}, cfg, winCyc, 50)

	steady := map[string]int64{"A": 200, "B": 200}
	for i := 0; i < winCyc; i++ {
		sim.step(steady)
	}

	degraded := map[string]int64{"A": 2000, "B": 200}
	target := chaosAnalyticShares(t, cfg, degraded)

	const kPicks = 10000
	convCyc := -1
	minShareA := 1.0
	prevShareA := 1.0
	for cyc := 1; cyc <= 4*winCyc; cyc++ {
		sim.step(degraded)
		sa := chaosShareOf(sim.shares(kPicks), "A", kPicks)
		if sa < minShareA {
			minShareA = sa
		}
		if sa > prevShareA+0.05 {
			t.Fatalf("SC-1 A 份额不应回升（单调收敛）：cyc=%d %.4f → %.4f", cyc, prevShareA, sa)
		}
		prevShareA = sa
		if math.Abs(sa-target["A"])/target["A"] < 0.10 && convCyc < 0 {
			convCyc = cyc
		}
	}
	if convCyc < 0 {
		t.Fatalf("SC-1 未在 %d 周期内收敛到目标 %.4f", 4*winCyc, target["A"])
	}
	if convCyc > 2*winCyc {
		t.Fatalf("SC-1 收敛超期：%d 周期 > 2×窗口(%d)", convCyc, 2*winCyc)
	}
	if minShareA <= 0 {
		t.Fatalf("SC-1 端点 A 出现 0 流量（min_weight 相对下界失效）：min share=%.4f", minShareA)
	}
	t.Logf("SC-1 通过：A 目标份额 %.4f，收敛 %d 周期（≤2×窗口=%d），最小份额 %.4f（无 0 流量）",
		target["A"], convCyc, 2*winCyc, minShareA)
}

// ============================================================
// SC-2 周期性抖动：B 每 60s 在 150ms ↔ 1500ms 抖动
// ============================================================

func TestChaos_SC2_PeriodicJitter(t *testing.T) {
	chaosSetRand(t, newChaosRand(20261016))
	cfg := DefaultLatencyConfig()
	cfg.WindowSec = 300 // 1 窗口 = 30 周期（周期 = 10s）
	const winCyc = 30
	const periodCyc = 6 // 60s 抖动周期
	sim := newChaosSim(t, []string{"A", "B"}, cfg, winCyc, 50)

	latAt := func(cyc int) map[string]int64 {
		b := int64(1500)
		if (cyc/periodCyc)%2 == 1 {
			b = 150
		}
		return map[string]int64{"A": 200, "B": b}
	}
	for i := 0; i < winCyc; i++ { // 预热填满窗口
		sim.step(latAt(i))
	}

	const kPicks = 10000
	var maxB, minB, maxA = 0.0, 1.0, 0.0
	for cyc := 0; cyc < 5*periodCyc; cyc++ {
		sim.step(latAt(winCyc + cyc))
		counts := sim.shares(kPicks)
		sb := chaosShareOf(counts, "B", kPicks)
		sa := chaosShareOf(counts, "A", kPicks)
		if sb > maxB {
			maxB = sb
		}
		if sb < minB {
			minB = sb
		}
		if sa > maxA {
			maxA = sa
		}
		if sb <= 0 {
			t.Fatalf("SC-2 端点 B 被打满至 0 流量（探索未生效）：cyc=%d", cyc)
		}
	}
	amp := (maxB - minB) / maxB
	if amp >= 0.30 {
		t.Fatalf("SC-2 权重振荡超阈：振幅 %.2f >= 0.30（窗口应抑制 <1 窗口的周期抖动）", amp)
	}
	if maxA >= 1.0 {
		t.Fatalf("SC-2 端点 A 被打满（探索未生效）：maxA=%.4f", maxA)
	}
	t.Logf("SC-2 通过：B 份额振幅 %.4f < 0.30（max=%.4f min=%.4f）；A 最大份额 %.4f < 1（探索生效）",
		amp, maxB, minB, maxA)
}

// ============================================================
// SC-3 全体劣化：A、B 同时 200ms → 1500ms
// ============================================================

func TestChaos_SC3_GlobalDegradation(t *testing.T) {
	chaosSetRand(t, newChaosRand(20261016))
	cfg := DefaultLatencyConfig()
	cfg.WindowSec = 60
	const winCyc = 6
	sim := newChaosSim(t, []string{"A", "B"}, cfg, winCyc, 50)

	steady := map[string]int64{"A": 200, "B": 200}
	for i := 0; i < winCyc; i++ {
		sim.step(steady)
	}

	degraded := map[string]int64{"A": 1500, "B": 1500}
	const kPicks = 10000
	for cyc := 1; cyc <= 2*winCyc; cyc++ {
		sim.step(degraded)
		counts := sim.shares(kPicks)
		sa := chaosShareOf(counts, "A", kPicks)
		sb := chaosShareOf(counts, "B", kPicks)
		// 不雪崩：等量劣化下份额保持均衡，无端点吸收全部流量。
		if sa < 0.40 || sa > 0.60 || sb < 0.40 || sb > 0.60 {
			t.Fatalf("SC-3 份额失衡（雪崩）：cyc=%d A=%.4f B=%.4f", cyc, sa, sb)
		}
		// 不误熔断（C-2）：仅 TTFT 劣化不应触发熔断。
		for _, es := range sim.e.Snapshot().Endpoints {
			if es.CircuitState != CircuitClosed {
				t.Fatalf("SC-3 误熔断（C-2）：端点 %s 熔断状态=%v", es.Name, es.CircuitState)
			}
		}
	}

	// 恢复：劣化消退 → 份额回归（偏差 < 10%）。
	recovered := map[string]int64{"A": 200, "B": 200}
	target := chaosAnalyticShares(t, cfg, recovered)
	convCyc := -1
	for cyc := 1; cyc <= 2*winCyc; cyc++ {
		sim.step(recovered)
		sa := chaosShareOf(sim.shares(kPicks), "A", kPicks)
		if math.Abs(sa-target["A"])/target["A"] < 0.10 && convCyc < 0 {
			convCyc = cyc
		}
	}
	if convCyc < 0 {
		t.Fatalf("SC-3 恢复未在 %d 周期内回归（目标 %.4f）", 2*winCyc, target["A"])
	}
	t.Logf("SC-3 通过：等量劣化份额均衡（[0.40,0.60]）；无熔断；恢复回归 %d 周期", convCyc)
}

// ============================================================
// SC-4 统计中断：停止上报 / 控制面不可达 / 随机源耗尽
// ============================================================

func TestChaos_SC4_StatsOutage(t *testing.T) {
	reasons := map[string]int{}
	oldObs := latencyFallbackObserver
	SetLatencyFallbackObserver(func(r string) { reasons[r]++ })
	t.Cleanup(func() { SetLatencyFallbackObserver(oldObs) })

	cfg := DefaultLatencyConfig()
	cfg.WindowSec = 60
	const winCyc = 6
	sim := newChaosSim(t, []string{"A", "B"}, cfg, winCyc, 50)
	steady := map[string]int64{"A": 200, "B": 200}
	for i := 0; i < winCyc; i++ {
		sim.step(steady)
	}

	// (1) 控制面不可达 → unreachable（R2-19 序 1）。
	sim.valid = false
	sim.e.SetTTFTStatsUnreachable(true)
	sim.step(steady)
	reasons = map[string]int{}
	for i := 0; i < 20; i++ {
		if d := sim.e.PickEndpoint(); d.EndpointName == "" {
			t.Fatal("SC-4[unreachable] 选路返回空端点")
		}
	}
	if reasons[fallbackUnreachable] == 0 {
		t.Fatalf("SC-4 控制面不可达未按 unreachable 回退：%v", reasons)
	}

	// (2) 陈旧（样本充足但 Valid=false）→ stale（R2-19 序 2）。
	sim.e.SetTTFTStatsUnreachable(false)
	sim.samplesOverride = 500
	sim.step(steady)
	reasons = map[string]int{}
	for i := 0; i < 20; i++ {
		if d := sim.e.PickEndpoint(); d.EndpointName == "" {
			t.Fatal("SC-4[stale] 选路返回空端点")
		}
	}
	if reasons[fallbackStale] == 0 {
		t.Fatalf("SC-4 陈旧统计未按 stale 回退：%v", reasons)
	}

	// (3) 样本不足 → low_samples（R2-19 序 3/4）。
	sim.samplesOverride = 5
	sim.step(steady)
	reasons = map[string]int{}
	for i := 0; i < 20; i++ {
		if d := sim.e.PickEndpoint(); d.EndpointName == "" {
			t.Fatal("SC-4[low_samples] 选路返回空端点")
		}
	}
	if reasons[fallbackLowSamples] == 0 {
		t.Fatalf("SC-4 样本不足未按 low_samples 回退：%v", reasons)
	}

	// (4) 全无样本 → no_samples（非流式流量常态）。
	sim.samplesOverride = 0
	sim.step(steady)
	reasons = map[string]int{}
	for i := 0; i < 20; i++ {
		if d := sim.e.PickEndpoint(); d.EndpointName == "" {
			t.Fatal("SC-4[no_samples] 选路返回空端点")
		}
	}
	if reasons[fallbackNoSamples] == 0 {
		t.Fatalf("SC-4 全无样本未按 no_samples 回退：%v", reasons)
	}

	// (5) 随机源耗尽 → no_rand 确定性回退（§3.5）。
	sim.valid = true
	sim.samplesOverride = -1
	sim.step(steady)
	chaosSetRand(t, nil) // 随机源不可用
	reasons = map[string]int{}
	var fallbackFastest int
	for i := 0; i < 20; i++ {
		d := sim.e.PickEndpoint()
		if d.EndpointName == "" {
			t.Fatal("SC-4[no_rand] 选路返回空端点")
		}
		if d.Reason == "latency_fallback_fastest" {
			fallbackFastest++
		}
	}
	if reasons[fallbackNoRand] != 20 || fallbackFastest != 20 {
		t.Fatalf("SC-4 随机源耗尽未按 no_rand 确定性回退：reasons=%v reason 计数=%d", reasons, fallbackFastest)
	}
	t.Log("SC-4 通过：unreachable / stale / low_samples / no_samples / no_rand 五原因均按 R2-19 序回退，成功率不变")
}

// ============================================================
// SC-5 单端点变快：A 2000ms → 200ms（骤降）
// ============================================================

func TestChaos_SC5_EndpointImproves(t *testing.T) {
	chaosSetRand(t, newChaosRand(20261016))
	cfg := DefaultLatencyConfig()
	cfg.WindowSec = 60
	const winCyc = 6
	sim := newChaosSim(t, []string{"A", "B"}, cfg, winCyc, 50)

	slow := map[string]int64{"A": 2000, "B": 200}
	for i := 0; i < winCyc; i++ {
		sim.step(slow)
	}

	improved := map[string]int64{"A": 200, "B": 200}
	target := chaosAnalyticShares(t, cfg, improved)

	const kPicks = 10000
	before := chaosShareOf(sim.shares(kPicks), "A", kPicks) // 变快前 A 份额（应低）
	sim.step(improved)
	first := chaosShareOf(sim.shares(kPicks), "A", kPicks)
	if first >= 0.90 {
		t.Fatalf("SC-5 出现流量瞬间全迁（探索/相对下界失效）：首周期 A=%.4f", first)
	}
	convCyc := -1
	shareAtConv := 0.0
	for cyc := 2; cyc <= 2*winCyc; cyc++ {
		sim.step(improved)
		counts := sim.shares(kPicks)
		sa := chaosShareOf(counts, "A", kPicks)
		if chaosShareOf(counts, "B", kPicks) <= 0 {
			t.Fatalf("SC-5 端点 B 被打满至 0 流量（探索未生效）：cyc=%d", cyc)
		}
		if math.Abs(sa-target["A"])/target["A"] < 0.10 && convCyc < 0 {
			convCyc, shareAtConv = cyc, sa
		}
	}
	if convCyc < 0 || convCyc > 2*winCyc {
		t.Fatalf("SC-5 A 权重未在 2 窗口内上升至目标：convCyc=%d 目标=%.4f", convCyc, target["A"])
	}
	if shareAtConv <= before+0.05 {
		t.Fatalf("SC-5 变快后 A 份额未显著上升：before=%.4f conv=%.4f", before, shareAtConv)
	}
	t.Logf("SC-5 通过：A 份额 %.4f → %.4f（目标 %.4f），收敛 %d 周期（≤2×窗口=%d）；无瞬间全迁（首周期 %.4f < 0.90）",
		before, shareAtConv, target["A"], convCyc, 2*winCyc, first)
}
