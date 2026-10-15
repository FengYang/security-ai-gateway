package route

// ttft_test.go — P1-6 M3.1：分片环形聚合器用例（滑动/淘汰/无流量失效，TT2-02/§3.4）。

import "testing"

// fakeClock 返回可推进的伪时钟（秒级）。
func fakeClock(t0 int64) (func() int64, func(int64)) {
	now := t0
	return func() int64 { return now }, func(d int64) { now += d }
}

func bk(vals ...int) *[TTFTBucketCount]uint64 {
	var b [TTFTBucketCount]uint64
	for i, v := range vals {
		b[i] = uint64(v)
	}
	return &b
}

func sumWindow(w TTFTWindow) uint64 {
	var s uint64
	for _, v := range w.Buckets {
		s += v
	}
	return s
}

// TestTTFTRing_LandAndMerge：同分片批量累加（桶求和 + samples + updated_at 取最大）。
func TestTTFTRing_LandAndMerge(t *testing.T) {
	const t0 = int64(1760000000) // 25s 整边界
	now, _ := fakeClock(t0 + 25)
	r := NewTTFTRing(now)
	k := TTFTKey{Tenant: "t-001", Model: "qwen-max", Endpoint: "tee-gpu-a", Cache: "miss"}

	r.Record(k, bk(1, 2, 3), t0+10, 300)
	r.Record(k, bk(4, 0, 1), t0+20, 300) // 同分片（[t0,t0+25)）
	w, ok := r.Merge(k)
	if !ok {
		t.Fatal("键应存在")
	}
	if w.Buckets[0] != 5 || w.Buckets[1] != 2 || w.Buckets[2] != 4 {
		t.Fatalf("桶求和不符：%v", w.Buckets)
	}
	if w.Samples != 11 || sumWindow(w) != 11 {
		t.Fatalf("samples 应=11，got %d（Σ桶=%d）", w.Samples, sumWindow(w))
	}
	if w.UpdatedAt != t0+20 {
		t.Fatalf("updated_at 应取最大 reported_at，got %d", w.UpdatedAt)
	}
	if got := w.Buckets[10]; got != 0 {
		t.Fatalf("未写桶应为 0，got %d", got)
	}
}

// TestTTFTRing_WindowSlidingEvicts：时间驱动淘汰逐分片滑出（非上报驱动）。
func TestTTFTRing_WindowSlidingEvicts(t *testing.T) {
	const t0 = int64(1760000000)
	now, advance := fakeClock(t0 + 60)
	r := NewTTFTRing(now)
	k := TTFTKey{Tenant: "t", Model: "m", Endpoint: "ep", Cache: "miss"}

	// window=75 → N=3；三批分别落 shard0(t0)/shard1(t0+25)/shard2(t0+50)
	r.Record(k, bk(10), t0+10, 75)
	r.Record(k, bk(20), t0+35, 75)
	r.Record(k, bk(40), t0+60, 75)

	w, _ := r.Merge(k)
	if w.Samples != 70 {
		t.Fatalf("全窗口 samples 应=70，got %d", w.Samples)
	}

	// now=t0+76 → cut=t0+1：shard0（t0）淘汰，shard1/2 保留
	advance(16)
	w, _ = r.Merge(k)
	if w.Samples != 60 {
		t.Fatalf("shard0 淘汰后 samples 应=60，got %d（%v）", w.Samples, w.Buckets)
	}

	// now=t0+101 → cut=t0+26：shard1（t0+25）淘汰，shard2 保留
	advance(25)
	w, _ = r.Merge(k)
	if w.Samples != 40 {
		t.Fatalf("shard1 淘汰后 samples 应=40，got %d（%v）", w.Samples, w.Buckets)
	}

	// now=t0+126 → cut=t0+51：shard2（t0+50）淘汰 → 空窗
	advance(25)
	w, _ = r.Merge(k)
	if w.Samples != 0 {
		t.Fatalf("全部淘汰后 samples 应=0，got %d", w.Samples)
	}
}

// TestTTFTRing_NoTrafficAutoInvalidation：无流量端点样本随时间归零（TT2-02，防统计粘滞）。
func TestTTFTRing_NoTrafficAutoInvalidation(t *testing.T) {
	const t0 = int64(1760000000)
	now, advance := fakeClock(t0 + 20)
	r := NewTTFTRing(now)
	k := TTFTKey{Tenant: "t", Model: "m", Endpoint: "ep", Cache: "miss"}

	r.Record(k, bk(30), t0+10, 300)
	w, _ := r.Merge(k)
	if w.Samples != 30 {
		t.Fatalf("有流量时 samples 应=30，got %d", w.Samples)
	}

	// 超过总窗口（300s）无新样本 → 分片全部滑出
	advance(500)
	w, ok := r.Merge(k)
	if !ok {
		t.Fatal("条目应仍存在（空壳），以便 stale 判定读取 updated_at")
	}
	if w.Samples != 0 {
		t.Fatalf("无流量超窗后 samples 应=0，got %d", w.Samples)
	}
	if w.UpdatedAt != t0+10 {
		t.Fatalf("updated_at 应保留最近样本时间（供 stale 判定），got %d", w.UpdatedAt)
	}
}

// TestTTFTRing_IndexReuseNoGhost：同一分片索引在新周期复用时不混入旧计数。
func TestTTFTRing_IndexReuseNoGhost(t *testing.T) {
	const t0 = int64(1760000000)
	now, advance := fakeClock(t0 + 10)
	r := NewTTFTRing(now)
	k := TTFTKey{Tenant: "t", Model: "m", Endpoint: "ep", Cache: "miss"}

	r.Record(k, bk(5), t0+10, 300) // 落 shard idx=(t0/25)%12
	advance(410)                   // now=t0+420，旧分片（t0）已超窗
	r.Record(k, bk(7), t0+410, 300)
	w, _ := r.Merge(k)
	if w.Samples != 7 {
		t.Fatalf("索引复用后 samples 应=7（无幽灵累加），got %d（%v）", w.Samples, w.Buckets)
	}
	if w.UpdatedAt != t0+410 {
		t.Fatalf("updated_at 应为新批次时间，got %d", w.UpdatedAt)
	}
}

// TestTTFTRing_WindowChangeRebuilds：窗口配置变化 → 条目重建（统计清零，避免新旧窗口混算）。
func TestTTFTRing_WindowChangeRebuilds(t *testing.T) {
	const t0 = int64(1760000000)
	now, _ := fakeClock(t0 + 30)
	r := NewTTFTRing(now)
	k := TTFTKey{Tenant: "t", Model: "m", Endpoint: "ep", Cache: "miss"}

	r.Record(k, bk(9), t0+10, 300)
	r.Record(k, bk(3), t0+20, 60) // 窗口变更 → 重建
	w, _ := r.Merge(k)
	if w.Samples != 3 {
		t.Fatalf("窗口变更后应仅保留新批次，got %d", w.Samples)
	}
	if w.UpdatedAt != t0+20 {
		t.Fatalf("重建后 updated_at 应为新批次时间，got %d", w.UpdatedAt)
	}
}

// TestTTFTRing_StaleLandingDoesNotWipe：边界旧批次（同索引、更旧分片起点，已列淘汰线）丢弃且不破坏在窗数据。
func TestTTFTRing_StaleLandingDoesNotWipe(t *testing.T) {
	const t0 = int64(1760000000)
	now, _ := fakeClock(t0 + 10)
	r := NewTTFTRing(now)
	k := TTFTKey{Tenant: "t", Model: "m", Endpoint: "ep", Cache: "miss"}

	r.Record(k, bk(5), t0+10, 300) // 当前分片（idx 8，start t0）
	// 同索引更旧批次：start = t0-300（idx 8），其分片起点已 ≤ 淘汰线（now-300 = t0-290）
	if got := r.Record(k, bk(9), t0-290, 300); got != TTFTIngestStale {
		t.Fatalf("边界旧批次应 Stale（已受理但边界丢弃），got %v", got)
	}
	w, _ := r.Merge(k)
	if w.Samples != 5 {
		t.Fatalf("在窗数据不得被覆写/叠加，got samples=%d", w.Samples)
	}
	if w.UpdatedAt != t0+10 {
		t.Fatalf("updated_at 不应被边界旧批次推进，got %d", w.UpdatedAt)
	}
}

// TestTTFTRing_Reset：重置清空且二次重置返回 false。
func TestTTFTRing_Reset(t *testing.T) {
	const t0 = int64(1760000000)
	now, _ := fakeClock(t0 + 10)
	r := NewTTFTRing(now)
	k := TTFTKey{Tenant: "t", Model: "m", Endpoint: "ep", Cache: "miss"}

	if r.Reset(k) {
		t.Fatal("未存在条目 reset 应返回 false")
	}
	r.Record(k, bk(4), t0+5, 300)
	if !r.Reset(k) {
		t.Fatal("已存在条目 reset 应返回 true")
	}
	if _, ok := r.Merge(k); ok {
		t.Fatal("reset 后条目应不存在")
	}
}

// TestNormalizeWindow：窗口归一化与分片数（§3.4 参数联动，R2-08）。
func TestNormalizeWindow(t *testing.T) {
	cases := []struct {
		in         int
		wantWin    int
		wantShards int
	}{
		{0, 300, 12}, {24, 300, 12}, {25, 25, 1}, {60, 60, 3}, {61, 61, 3},
		{300, 300, 12}, {301, 301, 13}, {3600, 3600, 144}, {3700, 3600, 144},
	}
	for _, c := range cases {
		win, n := normalizeWindow(c.in)
		if win != c.wantWin || n != c.wantShards {
			t.Errorf("normalizeWindow(%d)=(%d,%d)，期望 (%d,%d)", c.in, win, n, c.wantWin, c.wantShards)
		}
	}
}

// TestTTFTRing_MergeUnknownKey：未记录键 Merge 返回 ok=false 与零值。
func TestTTFTRing_MergeUnknownKey(t *testing.T) {
	r := NewTTFTRing(func() int64 { return 1760000000 })
	w, ok := r.Merge(TTFTKey{Tenant: "x"})
	if ok || w.Samples != 0 || w.UpdatedAt != 0 {
		t.Fatalf("未知键应 (零值,false)，got (%+v,%v)", w, ok)
	}
	// nil 桶 / 非法 reported_at 忽略
	r.Record(TTFTKey{Tenant: "x"}, nil, 1760000000, 300)
	r.Record(TTFTKey{Tenant: "x"}, bk(1), 0, 300)
	if _, ok := r.Merge(TTFTKey{Tenant: "x"}); ok {
		t.Fatal("非法输入不应创建条目")
	}
}

// ============================================================
// M3.2 分位插值（桶内线性；排序一致性口径，§3.4）
// ============================================================

// bucketize 测试辅助：按 le 语义（上界含；>30000 归末桶）将样本值分桶。
func bucketize(vals []int64) *[TTFTBucketCount]uint64 {
	var b [TTFTBucketCount]uint64
	for _, v := range vals {
		idx := TTFTBucketCount - 1
		for i := 0; i < TTFTBucketCount; i++ {
			if v <= TTFTBucketUpperMs[i] {
				idx = i
				break
			}
		}
		b[idx]++
	}
	return &b
}

// TestTTFTWindow_QuantileBasic：跨桶插值解析值 + 单调性（p95 ≥ p50）。
func TestTTFTWindow_QuantileBasic(t *testing.T) {
	var w TTFTWindow
	w.Buckets[0], w.Buckets[1], w.Buckets[2] = 100, 100, 100
	w.Samples = 300
	// p50：target=150 → 桶(10,25]：10 + 15×(150-100)/100 = 17.5 → 18
	p50, ok := w.Quantile(0.5)
	if !ok || p50 != 18 {
		t.Fatalf("p50 应=18，got (%d,%v)", p50, ok)
	}
	// p95：target=285 → 桶(25,50]：25 + 25×(285-200)/100 = 46.25 → 46
	p95, ok := w.Quantile(0.95)
	if !ok || p95 != 46 {
		t.Fatalf("p95 应=46，got (%d,%v)", p95, ok)
	}
	if p95 < p50 {
		t.Fatalf("单调性破坏：p95=%d < p50=%d", p95, p50)
	}
}

// TestTTFTWindow_QuantileBoundaries：单桶内插值区间、q=1、空窗/越界及 le 边界分桶。
func TestTTFTWindow_QuantileBoundaries(t *testing.T) {
	// 全样本落单桶 (100,250]（idx4）：插值必须落在桶区间内
	var w TTFTWindow
	w.Buckets[4] = 10
	w.Samples = 10
	p50, ok := w.Quantile(0.5) // 100 + 150×0.5 = 175
	if !ok || p50 != 175 {
		t.Fatalf("单桶 p50 应=175，got (%d,%v)", p50, ok)
	}
	p95, ok := w.Quantile(0.95) // 100 + 150×0.95 = 242.5 → 243
	if !ok || p95 != 243 {
		t.Fatalf("单桶 p95 应=243，got (%d,%v)", p95, ok)
	}
	p100, ok := w.Quantile(1.0) // 桶上界 250
	if !ok || p100 != 250 {
		t.Fatalf("q=1 应=桶上界 250，got (%d,%v)", p100, ok)
	}
	// 空窗口 / q 越界
	var e TTFTWindow
	if _, ok := e.Quantile(0.5); ok {
		t.Fatal("空窗口应 ok=false")
	}
	if _, ok := w.Quantile(0); ok {
		t.Fatal("q=0 应 ok=false")
	}
	if _, ok := w.Quantile(1.5); ok {
		t.Fatal("q>1 应 ok=false")
	}
	// le 边界分桶语义：10→首桶；11/25→(10,25]；25000/99999（>30000 归末桶）
	b := bucketize([]int64{10, 11, 25, 25000, 30000, 99999})
	if b[0] != 1 || b[1] != 2 || b[10] != 3 {
		t.Fatalf("le 边界分桶不符：%v", b)
	}
}

// TestTTFTWindow_QuantileSortConsistency：与全量排序的**排序一致性**（§3.4 精度口径；TT2-04，
// 不做 100% 排序断言）：三端点 P95 分属不同桶时，插值序必须与真实序一致。
func TestTTFTWindow_QuantileSortConsistency(t *testing.T) {
	rep := func(v int64, n int) []int64 {
		s := make([]int64, n)
		for i := range s {
			s[i] = v
		}
		return s
	}
	cases := []struct {
		name string
		vals []int64
		want int64 // 桶内插值解析值（与真实值同序）
	}{
		{"ep-a(20ms→桶(10,25])", rep(20, 50), 24},      // 10+15×0.95=24.25→24
		{"ep-c(200ms→桶(100,250])", rep(200, 50), 243}, // 100+150×0.95=242.5→243
		{"ep-b(400ms→桶(250,500])", rep(400, 50), 488}, // 250+250×0.95=487.5→488
	}
	prev := int64(-1)
	prevName := ""
	for _, c := range cases {
		b := bucketize(c.vals)
		var w TTFTWindow
		w.Buckets = *b
		w.Samples = uint64(len(c.vals))
		p95, ok := w.Quantile(0.95)
		if !ok || p95 != c.want {
			t.Fatalf("%s：p95 应=%d，got (%d,%v)", c.name, c.want, p95, ok)
		}
		if p95 <= prev {
			t.Fatalf("排序一致性破坏：%s(%d) 应大于前序 %s(%d)", c.name, p95, prevName, prev)
		}
		prev, prevName = p95, c.name
	}
}

// TestTTFTWindow_QuantileMixedWindow：多桶混合下 p50/p95 解析值（含累积路径）。
func TestTTFTWindow_QuantileMixedWindow(t *testing.T) {
	// 40 样本：idx0(≤10)×8、idx2(≤50)×24、idx6(≤1000)×8
	var w TTFTWindow
	w.Buckets[0], w.Buckets[2], w.Buckets[6] = 8, 24, 8
	w.Samples = 40
	// p50：target=20；桶2 累积 8+24=32≥20：(25,50] 内 25 + 25×(20-8)/24 = 25+12.5 = 37.5 → 38
	p50, _ := w.Quantile(0.5)
	if p50 != 38 {
		t.Fatalf("p50 应=38，got %d", p50)
	}
	// p95：target=38；桶6 累积 40≥38：(500,1000] 内 500 + 500×(38-32)/8 = 500+375 = 875
	p95, _ := w.Quantile(0.95)
	if p95 != 875 {
		t.Fatalf("p95 应=875，got %d", p95)
	}
}
