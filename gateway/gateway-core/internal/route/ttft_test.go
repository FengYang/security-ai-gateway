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
