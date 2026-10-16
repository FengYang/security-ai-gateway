package route

// ttftguard_test.go — P1-6 M3.3：去重 + 值域钳制 + 白名单 + 内存上限（TT2-03/TT2-08）。

import "testing"

// TestTTFTRing_EntryLimit：条目数上限只拦新增键；既有键不受影响；释放后可再增。
func TestTTFTRing_EntryLimit(t *testing.T) {
	const t0 = int64(1760000000)
	now, _ := fakeClock(t0 + 10)
	r := NewTTFTRingWithLimit(now, 2)
	k1 := TTFTKey{Tenant: "t", Model: "m", Endpoint: "ep-1", Cache: "miss"}
	k2 := TTFTKey{Tenant: "t", Model: "m", Endpoint: "ep-2", Cache: "miss"}
	k3 := TTFTKey{Tenant: "t", Model: "m", Endpoint: "ep-3", Cache: "miss"}

	if got := r.Record(k1, bk(1), t0+5, 300); got != TTFTIngestOK {
		t.Fatalf("k1 应 OK，got %v", got)
	}
	if got := r.Record(k2, bk(1), t0+5, 300); got != TTFTIngestOK {
		t.Fatalf("k2 应 OK，got %v", got)
	}
	if got := r.Record(k3, bk(1), t0+5, 300); got != TTFTIngestEntryLimit {
		t.Fatalf("k3 超限应被拒，got %v", got)
	}
	if _, ok := r.Merge(k3); ok {
		t.Fatal("被拒键不应创建条目")
	}
	// 既有键照常落片
	if got := r.Record(k1, bk(2), t0+6, 300); got != TTFTIngestOK {
		t.Fatalf("既有键应不受上限影响，got %v", got)
	}
	// 释放后新键可入
	r.Reset(k1)
	if got := r.Record(k3, bk(1), t0+7, 300); got != TTFTIngestOK {
		t.Fatalf("释放后 k3 应 OK，got %v", got)
	}
	// 非法输入 → Invalid
	if got := r.Record(k1, nil, t0, 300); got != TTFTIngestInvalid {
		t.Fatalf("nil 桶应 Invalid，got %v", got)
	}
	if got := r.Record(k1, bk(1), 0, 300); got != TTFTIngestInvalid {
		t.Fatalf("reported_at=0 应 Invalid，got %v", got)
	}
}

// TestTTFTDedup_SeenAndTTL：首见 false / 重复 true / 过期后可再登记。
func TestTTFTDedup_SeenAndTTL(t *testing.T) {
	const t0 = int64(1760000000)
	d := NewTTFTDedupWithLimit(10, 300)
	if d.Seen("envoy-0|2|1760000000", t0) {
		t.Fatal("首见应 false")
	}
	if !d.Seen("envoy-0|2|1760000000", t0+5) {
		t.Fatal("重复应 true（未过期）")
	}
	if d.Seen("envoy-0|2|1760000010", t0+5) {
		t.Fatal("不同 batch_id 应 false")
	}
	if d.Seen("envoy-0|2|1760000000", t0+301) {
		t.Fatal("TTL 过期后应可再登记（false）")
	}
	if d.Seen("", t0) {
		t.Fatal("空 batch_id 应 false（不参与去重）")
	}
}

// TestTTFTDedup_CapacityEvictsOldest：容量超限 FIFO 淘汰最旧。
func TestTTFTDedup_CapacityEvictsOldest(t *testing.T) {
	const t0 = int64(1760000000)
	d := NewTTFTDedupWithLimit(2, 300)
	d.Seen("a", t0)
	d.Seen("b", t0)
	d.Seen("c", t0) // 超限 → 淘汰 a
	if !d.Seen("b", t0+1) {
		t.Fatal("b 应仍在去重集合")
	}
	if !d.Seen("c", t0+1) {
		t.Fatal("c 应仍在去重集合")
	}
	if d.Seen("a", t0+1) {
		t.Fatal("a 已被 FIFO 淘汰，应 false")
	}
}

// TestValidateTTFTBucketCounts：单桶上限（边界含等式）。
func TestValidateTTFTBucketCounts(t *testing.T) {
	ok := bk(0, 1, int(TTFTMaxBucketCount))
	if err := ValidateTTFTBucketCounts(ok); err != nil {
		t.Fatalf("边界值应通过：%v", err)
	}
	over := bk(int(TTFTMaxBucketCount) + 1)
	if err := ValidateTTFTBucketCounts(over); err == nil {
		t.Fatal("超单桶上限应报错")
	}
	if err := ValidateTTFTBucketCounts(nil); err == nil {
		t.Fatal("nil 桶应报错")
	}
}

// TestValidateTTFTBatchTotal：单批总样本上限。
func TestValidateTTFTBatchTotal(t *testing.T) {
	if err := ValidateTTFTBatchTotal(TTFTMaxBatchSamples); err != nil {
		t.Fatalf("边界值应通过：%v", err)
	}
	if err := ValidateTTFTBatchTotal(TTFTMaxBatchSamples + 1); err == nil {
		t.Fatal("超上限应报错")
	}
}

// TestTTFTReportedAtInWindow：reported_at 时间窗（回退 ≤ window；超前 ≤ 25s）。
func TestTTFTReportedAtInWindow(t *testing.T) {
	const t0 = int64(1760000000)
	cases := []struct {
		reportedAt int64
		window     int
		want       bool
	}{
		{t0, 300, true},
		{t0 - 300, 300, true},  // 边界（含）
		{t0 - 301, 300, false}, // 越窗（过旧）
		{t0 + 25, 300, true},   // 超前容忍边界（含）
		{t0 + 26, 300, false},  // 超前越限
		{0, 300, false},        // 非法
		{t0 - 100, 0, true},    // 窗口非法 → 归一化缺省 300
		{t0 - 100, 60, false},  // 小窗口下越窗
	}
	for _, c := range cases {
		if got := TTFTReportedAtInWindow(c.reportedAt, t0, c.window); got != c.want {
			t.Errorf("TTFTReportedAtInWindow(%d, %d, %d)=%v，期望 %v", c.reportedAt, t0, c.window, got, c.want)
		}
	}
}

// TestRouteTable_KnowsEndpoint：白名单（命中路由 + 端点名属集合；v1 无端点条目不构成合法来源）。
func TestRouteTable_KnowsEndpoint(t *testing.T) {
	tbl := &RouteTable{Routes: []TableRoute{
		{
			Tenant: "t", Model: "m", DefaultEngine: "cmaas",
			Endpoints: []TableEndpoint{
				{Name: "ep-a", URL: "https://a/v1", Weight: 1, Priority: 1, Enabled: true},
				{Name: "ep-b", URL: "https://b/v1", Weight: 0, Priority: 2}, // 未启用亦属已知集合
			},
		},
		{Tenant: "t2", Model: "m2", DefaultEngine: "cmaas"}, // v1 二元模式（无端点）
	}}
	cases := []struct {
		tenant, model, endpoint string
		want                    bool
	}{
		{"t", "m", "ep-a", true},
		{"t", "m", "ep-b", true},
		{"t", "m", "ghost", false},
		{"t", "unknown", "ep-a", false},
		{"t2", "m2", "ep-x", false},
		{"t", "m", "", false},
	}
	for _, c := range cases {
		if got := tbl.KnowsEndpoint(c.tenant, c.model, c.endpoint); got != c.want {
			t.Errorf("KnowsEndpoint(%q,%q,%q)=%v，期望 %v", c.tenant, c.model, c.endpoint, got, c.want)
		}
	}
	var nilTbl *RouteTable
	if nilTbl.KnowsEndpoint("t", "m", "ep-a") {
		t.Fatal("nil 表应 false")
	}
}
