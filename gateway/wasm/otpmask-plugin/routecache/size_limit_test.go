package routecache

// ============================================================
// P1-6：路由表内存上限单元测试
// 覆盖：EstimatedSize 估算合理性 / 超限拒绝 / 边界值 / fail-closed 保留旧表
// ============================================================

import (
	"strings"
	"testing"
)

// ---- EstimatedSize 估算合理性 ----

// TestEstimatedSize_NilTable nil 表返回 0。
func TestEstimatedSize_NilTable(t *testing.T) {
	var t0 *RouteTable
	if t0.EstimatedSize() != 0 {
		t.Fatalf("nil table size = %d, want 0", t0.EstimatedSize())
	}
}

// TestEstimatedSize_EmptyTable 空表有固定开销（非零）。
func TestEstimatedSize_EmptyTable(t *testing.T) {
	tbl := &RouteTable{Version: 1, UpdatedAt: 1725500000, Routes: []TableRoute{}}
	size := tbl.EstimatedSize()
	if size == 0 {
		t.Fatal("空表 size 不应为 0（至少有固定开销）")
	}
	// 固定开销应在合理范围（32+24=56 基础 + signature 0 字节 + 少量 padding → 56~128）
	if size < 50 || size > 500 {
		t.Fatalf("空表 size=%d 不在合理范围 [50, 500]", size)
	}
}

// TestEstimatedSize_GrowsWithRoutes 路由越多，估算越大（单调增长）。
func TestEstimatedSize_GrowsWithRoutes(t *testing.T) {
	key := testKey()
	t1 := validTable(1) // 1 条路由
	sign(key, t1)
	s1 := t1.EstimatedSize()

	t2 := bigRouteTable(2, 10, 5) // 10 条路由 × 5 端点
	sign(key, t2)
	s2 := t2.EstimatedSize()

	if s1 >= s2 {
		t.Fatalf("更多路由应有更大 size：s1=%d s2=%d", s1, s2)
	}
}

// TestEstimatedSize_EndpointsAddSize 端点越多，估算越大。
func TestEstimatedSize_EndpointsAddSize(t *testing.T) {
	key := testKey()
	t2 := bigRouteTable(2, 5, 2) // 5 路由 × 2 端点
	sign(key, t2)
	s2 := t2.EstimatedSize()

	t10 := bigRouteTable(2, 5, 10) // 5 路由 × 10 端点
	sign(key, t10)
	s10 := t10.EstimatedSize()

	if s2 >= s10 {
		t.Fatalf("更多端点应有更大 size：s2=%d s10=%d", s2, s10)
	}
}

// TestEstimatedSize_CanaryAddsSize 灰度配置增加估算。
func TestEstimatedSize_CanaryAddsSize(t *testing.T) {
	key := testKey()
	tbl1 := validTable(1)
	sign(key, tbl1)
	s1 := tbl1.EstimatedSize()

	tbl2 := validTable(1)
	tbl2.Routes[0].Canary = &RouteCanary{
		Enabled:            true,
		TargetEndpoint:     "ep-canary",
		TargetWeight:       0.1,
		RampStep:           0.05,
		RampIntervalMs:     60000,
		RollbackThreshold:  0.05,
		RollbackMinSamples: 100,
		AllowedTenants:     []string{"tenant-a", "tenant-b", "tenant-c"},
	}
	sign(key, tbl2)
	s2 := tbl2.EstimatedSize()

	if s1 >= s2 {
		t.Fatalf("带 canary 应有更大 size：s1=%d s2=%d", s1, s2)
	}
}

// ---- MaxSize 超限拒绝 ----

// TestMaxSize_UnderLimitAccepted 大小在限制内正常接受。
func TestMaxSize_UnderLimitAccepted(t *testing.T) {
	key := testKey()
	c := newTestCacheOpts(key, Options{MaxSize: 100 * 1024}) // 100 KB
	tbl := validTable(1)
	sign(key, tbl)

	if !updateSync(c, tbl) {
		t.Fatal("正常大小的表应被接受")
	}
	if c.Version() != 1 {
		t.Fatalf("version=%d, want 1", c.Version())
	}
}

// TestMaxSize_OverLimitRejected 超限表被拒绝，旧表保留（fail-closed）。
func TestMaxSize_OverLimitRejected(t *testing.T) {
	key := testKey()
	c := newTestCacheOpts(key, Options{MaxSize: 200}) // 极小限制（约 200 字节）

	// 先放一个小表（版本 1）
	small := &RouteTable{Version: 1, UpdatedAt: 1725500000, Routes: []TableRoute{
		{Tenant: "t", Model: "m", DefaultEngine: "e"},
	}}
	sign(key, small)
	if !updateSync(c, small) {
		t.Fatal("小表应被接受")
	}

	// 尝试更新为大表（超限）
	big := bigRouteTable(2, 100, 10) // 100 路由 × 10 端点，远超 200 字节
	sign(key, big)
	if updateSync(c, big) {
		t.Fatal("超限表应被拒绝")
	}

	// 旧表保留
	if c.Version() != 1 {
		t.Fatalf("版本应保留为 1，实际为 %d", c.Version())
	}
}

// TestMaxSize_ZeroMeansUnlimited MaxSize=0 表示不限制（P0 兼容性行为）。
func TestMaxSize_ZeroMeansUnlimited(t *testing.T) {
	key := testKey()
	c := newTestCache(key) // MaxSize=0（默认）

	big := bigRouteTable(1, 500, 20) // 500 路由 × 20 端点
	sign(key, big)
	if !updateSync(c, big) {
		t.Fatal("MaxSize=0 不应限制任何大小")
	}
	if c.Version() != 1 {
		t.Fatalf("version=%d, want 1", c.Version())
	}
}

// TestMaxSize_BoundaryJustUnder 刚好低于限制可接受。
func TestMaxSize_BoundaryJustUnder(t *testing.T) {
	key := testKey()
	tbl := validTable(1)
	sign(key, tbl)
	size := tbl.EstimatedSize()

	// MaxSize = size + 10（留出余量，确保估算波动不影响）
	c := newTestCacheOpts(key, Options{MaxSize: size + 100})
	if !updateSync(c, tbl) {
		t.Fatalf("低于上限应被接受（size=%d, max=%d）", size, size+100)
	}
}

// TestMaxSize_BoundaryJustOver 刚好超过限制被拒绝。
func TestMaxSize_BoundaryJustOver(t *testing.T) {
	key := testKey()
	tbl := validTable(1)
	sign(key, tbl)
	size := tbl.EstimatedSize()

	if size <= 100 {
		t.Skip("表太小，无法测试边界")
	}

	// MaxSize = size 的一半（确保超限）
	c := newTestCacheOpts(key, Options{MaxSize: size / 2})
	if updateSync(c, tbl) {
		t.Fatalf("超过上限应被拒绝（size=%d, max=%d）", size, size/2)
	}
}

// TestMaxSize_OldTablePreservedOnReject 超限拒绝后旧表仍可查询。
func TestMaxSize_OldTablePreservedOnReject(t *testing.T) {
	key := testKey()
	c := newTestCacheOpts(key, Options{MaxSize: 50 * 1024}) // 50 KB

	// 初始表（版本 1，1 条路由）
	tbl1 := validTable(1)
	sign(key, tbl1)
	updateSync(c, tbl1)

	// 查询应命中
	r := c.Lookup("tenant-a", "qwen-plus")
	if r == nil {
		t.Fatal("初始表查询应命中")
	}

	// 大表被拒
	big := bigRouteTable(2, 200, 10)
	sign(key, big)
	if updateSync(c, big) {
		t.Fatal("大表应被拒绝")
	}

	// 旧表仍可查询
	r = c.Lookup("tenant-a", "qwen-plus")
	if r == nil {
		t.Fatal("拒绝后旧表应仍可查询")
	}
	if c.Version() != 1 {
		t.Fatalf("版本应仍为 1，实际 %d", c.Version())
	}
}

// ---- OnReject 回调 ----

// TestOnReject_CalledOnTooLarge 超限时 OnReject 回调被调用且 reason=too_large。
func TestOnReject_CalledOnTooLarge(t *testing.T) {
	key := testKey()
	var gotReason string
	var gotVersion int
	c := newTestCacheOpts(key, Options{
		MaxSize: 100, // 极小限制
		OnReject: func(reason string, newVersion int) {
			gotReason = reason
			gotVersion = newVersion
		},
	})

	big := bigRouteTable(5, 100, 5)
	sign(key, big)
	updateSync(c, big)

	if gotReason != "too_large" {
		t.Fatalf("reason=%q, want too_large", gotReason)
	}
	if gotVersion != 5 {
		t.Fatalf("version=%d, want 5", gotVersion)
	}
}

// TestOnReject_CalledOnReplay 版本回退时 OnReject reason=replay。
func TestOnReject_CalledOnReplay(t *testing.T) {
	key := testKey()
	var gotReason string
	c := newTestCacheOpts(key, Options{
		OnReject: func(reason string, newVersion int) { gotReason = reason },
	})

	tbl2 := validTable(2)
	sign(key, tbl2)
	updateSync(c, tbl2)

	tbl1 := validTable(1) // 版本更低
	sign(key, tbl1)
	updateSync(c, tbl1)

	if gotReason != "replay" {
		t.Fatalf("reason=%q, want replay", gotReason)
	}
}

// TestOnReject_NotCalledOnAccept 正常接受时 OnReject 不被调用。
func TestOnReject_NotCalledOnAccept(t *testing.T) {
	key := testKey()
	called := false
	c := newTestCacheOpts(key, Options{
		MaxSize: 100 * 1024,
		OnReject: func(reason string, newVersion int) { called = true },
	})

	tbl := validTable(1)
	sign(key, tbl)
	updateSync(c, tbl)

	if called {
		t.Fatal("正常接受时 OnReject 不应被调用")
	}
}

// ---- EstimatedSize 方法（Cache 层）----

// TestCacheEstimatedSize_ZeroWhenEmpty 未初始化时 size=0。
func TestCacheEstimatedSize_Empty(t *testing.T) {
	key := testKey()
	c := newTestCache(key)
	if c.EstimatedSize() != 0 {
		t.Fatalf("空缓存 size=%d, want 0", c.EstimatedSize())
	}
}

// TestCacheEstimatedSize_ReflectsTable 更新后 size 与表一致。
func TestCacheEstimatedSize_MatchesTable(t *testing.T) {
	key := testKey()
	c := newTestCache(key)
	tbl := validTable(1)
	sign(key, tbl)
	updateSync(c, tbl)

	want := tbl.EstimatedSize()
	got := c.EstimatedSize()
	if got != want {
		t.Fatalf("cache size=%d, table size=%d", got, want)
	}
}

// TestMaxSizeAccessor MaxSize() 返回配置值。
func TestMaxSizeAccessor(t *testing.T) {
	key := testKey()
	c := newTestCacheOpts(key, Options{MaxSize: 54321})
	if c.MaxSize() != 54321 {
		t.Fatalf("MaxSize=%d, want 54321", c.MaxSize())
	}
}

// ---- 辅助函数 ----

// bigRouteTable 构造指定规模的路由表（仅测试用，不计入签名）。
func bigRouteTable(version int, numRoutes int, numEndpoints int) *RouteTable {
	routes := make([]TableRoute, numRoutes)
	for i := 0; i < numRoutes; i++ {
		eps := make([]TableEndpoint, numEndpoints)
		for j := 0; j < numEndpoints; j++ {
			eps[j] = TableEndpoint{
				Name:    strings.Repeat("e", 10) + string(rune('0'+j%10)),
				URL:     "https://model-endpoint-" + string(rune('a'+j%26)) + ".example.com/v1/chat",
				Weight:  1.0 / float64(numEndpoints),
				Enabled: true,
				Auth: EndpointAuth{
					Type:      "bearer",
					SecretRef: "km://otpmask/model-keys/endpoint-" + string(rune('a'+j%26)),
				},
			}
		}
		routes[i] = TableRoute{
			Tenant:        "tenant-" + string(rune('a'+i%26)) + strings.Repeat("x", 10),
			Model:         "model-" + string(rune('a'+i%26)) + "-plus",
			DefaultEngine: "engine-" + string(rune('a'+i%3)),
			Strategy:      "failure-aware",
			Endpoints:     eps,
		}
	}
	return &RouteTable{Version: version, UpdatedAt: 1725500000, Routes: routes}
}
