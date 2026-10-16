package routecache

import (
	"testing"
)

// ============================================================
// P1-6 M4.2：routecache 与 gateway-core 的 CanonicalBytes 逐字节一致（C-5）
// ============================================================

// canonical 基线（与 gateway-core internal/route/routetable_test.go 的
// TestRouteLatencyCanonicalAndPresence **同一字面量**共同锁定；任一侧字段/标签/序变更
// 都会打破对应基线，从而暴露签名不一致）。
//
// 生成方式：双侧实测打印比对（2026-10-15，M4.2 实施时），非手写。
const (
	// canonLatencyBaseline：含 latency 段（显式零值 gamma=0 / explore_ratio=1 / cache_partition=false）的表。
	canonLatencyBaseline = `{"version":2,"updated_at":1725500000,"routes":[{"tenant":"t-001","model":"qwen-max","default_engine":"cmaas","endpoints":[{"name":"a","url":"https://a.internal/v1","weight":0.5,"priority":1,"enabled":true,"auth":{}}],"strategy":"latency-aware","latency":{"quantile":"p95","gamma":0,"explore_ratio":1,"cache_partition":false}}]}`
	// canonLegacyBaseline：旧表（无 latency/endpoints），与外部签发 fixture 同源。
	canonLegacyBaseline = `{"version":1,"updated_at":1725500000,"routes":[{"tenant":"tenant-a","model":"qwen-plus","default_engine":"cmaas","target":"https://cmaas.local"}]}`
)

// latencyTableM42 构造与 gateway-core 侧 M4.1 测试相同的固定向量表。
func latencyTableM42() *RouteTable {
	gamma := 0.0
	explore := 1.0
	partition := false
	return &RouteTable{Version: 2, UpdatedAt: 1725500000, Routes: []TableRoute{{
		Tenant: "t-001", Model: "qwen-max", DefaultEngine: "cmaas", Strategy: "latency-aware",
		Endpoints: []TableEndpoint{{Name: "a", URL: "https://a.internal/v1", Weight: 0.5, Priority: 1, Enabled: true}},
		Latency:   &RouteLatency{Quantile: "p95", Gamma: &gamma, ExploreRatio: &explore, CachePartition: &partition},
	}}}
}

// TestCanonLatencyByteBaseline：两侧规范字节基线逐字节一致（含旧表基线）；
// 含 latency 的表可验签、可被缓存接受、可查询；篡改 latency 验签失败。
func TestCanonLatencyByteBaseline(t *testing.T) {
	tbl := latencyTableM42()
	if got := string(tbl.canon()); got != canonLatencyBaseline {
		t.Fatalf("含 latency 表的规范字节与基线不一致（C-5）:\n got = %s\nwant = %s", got, canonLatencyBaseline)
	}
	// 旧表基线：无 latency 字段逐字节不变
	legacy := &RouteTable{Version: 1, UpdatedAt: 1725500000, Routes: []TableRoute{
		{Tenant: "tenant-a", Model: "qwen-plus", DefaultEngine: "cmaas", Target: "https://cmaas.local"},
	}}
	if got := string(legacy.canon()); got != canonLegacyBaseline {
		t.Fatalf("旧表规范字节变化（C-5）:\n got = %s\nwant = %s", got, canonLegacyBaseline)
	}

	// 签名 → 验签 → 缓存接受 → 查询可见 latency 段
	sign(testKey(), tbl)
	if !verifySync(testVerifier{key: testKey()}, tbl) {
		t.Fatal("含 latency 的表应验签通过")
	}
	c := newTestCache(testKey())
	if !updateSync(c, tbl) {
		t.Fatal("含 latency 的合法表应被缓存接受")
	}
	if r := c.Lookup("t-001", "qwen-max"); r == nil || r.Latency == nil || r.Latency.Quantile != "p95" {
		t.Fatalf("缓存查询应返回 latency 段，got %+v", r)
	}

	// 篡改 latency → 验签失败
	tbl.Routes[0].Latency.Quantile = "p50"
	if verifySync(testVerifier{key: testKey()}, tbl) {
		t.Fatal("篡改 latency 应验签失败")
	}
}

// TestEstimatedSizeIncludesLatency（M4.2）：latency 段计入内存估算。
func TestEstimatedSizeIncludesLatency(t *testing.T) {
	base := &RouteTable{Version: 1, UpdatedAt: 1, Routes: []TableRoute{
		{Tenant: "t", Model: "m", DefaultEngine: "cmaas"},
	}}
	withLat := &RouteTable{Version: 1, UpdatedAt: 1, Routes: []TableRoute{
		{Tenant: "t", Model: "m", DefaultEngine: "cmaas", Latency: &RouteLatency{Quantile: "p95"}},
	}}
	want := 8 + len("p95") + 88 // 指针 + Quantile 字符串 + 固定字段（见 EstimatedSize 注释）
	if got := withLat.EstimatedSize() - base.EstimatedSize(); got != want {
		t.Fatalf("EstimatedSize 增量=%d，want %d", got, want)
	}
}
