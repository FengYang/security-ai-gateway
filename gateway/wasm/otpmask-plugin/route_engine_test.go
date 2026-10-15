package main

// route_engine_test.go — P0-1 多端点路由引擎接线的纯逻辑用例（engineFor/routeStrategy 等无 hostcall）。

import (
	"testing"
	"time"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
)

// endpointTable 构造带多端点的已签名路由表。
func endpointTable(version int, updatedAt int64, tenant, model, strategy string, eps []routecache.TableEndpoint) *routecache.RouteTable {
	t := &routecache.RouteTable{Version: version, UpdatedAt: updatedAt, Routes: []routecache.TableRoute{
		{Tenant: tenant, Model: model, Strategy: strategy, Endpoints: eps},
	}}
	signTableForTest(routeKey(), t)
	return t
}

// TestRouteStrategyParsing 策略字符串解析：兼容 §4.1.3/§6.1 枚举与引擎内部取值，
// 未知回落 priority（P1-6 M4.4：未知/空值区分——空值=缺省无信号，未知=显式信号）。
func TestRouteStrategyParsing(t *testing.T) {
	cases := map[string]routeengine.Strategy{
		"":                   routeengine.StrategyPriority,
		"priority":           routeengine.StrategyPriority,
		"primary-backup":     routeengine.StrategyPriority,
		"PRIMARY-BACKUP":     routeengine.StrategyPriority,
		"weighted":           routeengine.StrategyWeighted,
		" weight ":           routeengine.StrategyWeighted,
		"failure-rate-aware": routeengine.StrategyFailureAware,
		"failure_rate_aware": routeengine.StrategyFailureAware,
		// P1-6 M4.4：延迟择优三策略映射
		"latency-aware":   routeengine.StrategyLatencyAware,
		"latency_aware":   routeengine.StrategyLatencyAware,
		"LATENCY-AWARE":   routeengine.StrategyLatencyAware,
		"latency-fastest": routeengine.StrategyLatencyFastest,
		"latency_fastest": routeengine.StrategyLatencyFastest,
		"hybrid":          routeengine.StrategyHybrid,
		// 未知：显式信号（计数 + 错误日志，host 单测下均 no-op），回退 priority
		"unknown": routeengine.StrategyPriority,
	}
	for in, want := range cases {
		if got := routeStrategy(in); got != want {
			t.Errorf("routeStrategy(%q)=%q，期望 %q", in, got, want)
		}
	}
}

// TestRouteEndpointSuccess 结果判定矩阵（§6.5.8）：5xx 与 429 计失败，其余计成功。
func TestRouteEndpointSuccess(t *testing.T) {
	if !routeEndpointSuccess(200) || !routeEndpointSuccess(400) || !routeEndpointSuccess(401) || !routeEndpointSuccess(403) {
		t.Fatal("2xx/400/401/403 应计为成功（不触发熔断）")
	}
	for _, code := range []int{429, 500, 502, 503, 504} {
		if routeEndpointSuccess(code) {
			t.Errorf("状态码 %d 应计为失败", code)
		}
	}
}

// TestEntryForNilWhenNoEndpoints 向后兼容：未命中路由表或无端点 → nil（行为零变化）。
func TestEntryForNilWhenNoEndpoints(t *testing.T) {
	c := newRouteCacheForTest(routeKey())
	if e := entryFor(c, "t-none", "m-none"); e != nil {
		t.Fatal("空缓存应返回 nil 条目")
	}
	// 命中路由表但未配置端点（v1 二元模式）→ 同样 nil。
	updateRouteCacheSync(c, signedTable(1, time.Now().Unix()))
	if e := entryFor(c, "tenant-a", "qwen-plus"); e != nil {
		t.Fatal("无 Endpoints 的条目应返回 nil（回退 v1 二元模式）")
	}
	if e := entryFor(nil, "tenant-a", "qwen-plus"); e != nil {
		t.Fatal("cache 为 nil 应返回 nil 条目")
	}
}

// TestEntryForSmoothMigration 路由表版本变化时复用同一条目/引擎实例（统计状态不丢失）。
func TestEntryForSmoothMigration(t *testing.T) {
	tenant, model := "t-smooth", "m-smooth"
	eps := []routecache.TableEndpoint{
		{Name: "ep-a", Weight: 1, Priority: 1},
		{Name: "ep-b", Weight: 1, Priority: 1},
	}
	now := time.Now().Unix()
	c := newRouteCacheForTest(routeKey())
	updateRouteCacheSync(c, endpointTable(1, now, tenant, model, "weighted", eps))

	e1 := entryFor(c, tenant, model)
	if e1 == nil {
		t.Fatal("配置了端点应返回路由条目")
	}
	if e1.degrade == nil {
		t.Fatal("路由条目应携带降级管理器")
	}
	// 记录失败，制造可观测状态。
	e1.engine.RecordResult("ep-a", false)
	rate1, _ := e1.engine.GetEndpointFailureRate("ep-a")

	// 版本升级（同端点，仅权重变化）→ 平滑迁移：实例复用、状态保留。
	updateRouteCacheSync(c, endpointTable(2, now+1, tenant, model, "weighted", []routecache.TableEndpoint{
		{Name: "ep-a", Weight: 2, Priority: 1},
		{Name: "ep-b", Weight: 1, Priority: 1},
	}))
	e2 := entryFor(c, tenant, model)
	if e2 != e1 {
		t.Fatal("版本升级应复用同一条目（平滑迁移）")
	}
	rate2, _ := e2.engine.GetEndpointFailureRate("ep-a")
	if rate2 != rate1 {
		t.Fatalf("平滑迁移应保留 EWMA 状态：before=%v after=%v", rate1, rate2)
	}
	if e2.engine.EndpointCount() != 2 {
		t.Fatalf("端点数量应为 2，got %d", e2.engine.EndpointCount())
	}
}

// TestBuildEngineConfigSkipsUnnamed 无名端点不参与选择；策略透传到引擎。
func TestBuildEngineConfigSkipsUnnamed(t *testing.T) {
	cfg := buildEngineConfig(&routecache.TableRoute{
		Strategy: "failure-rate-aware",
		Endpoints: []routecache.TableEndpoint{
			{Name: "", Weight: 1, Priority: 1},
			{Name: "ep-x", Weight: 1, Priority: 1},
		},
	})
	if cfg.Strategy != routeengine.StrategyFailureAware {
		t.Fatalf("策略应透传 failure-aware，got %q", cfg.Strategy)
	}
	if len(cfg.Endpoints) != 1 || cfg.Endpoints[0].Name != "ep-x" {
		t.Fatalf("应仅保留有名端点，got %+v", cfg.Endpoints)
	}
	if !cfg.Endpoints[0].Enabled {
		t.Fatal("W3 语义：Name 非空即启用")
	}
}

// ============================================================
// P1-6 M4.5：buildLatencyConfig 字段映射 / 缺省值（按存在性填充；§6.1）
// ============================================================

// TestBuildLatencyConfig_DefaultsAndPresence：nil/空段 → 全缺省；指针字段显式零值保留；
// 值字段非零覆盖；未提供字段保持缺省。
func TestBuildLatencyConfig_DefaultsAndPresence(t *testing.T) {
	def := routeengine.DefaultLatencyConfig()
	if def.WindowSec != 300 || def.Quantile != "p95" || def.Gamma != 1.0 ||
		def.MinWeight != 0.05 || def.ExploreRatio != 0.05 || def.MinSamples != 20 ||
		def.StaleSec != 75 || !def.CachePartition || def.MaxTTFTMs != 30000 {
		t.Fatalf("DefaultLatencyConfig 与 §6.1 缺省值不符：%+v", def)
	}
	// nil 段 / 空段 → 全缺省
	if got := buildLatencyConfig(nil); got != def {
		t.Fatalf("nil 段应全缺省：%+v", got)
	}
	if got := buildLatencyConfig(&routecache.RouteLatency{}); got != def {
		t.Fatalf("空段应全缺省：%+v", got)
	}
	// 指针字段显式零值保留（γ=0 / min_weight=0 / explore_ratio=0 / cache_partition=false）
	zero, no := 0.0, false
	got := buildLatencyConfig(&routecache.RouteLatency{
		Gamma: &zero, MinWeight: &zero, ExploreRatio: &zero, CachePartition: &no,
	})
	if got.Gamma != 0 || got.MinWeight != 0 || got.ExploreRatio != 0 || got.CachePartition {
		t.Fatalf("指针字段显式零值应保留：%+v", got)
	}
	if got.WindowSec != 300 || got.Quantile != "p95" || got.MinSamples != 20 ||
		got.StaleSec != 75 || got.MaxTTFTMs != 30000 {
		t.Fatalf("未提供字段应保持缺省：%+v", got)
	}
	// 值字段部分覆盖
	got2 := buildLatencyConfig(&routecache.RouteLatency{
		WindowSec: 600, Quantile: "p50", MinSamples: 50, StaleSec: 30, MaxTTFTMs: 5000,
	})
	want := def
	want.WindowSec, want.Quantile, want.MinSamples, want.StaleSec, want.MaxTTFTMs = 600, "p50", 50, 30, 5000
	if got2 != want {
		t.Fatalf("部分覆盖错误：got %+v want %+v", got2, want)
	}
	// 全字段显式（合法范围内）
	g2, mw03, er05 := 2.0, 0.3, 0.5
	yes := true
	got3 := buildLatencyConfig(&routecache.RouteLatency{
		WindowSec: 120, Quantile: "p50", Gamma: &g2, MinWeight: &mw03,
		ExploreRatio: &er05, MinSamples: 5, StaleSec: 25, CachePartition: &yes, MaxTTFTMs: 1000,
	})
	full := routeengine.LatencyConfig{
		WindowSec: 120, Quantile: "p50", Gamma: 2, MinWeight: 0.3, ExploreRatio: 0.5,
		MinSamples: 5, StaleSec: 25, CachePartition: true, MaxTTFTMs: 1000,
	}
	if got3 != full {
		t.Fatalf("全字段显式映射错误：got %+v want %+v", got3, full)
	}
}

// TestBuildEngineConfig_LatencyWiring：buildEngineConfig 接线（策略映射 + latency 段解析）；
// 旧表（无 latency 段）策略透传且 latency 全缺省（零回归）。
func TestBuildEngineConfig_LatencyWiring(t *testing.T) {
	g0 := 0.0
	cfg := buildEngineConfig(&routecache.TableRoute{
		Strategy:  "latency-aware",
		Endpoints: []routecache.TableEndpoint{{Name: "ep-a", Weight: 1, Priority: 1}},
		Latency:   &routecache.RouteLatency{WindowSec: 600, Gamma: &g0},
	})
	if cfg.Strategy != routeengine.StrategyLatencyAware {
		t.Fatalf("策略应映射 latency-aware，got %q", cfg.Strategy)
	}
	if cfg.Latency.WindowSec != 600 || cfg.Latency.Gamma != 0 {
		t.Fatalf("latency 段解析错误（显式值/显式零值）：%+v", cfg.Latency)
	}
	if cfg.Latency.Quantile != "p95" || !cfg.Latency.CachePartition || cfg.Latency.MinWeight != 0.05 {
		t.Fatalf("未提供字段应缺省：%+v", cfg.Latency)
	}
	// 旧表（无 latency 段 / 非延迟策略）不受影响
	cfg2 := buildEngineConfig(&routecache.TableRoute{
		Strategy:  "failure-rate-aware",
		Endpoints: []routecache.TableEndpoint{{Name: "ep-b", Weight: 1, Priority: 1}},
	})
	if cfg2.Strategy != routeengine.StrategyFailureAware || cfg2.Latency != routeengine.DefaultLatencyConfig() {
		t.Fatalf("旧表应策略透传且 latency 全缺省：%+v", cfg2)
	}
}
