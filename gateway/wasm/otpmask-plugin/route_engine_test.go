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
