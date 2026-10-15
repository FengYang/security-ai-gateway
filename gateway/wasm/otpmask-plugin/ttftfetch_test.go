package main

// ttftfetch_test.go — P1-6 M2.6：统计拉取（round-robin 分片 / 写入与过期判定 / 404 失效 /
// 不可达标记 / 单飞自愈）用例。

import (
	"fmt"
	"testing"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
)

// ttftSwapRegistry 替换全局引擎注册表（测试单线程；仅换 entries map，避免复制锁）。
func ttftSwapRegistry(t *testing.T, entries map[string]*routingEntry) {
	t.Helper()
	old := routingEngines.entries
	routingEngines.entries = entries
	t.Cleanup(func() { routingEngines.entries = old })
}

// ttftNewTestEngine 构造测试引擎（端点启用、权重 1、缺省延迟配置 StaleSec=75）。
func ttftNewTestEngine(names ...string) *routeengine.Engine {
	eps := make([]routeengine.EndpointConfig, 0, len(names))
	for _, n := range names {
		eps = append(eps, routeengine.EndpointConfig{Name: n, URL: "http://" + n, Enabled: true, Weight: 1.0})
	}
	return routeengine.NewEngine(routeengine.Config{
		Endpoints: eps,
		Latency:   routeengine.DefaultLatencyConfig(),
	})
}

// ttftStatesByName 端点状态按名索引。
func ttftStatesByName(eng *routeengine.Engine) map[string]*routeengine.EndpointState {
	out := map[string]*routeengine.EndpointState{}
	for _, st := range eng.EndpointStates() {
		out[st.Name] = st
	}
	return out
}

// TestTTFTSelectTenantsRoundRobin：游标推进与回绕（9 租户 × 每 tick 4：4/4/4 且第 3 tick 回绕）。
func TestTTFTSelectTenantsRoundRobin(t *testing.T) {
	rt := &ttftRuntimeState{}
	all := []string{"t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8"}
	want := [][]string{
		{"t0", "t1", "t2", "t3"},
		{"t4", "t5", "t6", "t7"},
		{"t8", "t0", "t1", "t2"},
	}
	for i, w := range want {
		got := rt.selectTenants(all, 4)
		if len(got) != len(w) {
			t.Fatalf("第 %d 轮选取数不符：%v", i+1, got)
		}
		for j := range w {
			if got[j] != w[j] {
				t.Fatalf("第 %d 轮顺序不符：got=%v want=%v", i+1, got, w)
			}
		}
	}
	if got := rt.selectTenants(nil, 4); got != nil {
		t.Fatalf("空列表应返回 nil：%v", got)
	}
	if got := rt.selectTenants(all, 0); got != nil {
		t.Fatalf("max<=0 应返回 nil：%v", got)
	}
	full := rt.selectTenants(all, 16) // 上限大于租户数 → 全量
	if len(full) != 9 {
		t.Fatalf("租户数不足上限应全量：%v", full)
	}
}

// TestTTFTFetchTickRoundRobinCoverage：tick 级分片——9 租户 3 个 tick 内全量覆盖
// （更新周期 ≤ ceil(N/上限)=3 个 tick，TT2-12 估算式）。
func TestTTFTFetchTickRoundRobinCoverage(t *testing.T) {
	entries := map[string]*routingEntry{}
	for i := 0; i < 9; i++ {
		entries[fmt.Sprintf("t%d\x00m", i)] = &routingEntry{engine: ttftNewTestEngine("e")}
	}
	ttftSwapRegistry(t, entries)

	oldRT := ttftRuntime
	defer func() { ttftRuntime = oldRT }()
	ttftRuntime = ttftRuntimeState{enabled: true, intervalMs: 10000}

	oldDispatch := ttftFetchDispatch
	defer func() { ttftFetchDispatch = oldDispatch }()
	var rounds [][]string
	ttftFetchDispatch = func(rt *ttftRuntimeState, tenant string, nowSec int64) {
		rounds[len(rounds)-1] = append(rounds[len(rounds)-1], tenant)
	}

	for i := 0; i < 3; i++ {
		rounds = append(rounds, nil)
		ttftFetchTickAt(int64(1000 + i*10))
	}
	if len(rounds[0]) != 4 || len(rounds[1]) != 4 || len(rounds[2]) != 4 {
		t.Fatalf("每 tick 应为 4 租户：%v", rounds)
	}
	seen := map[string]bool{}
	for _, r := range rounds {
		for _, tn := range r {
			seen[tn] = true
		}
	}
	for i := 0; i < 9; i++ {
		if !seen[fmt.Sprintf("t%d", i)] {
			t.Fatalf("3 个 tick 内应覆盖全部租户，缺 t%d：%v", i, rounds)
		}
	}
	// 禁用态零网络
	ttftRuntime.enabled = false
	before := len(rounds)
	ttftFetchTickAt(2000)
	if len(rounds) != before {
		t.Fatal("禁用态不应触发拉取")
	}
}

// TestTTFTFetchTickSingleflightSelfHeal：在飞门；超过 2×周期视为回调丢弃 → 自愈继续。
func TestTTFTFetchTickSingleflightSelfHeal(t *testing.T) {
	ttftSwapRegistry(t, map[string]*routingEntry{"t0\x00m": {engine: ttftNewTestEngine("e")}})

	oldRT := ttftRuntime
	defer func() { ttftRuntime = oldRT }()
	ttftRuntime = ttftRuntimeState{enabled: true, intervalMs: 10000, fetchInflight: 1, fetchStartSec: 1000}

	oldDispatch := ttftFetchDispatch
	defer func() { ttftFetchDispatch = oldDispatch }()
	var calls int
	ttftFetchDispatch = func(rt *ttftRuntimeState, tenant string, nowSec int64) { calls++ }

	ttftFetchTickAt(1005) // 5s ≤ 2×10s → 单飞跳过
	if calls != 0 {
		t.Fatalf("在飞未陈旧不应发起：calls=%d", calls)
	}
	ttftFetchTickAt(1021) // 21s > 20s → 自愈重置并继续
	if calls != 1 {
		t.Fatalf("陈旧自愈后应发起：calls=%d", calls)
	}
	if ttftRuntime.fetchStartSec != 1021 {
		t.Fatalf("发起秒应更新：%d", ttftRuntime.fetchStartSec)
	}
}

// TestTTFTApplyStatsResponseWrites：200 写入——miss 维度、未知端点/引擎跳过、
// 过期（updated_at 超 stale_sec）写时置 Valid=false、数值保留。
func TestTTFTApplyStatsResponseWrites(t *testing.T) {
	eng := ttftNewTestEngine("tee-gpu-a", "tee-gpu-b")
	ttftSwapRegistry(t, map[string]*routingEntry{"t-001\x00qwen-max": {engine: eng}})

	now := int64(1760000000)
	body := []byte(`{"generated_at":1760000000000,"stats":[
		{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"miss","p50_ms":210,"p95_ms":480,"samples":1200,"valid":true,"updated_at":1759999990},
		{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-b","cache":"miss","p50_ms":260,"p95_ms":900,"samples":950,"valid":true,"updated_at":1759999900},
		{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"hit","p50_ms":1,"p95_ms":2,"samples":3,"valid":true,"updated_at":1759999999},
		{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-c","cache":"miss","p50_ms":100,"p95_ms":200,"samples":10,"valid":true,"updated_at":1759999990},
		{"tenant":"t-001","model":"no-such","endpoint":"tee-gpu-a","cache":"miss","p50_ms":1,"p95_ms":2,"samples":3,"valid":true,"updated_at":1759999999}
	]}`)
	applied, rejected := ttftApplyStatsResponse("t-001", 200, body, now)
	if applied != 2 || rejected != 0 {
		t.Fatalf("写入数不符：applied=%d rejected=%d", applied, rejected)
	}
	st := ttftStatesByName(eng)
	a := st["tee-gpu-a"].TTFT
	if !a.Valid || a.P95Ms != 480 || a.P50Ms != 210 || a.Samples != 1200 ||
		a.UpdatedAt != 1759999990 || a.Cache != "miss" {
		t.Fatalf("tee-gpu-a 统计不符：%+v", a)
	}
	b := st["tee-gpu-b"].TTFT
	if b.Valid || b.P95Ms != 900 { // now-100 > 75 → 过期置 false（数值保留）
		t.Fatalf("tee-gpu-b 过期判定不符：%+v", b)
	}
	if eng.TTFTStatsUnreachable() {
		t.Fatal("200 成功后不应标记不可达")
	}
}

// TestTTFTApplyStatsResponse404Invalidates：404 = 无统计 → 通道可达 + 旧画像失效（置零）。
func TestTTFTApplyStatsResponse404Invalidates(t *testing.T) {
	eng := ttftNewTestEngine("tee-gpu-a", "tee-gpu-b")
	ttftSwapRegistry(t, map[string]*routingEntry{"t-001\x00qwen-max": {engine: eng}})
	eng.SetEndpointTTFT("tee-gpu-a", routeengine.TTFTStat{Valid: true, P95Ms: 500, UpdatedAt: 1760000000})

	applied, rejected := ttftApplyStatsResponse("t-001", 404, []byte(`{"error":"not_found"}`), 1760000000)
	if applied != 0 || rejected != 0 {
		t.Fatalf("404 语义：applied=%d rejected=%d（应为 0/0）", applied, rejected)
	}
	st := ttftStatesByName(eng)
	if st["tee-gpu-a"].TTFT.Valid || st["tee-gpu-a"].TTFT.P95Ms != 0 {
		t.Fatalf("404 后旧画像应失效置零：%+v", st["tee-gpu-a"].TTFT)
	}
	if eng.TTFTStatsUnreachable() {
		t.Fatal("404 属通道可达，不应标记不可达")
	}
}

// TestTTFTApplyStatsRejectMarksUnreachable：503/非契约载荷 → 不可达标记 + 存量保留；
// 恢复 200 → 清除不可达；400 → 可达 + 拒绝但存量保留。
func TestTTFTApplyStatsRejectMarksUnreachable(t *testing.T) {
	eng := ttftNewTestEngine("tee-gpu-a")
	ttftSwapRegistry(t, map[string]*routingEntry{"t-001\x00qwen-max": {engine: eng}})
	now := int64(1760000000)

	if _, rejected := ttftApplyStatsResponse("t-001", 503, []byte(`{"error":"source_unavailable"}`), now); rejected != 1 {
		t.Fatal("503 应计拒绝")
	}
	if !eng.TTFTStatsUnreachable() {
		t.Fatal("503 应标记不可达（R2-19 序 1）")
	}
	if _, rejected := ttftApplyStatsResponse("t-001", 200, []byte("not-json"), now); rejected != 1 {
		t.Fatal("非契约载荷应计拒绝")
	}
	if !eng.TTFTStatsUnreachable() {
		t.Fatal("非契约载荷不应清除不可达标记")
	}
	eng.SetEndpointTTFT("tee-gpu-a", routeengine.TTFTStat{Valid: true, P95Ms: 500, UpdatedAt: now - 5})
	ok := []byte(`{"generated_at":1,"stats":[{"tenant":"t-001","model":"qwen-max","endpoint":"tee-gpu-a","cache":"miss","p50_ms":100,"p95_ms":500,"samples":100,"valid":true,"updated_at":1759999995}]}`)
	if applied, rejected := ttftApplyStatsResponse("t-001", 200, ok, now); applied != 1 || rejected != 0 {
		t.Fatalf("恢复 200 应写入：applied=%d rejected=%d", applied, rejected)
	}
	if eng.TTFTStatsUnreachable() {
		t.Fatal("恢复 200 应清除不可达标记")
	}
	st := ttftStatesByName(eng)
	if _, rejected := ttftApplyStatsResponse("t-001", 400, []byte(`{"error":"invalid_request"}`), now); rejected != 1 {
		t.Fatal("400 应计拒绝")
	}
	if st["tee-gpu-a"].TTFT.P95Ms != 500 || !st["tee-gpu-a"].TTFT.Valid {
		t.Fatalf("400 不应改动存量统计：%+v", st["tee-gpu-a"].TTFT)
	}
	if eng.TTFTStatsUnreachable() {
		t.Fatal("400 属通道可达，不应标记不可达")
	}
}
