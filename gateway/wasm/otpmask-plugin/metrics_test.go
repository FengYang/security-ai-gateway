package main

// W-1 metrics 单测：hostcall 守卫下计数 no-op 不 panic；计数器命名正确。
// TestMain 置 metricsHostGuard=true——go:wasmimport 在宿主测试进程不可调用，
// 全包测试均在守卫下运行（与 streamdone_test 纯逻辑策略一致）。

import (
	"os"
	"testing"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
)

func TestMain(m *testing.M) {
	metricsHostGuard = true
	os.Exit(m.Run())
}

func TestMetricIncrGuardedNoop(t *testing.T) {
	// 守卫下 incr 必须为安全 no-op（不触发 hostcall / 不 panic）。
	for _, c := range []*pwCounter{metricRequests, metricFailClosed, metricDecryptError, metricContentFilter, metricKeysIssued, metricKeysDeleted, metricMasked} {
		c.incr()
		c.incr()
	}
}

func TestMetricNames(t *testing.T) {
	want := map[string]string{
		"otpmask_request_total":        metricRequests.name,
		"otpmask_fail_closed_total":    metricFailClosed.name,
		"otpmask_decrypt_error_total":  metricDecryptError.name,
		"otpmask_content_filter_total": metricContentFilter.name,
		"otpmask_keys_issued_total":    metricKeysIssued.name,
		"otpmask_keys_deleted_total":   metricKeysDeleted.name,
		"otpmask_masked_total":         metricMasked.name,
	}
	for name, got := range want {
		if name != got {
			t.Fatalf("计数器命名不符: want %q got %q", name, got)
		}
	}
}

// TestTTFTMetricBucketsAlignReportBuckets：M5.1 指标桶与 M2.2 上报桶逐边界一致（秒制换算），
// 桶 Counter 命名（le 值编码）正确。
func TestTTFTMetricBucketsAlignReportBuckets(t *testing.T) {
	if len(ttftBuckets) != TTFTBucketCount {
		t.Fatalf("桶数不符：metric=%d report=%d", len(ttftBuckets), TTFTBucketCount)
	}
	for i, ms := range ttftBucketUpperBoundsMs {
		if ttftBuckets[i] != float64(ms)/1000 {
			t.Fatalf("第 %d 桶上界不符：metric=%v report=%dms", i, ttftBuckets[i], ms)
		}
	}
	if len(ttftBucketCounters) != len(ttftBuckets) {
		t.Fatalf("桶 Counter 数不符：%d", len(ttftBucketCounters))
	}
	for i, le := range ttftBuckets {
		want := "otpmask_route_ttft_seconds_bucket_le_" + formatFloatForMetric(le)
		if ttftBucketCounters[i].name != want {
			t.Fatalf("第 %d 桶命名不符：got=%q want=%q", i, ttftBucketCounters[i].name, want)
		}
	}
	// le 编码抽样（防 formatFloatForMetric 漂移）：0.025 → le_0_025；30 → le_30
	if got := ttftBucketCounters[1].name; got != "otpmask_route_ttft_seconds_bucket_le_0_025" {
		t.Fatalf("桶名编码不符：%q", got)
	}
	if got := ttftBucketCounters[10].name; got != "otpmask_route_ttft_seconds_bucket_le_30" {
		t.Fatalf("桶名编码不符：%q", got)
	}
}

// TestObserveTTFTGuardedNoop：守卫下 observeTTFT 边界值遍历安全 no-op（不 panic）。
func TestObserveTTFTGuardedNoop(t *testing.T) {
	for _, ms := range []int64{0, 1, 9, 10, 11, 25, 25000, 30000, 999999} {
		observeTTFT(ms)
	}
}

// TestLatencyPickCounterNaming：M5.2 选路拆名与 §6.5 契约名一致（三形态，别无维度）。
func TestLatencyPickCounterNaming(t *testing.T) {
	want := map[routeengine.Strategy]string{
		routeengine.StrategyLatencyAware:   "otpmask_route_latency_pick_weighted_total",
		routeengine.StrategyLatencyFastest: "otpmask_route_latency_pick_fastest_total",
		routeengine.StrategyHybrid:         "otpmask_route_latency_pick_hybrid_total",
	}
	if len(latencyPickCounters) != len(want) {
		t.Fatalf("选路计数维度数不符：got=%d want=%d", len(latencyPickCounters), len(want))
	}
	for strategy, name := range want {
		c, ok := latencyPickCounters[strategy]
		if !ok {
			t.Fatalf("缺策略映射：%q", strategy)
		}
		if c.name != name {
			t.Fatalf("策略 %q 指标名不符：got=%q want=%q", strategy, c.name, name)
		}
	}
}

// TestTTFTFallbackCounterNaming：M5.2 五原因拆名与 §6.5/R2-19 契约名一致
// （取值来源 = routeengine.Fallback* 常量，防字面量漂移）。
func TestTTFTFallbackCounterNaming(t *testing.T) {
	want := map[string]string{
		routeengine.FallbackUnreachable: "otpmask_route_ttft_fallback_unreachable_total",
		routeengine.FallbackStale:       "otpmask_route_ttft_fallback_stale_total",
		routeengine.FallbackLowSamples:  "otpmask_route_ttft_fallback_low_samples_total",
		routeengine.FallbackNoSamples:   "otpmask_route_ttft_fallback_no_samples_total",
		routeengine.FallbackNoRand:      "otpmask_route_ttft_fallback_no_rand_total",
	}
	if len(ttftFallbackCounters) != len(want) {
		t.Fatalf("回退计数维度数不符：got=%d want=%d", len(ttftFallbackCounters), len(want))
	}
	for reason, name := range want {
		c, ok := ttftFallbackCounters[reason]
		if !ok {
			t.Fatalf("缺原因映射：%q", reason)
		}
		if c.name != name {
			t.Fatalf("原因 %q 指标名不符：got=%q want=%q", reason, c.name, name)
		}
	}
}

// TestRecordLatencyPickGuardedNoop：守卫下记录调用安全 no-op——
// latency 三形态与未知/非延迟策略均不 panic；未知原因不误计。
func TestRecordLatencyPickGuardedNoop(t *testing.T) {
	recordLatencyPick(routeengine.StrategyLatencyAware)
	recordLatencyPick(routeengine.StrategyLatencyFastest)
	recordLatencyPick(routeengine.StrategyHybrid)
	recordLatencyPick(routeengine.StrategyPriority)
	recordLatencyPick(routeengine.StrategyWeighted)
	recordLatencyPick(routeengine.StrategyFailureAware)
	recordLatencyPick(routeengine.Strategy("unknown"))
}

// TestInitLatencyMetricsInjectsObserver：装配期注入不 panic（映射正确性由命名用例覆盖）。
func TestInitLatencyMetricsInjectsObserver(t *testing.T) {
	initLatencyMetrics()
}
