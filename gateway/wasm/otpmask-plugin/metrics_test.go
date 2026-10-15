package main

// W-1 metrics 单测：hostcall 守卫下计数 no-op 不 panic；计数器命名正确。
// TestMain 置 metricsHostGuard=true——go:wasmimport 在宿主测试进程不可调用，
// 全包测试均在守卫下运行（与 streamdone_test 纯逻辑策略一致）。

import (
	"os"
	"testing"
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
