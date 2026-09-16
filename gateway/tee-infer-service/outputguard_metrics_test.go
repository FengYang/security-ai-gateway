package main

import (
	"bytes"
	"strings"
	"testing"
)

// OG-6（指标补齐）验收单测：histogram 正确性 + 新指标可观测。

// TestHistogramObserveAndBuckets：observe 后各桶计数正确（累积），sum/count 正确。
func TestHistogramObserveAndBuckets(t *testing.T) {
	h := newHistogram([]float64{1, 5, 10, 100})
	// 样本：0.5, 3, 7, 50, 200
	h.observe(0.5) // → [1, 1, 1, 1] 累积
	h.observe(3)   // → [0, 1, 1, 1]
	h.observe(7)   // → [0, 0, 1, 1]
	h.observe(50)  // → [0, 0, 0, 1]
	h.observe(200) // → [0, 0, 0, 0]（全部不在桶内，只进 +Inf）

	if h.count != 5 {
		t.Fatalf("count 期望 5，实际 %d", h.count)
	}
	if h.sum != 0.5+3+7+50+200 {
		t.Fatalf("sum 期望 260.5，实际 %g", h.sum)
	}
	// 各独立桶计数（非累积）
	expect := []int64{1, 1, 1, 1} // 0.5在桶0，3在桶1，7在桶2，50在桶3，200不在桶里
	for i, v := range expect {
		if h.buckets[i] != v {
			t.Fatalf("桶[%d]=%d 期望 %d", i, h.buckets[i], v)
		}
	}
}

// TestHistogramRenderFormat：渲染输出符合 Prometheus text 格式（累积桶 + +Inf + sum + count）。
func TestHistogramRenderFormat(t *testing.T) {
	h := newHistogram([]float64{10, 100})
	h.observe(5)
	h.observe(50)
	h.observe(200)

	var buf bytes.Buffer
	writeHistogram(&buf, "test_metric_seconds", "测试直方图", h, "")
	out := buf.String()

	// 期望：
	//   test_metric_seconds_bucket{le="10"} 1
	//   test_metric_seconds_bucket{le="100"} 2
	//   test_metric_seconds_bucket{le="+Inf"} 3
	//   test_metric_seconds_sum 255
	//   test_metric_seconds_count 3
	for _, want := range []string{
		`test_metric_seconds_bucket{le="10"} 1`,
		`test_metric_seconds_bucket{le="100"} 2`,
		`test_metric_seconds_bucket{le="+Inf"} 3`,
		`test_metric_seconds_sum 255`,
		`test_metric_seconds_count 3`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("histogram 渲染缺失 %q\n---\n%s", want, out)
		}
	}
}

// TestHistogramZeroSamplesNoOutput：零样本时不输出（与 writeCounter 零 map 行为一致）。
func TestHistogramZeroSamplesNoOutput(t *testing.T) {
	h := newHistogram([]float64{1, 5, 10})
	var buf bytes.Buffer
	writeHistogram(&buf, "test_empty", "空直方图", h, "")
	if buf.Len() != 0 {
		t.Fatalf("零样本直方图不应输出，实际：\n%s", buf.String())
	}
}

// TestOGBlockedMaskedMetrics：blocked/masked 指标正确渲染（enforcing 模式会触发）。
func TestOGBlockedMaskedMetrics(t *testing.T) {
	m := newMetrics()
	m.incOGBlocked("A1-06", "enforcing")
	m.incOGBlocked("A1-07", "enforcing")
	m.incOGMasked("A4-06")

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()

	for _, want := range []string{
		`otpmask_output_guard_blocked_total{category="A1-06",mode="enforcing"} 1`,
		`otpmask_output_guard_blocked_total{category="A1-07",mode="enforcing"} 1`,
		`otpmask_output_guard_masked_total{category="A4-06"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("缺失指标样本 %q\n---\n%s", want, body)
		}
	}
}

// TestOGPolicyRollbackDegradedMetrics：policy_rollback / degraded 指标正确渲染。
func TestOGPolicyRollbackDegradedMetrics(t *testing.T) {
	m := newMetrics()
	m.incOGPolicyRollback("hash_mismatch")
	m.incOGDegraded("l2", "timeout")

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()

	for _, want := range []string{
		`otpmask_output_guard_policy_rollback_total{reason="hash_mismatch"} 1`,
		`otpmask_output_guard_degraded_total{backend="l2",reason="timeout"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("缺失指标样本 %q\n---\n%s", want, body)
		}
	}
}

// TestOGInflightBytesGauge：inflight_bytes gauge 增减正确。
func TestOGInflightBytesGauge(t *testing.T) {
	m := newMetrics()
	m.addOGInflightBytes(1024)
	m.addOGInflightBytes(2048)
	m.addOGInflightBytes(-512)

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()
	want := `otpmask_output_guard_inflight_bytes 2560`
	if !strings.Contains(body, want) {
		t.Fatalf("inflight_bytes 期望 2560\n---\n%s", body)
	}

	// 防御：减到 0 以下时钳位到 0。
	m.addOGInflightBytes(-100000)
	buf.Reset()
	m.render(&buf, 0)
	body = buf.String()
	if !strings.Contains(body, `otpmask_output_guard_inflight_bytes 0`) {
		t.Fatalf("inflight_bytes 不应为负\n---\n%s", body)
	}
}

// TestOGLatencyHistogram：latency_ms histogram 有样本时正确输出。
func TestOGLatencyHistogram(t *testing.T) {
	m := newMetrics()
	m.observeOGLatencyMs(2.5)
	m.observeOGLatencyMs(50)
	m.observeOGLatencyMs(2000)

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()

	for _, want := range []string{
		`otpmask_output_guard_latency_ms_bucket{le="5"} 1`,
		`otpmask_output_guard_latency_ms_bucket{le="100"} 2`,
		`otpmask_output_guard_latency_ms_bucket{le="+Inf"} 3`,
		`otpmask_output_guard_latency_ms_sum 2052.5`,
		`otpmask_output_guard_latency_ms_count 3`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("latency_ms 缺失 %q\n---\n%s", want, body)
		}
	}
}
