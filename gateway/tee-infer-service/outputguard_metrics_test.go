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

// ---- L2 级联指标骨架测试（M3；验证指标名/标签/类型与 §4.10 一致）----

// TestOGL2CallMetrics：L2 调用计数按 category|result 维度正确渲染。
func TestOGL2CallMetrics(t *testing.T) {
	m := newMetrics()
	m.incOGL2Call("A1-06", "hit")
	m.incOGL2Call("A1-06", "miss")
	m.incOGL2Call("A2-01", "timeout")

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()

	for _, want := range []string{
		`otpmask_output_guard_l2_call_total{category="A1-06",result="hit"} 1`,
		`otpmask_output_guard_l2_call_total{category="A1-06",result="miss"} 1`,
		`otpmask_output_guard_l2_call_total{category="A2-01",result="timeout"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("l2_call_total 缺失 %q\n---\n%s", want, body)
		}
	}
}

// TestOGL2OnlyHitMetrics：L2 专属贡献计数按 category 维度正确渲染。
func TestOGL2OnlyHitMetrics(t *testing.T) {
	m := newMetrics()
	m.incOGL2OnlyHit("A3-02")
	m.incOGL2OnlyHit("A3-02")
	m.incOGL2OnlyHit("A4-06")

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()

	for _, want := range []string{
		`otpmask_output_guard_l2_only_hit_total{category="A3-02"} 2`,
		`otpmask_output_guard_l2_only_hit_total{category="A4-06"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("l2_only_hit_total 缺失 %q\n---\n%s", want, body)
		}
	}
}

// TestOGBufferFullGauge：buffer_full counter 与 buffer_queue_depth gauge 正确渲染。
func TestOGBufferMetrics(t *testing.T) {
	m := newMetrics()
	m.incOGBufferFull()
	m.incOGBufferFull()
	m.addOGBufferQueueDepth(7)

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()

	for _, want := range []string{
		`otpmask_output_guard_buffer_full_total 2`,
		`otpmask_output_guard_buffer_queue_depth 7`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("buffer 指标缺失 %q\n---\n%s", want, body)
		}
	}
}

// TestOGL2DurationHistogram：L2 延迟 histogram 有样本时正确输出（秒口径）。
func TestOGL2DurationHistogram(t *testing.T) {
	m := newMetrics()
	m.observeOGL2DurationSeconds(0.08)
	m.observeOGL2DurationSeconds(0.3)
	m.observeOGL2DurationSeconds(3.0)

	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()

	for _, want := range []string{
		`otpmask_output_guard_l2_duration_seconds_bucket{le="0.1"} 1`,
		`otpmask_output_guard_l2_duration_seconds_bucket{le="0.5"} 2`,
		`otpmask_output_guard_l2_duration_seconds_bucket{le="5"} 3`,
		`otpmask_output_guard_l2_duration_seconds_bucket{le="+Inf"} 3`,
		`otpmask_output_guard_l2_duration_seconds_count 3`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("l2_duration_seconds 缺失 %q\n---\n%s", want, body)
		}
	}
}

// TestOGL2MetricsZeroInvisible：L2 级联指标零样本时不出现在 /metrics（与 writeCounter 行为一致）。
func TestOGL2MetricsZeroInvisible(t *testing.T) {
	m := newMetrics()
	var buf bytes.Buffer
	m.render(&buf, 0)
	body := buf.String()

	// counter 型：零样本不可见
	for _, name := range []string{
		"otpmask_output_guard_l2_call_total",
		"otpmask_output_guard_l2_only_hit_total",
	} {
		if strings.Contains(body, name) {
			t.Fatalf("零样本时 %s 不应出现在 /metrics\n---\n%s", name, body)
		}
	}
	// histogram 型：零样本不可见
	if strings.Contains(body, "otpmask_output_guard_l2_duration_seconds") {
		t.Fatalf("零样本时 l2_duration_seconds 不应出现在 /metrics\n---\n%s", body)
	}
	// gauge 型：始终可见（零值有意义，代表当前无积压）
	if !strings.Contains(body, "otpmask_output_guard_buffer_queue_depth 0") {
		t.Fatalf("buffer_queue_depth gauge 零值时也应可见\n---\n%s", body)
	}
	if !strings.Contains(body, "otpmask_output_guard_buffer_full_total 0") {
		t.Fatalf("buffer_full_total counter 零值时也应可见（非 map 型，恒输出）\n---\n%s", body)
	}
}
