package billing

import (
	"bytes"
	"strings"
	"testing"
)

// ---------- T10 指标渲染测试 ----------

func TestRegistry_RenderCounter(t *testing.T) {
	r := NewRegistry()
	r.IncCounter("test_counter_total", map[string]string{"a": "b"}, 3)
	r.IncCounter("test_counter_total", map[string]string{"a": "b"}, 2)
	r.IncCounter("test_counter_total", map[string]string{"a": "c"}, 1)

	var buf bytes.Buffer
	r.Render(&buf)
	out := buf.String()

	if !strings.Contains(out, "# TYPE test_counter_total counter") {
		t.Errorf("missing TYPE line:\n%s", out)
	}
	if !strings.Contains(out, `test_counter_total{a="b"} 5`) {
		t.Errorf("missing b series:\n%s", out)
	}
	if !strings.Contains(out, `test_counter_total{a="c"} 1`) {
		t.Errorf("missing c series:\n%s", out)
	}
}

func TestRegistry_RenderGauge(t *testing.T) {
	r := NewRegistry()
	r.SetGauge("test_gauge", nil, 42)
	r.SetGauge("test_gauge", nil, 7) // 覆盖

	var buf bytes.Buffer
	r.Render(&buf)
	out := buf.String()
	if !strings.Contains(out, "# TYPE test_gauge gauge") {
		t.Errorf("missing gauge TYPE:\n%s", out)
	}
	if !strings.Contains(out, "test_gauge 7") {
		t.Errorf("gauge should be overwritten to 7:\n%s", out)
	}
}

func TestRegistry_RenderHistogram(t *testing.T) {
	r := NewRegistry()
	r.ObserveHistogram("test_hist_seconds", nil, 0.03)
	r.ObserveHistogram("test_hist_seconds", nil, 0.5)

	var buf bytes.Buffer
	r.Render(&buf)
	out := buf.String()
	if !strings.Contains(out, "# TYPE test_hist_seconds histogram") {
		t.Errorf("missing histogram TYPE:\n%s", out)
	}
	if !strings.Contains(out, "test_hist_seconds_count 2") {
		t.Errorf("missing count:\n%s", out)
	}
	if !strings.Contains(out, `le="+Inf"`) {
		t.Errorf("missing +Inf bucket:\n%s", out)
	}
}

func TestRenderMetrics_EmptyWhenDisabled(t *testing.T) {
	// billing 关闭时注册表为空 → 渲染 0 字节（R-1/M10 逐字节一致）
	r := NewRegistry()
	var buf bytes.Buffer
	r.Render(&buf)
	if buf.Len() != 0 {
		t.Errorf("empty registry rendered %d bytes, want 0", buf.Len())
	}
}

func TestMetricsProducers(t *testing.T) {
	// 生产者最小验证：调用不 panic 且默认注册表出现样本
	defer SetChainBroken(false) // chain_broken 为进程级标志，测后复位避免污染出账门禁
	IncLedgerEntries(1)
	SetLedgerHeadSeq(5)
	SetChainBroken(true)
	IncPull("ok")
	IncPricingMissing("m1")
	IncFreeze("reconcile_diff", "critical")
	IncExport("csv", "ok")
	IncSignatureVerify("valid")
	IncAssocVerify("pass")
	IncAnomaly("spike", "critical")
	IncPlanExpiring(7)
	IncLedgerError("append")
	IncClockSkew()
	IncBillIssued("daily")
	SetReconcileDiff("t1", 0.001)
	SetPlatformRetryTokens("t1", 100)
	ObserveClose("daily", 0.1)
	ObserveAPI("bills", 0.02)
	IncBillingRequests("GET", "200")

	var buf bytes.Buffer
	DefaultMetrics.Render(&buf)
	out := buf.String()
	for _, name := range []string{
		"gateway_admin_billing_ledger_entries_total",
		"gateway_admin_billing_ledger_head_seq",
		"gateway_admin_billing_ledger_chain_broken",
		"gateway_admin_billing_freeze_total",
		"gateway_admin_billing_pricing_missing_total",
		"gateway_admin_billing_assoc_verify_total",
		"gateway_admin_billing_plan_expiring_total",
		"gateway_admin_billing_ledger_error_total",
		"gateway_admin_billing_requests_total",
	} {
		if !strings.Contains(out, name) {
			t.Errorf("metric %s not rendered:\n%s", name, out)
		}
	}
	// MET-004：#14 必带 kind/severity 标签（§9.1；供 §10.4 REC-2b 按标签检索）。
	// 只断言标签组合（DefaultMetrics 为进程级共享，计数值受前序用例影响，不断言具体值）。
	if !strings.Contains(out, `gateway_admin_billing_freeze_total{kind="reconcile_diff",severity="critical"}`) {
		t.Errorf("freeze_total 缺 kind/severity 标签:\n%s", out)
	}
}

func TestLedger_MetricsOnAppend(t *testing.T) {
	// 集成：账本 Append 触发指标 #2/#3（唯一生产者）
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "m1", Day: "2026-10-01", TokensIn: 1, StdIn: 1, EventKey: "k1",
	})
	head, _ := s.Ledger().Head()
	if head.Seq != 1 {
		t.Fatalf("head seq = %d, want 1", head.Seq)
	}
	// 默认注册表应已有账本条目样本
	var buf bytes.Buffer
	DefaultMetrics.Render(&buf)
	if !strings.Contains(buf.String(), "gateway_admin_billing_ledger_entries_total") {
		t.Error("expected ledger entries metric recorded by Append")
	}
}

// ---------- 自定义直方图桶 ----------

// TestRegistry_CustomHistogramBuckets 登记自定义桶后，观测值按自定义边界累积。
func TestRegistry_CustomHistogramBuckets(t *testing.T) {
	r := NewRegistry()
	r.RegisterHistogram("test_hist_custom", []float64{1, 5, 60})
	r.ObserveHistogram("test_hist_custom", nil, 30) // 落 (5,60]

	var buf bytes.Buffer
	r.Render(&buf)
	out := buf.String()
	for _, want := range []string{
		`test_hist_custom_bucket{le="1"} 0`,
		`test_hist_custom_bucket{le="5"} 0`,
		`test_hist_custom_bucket{le="60"} 1`,
		`test_hist_custom_bucket{le="+Inf"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("缺 %q（自定义桶未生效）:\n%s", want, out)
		}
	}
	// 未登记 → 仍用默认桶（上限 10，无 le=60）
	r2 := NewRegistry()
	r2.ObserveHistogram("test_hist_default", nil, 30)
	var buf2 bytes.Buffer
	r2.Render(&buf2)
	if strings.Contains(buf2.String(), `le="60"`) {
		t.Errorf("未登记不应含自定义桶 le=60:\n%s", buf2.String())
	}
	if !strings.Contains(buf2.String(), `le="10"`) {
		t.Errorf("未登记应含默认桶 le=10:\n%s", buf2.String())
	}
}

// TestObserveQuotaApply_CustomBuckets M6（#13）已登记自定义桶（默认上限 10s < SLA 60s）。
func TestObserveQuotaApply_CustomBuckets(t *testing.T) {
	ObserveQuotaApply(30) // > 默认上限 10s
	out := renderDefaultMetrics()
	if !strings.Contains(out, `gateway_admin_billing_quota_apply_duration_seconds_bucket{le="60"} `) {
		t.Errorf("M6 直方图应含自定义桶 le=60（否则 >10s 全落 +Inf）:\n%s", out)
	}
}

// TestObserveClose_CustomBuckets M3/M4（#7）已登记自定义桶（分钟级预算，默认上限 10s 远不够）。
func TestObserveClose_CustomBuckets(t *testing.T) {
	ObserveClose("daily", 900) // 15min > 默认上限 10s
	out := renderDefaultMetrics()
	if !strings.Contains(out, `gateway_admin_billing_close_duration_seconds_bucket{kind="daily",le="1200"} `) {
		t.Errorf("close_duration 应含自定义桶 le=1200（日结预算 20min 边界）:\n%s", out)
	}
}
