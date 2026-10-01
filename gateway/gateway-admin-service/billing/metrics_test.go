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
	IncLedgerEntries(1)
	SetLedgerHeadSeq(5)
	SetChainBroken(true)
	IncPull("ok")
	IncPricingMissing("m1")
	IncFreeze()
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
