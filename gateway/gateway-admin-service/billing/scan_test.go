package billing

import (
	"context"
	"testing"
	"time"
)

// ---------- S-5 异常扫描（§6.9.1 四类规则） ----------

func newScanDetector(s Store, rec *Reconciler) *AnomalyDetector {
	return NewAnomalyDetectorForStore(s, NewStaticPriceTable(testPriceTable()), rec,
		AnomalyConfig{}, func() int64 { return time.Now().UnixNano() })
}

func hasAnomalyKind(out []Anomaly, kind AnomalyKind) bool {
	for _, a := range out {
		if a.Kind == kind {
			return true
		}
	}
	return false
}

// T-6.9-3 单价缺失 → critical（④）
func TestScan_PricingMissing(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{TenantID: "t1", ModelKey: "unknown-model",
		Day: "2026-10-01", TokensIn: 10, StdIn: 10, EventKey: "e1"})

	d := newScanDetector(s, nil)
	out := d.Scan([]string{"t1"}, "2026-10-01")
	if !hasAnomalyKind(out, KindPricingMissing) {
		t.Fatalf("expected pricing_missing, got %+v", out)
	}
	for _, a := range out {
		if a.Kind == KindPricingMissing && a.Severity != SeverityCritical {
			t.Errorf("pricing_missing severity = %q, want critical", a.Severity)
		}
	}
}

// T-6.9-4 配额剩余 < 阈值 → quota_warn（③）
func TestScan_QuotaWarn(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := InitDefaultPlans(s); err != nil {
		t.Fatalf("init plans: %v", err)
	}
	if err := s.Plans().Bind(Subscription{TenantID: "t1", PlanID: "free", EffectiveAt: 0}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// free 月配额 5,000,000；用 4.6M → 剩余 8% < 20% → 预警
	seedLedger(t, s, LedgerEntry{TenantID: "t1", ModelKey: "cheap-model",
		Day: "2026-10-01", TokensIn: 4600000, StdIn: 4600000, EventKey: "e1"})

	d := newScanDetector(s, nil)
	out := d.Scan([]string{"t1"}, "2026-10-01")
	if !hasAnomalyKind(out, KindQuotaWarn) {
		t.Fatalf("expected quota_warn, got %+v", out)
	}
}

// ② L2 差异 → reconcile_diff
func TestScan_ReconcileDiff(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{TenantID: "t1", ModelKey: "cheap-model",
		Day: "2026-10-01", TokensIn: 1000, StdIn: 1000, EventKey: "e1"})
	rec := NewReconciler(concreteLedger(s), &stubReader{net: NetTotals{TokensIn: 900}}, 0.001)

	d := newScanDetector(s, rec)
	out := d.Scan([]string{"t1"}, "2026-10-01")
	if !hasAnomalyKind(out, KindReconcileDiff) {
		t.Fatalf("expected reconcile_diff, got %+v", out)
	}
}

// 无异常：单日数据（spike 样本不足）+ 已知模型 + 无套餐差异
func TestScan_NoAnomaly(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{TenantID: "t1", ModelKey: "cheap-model",
		Day: "2026-10-01", TokensIn: 100, StdIn: 100, EventKey: "e1"})

	d := newScanDetector(s, nil)
	if out := d.Scan([]string{"t1"}, "2026-10-01"); len(out) != 0 {
		t.Errorf("expected no anomaly, got %+v", out)
	}
}

// S-5 任务可运行（枚举租户 + 扫描；不 panic）
func TestScanAnomaliesTask_Runs(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{TenantID: "t1", ModelKey: "unknown-model",
		Day: dayOfNs(time.Now().UnixNano()), TokensIn: 10, StdIn: 10, EventKey: "e1"})

	d := newScanDetector(s, nil)
	ScanAnomaliesTask(d)(context.Background()) // 不应 panic
}
