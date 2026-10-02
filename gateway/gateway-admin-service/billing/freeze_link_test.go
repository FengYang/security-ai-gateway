package billing

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// ---------- 异常 → 冻结自动联动（§6.10.1） ----------

func newFreezeLinkDetector(t *testing.T, s Store) (*AnomalyDetector, *FreezeController) {
	t.Helper()
	det := NewAnomalyDetectorForStore(s, nil, nil, AnomalyConfig{}, nil)
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return 1 })
	det.SetFreezeLinker(fc)
	return det, fc
}

// 仅 critical 且 kind ∈ {spike,reconcile_diff,pricing_missing} → 冻结
func TestApplyFreezes_KindAndSeverity(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	det, fc := newFreezeLinkDetector(t, s)

	n := det.ApplyFreezes([]Anomaly{
		{Tenant: "t1", Kind: KindSpike, Severity: SeverityCritical},          // 冻结
		{Tenant: "t2", Kind: KindSpike, Severity: SeverityWarning},           // 不冻结（warning）
		{Tenant: "t3", Kind: KindPlanExpired, Severity: SeverityCritical},    // 不冻结（§6.4.2）
		{Tenant: "t4", Kind: KindPricingMissing, Severity: SeverityCritical}, // 冻结
		{Tenant: "t5", Kind: KindReconcileDiff, Severity: SeverityCritical},  // 冻结
		{Tenant: "t6", Kind: KindQuotaWarn, Severity: SeverityCritical},      // 不冻结（配额预警）
	})
	if n != 3 {
		t.Fatalf("frozen = %d, want 3", n)
	}
	want := map[string]bool{"t1": true, "t2": false, "t3": false, "t4": true, "t5": true, "t6": false}
	for tenant, exp := range want {
		got, _ := fc.Frozen(tenant)
		if got != exp {
			t.Errorf("Frozen(%s) = %v, want %v", tenant, got, exp)
		}
	}
}

// 已冻结 → 不重复冻结（保留首次 reason，B-6.10-1）
func TestApplyFreezes_SkipIfAlreadyFrozen(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	det, fc := newFreezeLinkDetector(t, s)
	if err := fc.Freeze("t1", "manual", "critical", "admin"); err != nil {
		t.Fatalf("pre-freeze: %v", err)
	}

	n := det.ApplyFreezes([]Anomaly{{Tenant: "t1", Kind: KindSpike, Severity: SeverityCritical}})
	if n != 0 {
		t.Errorf("frozen = %d, want 0 (already frozen)", n)
	}
	rec, err := s.Freezes().Get("t1")
	if err != nil || rec == nil {
		t.Fatalf("get freeze: %v", err)
	}
	if rec.Reason != "manual" {
		t.Errorf("reason = %q, want manual (首次原因应保留)", rec.Reason)
	}
}

// 未注入 FreezeLinker → no-op
func TestApplyFreezes_NoLinker(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	det := NewAnomalyDetectorForStore(s, nil, nil, AnomalyConfig{}, nil)
	if n := det.ApplyFreezes([]Anomaly{{Tenant: "t1", Kind: KindSpike, Severity: SeverityCritical}}); n != 0 {
		t.Errorf("frozen = %d, want 0 (no linker)", n)
	}
}

// 端到端：S-5 任务扫描出 critical spike → 冻结
func TestScanAnomaliesTask_FreezesCriticalSpike(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	today := dayOfNs(time.Now().UnixNano())
	for i := 1; i <= 7; i++ {
		seedLedger(t, s, LedgerEntry{
			TenantID: "t1", ModelKey: "cheap-model",
			Day:      dayOfNs(time.Now().AddDate(0, 0, -i).UnixNano()),
			TokensIn: 100, StdIn: 100, EventKey: fmt.Sprintf("b%d", i),
		})
	}
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: today,
		TokensIn: 5000, StdIn: 5000, EventKey: "spike", // ratio=50 > critical 10
	})

	det := newScanDetector(s, nil)
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return time.Now().UnixNano() })
	det.SetFreezeLinker(fc)

	ScanAnomaliesTask(det)(context.Background())
	frozen, err := fc.Frozen("t1")
	if err != nil {
		t.Fatalf("Frozen err: %v", err)
	}
	if !frozen {
		t.Fatalf("expected t1 frozen after critical spike")
	}
}
