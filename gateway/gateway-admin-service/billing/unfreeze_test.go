package billing

import (
	"testing"
)

// ---------- 自动解冻（B-6.10-2：仅 reconcile_diff 触发者，对账恢复即解冻） ----------

func freezeWith(t *testing.T, s Store, tenant, reason string) *FreezeController {
	t.Helper()
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return 1 })
	if err := fc.Freeze(tenant, reason, string(SeverityCritical), "system"); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	return fc
}

func seedReconcilePass(t *testing.T, s Store) *Reconciler {
	t.Helper()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, Requests: 1, EventKey: "e1",
	})
	return NewReconciler(concreteLedger(s), &stubReader{
		net: NetTotals{TokensIn: 1000, Requests: 1}, // 与账本一致 → L2 Pass
	}, 0.001)
}

// 对账恢复 → 解冻（reason=reconcile_diff）
func TestAutoUnfreeze_ReconcileRecovered(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	det := newScanDetector(s, seedReconcilePass(t, s))
	fc := freezeWith(t, s, "t1", string(KindReconcileDiff))
	det.SetFreezeLinker(fc)

	if n := det.AutoUnfreeze("2026-10-01"); n != 1 {
		t.Fatalf("unfrozen = %d, want 1", n)
	}
	if frozen, _ := fc.Frozen("t1"); frozen {
		t.Error("t1 should be auto-unfrozen after reconcile recovery")
	}
}

// 对账仍未恢复 → 保持冻结
func TestAutoUnfreeze_StillMismatched(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, Requests: 1, EventKey: "e1",
	})
	rec := NewReconciler(concreteLedger(s), &stubReader{
		net: NetTotals{TokensIn: 900, Requests: 1}, // 仍不一致
	}, 0.001)
	det := newScanDetector(s, rec)
	fc := freezeWith(t, s, "t1", string(KindReconcileDiff))
	det.SetFreezeLinker(fc)

	if n := det.AutoUnfreeze("2026-10-01"); n != 0 {
		t.Errorf("unfrozen = %d, want 0 (still mismatched)", n)
	}
	if frozen, _ := fc.Frozen("t1"); !frozen {
		t.Error("t1 should stay frozen while mismatch persists")
	}
}

// manual 冻结 → 不自动解冻（须人工）
func TestAutoUnfreeze_ManualKept(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	det := newScanDetector(s, seedReconcilePass(t, s))
	fc := freezeWith(t, s, "t1", "manual") // 非 reconcile_diff
	det.SetFreezeLinker(fc)

	if n := det.AutoUnfreeze("2026-10-01"); n != 0 {
		t.Errorf("unfrozen = %d, want 0 (manual 须人工)", n)
	}
	if frozen, _ := fc.Frozen("t1"); !frozen {
		t.Error("manual freeze should persist")
	}
}

// pricing_missing 冻结 → 不自动解冻（须人工）
func TestAutoUnfreeze_PricingMissingKept(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	det := newScanDetector(s, seedReconcilePass(t, s))
	fc := freezeWith(t, s, "t1", string(KindPricingMissing))
	det.SetFreezeLinker(fc)

	if n := det.AutoUnfreeze("2026-10-01"); n != 0 {
		t.Errorf("unfrozen = %d, want 0 (pricing_missing 须人工)", n)
	}
	if frozen, _ := fc.Frozen("t1"); !frozen {
		t.Error("pricing_missing freeze should persist")
	}
}

// 未注入 reconciler → no-op
func TestAutoUnfreeze_NoReconciler(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	det := NewAnomalyDetectorForStore(s, nil, nil, AnomalyConfig{}, nil) // rec=nil
	fc := freezeWith(t, s, "t1", string(KindReconcileDiff))
	det.SetFreezeLinker(fc)

	if n := det.AutoUnfreeze("2026-10-01"); n != 0 {
		t.Errorf("unfrozen = %d, want 0 (no reconciler)", n)
	}
}
