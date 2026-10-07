package billing

import (
	"context"
	"testing"
	"time"
)

// ---------- S-7 余额告警（§6.11） ----------

// B-6.11-1 去重存储：首次 true，重复 false，换周期 true
func TestQuotaAlertStore_MarkIfNew(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()

	first, err := s.AlertDedup().MarkIfNew("t1", "2026-10", 1)
	if err != nil || !first {
		t.Fatalf("first MarkIfNew = %v, err=%v, want true", first, err)
	}
	again, err := s.AlertDedup().MarkIfNew("t1", "2026-10", 2)
	if err != nil || again {
		t.Fatalf("second MarkIfNew = %v, err=%v, want false", again, err)
	}
	other, err := s.AlertDedup().MarkIfNew("t1", "2026-11", 3)
	if err != nil || !other {
		t.Errorf("new period MarkIfNew = %v, err=%v, want true", other, err)
	}
}

// B-6.11-1 通知器幂等：同 (tenant,periodKey) 仅交付一次
func TestQuotaNotifier_Dedup(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	var got []string
	n := NewQuotaNotifier(s.AlertDedup(), func(e AlertEvent) {
		got = append(got, e.Tenant+"@"+e.Period)
	}, func() int64 { return 1 })

	if err := n.WarnQuotaLow("t1", 0.10, "2026-10"); err != nil {
		t.Fatalf("warn1: %v", err)
	}
	if err := n.WarnQuotaLow("t1", 0.05, "2026-10"); err != nil { // 同键 → 跳过
		t.Fatalf("warn2: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("sink calls = %d, want 1 (dedup by periodKey)", len(got))
	}
	if err := n.WarnQuotaLow("t1", 0.05, "2026-11"); err != nil { // 换周期 → 交付
		t.Fatalf("warn3: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("sink calls = %d, want 2", len(got))
	}
}

type fakeNotifier struct{ tenants []string }

func (f *fakeNotifier) WarnQuotaLow(tenant string, rem float64, periodKey string) error {
	f.tenants = append(f.tenants, tenant)
	return nil
}

// S-7 任务：剩余低于阈值 → 通知；无套餐/不限量 → 不通知（B-6.11-3）
func TestCheckQuotaTask_Notifies(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	if err := InitDefaultPlans(s); err != nil {
		t.Fatalf("init plans: %v", err)
	}
	if err := s.Plans().Bind(Subscription{TenantID: "t1", PlanID: "free", EffectiveAt: 0}); err != nil {
		t.Fatalf("bind: %v", err)
	}
	// free 月配额 1,000,000（附录 D.1）；用 4.6M → 剩余 0 < 20% → 通知
	seedLedger(t, s, LedgerEntry{TenantID: "t1", ModelKey: "cheap-model",
		Day: dayOfNs(time.Now().UnixNano()), TokensIn: 4600000, StdIn: 4600000, EventKey: "e1"})

	det := newScanDetector(s, nil)
	fn := &fakeNotifier{}
	CheckQuotaTask(det, fn)(context.Background())
	if len(fn.tenants) != 1 || fn.tenants[0] != "t1" {
		t.Fatalf("notifier calls = %v, want [t1]", fn.tenants)
	}
}

// B-6.11-3 无套餐（不限量）→ 不告警
func TestCheckQuotaTask_NoPlan(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{TenantID: "t1", ModelKey: "cheap-model",
		Day: dayOfNs(time.Now().UnixNano()), TokensIn: 100, StdIn: 100, EventKey: "e1"})

	det := newScanDetector(s, nil)
	fn := &fakeNotifier{}
	CheckQuotaTask(det, fn)(context.Background())
	if len(fn.tenants) != 0 {
		t.Errorf("notifier calls = %v, want none (no plan)", fn.tenants)
	}
}

// B-6.11-2 已耗尽（rem=0）→ critical
func TestScanQuotaWarn_ExhaustedCritical(t *testing.T) {
	d := NewAnomalyDetector(nil, AnomalyConfig{QuotaWarnRatio: 0.2})
	a := d.ScanQuotaWarn("t1", "2026-10-01", 1000, 1000) // rem=0
	if a == nil || a.Severity != SeverityCritical {
		t.Errorf("expected critical at rem=0, got %+v", a)
	}
}
