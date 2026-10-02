package billing

import (
	"context"
	"testing"
	"time"
)

// ---------- S-9 到期扫描（§6.4.2） ----------

func bindExpiry(t *testing.T, s Store, tenant string, effectiveAt, expiresAt int64) {
	t.Helper()
	if err := s.Plans().Bind(Subscription{
		TenantID: tenant, PlanID: "free", EffectiveAt: effectiveAt, ExpiresAt: expiresAt,
	}); err != nil {
		t.Fatalf("bind: %v", err)
	}
}

// T-30 阈值触发 + 幂等（重复扫描不重复提醒）
func TestScanExpiries_ThresholdAndDedup(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	now := time.Now().UnixNano()
	bindExpiry(t, s, "t1", now-1, now+25*nsPerDay) // 剩余 25 天 → 仅 T-30

	svc := newTestBillingService(s, nil)
	rep, err := svc.ScanExpiries(now)
	if err != nil {
		t.Fatalf("ScanExpiries err: %v", err)
	}
	if rep.Tenants != 1 || rep.Days30 != 1 || rep.Days7 != 0 || rep.Days0 != 0 || rep.Expired != 0 {
		t.Fatalf("rep = %+v, want Tenants=1 Days30=1", rep)
	}
	// 幂等：同订阅同阈值只提醒一次
	rep2, err := svc.ScanExpiries(now)
	if err != nil {
		t.Fatalf("ScanExpiries#2 err: %v", err)
	}
	if rep2.Days30 != 0 || rep2.Days7 != 0 || rep2.Days0 != 0 {
		t.Errorf("second scan rep = %+v, want all zero (dedup)", rep2)
	}
}

// 到期当日 → T-30/T-7/T-0 三档各一次
func TestScanExpiries_AtExpiryFiresAllTiers(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	now := time.Now().UnixNano()
	bindExpiry(t, s, "t1", now-1, now) // 剩余 0 天

	svc := newTestBillingService(s, nil)
	rep, _ := svc.ScanExpiries(now)
	if rep.Days30 != 1 || rep.Days7 != 1 || rep.Days0 != 1 || rep.Expired != 0 {
		t.Fatalf("rep = %+v, want Days30=Days7=Days0=1", rep)
	}
}

// 宽限（到期后 7 天）结束仍逾期 → plan_expired（幂等）
func TestScanExpiries_GraceEndedExpired(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	now := time.Now().UnixNano()
	bindExpiry(t, s, "t1", now-1, now-8*nsPerDay) // 到期后 8 天

	svc := newTestBillingService(s, nil)
	rep, _ := svc.ScanExpiries(now)
	if rep.Expired != 1 {
		t.Fatalf("rep = %+v, want Expired=1", rep)
	}
	rep2, _ := svc.ScanExpiries(now)
	if rep2.Expired != 0 {
		t.Errorf("second scan Expired = %d, want 0 (dedup)", rep2.Expired)
	}
}

// 不过期（expires_at=0）→ 跳过
func TestScanExpiries_NoExpirySkipped(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	now := time.Now().UnixNano()
	bindExpiry(t, s, "t1", now-1, 0)

	svc := newTestBillingService(s, nil)
	rep, _ := svc.ScanExpiries(now)
	if rep.Tenants != 0 {
		t.Errorf("Tenants = %d, want 0 (no expiry)", rep.Tenants)
	}
}

// 任务可运行（不 panic）
func TestScanExpiriesTask_Runs(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	now := time.Now().UnixNano()
	bindExpiry(t, s, "t1", now-1, now+25*nsPerDay)

	svc := newTestBillingService(s, nil)
	ScanExpiriesTask(svc)(context.Background())
}
