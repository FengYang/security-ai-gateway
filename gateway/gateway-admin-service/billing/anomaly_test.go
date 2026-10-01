package billing

import (
	"context"
	"testing"
	"time"
)

// ---------- T-6.9 异常检测测试 ----------

func seedDayStd(t *testing.T, s Store, tenant, day string, std int64) {
	t.Helper()
	seedLedger(t, s, LedgerEntry{
		TenantID: tenant, ModelKey: "cheap-model", Day: day,
		TokensIn: std, StdIn: std, EventKey: "k-" + tenant + "-" + day,
	})
}

func TestScanSpike_NewTenantNoAlert(t *testing.T) {
	// T-6.9：新租户（有效基准日 < 3）不告警（A-36/B-6.9-5）
	s := openTestStore(t)
	defer s.Close()
	// 仅 2 天数据
	seedDayStd(t, s, "t1", "2026-10-01", 100)
	seedDayStd(t, s, "t1", "2026-10-02", 10000) // 突增

	d := NewAnomalyDetector(concreteLedger(s), AnomalyConfig{})
	a, err := d.ScanSpike("t1", "2026-10-02")
	if err != nil {
		t.Fatalf("ScanSpike err: %v", err)
	}
	if a != nil {
		t.Errorf("new tenant should not alert, got %+v", a)
	}
}

func TestScanSpike_Critical(t *testing.T) {
	// 7 日基准 + 当日突增 > critical ratio → critical
	s := openTestStore(t)
	defer s.Close()
	// 前 7 日各 100
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 7; i++ {
		day := base.AddDate(0, 0, i).Format("2006-01-02")
		seedDayStd(t, s, "t1", day, 100)
	}
	// 第 8 日 5000（ratio=50 > critical 10）
	spikeDay := base.AddDate(0, 0, 7).Format("2006-01-02")
	seedDayStd(t, s, "t1", spikeDay, 5000)

	d := NewAnomalyDetector(concreteLedger(s), AnomalyConfig{DailySpikeRatio: 3, SpikeCriticalRatio: 10})
	a, err := d.ScanSpike("t1", spikeDay)
	if err != nil {
		t.Fatalf("ScanSpike err: %v", err)
	}
	if a == nil {
		t.Fatal("expected critical anomaly, got nil")
	}
	if a.Severity != SeverityCritical {
		t.Errorf("severity = %q, want critical", a.Severity)
	}
	if a.Kind != KindSpike {
		t.Errorf("kind = %q, want spike", a.Kind)
	}
}

func TestScanSpike_Warning(t *testing.T) {
	// ratio 在 (daily, critical] 之间 → warning（不冻结）
	s := openTestStore(t)
	defer s.Close()
	base := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	for i := 0; i < 7; i++ {
		day := base.AddDate(0, 0, i).Format("2006-01-02")
		seedDayStd(t, s, "t1", day, 1000)
	}
	// 第 8 日 5000（ratio=5，在 3<5<=10）
	spikeDay := base.AddDate(0, 0, 7).Format("2006-01-02")
	seedDayStd(t, s, "t1", spikeDay, 5000)

	d := NewAnomalyDetector(concreteLedger(s), AnomalyConfig{DailySpikeRatio: 3, SpikeCriticalRatio: 10})
	a, _ := d.ScanSpike("t1", spikeDay)
	if a == nil {
		t.Fatal("expected warning anomaly, got nil")
	}
	if a.Severity != SeverityWarning {
		t.Errorf("severity = %q, want warning", a.Severity)
	}
}

func TestScanSpike_NoUsage(t *testing.T) {
	// 当日无用量 → 不告警
	s := openTestStore(t)
	defer s.Close()
	d := NewAnomalyDetector(concreteLedger(s), AnomalyConfig{})
	a, err := d.ScanSpike("t1", "2026-10-01")
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if a != nil {
		t.Errorf("no usage should not alert, got %+v", a)
	}
}

func TestScanQuotaWarn(t *testing.T) {
	d := NewAnomalyDetector(nil, AnomalyConfig{QuotaWarnRatio: 0.2})
	// 剩余 10% → warning
	a := d.ScanQuotaWarn("t1", "2026-10-01", 900, 1000)
	if a == nil || a.Kind != KindQuotaWarn {
		t.Errorf("expected quota_warn, got %+v", a)
	}
	// 剩余 50% → 无告警
	a = d.ScanQuotaWarn("t1", "2026-10-01", 500, 1000)
	if a != nil {
		t.Errorf("expected no alert, got %+v", a)
	}
	// limit=0（不限量）→ 无告警
	a = d.ScanQuotaWarn("t1", "2026-10-01", 500, 0)
	if a != nil {
		t.Errorf("unlimited should not alert, got %+v", a)
	}
}

// ---------- T-6.10 冻结状态机测试 ----------

func TestFreeze_StateMachine(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return 1000 })

	// 初始未冻结
	frozen, _ := fc.Frozen("t1")
	if frozen {
		t.Error("should not be frozen initially")
	}
	// 冻结
	if err := fc.Freeze("t1", "spike", "critical", "system"); err != nil {
		t.Fatalf("Freeze err: %v", err)
	}
	frozen, _ = fc.Frozen("t1")
	if !frozen {
		t.Error("should be frozen after Freeze")
	}
	// 解除
	if err := fc.Unfreeze("t1", "admin"); err != nil {
		t.Fatalf("Unfreeze err: %v", err)
	}
	frozen, _ = fc.Frozen("t1")
	if frozen {
		t.Error("should not be frozen after Unfreeze")
	}
}

func TestFreeze_ExpiredAutoRelease(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	now := int64(2000)
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return now })

	s.Freezes().Put(FreezeRecord{TenantID: "t1", Reason: "manual", Severity: "critical",
		FrozenAt: 1000, Until: 1500, By: "admin"}) // 已到期（1500 < 2000）

	frozen, _ := fc.Frozen("t1")
	if frozen {
		t.Error("expired freeze should auto-release")
	}
}

func TestFreeze_InvalidSeverity(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return 1 })
	if err := fc.Freeze("t1", "spike", "bogus", "system"); err == nil {
		t.Error("expected error for invalid severity")
	}
}

// ---------- 调度器测试 ----------

func TestScheduler_StartStop(t *testing.T) {
	var called int
	tasks := SchedulerTasks{
		ScanAnomalies: func(context.Context) { called++ },
		VerifyChain:   func(context.Context) {},
		CheckQuota:    func(context.Context) {},
		ScanExpiries:  func(context.Context) {},
		VerifyAssoc:   func(context.Context) {},
		Backfill:      func(context.Context) { called++ },
	}
	cfg := ScheduleConfig{
		AnomalyScanInterval: 10 * time.Millisecond,
		VerifyInterval:      10 * time.Millisecond,
		QuotaScanInterval:   10 * time.Millisecond,
		ExpiryScanInterval:  10 * time.Millisecond,
		VerifyAssocInterval: 10 * time.Millisecond,
	}
	sc := NewScheduler(cfg, tasks)
	sc.Start(context.Background())
	// 启动时 Backfill 立即执行一次
	time.Sleep(50 * time.Millisecond)
	sc.Stop()
	if called == 0 {
		t.Error("expected scheduled tasks to run at least once")
	}
}
