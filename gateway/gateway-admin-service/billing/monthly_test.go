package billing

import (
	"context"
	"testing"
	"time"
)

// ---------- S-3 月结（§6.7 / §6.16） ----------

func TestPrevMonth(t *testing.T) {
	cases := map[string]string{
		"2026-10-01": "2026-09",
		"2026-01-01": "2025-12",
		"2026-03-15": "2026-02",
		"bad":        "",
	}
	for in, want := range cases {
		if got := prevMonth(in); got != want {
			t.Errorf("prevMonth(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestClockAndDayOfMonthOfNs(t *testing.T) {
	// 2026-10-01 03:10 UTC → UTC+8 = 2026-10-01 11:10
	ns := time.Date(2026, 10, 1, 3, 10, 0, 0, time.UTC).UnixNano()
	if got := clockOfNs(ns); got != "11:10" {
		t.Errorf("clockOfNs = %q, want 11:10", got)
	}
	if got := dayOfMonthOfNs(ns); got != 1 {
		t.Errorf("dayOfMonthOfNs = %d, want 1", got)
	}
}

// 月结任务结算「上月」且幂等
func TestCloseMonthlyTask_ClosesPreviousMonth(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)

	prev := prevMonth(dayOfNs(time.Now().UnixNano()))
	if prev == "" {
		t.Fatal("prevMonth empty")
	}
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: prev + "-15",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})

	CloseMonthlyTask(svc)(context.Background())
	id := "monthly-t1-" + prev
	bill, err := s.Bills().Get(id)
	if err != nil {
		t.Fatalf("Get monthly bill err: %v", err)
	}
	if bill == nil {
		t.Fatalf("monthly bill %s not created", id)
	}
	if bill.Kind != BillKindMonthly || bill.Period != prev {
		t.Errorf("bill kind/period = %s/%s, want monthly/%s", bill.Kind, bill.Period, prev)
	}

	// 幂等：重复执行不报错、账单不变
	CloseMonthlyTask(svc)(context.Background())
	bill2, _ := s.Bills().Get(id)
	if bill2 == nil || bill2.Total != bill.Total {
		t.Errorf("second run changed bill: %+v vs %+v", bill2, bill)
	}
}

// 调度器按月触发注册（不 panic；当刻不满足则不计）
func TestScheduler_MonthlySpawnNoPanic(t *testing.T) {
	cfg := ScheduleConfig{MonthlyCloseDay: 1, MonthlyCloseAt: "03:10"}
	sc := NewScheduler(cfg, SchedulerTasks{CloseMonthly: func(context.Context) {}})
	sc.Start(context.Background())
	sc.Stop()
}
