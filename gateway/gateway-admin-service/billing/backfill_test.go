package billing

import (
	"context"
	"testing"
	"time"
)

// ---------- S-8 缺口扫描（补账，§6.6.2）单测 ----------

// newBackfillService 构造启用月累计缓存的计费服务（与 main 接线一致）。
func newBackfillService(s Store) *BillingService {
	return newTestBillingService(s, nil)
}

func TestBackfillGaps_ClosesMissingDays(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	for _, e := range []LedgerEntry{
		{TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01", TokensIn: 1000, StdIn: 1000, EventKey: "a"},
		{TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-02", TokensIn: 500, StdIn: 500, EventKey: "b"},
	} {
		seedLedger(t, s, e)
	}
	svc := newBackfillService(s)

	rep, err := svc.BackfillGaps(context.Background(), "2026-10-03", 7)
	if err != nil {
		t.Fatalf("BackfillGaps err: %v", err)
	}
	if rep.Tenants != 1 || rep.Missing != 2 || rep.Closed != 2 || rep.Failed != 0 {
		t.Fatalf("report = %+v, want {Tenants:1 Missing:2 Closed:2 Failed:0}", rep)
	}
	bills, _ := s.Bills().List(BillQuery{TenantID: "t1", Kind: BillKindDaily})
	if len(bills) != 2 {
		t.Fatalf("bills = %d, want 2", len(bills))
	}
}

func TestBackfillGaps_Idempotent(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "a",
	})
	svc := newBackfillService(s)

	if _, err := svc.BackfillGaps(context.Background(), "2026-10-02", 7); err != nil {
		t.Fatal(err)
	}
	// 第二轮：已出账 → 无缺口（幂等）
	rep, err := svc.BackfillGaps(context.Background(), "2026-10-02", 7)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Missing != 0 || rep.Closed != 0 {
		t.Errorf("second run = %+v, want no gaps", rep)
	}
	bills, _ := s.Bills().List(BillQuery{TenantID: "t1", Kind: BillKindDaily})
	if len(bills) != 1 {
		t.Errorf("bills = %d, want 1（不重复出账）", len(bills))
	}
}

func TestBackfillGaps_SkipsTodayAndFuture(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	for _, e := range []LedgerEntry{
		{TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-02", TokensIn: 1000, StdIn: 1000, EventKey: "today"},
		{TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-03", TokensIn: 1000, StdIn: 1000, EventKey: "future"},
	} {
		seedLedger(t, s, e)
	}
	svc := newBackfillService(s)
	// today = 2026-10-02 → 当日与未来日均不出账
	rep, err := svc.BackfillGaps(context.Background(), "2026-10-02", 7)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Missing != 0 || rep.Closed != 0 {
		t.Errorf("report = %+v, want no closure for today/future", rep)
	}
}

func TestBackfillGaps_RespectsLookback(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	for _, e := range []LedgerEntry{
		{TenantID: "t1", ModelKey: "cheap-model", Day: "2026-09-01", TokensIn: 1000, StdIn: 1000, EventKey: "old"},
		{TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01", TokensIn: 1000, StdIn: 1000, EventKey: "new"},
	} {
		seedLedger(t, s, e)
	}
	svc := newBackfillService(s)
	// today=2026-10-02，回看 3 天 → 仅 2026-10-01 在内（09-01 超窗）
	rep, err := svc.BackfillGaps(context.Background(), "2026-10-02", 3)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Missing != 1 || rep.Closed != 1 {
		t.Fatalf("report = %+v, want {Missing:1 Closed:1}", rep)
	}
	bills, _ := s.Bills().List(BillQuery{TenantID: "t1", Kind: BillKindDaily})
	if len(bills) != 1 || bills[0].Period != "2026-10-01" {
		t.Fatalf("bills = %+v, want only 2026-10-01", bills)
	}
}

func TestBackfillGaps_FrozenTenantSkipped(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "a",
	})
	svc := newBackfillService(s)
	// 冻结租户 → 不出账（B-6.10-3：解冻后由下轮补出）
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return 1 })
	if err := fc.Freeze("t1", "manual", "critical", "ops"); err != nil {
		t.Fatalf("freeze err: %v", err)
	}
	rep, err := svc.BackfillGaps(context.Background(), "2026-10-02", 7)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Missing != 1 || rep.Closed != 0 || rep.Skipped != 1 {
		t.Fatalf("report = %+v, want {Missing:1 Closed:0 Skipped:1}", rep)
	}
}

func TestBackfillGaps_UnfrozenThenBackfilled(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "a",
	})
	svc := newBackfillService(s)
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return 1 })
	if err := fc.Freeze("t1", "manual", "critical", "ops"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.BackfillGaps(context.Background(), "2026-10-02", 7); err != nil {
		t.Fatal(err)
	}
	if err := fc.Unfreeze("t1", "ops"); err != nil {
		t.Fatal(err)
	}
	// 解冻后补账成功（B-6.10-3）
	rep, err := svc.BackfillGaps(context.Background(), "2026-10-02", 7)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Closed != 1 {
		t.Errorf("after unfreeze = %+v, want Closed:1", rep)
	}
}

func TestBackfillGaps_EmptyLedgerNoop(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newBackfillService(s)
	rep, err := svc.BackfillGaps(context.Background(), "2026-10-02", 7)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Tenants != 0 || rep.Missing != 0 {
		t.Errorf("report = %+v, want empty", rep)
	}
}

// TestBackfillTask_NoPanic 任务包一层后仍安全（含枚举失败路径）。
//
// 【时间炸弹修复】原用例依赖墙上时钟：任务内 today = 今天（UTC+8），账本种子日
// 固定为 2026-10-01，一旦今天越过 2026-10-08，种子日即超出 7 天回看窗口 →
// 用例恒失败（与产品缺陷无关）。现改为**注入确定性时钟**：today 固定 2026-10-03，
// 回看窗口 = [2026-09-26, 2026-10-03)，稳定覆盖种子日 2026-10-01。
func TestBackfillTask_NoPanic(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "a",
	})
	svc := newBackfillService(s)
	fixedNow := func() time.Time { return time.Date(2026, 10, 3, 0, 0, 0, 0, time.UTC) }
	task := BackfillTaskWithClock(svc, 7, fixedNow)
	task(context.Background()) // 首次触发
	task(context.Background()) // 幂等重入
	bills, _ := s.Bills().List(BillQuery{TenantID: "t1", Kind: BillKindDaily})
	if len(bills) != 1 {
		t.Errorf("bills = %d, want 1", len(bills))
	}
}
