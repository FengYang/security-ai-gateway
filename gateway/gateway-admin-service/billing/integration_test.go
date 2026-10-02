package billing

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// ---------- INT-1 拉取 → 入账 → 日结 ----------

func TestINT1_PullIngestCloseDaily(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)

	win := &UsageWindow{
		FromNs: 1, ToNs: 2,
		Tenants: map[string]*TenantAgg{
			"t1": {
				TokensIn: 100000, TokensOut: 50000, Requests: 4,
				ByModel: map[string]*ModelAgg{
					"cheap-model": {TokensIn: 100000, TokensOut: 50000, Requests: 4},
				},
			},
		},
		Source: "pull", EventKey: "pull-1-2",
	}
	added, err := svc.IngestWindow(context.Background(), win, SyncModePull)
	if err != nil {
		t.Fatalf("IngestWindow err: %v", err)
	}
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}

	// 账本 == 注入用量
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Fatalf("ledger entries = %d, want 1", len(entries))
	}
	if entries[0].TokensIn != 100000 || entries[0].TokensOut != 50000 {
		t.Errorf("ledger tokens = (%d,%d), want (100000,50000)",
			entries[0].TokensIn, entries[0].TokensOut)
	}
	// std 锁定
	if entries[0].StdIn != 100000 || entries[0].StdOut != 50000 {
		t.Errorf("locked std = (%d,%d), want (100000,50000) [A-32]",
			entries[0].StdIn, entries[0].StdOut)
	}
	if entries[0].PriceVer != "v1" {
		t.Errorf("price_ver = %q, want v1", entries[0].PriceVer)
	}

	// 日结金额 == 手算（100k×1/千 + 50k×2/千 = 200 元 = 20000 分）
	day := entries[0].Day
	bill, err := svc.CloseDaily(context.Background(), "t1", day)
	if err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}
	if bill.Total != Amount(20000) {
		t.Errorf("bill total = %d 分, want 20000", bill.Total)
	}
}

// ---------- INT-2 单写者互斥（A-12/R-30） ----------

func TestINT2_SingleWriterExclusive(t *testing.T) {
	win := &UsageWindow{
		Tenants: map[string]*TenantAgg{"t1": {TokensIn: 100, ByModel: map[string]*ModelAgg{"cheap-model": {TokensIn: 100}}}},
		Source:  "push", EventKey: "push-x",
	}

	// pull 模式：push 不写账
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	added, err := svc.IngestWindow(context.Background(), win, SyncModePull)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if added != 0 {
		t.Errorf("pull mode: push source wrote %d entries, want 0 (A-12)", added)
	}
	entries, _ := s.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 0 {
		t.Errorf("pull mode: ledger has %d entries from push, want 0", len(entries))
	}

	// push 模式：push 写账
	s2 := openTestStore(t)
	defer s2.Close()
	svc2 := newTestBillingService(s2, nil)
	added2, err := svc2.IngestWindow(context.Background(), win, SyncModePush)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if added2 != 1 {
		t.Errorf("push mode: push source wrote %d entries, want 1", added2)
	}
}

func TestINT2_PushModePullDoesNotWrite(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	win := &UsageWindow{
		Tenants: map[string]*TenantAgg{"t1": {TokensIn: 100, ByModel: map[string]*ModelAgg{"cheap-model": {TokensIn: 100}}}},
		Source:  "pull", EventKey: "pull-x",
	}
	added, _ := svc.IngestWindow(context.Background(), win, SyncModePush)
	if added != 0 {
		t.Errorf("push mode: pull source wrote %d entries, want 0 (R-30)", added)
	}
}

// ---------- INT-3 套餐绑定 → 编译（含 month 窗口） ----------

func TestINT3_PlanCompileMonthWindow(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	InitDefaultPlans(s)

	plan, err := s.Plans().GetPlan("basic")
	if err != nil || plan == nil {
		t.Fatalf("GetPlan basic err: %v", err)
	}
	c := NewQuotaCompiler()
	updates, err := c.Compile("t1", plan)
	if err != nil {
		t.Fatalf("Compile err: %v", err)
	}
	found := false
	for _, l := range updates[0].Limits {
		if l.Window == "month" && l.MaxTokens == plan.MonthlyTokens {
			found = true
		}
	}
	if !found {
		t.Errorf("compiled limits missing month window: %+v", updates[0].Limits)
	}
}

// ---------- INT-4 冻结 → 出账拒绝 → 解冻 → 补账 ----------

func TestINT4_FreezeBlocksThenBackfill(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)

	// 冻结 → 出账被拒
	if err := s.Freezes().Put(FreezeRecord{TenantID: "t1", Reason: "spike", Severity: "critical", FrozenAt: 1}); err != nil {
		t.Fatalf("freeze err: %v", err)
	}
	if _, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01"); err == nil {
		t.Fatal("expected frozen close to be rejected")
	}

	// 解冻 → 补账
	fc := NewFreezeController(s.Freezes(), nil, func() int64 { return 2 })
	if err := fc.Unfreeze("t1", "admin"); err != nil {
		t.Fatalf("unfreeze err: %v", err)
	}
	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("close after unfreeze err: %v", err)
	}
	if bill.Status != BillStatusIssued {
		t.Errorf("status = %q, want issued", bill.Status)
	}
}

// ---------- INT-5 L2 不一致 → 不出账 ----------

func TestINT5_ReconcileGateBlocks(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 100000, StdIn: 100000, Requests: 1, EventKey: "e1",
	})
	// 仅入量差 100（请求数一致）→ diff>0 不出账；gateL2 不自动冻结（冻结由 S-5 判定，A-22）
	reader := &stubReader{net: NetTotals{TokensIn: 99900, Requests: 1}}
	svc := newTestBillingService(s, reader)

	if _, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01"); err == nil {
		t.Fatal("expected reconcile block")
	}
	// 不冻结（ratio ≤ 0.1%）
	frozen, _ := NewFreezeController(s.Freezes(), nil, func() int64 { return 1 }).Frozen("t1")
	if frozen {
		t.Error("0.05%% diff should NOT freeze (A-22)")
	}
}

// ---------- INT-6 导出内容 ----------

func TestINT6_ExportRoundTrip(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)
	bill, _ := svc.CloseDaily(context.Background(), "t1", "2026-10-01")

	data, _, err := ExportCSV(bill)
	if err != nil {
		t.Fatalf("export err: %v", err)
	}
	content := string(data)
	for _, want := range []string{bill.ID, "cheap-model", bill.PriceVersion, bill.Status} {
		if !strings.Contains(content, want) {
			t.Errorf("CSV missing %q:\n%s", want, content)
		}
	}
}

// ---------- INT-7 重启缺口扫描（持久化 → 重开出账） ----------

func TestINT7_RestartBackfill(t *testing.T) {
	dir := t.TempDir()
	dsn := filepath.Join(dir, "billing.db")

	// 第一次打开：入账
	s1, err := OpenSQLiteStore(dsn, true)
	if err != nil {
		t.Fatalf("open1 err: %v", err)
	}
	seedLedger(t, s1, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})
	if err := s1.Close(); err != nil {
		t.Fatalf("close1 err: %v", err)
	}

	// 重新打开（模拟重启）：账本仍在，补出日账
	s2, err := OpenSQLiteStore(dsn, true)
	if err != nil {
		t.Fatalf("open2 err: %v", err)
	}
	defer s2.Close()
	entries, _ := s2.Ledger().Range(LedgerQuery{TenantID: "t1"})
	if len(entries) != 1 {
		t.Fatalf("after restart ledger entries = %d, want 1", len(entries))
	}
	// 链完好
	if broken, _ := s2.Ledger().Verify(); broken != -1 {
		t.Errorf("chain broken at %d after restart", broken)
	}
	svc := newTestBillingService(s2, nil)
	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("backfill close err: %v", err)
	}
	if bill.Total != Amount(100) { // 1000 × 1元/千 = 1 元 = 100 分
		t.Errorf("bill total = %d, want 100", bill.Total)
	}
}
