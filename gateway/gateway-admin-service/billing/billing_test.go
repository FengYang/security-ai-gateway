package billing

import (
	"context"
	"strings"
	"testing"
)

// ---------- 测试辅助 ----------

// stubReader 计量侧净量读取器替身。
type stubReader struct {
	net NetTotals
	err error
}

func (s *stubReader) NetAggregate(tenant, from, to string) (NetTotals, error) {
	return s.net, s.err
}

// seedLedger 向账本写入一条条目（测试用）。
func seedLedger(t *testing.T, s Store, e LedgerEntry) {
	t.Helper()
	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if e.Source == "" {
		e.Source = "pull"
	}
	if e.PriceVer == "" {
		e.PriceVer = "v1"
	}
	if e.CreatedAt == 0 {
		e.CreatedAt = 1
	}
	added, _, err := s.Ledger().Append(tx, []LedgerEntry{e})
	if err != nil {
		tx.Rollback()
		t.Fatalf("Append: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if added != 1 {
		t.Fatalf("expected 1 added, got %d", added)
	}
}

func concreteLedger(s Store) *sqliteLedgerStore {
	return s.Ledger().(*sqliteLedgerStore)
}

// newTestBillingService 构造测试用账单服务（reader=nil 表示跳过 L2）。
func newTestBillingService(s Store, reader NetMeteringReader) *BillingService {
	ledger := concreteLedger(s)
	eng := NewRatingEngine("half_up", ledger)
	rec := NewReconciler(ledger, reader, 0.001)
	return NewBillingService(s, eng, NewStaticPriceTable(testPriceTable()), rec, s.Freezes())
}

// ---------- T-6.6 日结 ----------

func TestCloseDaily_Basic(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 100000, TokensOut: 50000, Requests: 3,
		StdIn: 100000, StdOut: 50000,
		EventKey: "e1",
	})

	svc := newTestBillingService(s, nil)
	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}
	if bill.Kind != BillKindDaily {
		t.Errorf("kind = %q, want daily", bill.Kind)
	}
	if bill.Status != BillStatusIssued {
		t.Errorf("status = %q, want issued", bill.Status)
	}
	// 100000×1/千 + 50000×2/千 = 200 元 = 20000 分
	if bill.Total != Amount(20000) {
		t.Errorf("total = %d 分, want 20000", bill.Total)
	}
	if len(bill.Items) != 1 {
		t.Fatalf("items = %d, want 1", len(bill.Items))
	}
	if bill.Items[0].ModelKey != "cheap-model" {
		t.Errorf("item model = %q, want cheap-model", bill.Items[0].ModelKey)
	}
	if bill.Items[0].StandardTokens != 150000 {
		t.Errorf("standard_tokens = %d, want 150000", bill.Items[0].StandardTokens)
	}
}

func TestCloseDaily_Idempotent(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, TokensOut: 0, StdIn: 1000, StdOut: 0, EventKey: "e1",
	})
	svc := newTestBillingService(s, nil)

	b1, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("first close err: %v", err)
	}
	b2, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("second close err: %v", err)
	}
	if b1.ID != b2.ID {
		t.Errorf("idempotency: id1=%s id2=%s", b1.ID, b2.ID)
	}
	bills, _ := s.Bills().List(BillQuery{TenantID: "t1", Kind: BillKindDaily})
	if len(bills) != 1 {
		t.Errorf("bills count = %d, want 1 (idempotent)", len(bills))
	}
}

func TestCloseDaily_ReconcileBlocked(t *testing.T) {
	// L2 diff>0 → 不出账（硬门禁 M1）
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, TokensOut: 0, StdIn: 1000, StdOut: 0, EventKey: "e1",
	})

	// reader 返回不匹配的净量（账本 1000，计量侧 900 → diff 100）
	reader := &stubReader{net: NetTotals{TokensIn: 900, Requests: 1}}
	svc := newTestBillingService(s, reader)

	_, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err == nil {
		t.Fatal("expected reconcile block error, got nil")
	}
	if !strings.Contains(err.Error(), "L2 reconcile") {
		t.Errorf("err = %v, want L2 reconcile block", err)
	}
	// 不应产生账单
	bills, _ := s.Bills().List(BillQuery{TenantID: "t1"})
	if len(bills) != 0 {
		t.Errorf("blocked close produced %d bills, want 0", len(bills))
	}
}

func TestCloseDaily_ReconcilePass(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, TokensOut: 500, StdIn: 1000, StdOut: 500, EventKey: "e1",
	})
	// 计量侧与账本一致 → diff=0 → 通过
	reader := &stubReader{net: NetTotals{TokensIn: 1000, TokensOut: 500, Requests: 1}}
	svc := newTestBillingService(s, reader)

	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err != nil {
		t.Fatalf("expected pass, got err: %v", err)
	}
	if bill.Status != BillStatusIssued {
		t.Errorf("status = %q, want issued", bill.Status)
	}
}

func TestCloseDaily_Frozen(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01",
		TokensIn: 1000, StdIn: 1000, EventKey: "e1",
	})
	// 冻结租户
	if err := s.Freezes().Put(FreezeRecord{
		TenantID: "t1", Reason: "spike", Severity: "critical", FrozenAt: 1, Until: 0, By: "system",
	}); err != nil {
		t.Fatalf("freeze put err: %v", err)
	}
	svc := newTestBillingService(s, nil)
	_, err := svc.CloseDaily(context.Background(), "t1", "2026-10-01")
	if err == nil {
		t.Fatal("expected ErrFrozen, got nil")
	}
}

// ---------- T-6.7 月结 + 超额单列 ----------

func TestCloseMonthly_WithOverage(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	InitDefaultPlans(s)

	// 套餐 pro: charge，MonthlyTokens=500M；这里绑定一个自定义小额度套餐便于触发超额
	chargePlan := &Plan{ID: "charge-small", Name: "Charge Small", MonthlyTokens: 1000,
		OverQuota: "charge", PayMode: "postpaid", CacheTier: "none"}
	if err := s.Plans().PutPlan(chargePlan); err != nil {
		t.Fatalf("put plan err: %v", err)
	}
	if err := s.Plans().Bind(Subscription{TenantID: "t1", PlanID: "charge-small", EffectiveAt: 1, BoundBy: "a"}); err != nil {
		t.Fatalf("bind err: %v", err)
	}

	// 用量 1200 标准 token（超额 200）
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-05",
		TokensIn: 1200, StdIn: 1200, EventKey: "e1",
	})

	svc := newTestBillingService(s, nil)
	bill, err := svc.CloseMonthly(context.Background(), "t1", "2026-10")
	if err != nil {
		t.Fatalf("CloseMonthly err: %v", err)
	}
	if bill.Kind != BillKindMonthly {
		t.Errorf("kind = %q, want monthly", bill.Kind)
	}

	// 应有独立超额账单
	overage, _ := s.Bills().Get("overage-t1-2026-10")
	if overage == nil {
		t.Fatal("expected overage bill, got nil")
	}
	if overage.Kind != BillKindOverage {
		t.Errorf("overage kind = %q, want overage", overage.Kind)
	}
	// 超额 200 × 1元/千 = 0.2 元 = 20 分
	if overage.Total != Amount(20) {
		t.Errorf("overage total = %d 分, want 20", overage.Total)
	}
}

func TestCloseMonthly_NoOverageForRejectPlan(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	InitDefaultPlans(s)

	rejectPlan := &Plan{ID: "reject-small", Name: "Reject Small", MonthlyTokens: 1000,
		OverQuota: "reject", PayMode: "postpaid", CacheTier: "none"}
	s.Plans().PutPlan(rejectPlan)
	s.Plans().Bind(Subscription{TenantID: "t1", PlanID: "reject-small", EffectiveAt: 1, BoundBy: "a"})

	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-05",
		TokensIn: 1200, StdIn: 1200, EventKey: "e1",
	})

	svc := newTestBillingService(s, nil)
	if _, err := svc.CloseMonthly(context.Background(), "t1", "2026-10"); err != nil {
		t.Fatalf("CloseMonthly err: %v", err)
	}
	overage, _ := s.Bills().Get("overage-t1-2026-10")
	if overage != nil {
		t.Errorf("reject plan should not produce overage bill, got %+v", overage)
	}
}

// ---------- 导出 ----------

func TestExportCSV(t *testing.T) {
	bill := &Bill{
		ID: "daily-t1-2026-10-01", TenantID: "t1", Kind: BillKindDaily,
		Period: "2026-10-01", Total: 20000, Currency: "CNY", PriceVersion: "v1",
		Status: BillStatusIssued, GeneratedAt: 123,
		Items: []BillItem{
			{ModelKey: "cheap-model", StandardTokens: 150000, TokensIn: 100000, TokensOut: 50000, Amount: 20000},
		},
	}
	data, mime, err := ExportCSV(bill)
	if err != nil {
		t.Fatalf("ExportCSV err: %v", err)
	}
	if !strings.HasPrefix(mime, "text/csv") {
		t.Errorf("mime = %q, want text/csv", mime)
	}
	content := string(data)
	if !strings.Contains(content, "cheap-model") {
		t.Error("CSV missing model_key")
	}
	if !strings.Contains(content, "20000") {
		t.Error("CSV missing amount")
	}
	// BOM 前缀
	if !strings.HasPrefix(content, "\xEF\xBB\xBF") {
		t.Error("CSV missing UTF-8 BOM")
	}
}

// ---------- monthRange ----------

func TestMonthRange(t *testing.T) {
	tests := []struct {
		month     string
		wantFirst string
		wantLast  string
	}{
		{"2026-10", "2026-10-01", "2026-10-31"},
		{"2026-02", "2026-02-01", "2026-02-28"},
		{"2024-02", "2024-02-01", "2024-02-29"}, // 闰年
		{"2026-10-15", "2026-10-01", "2026-10-31"},
	}
	for _, tt := range tests {
		first, last := monthRange(tt.month)
		if first != tt.wantFirst || last != tt.wantLast {
			t.Errorf("monthRange(%q) = (%s, %s), want (%s, %s)",
				tt.month, first, last, tt.wantFirst, tt.wantLast)
		}
	}
}
