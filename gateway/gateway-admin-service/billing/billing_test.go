package billing

import (
	"bytes"
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
	eng, monthCache := NewRatingEngineWithCache("half_up", ledger) // A-37
	rec := NewReconciler(ledger, reader, 0.001)
	svc := NewBillingService(s, eng, NewStaticPriceTable(testPriceTable()), rec, s.Freezes())
	svc.SetMonthStdCache(monthCache)
	return svc
}

// ---------- T-6.6 日结 ----------

// ★ A4：账单明细行取整须遵循配置的舍入法（floor 时明细/总额=1 分，而非硬编码 half_up 的 2 分）。
func TestBuildItems_HonorsConfiguredRounding(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	// cheap-model：InPer1K=1.0；std_in=15 → 亚分 = 15×1×100 = 1500。
	// floor → 1500/1000 = 1 分；half_up → (1500+500)/1000 = 2 分。
	agg := &UsageAgg{TenantID: "t1", Period: "2026-09-15",
		ByModel: map[string]*ModelStd{"cheap-model": {StdIn: 15}}}

	floorSvc := NewBillingService(s, NewRatingEngine("floor", nil),
		NewStaticPriceTable(testPriceTable()), nil, s.Freezes())
	items, total, err := floorSvc.buildItems(agg, testPriceTable())
	if err != nil {
		t.Fatalf("buildItems(floor): %v", err)
	}
	if len(items) != 1 || items[0].Amount != 1 || total != 1 {
		t.Fatalf("floor 应明细/总额=1/1，实际 items=%+v total=%d", items, total)
	}

	halfSvc := NewBillingService(s, NewRatingEngine("half_up", nil),
		NewStaticPriceTable(testPriceTable()), nil, s.Freezes())
	items2, total2, err := halfSvc.buildItems(agg, testPriceTable())
	if err != nil {
		t.Fatalf("buildItems(half_up): %v", err)
	}
	if len(items2) != 1 || items2[0].Amount != 2 || total2 != 2 {
		t.Fatalf("half_up 应明细/总额=2/2，实际 items=%+v total=%d", items2, total2)
	}
}

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

// wrapRating 把引擎包装为**非 *ratingEngine** 类型（验证计价不依赖具体类型断言，BUG-003）。
type wrapRating struct{ inner RatingEngine }

func (w wrapRating) RateMu(u *UsageAgg, t *PriceTable) (int64, error) { return w.inner.RateMu(u, t) }
func (w wrapRating) Rate(u *UsageAgg, t *PriceTable) (Amount, error)  { return w.inner.Rate(u, t) }
func (w wrapRating) RateMonthly(u *UsageAgg, t *PriceTable) (Amount, error) {
	return w.inner.RateMonthly(u, t)
}
func (w wrapRating) StandardTokens(i, o int64, mp *ModelPrice) (int64, int64) {
	return w.inner.StandardTokens(i, o, mp)
}
func (w wrapRating) ExtraAmount(u *UsageAgg, p *Plan, t *PriceTable) (int64, error) {
	return w.inner.ExtraAmount(u, p, t)
}

// BUG-003 回归锚：注入**非具体类型**的计价引擎时，日结金额仍按“月累计分档”正确。
// （旧实现经 `s.rating.(*ratingEngine)` 取月累计起点，断言失败即静默丢失起点 → 金额偏高。）
func TestCloseDaily_NonConcreteRatingEngine(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	// gpt-4o 阶梯 [≤1M: 30/60, ∞: 15/30]（元/千token；见 testPriceTable）
	// 月初已用 1,000,000 标准 token（跨出第一档），当日再用 500,000
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "gpt-4o", Day: "2026-09-10",
		TokensIn: 1_000_000, StdIn: 1_000_000, Requests: 1, EventKey: "e1",
	})
	seedLedger(t, s, LedgerEntry{
		TenantID: "t1", ModelKey: "gpt-4o", Day: "2026-09-15",
		TokensIn: 500_000, StdIn: 500_000, Requests: 1, EventKey: "e2",
	})
	svc := newTestBillingService(s, nil)
	svc.rating = wrapRating{inner: svc.rating} // 非 *ratingEngine

	bill, err := svc.CloseDaily(context.Background(), "t1", "2026-09-15")
	if err != nil {
		t.Fatalf("CloseDaily err: %v", err)
	}
	// 当日区间 [1,000,000, 1,500,000) 全在第二档（15 元/千）：500 × 15 = 7500 元 = 750000 分
	if bill.Total != Amount(750000) {
		t.Errorf("total = %d 分, want 750000（月累计分档；失败=丢失月起点/依赖类型断言）", bill.Total)
	}
}

// ---------- P3 修复回归（BUG-005 / BUG-006 / SEC-002） ----------

// BUG-005 回归锚：同租户多模型 retry → #19 指标取**租户聚合和**（旧实现仅保留最后一条）。
func TestIngestWindow_RetryGaugeAggregated(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	svc := newTestBillingService(s, nil)
	win := &UsageWindow{FromNs: 0, ToNs: 1, Source: "pull", EventKey: "pull-b5",
		Tenants: map[string]*TenantAgg{
			"t1": {TokensIn: 30, Requests: 2, RetryToks: 150, ByModel: map[string]*ModelAgg{
				"gpt-4o":      {TokensIn: 10, Requests: 1, RetryToks: 100},
				"cheap-model": {TokensIn: 20, Requests: 1, RetryToks: 50},
			}},
		}}
	if _, err := svc.IngestWindow(context.Background(), win, SyncModePull); err != nil {
		t.Fatalf("IngestWindow err: %v", err)
	}
	var buf bytes.Buffer
	DefaultMetrics.Render(&buf)
	if !strings.Contains(buf.String(), `gateway_admin_billing_platform_retry_tokens{tenant="t1"} 150`) {
		t.Errorf("BUG-005 回归：#19 应为租户聚合和 150：\n%s", buf.String())
	}
}

// BUG-006 回归锚：链尾 updated_at 取**实际新增末条** created_at（含重复被忽略时），返回值同源。
func TestLedgerAppend_HeadUpdatedAtFromInserted(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	entries := []LedgerEntry{
		{TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01", TokensIn: 1, StdIn: 1, EventKey: "k1", CreatedAt: 111},
		// 重复 EventKey（被忽略）→ 不得以其 CreatedAt 作为链尾 updated_at
		{TenantID: "t1", ModelKey: "cheap-model", Day: "2026-10-01", TokensIn: 1, StdIn: 1, EventKey: "k1", CreatedAt: 999},
	}
	added, head, err := s.Ledger().Append(tx, entries)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if added != 1 {
		t.Fatalf("added = %d, want 1", added)
	}
	if head.UpdatedAt != 111 {
		t.Errorf("BUG-006 回归：返回 head.UpdatedAt = %d, want 111（实际新增末条，非输入末条 999）", head.UpdatedAt)
	}
	if h, _ := s.Ledger().Head(); h.UpdatedAt != 111 {
		t.Errorf("BUG-006 回归：DB head.updated_at = %d, want 111", h.UpdatedAt)
	}
}

// SEC-002 回归锚：以公式前缀（= + - @）开头的文本单元格导出时前置 `'`，避免表格软件执行。
func TestExportCSV_FormulaInjectionEscaped(t *testing.T) {
	b := &Bill{
		ID: "b1", TenantID: "=cmd()", Kind: "daily", Period: "2026-10-01",
		Status: "issued", Currency: "CNY", PriceVersion: "v1", GeneratedAt: 1,
		Items: []BillItem{{ModelKey: "@evil", Amount: 100}},
	}
	out, _, err := ExportCSV(b)
	if err != nil {
		t.Fatalf("ExportCSV err: %v", err)
	}
	if !strings.Contains(string(out), "'=cmd()") || !strings.Contains(string(out), "'@evil") {
		t.Errorf("SEC-002 回归：公式前缀未转义：\n%s", out)
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
		TokensIn: 1000, TokensOut: 0, StdIn: 1000, StdOut: 0, Requests: 1, EventKey: "e1",
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
		TokensIn: 1000, TokensOut: 500, StdIn: 1000, StdOut: 500, Requests: 1, EventKey: "e1",
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
