package billing

import (
	"context"
	"errors"
	"testing"
)

// testJobPriceTable 含两类模型：token 单元（cheap-model）与 job 单元（secretflow-b）。
// 直接构造（不经 LoadPriceTable 校验），仅用于单元断言。
func testJobPriceTable() *PriceTable {
	return &PriceTable{
		Version:  "v1",
		Currency: "CNY",
		Models: map[string]*ModelPrice{
			"cheap-model": {
				InCoef: 1, OutCoef: 1,
				Tiers: []Tier{{UpToTokens: 0, InPer1K: 1, OutPer1K: 2}},
			},
			// P2-5：任务式按次计价，2 元/次（无 token 阶梯）。
			"secretflow-b": {Unit: "job", PerJob: 2},
		},
	}
}

// fakeJobAuditCounter 审计链事件计数替身（对账用）。
type fakeJobAuditCounter struct {
	counts map[string]int64 // key = tenant+":"+action
}

func (f *fakeJobAuditCounter) CountAction(_ context.Context, tenant, action string, _, _ int64) (int64, error) {
	return f.counts[tenant+":"+action], nil
}

func TestIngestJobUsage_AppendsJobEntry(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ledger := concreteLedger(s)
	eng, monthCache := NewRatingEngineWithCache("half_up", ledger)
	svc := NewBillingService(s, eng, NewStaticPriceTable(testJobPriceTable()), NewReconciler(ledger, nil, 0.001), s.Freezes())
	svc.SetMonthStdCache(monthCache)

	if err := svc.IngestJobUsage(context.Background(), "t1", "secretflow-b", "2026-10-01", "", "confllm-job-job123"); err != nil {
		t.Fatalf("IngestJobUsage err: %v", err)
	}

	// 断言账本写入：Requests=1，Source=SourceConfllmJob，哈希链完好。
	entries, err := s.Ledger().Range(LedgerQuery{TenantID: "t1", DayFrom: "2026-10-01", DayTo: "2026-10-01"})
	if err != nil {
		t.Fatalf("Range err: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("want 1 ledger entry, got %d", len(entries))
	}
	e := entries[0]
	if e.Requests != 1 {
		t.Errorf("Requests = %d, want 1", e.Requests)
	}
	if e.Source != SourceConfllmJob {
		t.Errorf("Source = %q, want %q", e.Source, SourceConfllmJob)
	}
	if e.ModelKey != "secretflow-b" {
		t.Errorf("ModelKey = %q, want secretflow-b", e.ModelKey)
	}
	if e.EventKey != "confllm-job-job123" {
		t.Errorf("EventKey = %q", e.EventKey)
	}
	if broken, _ := s.Ledger().Verify(); broken != -1 {
		t.Errorf("ledger chain broken at seq %d after job ingest", broken)
	}
}

func TestIngestJobUsage_UnknownModelFails(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ledger := concreteLedger(s)
	eng, monthCache := NewRatingEngineWithCache("half_up", ledger)
	svc := NewBillingService(s, eng, NewStaticPriceTable(testJobPriceTable()), NewReconciler(ledger, nil, 0.001), s.Freezes())
	svc.SetMonthStdCache(monthCache)

	// 价格表无此模型 → fail-closed 可见（ErrPricingMissing）。
	err := svc.IngestJobUsage(context.Background(), "t1", "unknown-model", "2026-10-01", "", "ek")
	if err == nil {
		t.Fatal("want error for unknown model, got nil")
	}
	if !errors.Is(err, ErrPricingMissing) {
		t.Errorf("err = %v, want ErrPricingMissing-wrapped", err)
	}
}

func TestRateMu_JobUnitPricing(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ledger := concreteLedger(s)
	eng, _ := NewRatingEngineWithCache("half_up", ledger)
	pt := testJobPriceTable()

	// 3 次任务，2 元/次 → 3×2×100000 = 600000 亚分 = 600 分。
	agg := &UsageAgg{TenantID: "t1", Period: "2026-10-01",
		ByModel: map[string]*ModelStd{"secretflow-b": {Requests: 3}}}
	mu, err := eng.RateMu(agg, pt)
	if err != nil {
		t.Fatalf("RateMu err: %v", err)
	}
	if mu != 600000 {
		t.Errorf("job RateMu = %d 亚分, want 600000", mu)
	}
	amt := roundAmount(mu, "half_up")
	if amt != Amount(600) {
		t.Errorf("job Amount = %d 分, want 600", amt)
	}
}

func TestBuildItems_JobUnitSeparated(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ledger := concreteLedger(s)
	eng, monthCache := NewRatingEngineWithCache("half_up", ledger)
	svc := NewBillingService(s, eng, NewStaticPriceTable(testJobPriceTable()), NewReconciler(ledger, nil, 0.001), s.Freezes())
	svc.SetMonthStdCache(monthCache)

	agg := &UsageAgg{TenantID: "t1", Period: "2026-10-01",
		ByModel: map[string]*ModelStd{
			// job 单元
			"secretflow-b": {Requests: 3},
			// token 单元（对照）
			"cheap-model": {TokensIn: 100000, TokensOut: 50000, StdIn: 100000, StdOut: 50000},
		}}
	items, total, err := svc.buildItems(agg, testJobPriceTable())
	if err != nil {
		t.Fatalf("buildItems err: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("items = %d, want 2", len(items))
	}
	byModel := map[string]BillItem{}
	for _, it := range items {
		byModel[it.ModelKey] = it
	}
	job := byModel["secretflow-b"]
	if job.Unit != "job" {
		t.Errorf("secretflow-b Unit = %q, want job", job.Unit)
	}
	if job.Amount != Amount(600) {
		t.Errorf("secretflow-b Amount = %d, want 600", job.Amount)
	}
	if job.StandardTokens != 0 {
		t.Errorf("secretflow-b StandardTokens = %d, want 0 (no tokens)", job.StandardTokens)
	}
	tok := byModel["cheap-model"]
	if tok.Unit != "token" {
		t.Errorf("cheap-model Unit = %q, want token", tok.Unit)
	}
	// 200 元 = 20000 分
	if tok.Amount != Amount(20000) {
		t.Errorf("cheap-model Amount = %d, want 20000", tok.Amount)
	}
	// 分列后总额 = 600 + 20000 = 20600
	if total != Amount(20600) {
		t.Errorf("total = %d, want 20600", total)
	}
}

func TestReconcileJobs_ZeroTolerance(t *testing.T) {
	s := openTestStore(t)
	defer s.Close()
	ledger := concreteLedger(s)
	eng, monthCache := NewRatingEngineWithCache("half_up", ledger)
	svc := NewBillingService(s, eng, NewStaticPriceTable(testJobPriceTable()), NewReconciler(ledger, nil, 0.001), s.Freezes())
	svc.SetMonthStdCache(monthCache)

	// 账本写入 2 条 job 条目（不同 eventKey，幂等键不冲突）。
	for i, ek := range []string{"confllm-job-a", "confllm-job-b"} {
		seedLedger(t, s, LedgerEntry{
			TenantID: "t1", ModelKey: "secretflow-b", Day: "2026-10-01",
			Requests: 1, Source: SourceConfllmJob, EventKey: ek, CreatedAt: int64(i + 1),
		})
	}

	// 未注入审计计数器 → 不对账，mismatch=false，ledgerJobs=2。
	lj, as, mismatch, err := svc.ReconcileJobs(context.Background(), "t1", 0, 1<<62)
	if err != nil {
		t.Fatalf("ReconcileJobs err: %v", err)
	}
	if lj != 2 || as != 0 || mismatch {
		t.Fatalf("no-audit: ledgerJobs=%d auditSubmits=%d mismatch=%v, want 2/0/false", lj, as, mismatch)
	}

	// 注入审计计数器（报告 1 条 submit）→ 不一致（零容差）。
	svc.SetJobAudit(&fakeJobAuditCounter{counts: map[string]int64{"t1:" + AuditActionConfllmGraphSubmit: 1}})
	lj, as, mismatch, err = svc.ReconcileJobs(context.Background(), "t1", 0, 1<<62)
	if err != nil {
		t.Fatalf("ReconcileJobs err: %v", err)
	}
	if lj != 2 || as != 1 || !mismatch {
		t.Fatalf("mismatch expected: ledgerJobs=%d auditSubmits=%d mismatch=%v, want 2/1/true", lj, as, mismatch)
	}

	// 审计报告 2 条 → 一致。
	svc.SetJobAudit(&fakeJobAuditCounter{counts: map[string]int64{"t1:" + AuditActionConfllmGraphSubmit: 2}})
	lj, as, mismatch, err = svc.ReconcileJobs(context.Background(), "t1", 0, 1<<62)
	if err != nil {
		t.Fatalf("ReconcileJobs err: %v", err)
	}
	if lj != 2 || as != 2 || mismatch {
		t.Fatalf("match expected: ledgerJobs=%d auditSubmits=%d mismatch=%v, want 2/2/false", lj, as, mismatch)
	}
}
