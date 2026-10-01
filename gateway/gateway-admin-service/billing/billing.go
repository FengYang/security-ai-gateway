package billing

import (
	"context"
	"fmt"
	"time"
)

// ---------- 账单生成（T5，§6.6 / §6.7） ----------

// PriceTableProvider 价格表提供器（支持热加载，§6.14）。
type PriceTableProvider interface {
	Current() *PriceTable
}

// BillingService 账单生成服务。
type BillingService struct {
	store       Store
	rating      RatingEngine
	prices      PriceTableProvider
	reconciler  *Reconciler        // nil = 跳过 L2（未接入计量侧）
	freeze      FreezeStore        // nil = 不判冻结
	signer      BillSigner         // nil = 不签名（T7b）
	auditAnchor AuditAnchorProvider // nil = 不锚定审计链（T7b）
	now         func() int64
}

// SetSigner 注入账单签名器（T7b）。
func (s *BillingService) SetSigner(sig BillSigner) { s.signer = sig }

// SetAuditAnchor 注入审计链锚定提供者（T7b）。
func (s *BillingService) SetAuditAnchor(a AuditAnchorProvider) { s.auditAnchor = a }

// NewBillingService 构造账单生成服务。
func NewBillingService(store Store, rating RatingEngine, prices PriceTableProvider,
	rec *Reconciler, frz FreezeStore) *BillingService {
	return &BillingService{
		store:      store,
		rating:     rating,
		prices:     prices,
		reconciler: rec,
		freeze:     frz,
		now:        func() int64 { return time.Now().UnixNano() },
	}
}

// IngestWindow 把一次拉取/推送窗口入账（§6.1.1 / §6.3.2）。
//
// 单写者门控（A-12/R-30）：仅当 CanWrite(syncMode, win.Source) 时写账本；
// 否则只更新实时视图（P0 无持久化视图 → no-op），返回 (0, nil)。
//
// std 锁定（A-32/A-39）：入账时按当前价格表算好 std_in/std_out 并写入 PriceVer，
// 之后永不修改（计价路径读锁定值，不重算）。
func (s *BillingService) IngestWindow(ctx context.Context, win *UsageWindow, syncMode string) (int, error) {
	if win == nil {
		return 0, nil
	}
	if !CanWrite(syncMode, win.Source) {
		IncPull("ok") // 拉取/推送成功但非写者（实时视图）
		return 0, nil
	}
	tbl := s.prices.Current()
	entries := AggToEntries(win)
	if len(entries) == 0 {
		IncPull("ok")
		return 0, nil
	}
	// 锁定 std（A-32）：仅入账路径调用 StandardTokens（A-9 唯一入口）
	for i := range entries {
		mp, ok := tbl.ModelPriceOf(entries[i].ModelKey)
		if !ok {
			if entries[i].ModelKey == "__retry__" {
				entries[i].PriceVer = tbl.Version
				continue // retry 聚合行无计价需求
			}
			IncPricingMissing(entries[i].ModelKey)
			return 0, fmt.Errorf("%w: model %q", ErrPricingMissing, entries[i].ModelKey)
		}
		stdIn, stdOut := s.rating.StandardTokens(entries[i].TokensIn, entries[i].TokensOut, mp)
		entries[i].StdIn = stdIn
		entries[i].StdOut = stdOut
		entries[i].PriceVer = tbl.Version
		// retry 归平台成本（M9）
		SetPlatformRetryTokens(entries[i].TenantID, entries[i].RetryToks)
	}

	tx, err := s.store.Begin()
	if err != nil {
		IncLedgerError("begin")
		return 0, err
	}
	added, _, err := s.store.Ledger().Append(tx, entries)
	if err != nil {
		_ = tx.Rollback()
		IncLedgerError("append")
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		IncLedgerError("append")
		return 0, err
	}
	IncPull("ok")
	return added, nil
}

// stamp 为账单锚定审计链尾并签名（T7b）；须在 LedgerHead 设定后调用。
func (s *BillingService) stamp(b *Bill) {
	if s.auditAnchor != nil {
		if h, err := s.auditAnchor.AuditHead(); err == nil {
			b.AuditHead = h
		}
	}
	if s.signer != nil {
		b.Sig = s.signer.Sign(b)
	}
}

// CloseDaily 生成某租户某日账单（幂等：同 (tenant,daily,period) 唯一）。
//
// 流程（§6.6.1）：
//  1. 冻结判定 → 冻结不出账（ErrFrozen）
//  2. L2 对账门禁：diff>0 → 不出账（返回错误，账单停留 draft）
//  3. 折叠当日账本 → UsageAgg（std 用锁定值 A-39）
//  4. 计价（唯一取整点 R-16/A-44）
//  5. 写账单（issued）
func (s *BillingService) CloseDaily(ctx context.Context, tenant, day string) (*Bill, error) {
	start := time.Now()
	// 幂等：已存在直接返回
	id := fmt.Sprintf("daily-%s-%s", tenant, day)
	if existing, _ := s.store.Bills().Get(id); existing != nil {
		return existing, nil
	}

	// 1. 冻结判定
	if err := s.checkFrozen(tenant); err != nil {
		return nil, err
	}

	// 2. L2 对账门禁
	if reason, err := s.gateL2(tenant, day, day); err != nil {
		return nil, err
	} else if reason != "" {
		return nil, fmt.Errorf("billing: daily close blocked by L2 reconcile: %s", reason)
	}

	// 3. 折叠账本
	ledger := s.store.Ledger().(interface {
		FoldByModel(tenant, from, to string) (*UsageAgg, error)
	})
	agg, err := ledger.FoldByModel(tenant, day, day)
	if err != nil {
		return nil, err
	}

	// 4. 计价
	tbl := s.prices.Current()
	items, total, err := s.buildItems(agg, tbl)
	if err != nil {
		return nil, err
	}

	// 5. 写账单
	head, _ := s.store.Ledger().Head()
	bill := &Bill{
		ID:           id,
		TenantID:     tenant,
		Kind:         BillKindDaily,
		Period:       day,
		Items:        items,
		Total:        total,
		Currency:     tbl.Currency,
		PriceVersion: tbl.Version,
		Status:       BillStatusIssued,
		LedgerHead:   head.EntryHash,
		GeneratedAt:  s.now(),
	}
	s.stamp(bill)
	if err := s.store.Bills().Put(bill); err != nil {
		if IsUnique(err) {
			// 并发：已被其他写入者创建 → 回读
			return s.store.Bills().Get(id)
		}
		return nil, err
	}
	IncBillIssued(BillKindDaily) // 指标 #8
	ObserveClose(BillKindDaily, time.Since(start).Seconds())
	return bill, nil
}

// CloseMonthly 生成某租户某月账单（+ 可选的独立超额账单，A-45）。
func (s *BillingService) CloseMonthly(ctx context.Context, tenant, month string) (*Bill, error) {
	id := fmt.Sprintf("monthly-%s-%s", tenant, month)
	if existing, _ := s.store.Bills().Get(id); existing != nil {
		return existing, nil
	}

	if err := s.checkFrozen(tenant); err != nil {
		return nil, err
	}

	first, last := monthRange(month)
	if reason, err := s.gateL2(tenant, first, last); err != nil {
		return nil, err
	} else if reason != "" {
		return nil, fmt.Errorf("billing: monthly close blocked by L2 reconcile: %s", reason)
	}

	ledger := s.store.Ledger().(interface {
		FoldByModel(tenant, from, to string) (*UsageAgg, error)
	})
	agg, err := ledger.FoldByModel(tenant, first, last)
	if err != nil {
		return nil, err
	}

	tbl := s.prices.Current()
	items, total, err := s.buildItems(agg, tbl)
	if err != nil {
		return nil, err
	}
	head, _ := s.store.Ledger().Head()

	bill := &Bill{
		ID:           id,
		TenantID:     tenant,
		Kind:         BillKindMonthly,
		Period:       month,
		Items:        items,
		Total:        total,
		Currency:     tbl.Currency,
		PriceVersion: tbl.Version,
		Status:       BillStatusIssued,
		LedgerHead:   head.EntryHash,
		GeneratedAt:  s.now(),
	}
	s.stamp(bill)
	if err := s.store.Bills().Put(bill); err != nil {
		if IsUnique(err) {
			return s.store.Bills().Get(id)
		}
		return nil, err
	}
	IncBillIssued(BillKindMonthly) // 指标 #8

	// 4b. 超额单列账单（A-45：charge 套餐超标独立成单，各自一次取整 R-16）
	if err := s.closeOverage(tenant, month, agg, tbl, head.EntryHash); err != nil {
		return nil, err
	}

	return bill, nil
}

// closeOverage 生成独立超额账单（若套餐为 charge 且存在超额）。
func (s *BillingService) closeOverage(tenant, month string, agg *UsageAgg, tbl *PriceTable, ledgerHead string) error {
	plan, err := s.store.Plans().Resolve(tenant, s.now())
	if err != nil {
		return err
	}
	if plan == nil || plan.OverQuota != "charge" {
		return nil // 非 charge 套餐无超额账单
	}
	mu, err := s.rating.ExtraAmount(agg, plan, tbl)
	if err != nil {
		return err
	}
	if mu <= 0 {
		return nil
	}
	extraTotal := roundAmount(mu, "half_up") // 超额账单唯一取整点（A-44①）
	id := fmt.Sprintf("overage-%s-%s", tenant, month)
	if existing, _ := s.store.Bills().Get(id); existing != nil {
		return nil // 幂等
	}
	bill := &Bill{
		ID:           id,
		TenantID:     tenant,
		Kind:         BillKindOverage,
		Period:       month,
		Total:        extraTotal,
		Currency:     tbl.Currency,
		PriceVersion: tbl.Version,
		Status:       BillStatusIssued,
		LedgerHead:   ledgerHead,
		GeneratedAt:  s.now(),
	}
	s.stamp(bill)
	if err := s.store.Bills().Put(bill); err != nil && !IsUnique(err) {
		return err
	}
	IncBillIssued(BillKindOverage) // 指标 #8
	return nil
}

// buildItems 由 UsageAgg 构造明细行 + 账单总额（唯一取整）。
// 明细行金额为可读性展示（各自取整）；账单总额 = roundAmount(Σ 亚分)（R-16 唯一取整点）。
func (s *BillingService) buildItems(agg *UsageAgg, tbl *PriceTable) ([]BillItem, Amount, error) {
	if agg == nil || len(agg.ByModel) == 0 {
		return nil, 0, nil
	}
	var items []BillItem
	var totalMu int64
	for mk, mu := range agg.ByModel {
		mp, ok := tbl.ModelPriceOf(mk)
		if !ok {
			return nil, 0, fmt.Errorf("%w: model %q", ErrPricingMissing, mk)
		}
		var inBefore, outBefore int64
		if s.rating != nil {
			if p, ok := s.rating.(*ratingEngine); ok && p.monthStd != nil {
				inBefore, outBefore = p.monthStd.MonthStdBefore(agg.TenantID, mk, agg.Period)
			}
		}
		itemMu := rateModel(mu.StdIn, mu.StdOut, inBefore, outBefore, mp)
		totalMu += itemMu
		items = append(items, BillItem{
			ModelKey:       mk,
			StandardTokens: mu.StdIn + mu.StdOut,
			TokensIn:       mu.TokensIn,
			TokensOut:      mu.TokensOut,
			RetryToks:      mu.RetryToks, // 展示"平台承担"（不计入 Amount，M9）
			Amount:         roundAmount(itemMu, "half_up"),
		})
	}
	return items, roundAmount(totalMu, "half_up"), nil
}

// checkFrozen 冻结判定（§6.10.3）。
func (s *BillingService) checkFrozen(tenant string) error {
	if s.freeze == nil {
		return nil
	}
	rec, err := s.freeze.Get(tenant)
	if err != nil {
		return nil
	}
	if rec != nil {
		if rec.Until == 0 || rec.Until > s.now() {
			return fmt.Errorf("%w: tenant %s reason=%s", ErrFrozen, tenant, rec.Reason)
		}
	}
	return nil
}

// gateL2 执行 L2 门禁；返回非空 reason 表示被阻止出账。
func (s *BillingService) gateL2(tenant, dayFrom, dayTo string) (string, error) {
	if s.reconciler == nil {
		return "", nil
	}
	res, err := s.reconciler.L2(tenant, dayFrom, dayTo)
	if err != nil {
		return "", err
	}
	SetReconcileDiff(tenant, res.Ratio) // 指标 #11（M1 判据）
	if !res.Pass {
		return fmt.Sprintf("diff=%d ratio=%.6f", res.Diff, res.Ratio), nil
	}
	return "", nil
}

// ---------- 工具 ----------

// monthRange 返回某月的首日与末日（"YYYY-MM" → "YYYY-MM-01", "YYYY-MM-DD"）。
func monthRange(month string) (string, string) {
	if len(month) < 7 {
		return "", ""
	}
	month = month[:7]
	t, err := time.Parse("2006-01", month)
	if err != nil {
		return month + "-01", month + "-01"
	}
	first := t.Format(dayLayout)
	last := t.AddDate(0, 1, -1).Format(dayLayout)
	return first, last
}
