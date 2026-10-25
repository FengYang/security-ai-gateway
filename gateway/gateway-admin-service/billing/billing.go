package billing

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"
)

// ---------- 账单生成（T5，§6.6 / §6.7） ----------

// PriceTableProvider 价格表提供器（支持热加载，§6.14）。
type PriceTableProvider interface {
	Current() *PriceTable
}

// BillingService 账单生成服务。
type BillingService struct {
	store         Store
	rating        RatingEngine
	prices        PriceTableProvider
	reconciler    *Reconciler         // nil = 跳过 L2（未接入计量侧）
	freeze        FreezeStore         // nil = 不判冻结
	signer        BillSigner          // nil = 不签名（T7b）
	auditAnchor   AuditAnchorProvider // nil = 不锚定审计链（T7b）
	monthStdCache *CachedMonthStd     // nil = 未启用月累计缓存（A-37）
	now           func() int64

	// S-1 增量拉取（§6.1.1）
	source       PullSource    // nil = 不拉取
	pullLookback time.Duration // 首次部署回溯窗口（R-7）
	syncMode     string        // 账本单写者（A-12/R-30）
	lastPollNs   int64         // 拉取游标 = 上轮成功窗口结束（★ BUG-001 非重叠；时钟回拨保护 B-6.1-3）
	pollMu       sync.Mutex    // 串行化 S-1 拉取与对账回补，保护 lastPollNs

	// 对账回补（§6.12.3）：(tenant,day) 进程内幂等，避免同 warning 反复触发
	repullMu sync.Mutex
	repulled map[string]bool

	// 告警外部交付（S-7 余额 / S-9 到期；nil = 仅本地日志 + Prometheus 规则）
	alertSink AlertSink

	// 审计链校验器（REC-6/B-6.12-4；nil = 不校验，全局停出账标志不变）
	auditVerifier AuditChainVerifier
}

// SetSigner 注入账单签名器（T7b）。
func (s *BillingService) SetSigner(sig BillSigner) { s.signer = sig }

// SetAlertSink 注入告警外部交付器（S-7 余额 / S-9 到期；nil = 仅本地日志 + Prometheus 规则）。
func (s *BillingService) SetAlertSink(sink AlertSink) { s.alertSink = sink }

// SetAuditAnchor 注入审计链锚定提供者（T7b）。
func (s *BillingService) SetAuditAnchor(a AuditAnchorProvider) { s.auditAnchor = a }

// SetMonthStdCache 注入月累计缓存句柄（A-37：入账补账时据此失效对应月份）。
func (s *BillingService) SetMonthStdCache(c *CachedMonthStd) { s.monthStdCache = c }

// monthModelsLister 枚举某租户某月内出现过的模型键（预热用；账本实现提供）。
type monthModelsLister interface {
	ModelKeysInMonth(tenant, month string) ([]string, error)
}

// WarmMonthStd 预热月累计缓存至 upToDay（A-37）。
// 供启动/缺口扫描（S-8）与日结后调用；未启用缓存或账本不支持枚举时为 no-op。
func (s *BillingService) WarmMonthStd(tenant, upToDay string) error {
	if s.monthStdCache == nil || len(upToDay) < 7 {
		return nil
	}
	lister, ok := s.store.Ledger().(monthModelsLister)
	if !ok {
		return nil
	}
	modelKeys, err := lister.ModelKeysInMonth(tenant, upToDay[:7])
	if err != nil {
		return err
	}
	s.monthStdCache.Warm(tenant, modelKeys, upToDay)
	return nil
}

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

// ValidatePlanPricing 校验套餐与单价表的**交叉约束**（R-29，§4.2 C-2）。
//
// `OverQuota=charge` 的套餐必须同时满足：
//   - 非免费档（`MonthlyTokens > 0`）；
//   - 计价能力非"全 0 价"（当前价格表至少一个非 0 单价）；
//
// 违反即拒（防"免费版产出金额账单"）。口径说明（P0）：P0 单价表为**全局单表**（按
// `model_key` 计价），`Plan.PriceID` 尚无到单价表的映射关系，故 R-29 的"`PriceID`
// 对应单价表"按**当前全局单价表**解释。
func (s *BillingService) ValidatePlanPricing(p *Plan) error {
	if p == nil || p.OverQuota != "charge" {
		return nil
	}
	if p.MonthlyTokens <= 0 {
		return fmt.Errorf("R-29: over_quota=charge 的套餐 %q 必须为非免费档（monthly_tokens > 0）", p.ID)
	}
	if s.prices == nil || !s.prices.Current().HasNonZeroPrice() {
		return fmt.Errorf("R-29: over_quota=charge 的套餐 %q 需单价表存在非 0 单价", p.ID)
	}
	return nil
}

// IngestWindow 把一次拉取/推送窗口入账（§6.1.1 / §6.3.2）。
//
// 单写者门控（A-12/R-30）：仅当 CanWrite(syncMode, win.Source) 时写账本；
// 否则只更新实时视图（P0 无持久化视图 → no-op），返回 (0, nil)。
//
// std 锁定（A-32/A-39）：入账时按当前价格表算好 std_in/std_out 并写入 PriceVer，
// 之后永不修改（计价路径读锁定值，不重算）。
//
// 注（指标所有权）：本方法**不发射** `pull_total`/`push_total`——由调用方按通道发射
// （`pullOnce`→#5、`ConsumePush`→#6），避免推送被计成拉取。
func (s *BillingService) IngestWindow(ctx context.Context, win *UsageWindow, syncMode string) (int, error) {
	if win == nil {
		return 0, nil
	}
	if !CanWrite(syncMode, win.Source) {
		return 0, nil // 非写者：仅更新实时视图（P0 无持久化视图 → no-op）
	}
	if s.prices == nil {
		// 防御：价格表提供器未注入（正常装配必注入）——返回错误而非 panic。
		return 0, fmt.Errorf("billing: price table provider is not configured")
	}
	tbl := s.prices.Current()
	entries := AggToEntries(win)
	if len(entries) == 0 {
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
	}
	// retry 归平台成本（M9；指标 #19）：按租户**聚合**后一次性置值。
	// ★ BUG-005：原实现逐条 Set，同租户多模型时 gauge 仅保留最后一条 → 值偏小。
	retryByTenant := map[string]int64{}
	for i := range entries {
		if entries[i].RetryToks != 0 {
			retryByTenant[entries[i].TenantID] += entries[i].RetryToks
		}
	}
	for tenant, toks := range retryByTenant {
		SetPlatformRetryTokens(tenant, toks)
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
	// A-37：补账失效——入账的某日若落在已推进的月累计区间内（迟到数据），
	// 则对应月份缓存失效；正常前进（day 晚于游标）不失效。价格表热更新不触发失效（A-51）。
	if s.monthStdCache != nil {
		for i := range entries {
			s.monthStdCache.InvalidateDayIfBackfill(entries[i].TenantID, entries[i].Day)
		}
	}
	return added, nil
}

// ConsumePush 消费单条推送事件（§6.3.1/§6.3.2，A-8：账本无第二写入路径）。
//
// 单写者门控（A-12/R-30）：`sync_mode=push` 才写账本；`=pull` 时仅更新实时视图（不写账）。
// 事件级幂等（§6.3.4：`push-{event_id}-{tenant}-{model}` 由 `LedgerStore.Append` 的 UNIQUE 兜底）。
// `is_retry=true` → `retry_toks` 归因（M9）；冻结租户**仍入账**供人工核账（B-6.3-6）。
// handler 只做验签/反序列化/委托（§6.3.1）。
func (s *BillingService) ConsumePush(ev PushEvent) error {
	win := pushEventToWindow(ev)
	if win == nil {
		IncPush("ok") // 正常接收但不落账（负 token B-6.3-4 / 字段缺失 / ts 非法）
		return nil
	}
	frozen := s.checkFrozen(ev.TenantID) != nil
	if _, err := s.IngestWindow(context.Background(), win, s.syncMode); err != nil {
		IncPush("error")
		return err
	}
	switch {
	case frozen:
		IncPush("frozen") // B-6.3-6：冻结租户仍入账（供人工核账），指标单记
	case ev.Result != pushResultOK && ev.Result != pushResultEngineError:
		IncPush("unknown_result") // B-6.3-3：未知 result 值 → 落账按 ok 兜底，指标单记
	default:
		IncPush("ok")
	}
	return nil
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

	// 1b. 完整性门禁（S-6 账本链 / REC-6 审计链：断裂 → 停出账，fail-closed；§6.15/§7.1）
	if err := s.integrityGate(); err != nil {
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
	// ledger_head 锚定"本租户本日链尾"（§7.3：账单→账本链须"重放可复现"；
	// 账本为全局单链，全局链尾不可由本租户重放复现）。
	bill := &Bill{
		ID:           id,
		TenantID:     tenant,
		Kind:         BillKindDaily,
		Period:       day,
		ClusterID:    s.clusterOfPeriod(tenant, day, day), // R-4/A5(6) 计费打标（证据列，不进签名域）
		Items:        items,
		Total:        total,
		Currency:     tbl.Currency,
		PriceVersion: tbl.Version,
		Status:       BillStatusIssued,
		LedgerHead:   s.periodTailHash(tenant, day, day),
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
	// A-37 预热：日结后把当月缓存推进到当日，使次日日结的 monthStdBefore 直接命中。
	// best-effort（预热失败不影响出账结果，仅退化为下次回源）。
	if err := s.WarmMonthStd(tenant, day); err != nil {
		log.Printf("[billing] 月累计缓存预热失败 tenant=%s day=%s: %v", tenant, day, err)
	}
	// S-10 出账后即时关联校验（不阻断已出账；失败仅标记 assoc_mismatch + 指标 #22，§7.3/A-34）
	s.verifyAssocAfterClose(bill)
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

	// 完整性门禁（S-6 账本链 / REC-6 审计链：断裂 → 停出账，fail-closed；§6.15/§7.1）
	if err := s.integrityGate(); err != nil {
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
	// ledger_head 锚定"本租户本月链尾"（§7.3 重放可复现，同 CloseDaily）
	tail := s.periodTailHash(tenant, first, last)

	bill := &Bill{
		ID:           id,
		TenantID:     tenant,
		Kind:         BillKindMonthly,
		Period:       month,
		ClusterID:    s.clusterOfPeriod(tenant, first, last), // R-4/A5(6) 计费打标
		Items:        items,
		Total:        total,
		Currency:     tbl.Currency,
		PriceVersion: tbl.Version,
		Status:       BillStatusIssued,
		LedgerHead:   tail,
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
	if err := s.closeOverage(tenant, month, bill.ClusterID, agg, tbl, tail); err != nil {
		return nil, err
	}

	// S-10 出账后即时关联校验（不阻断已出账；失败仅标记 assoc_mismatch + 指标 #22，§7.3/A-34）
	s.verifyAssocAfterClose(bill)
	return bill, nil
}

// closeOverage 生成独立超额账单（若套餐为 charge 且存在超额）。
// clusterID 与所属月账单同标（R-4/A5(6)）。
func (s *BillingService) closeOverage(tenant, month, clusterID string, agg *UsageAgg, tbl *PriceTable, ledgerHead string) error {
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
		ClusterID:    clusterID, // R-4/A5(6) 计费打标（与月账单同标）
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

// buildItems 由 UsageAgg 构造明细行 + 账单总额。
//
// ★ BUG-003：计价**一律经 RatingEngine**（权威实现，含月累计起点与唯一换算/取整口径），
// 不再内联 `rateModel`、也不再断言具体类型 `*ratingEngine`（消除两套计价路径与断言失败静默降级）。
//   - 明细行：对单模型子聚合调用 `RateMu`（亚分、未取整），逐行取整仅作展示（§6.10 展示口径）；
//   - 账单总额：调用 `RateMonthly`（= roundAmount(RateMu(整周期))，R-16 唯一取整点；honor 配置的舍入法）。
func (s *BillingService) buildItems(agg *UsageAgg, tbl *PriceTable) ([]BillItem, Amount, error) {
	if agg == nil || len(agg.ByModel) == 0 {
		return nil, 0, nil
	}
	if s.rating == nil {
		return nil, 0, fmt.Errorf("billing: rating engine is not configured")
	}
	mode := s.roundingMode() // ★ A4：明细行与总额取整同口径（此前硬编码 half_up）
	var items []BillItem
	for mk, mu := range agg.ByModel {
		if _, ok := tbl.ModelPriceOf(mk); !ok {
			return nil, 0, fmt.Errorf("%w: model %q", ErrPricingMissing, mk)
		}
		// 单模型子聚合：经引擎计价（月累计起点由引擎内部按 period 取，无需外部注入具体类型）
		sub := &UsageAgg{TenantID: agg.TenantID, Period: agg.Period,
			ByModel: map[string]*ModelStd{mk: mu}}
		itemMu, err := s.rating.RateMu(sub, tbl)
		if err != nil {
			return nil, 0, err
		}
		items = append(items, BillItem{
			ModelKey:       mk,
			StandardTokens: mu.StdIn + mu.StdOut,
			TokensIn:       mu.TokensIn,
			TokensOut:      mu.TokensOut,
			RetryToks:      mu.RetryToks, // 展示"平台承担"（不计入 Amount，M9）
			Amount:         roundAmount(itemMu, mode),
		})
	}
	total, err := s.rating.RateMonthly(agg, tbl) // 月结权威入口（唯一取整点）
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// roundingMode 返回计价引擎配置的舍入法（默认 half_up）。
// 经**可选接口**探测，避免依赖具体实现类型（不破坏 RatingEngine 可替换性）。
func (s *BillingService) roundingMode() string {
	if r, ok := s.rating.(interface{ Rounding() string }); ok {
		if m := r.Rounding(); m != "" {
			return m
		}
	}
	return "half_up"
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
		// §6.12.3 软分支：0<ratio≤alertRatio（ShouldFrz=false）→ 非阻塞排一次重叠窗口回补；
		// 不改变"diff>0 一律不出账"硬门禁（A-22）。硬分支（ratio>0.1%）由 S-5 判定冻结。
		if !res.ShouldFrz {
			s.onReconcileWarning(tenant, dayTo)
		}
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

// prevMonth 返回某自然日（"YYYY-MM-DD"）的上一月（"YYYY-MM"）；解析失败返回空串。
// 供 S-3 月结：monthly_close_day 当日结算"上月"。
func prevMonth(day string) string {
	t, err := time.Parse(dayLayout, day)
	if err != nil {
		return ""
	}
	return t.AddDate(0, -1, 0).Format("2006-01")
}
