package billing

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"
)

// ---------- 后台调度器（T8，§6.16 S-1..S-10） ----------

// SchedulerTasks 调度任务集合（由调用方注入具体实现，便于测试与解耦）。
type SchedulerTasks struct {
	Pull          func(context.Context) // S-1 增量拉取
	CloseDaily    func(context.Context) // S-2 日结（活跃租户）
	CloseMonthly  func(context.Context) // S-3 月结
	VerifyChain   func(context.Context) // S-6 链校验 → 指标 #4
	ScanAnomalies func(context.Context) // S-5 异常扫描
	CheckQuota    func(context.Context) // S-7 配额预警
	Backfill      func(context.Context) // S-8 缺口扫描（补账）
	ScanExpiries  func(context.Context) // S-9 到期扫描 → 指标 #21
	VerifyAssoc   func(context.Context) // S-10 关联校验 → 指标 #22
}

// Scheduler 后台任务调度器（单实例进程内；guard = 单飞防重入）。
type Scheduler struct {
	cfg   ScheduleConfig
	tasks SchedulerTasks

	stop    chan struct{}
	wg      sync.WaitGroup
	guardMu sync.Mutex
	running map[string]bool
}

// NewScheduler 构造调度器。
func NewScheduler(cfg ScheduleConfig, tasks SchedulerTasks) *Scheduler {
	return &Scheduler{
		cfg:     cfg,
		tasks:   tasks,
		running: map[string]bool{},
	}
}

// Start 启动全部周期任务（S-1..S-10）。幂等：重复调用无副作用。
func (s *Scheduler) Start(ctx context.Context) {
	if s.stop != nil {
		return // 已启动
	}
	s.stop = make(chan struct{})

	// S-1 增量拉取（可重入；guard 仅防重叠轮次）
	s.spawn(ctx, "S-1-pull", s.cfg.PullInterval, s.tasks.Pull)
	// S-5 异常扫描
	s.spawn(ctx, "S-5-anomaly", s.cfg.AnomalyScanInterval, s.tasks.ScanAnomalies)
	// S-6 链校验
	s.spawn(ctx, "S-6-verify", s.cfg.VerifyInterval, s.tasks.VerifyChain)
	// S-7 配额预警
	s.spawn(ctx, "S-7-quota", s.cfg.QuotaScanInterval, s.tasks.CheckQuota)
	// S-9 到期扫描
	s.spawn(ctx, "S-9-expiry", s.cfg.ExpiryScanInterval, s.tasks.ScanExpiries)
	// S-10 关联校验
	s.spawn(ctx, "S-10-assoc", s.cfg.VerifyAssocInterval, s.tasks.VerifyAssoc)

	// S-8 缺口扫描：启动时立即执行一次 + 每日
	if s.tasks.Backfill != nil {
		go s.guard("S-8-backfill", s.tasks.Backfill, ctx)
		s.spawn(ctx, "S-8-backfill-daily", 24*time.Hour, s.tasks.Backfill)
	}

	// S-3 月结：每月 monthly_close_day @ monthly_close_at（UTC+8）
	s.spawnMonthly(ctx, "S-3-monthly", s.cfg.MonthlyCloseDay, s.cfg.MonthlyCloseAt, s.tasks.CloseMonthly)
}

// Stop 停止全部任务并等待在途任务完成（优雅关闭 §6.15）。
func (s *Scheduler) Stop() {
	if s.stop == nil {
		return
	}
	close(s.stop)
	s.wg.Wait()
	s.stop = nil
}

// spawn 周期执行 fn（ticker）。fn 为 nil 或 interval<=0 时跳过。
func (s *Scheduler) spawn(ctx context.Context, name string, interval time.Duration, fn func(context.Context)) {
	if fn == nil || interval <= 0 {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(interval)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				s.guard(name, fn, ctx)
			}
		}
	}()
}

// --- 生产任务构造（供 main 接线；§6.16） ---

// BackfillTask 构造 S-8 缺口扫描任务（启动时 + 每日一次，§6.6.2）。
//
// lookbackDays: 只回看最近 N 天（<=0 = 不限）。today 取 UTC+8 自然日（与计量归日同口径）。
// 失败仅记录：任务本身不 panic、不退出（单点失败留待下轮重试）。
func BackfillTask(svc *BillingService, lookbackDays int) func(context.Context) {
	return func(ctx context.Context) {
		today := dayOfNs(time.Now().UnixNano())
		rep, err := svc.BackfillGaps(ctx, today, lookbackDays)
		if err != nil {
			log.Printf("[billing] S-8 缺口扫描失败：%v", err)
			return
		}
		if rep.Missing > 0 || rep.Failed > 0 {
			log.Printf("[billing] S-8 缺口扫描：租户=%d 缺口=%d 补出=%d 跳过=%d 失败=%d",
				rep.Tenants, rep.Missing, rep.Closed, rep.Skipped, rep.Failed)
		}
	}
}

// PullTask 构造 S-1 增量拉取任务（§6.1.1 / §6.16）。
//
// 调度器按 `source.pull_interval` 提供周期（≡ 文档 `RunMeteringLoop` 的 ticker）；
// 单轮 `pullOnce` 可重入，重叠窗口由 `event_key` 幂等去重（B-6.1-8）。
func PullTask(svc *BillingService) func(context.Context) {
	return func(ctx context.Context) { svc.pullOnce(ctx) }
}

// CloseMonthlyTask 构造 S-3 月结任务（§6.7 / §6.16）：对全部租户结算「上月」。
//
// 幂等（UNIQUE(tenant,monthly,period)：重复触发返回既有账单，故当日重复触发安全）；
// 冻结租户跳过（解冻后由下轮补出）；逐租户独立，单点失败不阻断其余。失败仅记录。
func CloseMonthlyTask(svc *BillingService) func(context.Context) {
	return func(ctx context.Context) {
		month := prevMonth(dayOfNs(time.Now().UnixNano()))
		if month == "" {
			return
		}
		lister, ok := svc.store.Ledger().(tenantDayLister)
		if !ok {
			return // 账本不支持枚举 → 无操作
		}
		tenants, err := lister.Tenants()
		if err != nil {
			log.Printf("[billing] S-3 月结：租户枚举失败：%v", err)
			return
		}
		closed, skipped, failed := 0, 0, 0
		for _, t := range tenants {
			if _, err := svc.CloseMonthly(ctx, t, month); err != nil {
				if errors.Is(err, ErrFrozen) {
					skipped++ // 冻结期不出账（解冻后由下轮补出）
					continue
				}
				failed++
				log.Printf("[billing] S-3 月结失败 tenant=%s month=%s: %v", t, month, err)
				continue
			}
			closed++
		}
		if closed+skipped+failed > 0 {
			log.Printf("[billing] S-3 月结 month=%s 处理=%d 跳过=%d 失败=%d", month, closed, skipped, failed)
		}
	}
}

// ScanAnomaliesTask 构造 S-5 异常扫描任务（§6.9 / §6.16）。
//
// 逐租户执行四类规则（spike / reconcile_diff / quota_warn / pricing_missing），
// 命中即记指标 #10（由 Scan 统一出口发射）；扫描日取 UTC+8 自然日（实时监控当日）。
// 失败仅记录（下轮重试）。
func ScanAnomaliesTask(det *AnomalyDetector) func(context.Context) {
	return func(ctx context.Context) {
		day := dayOfNs(time.Now().UnixNano())
		tenants, err := det.Tenants()
		if err != nil {
			log.Printf("[billing] S-5 异常扫描：租户枚举失败：%v", err)
			return
		}
		if len(tenants) == 0 {
			return
		}
		anomalies := det.Scan(tenants, day)
		frozen := det.ApplyFreezes(anomalies) // §6.10.1 冻结联动（critical → frozen）
		if len(anomalies) > 0 || frozen > 0 {
			log.Printf("[billing] S-5 异常扫描：租户=%d 异常=%d 冻结=%d day=%s",
				len(tenants), len(anomalies), frozen, day)
		}
	}
}

// CheckQuotaTask 构造 S-7 余额告警任务（§6.11 / §6.16）。
//
// 逐租户计算当月配额剩余比；低于 quota_warn_ratio → notifier.WarnQuotaLow
// （periodKey = 当月，幂等：同租户同月只告警一次）；无套餐/不限量不告警（B-6.11-3）。
// 失败仅记录。
func CheckQuotaTask(det *AnomalyDetector, notifier Notifier) func(context.Context) {
	return func(ctx context.Context) {
		day := dayOfNs(time.Now().UnixNano())
		tenants, err := det.Tenants()
		if err != nil {
			log.Printf("[billing] S-7 余额告警：租户枚举失败：%v", err)
			return
		}
		periodKey := day[:7] // 自然月周期
		threshold := det.QuotaWarnThreshold()
		warned := 0
		for _, t := range tenants {
			rem, ok := det.QuotaRemaining(t, day)
			if !ok || rem >= threshold {
				continue
			}
			warned++
			if notifier == nil {
				continue
			}
			if err := notifier.WarnQuotaLow(t, rem, periodKey); err != nil {
				log.Printf("[billing] S-7 余额告警发送失败 tenant=%s: %v", t, err)
			}
		}
		if warned > 0 {
			log.Printf("[billing] S-7 余额告警：命中租户=%d period=%s", warned, periodKey)
		}
	}
}

// ScanExpiriesTask 构造 S-9 到期扫描任务（§6.4.2 / §6.16）。
//
// 到期提醒 → 指标 #21；宽限结束仍逾期 → anomaly_total{kind="plan_expired"}（critical）；
// **不自动降级**。失败仅记录（下轮重试）。
func ScanExpiriesTask(svc *BillingService) func(context.Context) {
	return func(ctx context.Context) {
		rep, err := svc.ScanExpiries(time.Now().UnixNano())
		if err != nil {
			log.Printf("[billing] S-9 到期扫描失败：%v", err)
			return
		}
		if rep.Days30+rep.Days7+rep.Days0+rep.Expired > 0 {
			log.Printf("[billing] S-9 到期扫描：租户=%d T-30=%d T-7=%d T-0=%d 逾期=%d",
				rep.Tenants, rep.Days30, rep.Days7, rep.Days0, rep.Expired)
		}
	}
}

// VerifyChainTask 构造 S-6 链校验任务（§6.16）：全量校验账本哈希链 → 指标 #4；
// 断裂即置 chain_broken 并停出账（fail-closed）。纯读、无外部依赖；失败仅记录（下轮重试）。
func VerifyChainTask(svc *BillingService) func(context.Context) {
	return func(ctx context.Context) {
		brokenAt, err := svc.VerifyLedgerChain()
		if err != nil {
			log.Printf("[billing] S-6 链校验失败：%v", err)
			return
		}
		if brokenAt >= 0 {
			log.Printf("[billing] S-6 链校验：断裂 seq=%d", brokenAt)
		}
	}
}

// VerifyAssocTask 构造 S-10 关联校验任务（每日低峰巡检，§6.16，★ A-31/A-34）。
//
// lookbackDays > 0：只巡检最近 N 日出账的账单；<= 0：全量。
// 不符 → 标记账单 assoc_mismatch + 记指标 #22（**不阻断已出账**）。
func VerifyAssocTask(svc *BillingService, lookbackDays int) func(context.Context) {
	return func(ctx context.Context) {
		from := ""
		if lookbackDays > 0 {
			from = dayOfNs(time.Now().AddDate(0, 0, -lookbackDays).UnixNano())
		}
		checked, failed, err := svc.VerifyAssocRecent(from)
		if err != nil {
			log.Printf("[billing] S-10 关联校验失败：%v", err)
			return
		}
		if failed > 0 {
			log.Printf("[billing] S-10 关联校验：巡检=%d 不符=%d（已标记 assoc_mismatch，不阻断）", checked, failed)
		}
	}
}

// spawnMonthly 在每月 closeDay 日（UTC+8）达 closeAt（"HH:MM"）后触发 fn。
//
// 实现：每 10 分钟检查一次当前 UTC+8 的"日"与"时刻"；命中即经 guard 单飞执行。
// 由于 CloseMonthly 依 UNIQUE(tenant,kind,period) 幂等，当日重复触发**安全**（返回既有账单），
// 故无需额外"当日一次"状态。fn 为 nil 或参数非法时跳过。
func (s *Scheduler) spawnMonthly(ctx context.Context, name string, closeDay int, closeAt string, fn func(context.Context)) {
	if fn == nil || closeDay < 1 || closeAt == "" {
		return
	}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-s.stop:
				return
			case <-ctx.Done():
				return
			case <-t.C:
				now := time.Now().UnixNano()
				if dayOfMonthOfNs(now) != closeDay || clockOfNs(now) < closeAt {
					continue
				}
				s.guard(name, fn, ctx)
			}
		}
	}()
}

// guard 单飞执行：同一任务名并发触发时跳过（防重入）；panic 隔离（B-6.15-1）。
func (s *Scheduler) guard(name string, fn func(context.Context), ctx context.Context) {
	s.guardMu.Lock()
	if s.running[name] {
		s.guardMu.Unlock()
		return // 已有同任务在跑 → 跳过本次
	}
	s.running[name] = true
	s.guardMu.Unlock()

	defer func() {
		if r := recover(); r != nil {
			log.Printf("[billing] scheduler task %s panicked: %v", name, r)
		}
		s.guardMu.Lock()
		s.running[name] = false
		s.guardMu.Unlock()
	}()

	fn(ctx)
}
