package billing

import (
	"context"
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
