package billing

import (
	"context"
	"errors"
	"fmt"
	"log"
)

// ---------- S-8 缺口扫描（补账，§6.6.2 / §6.16） ----------
//
// 语义：启动时 + 每日一次，扫「账本有用量日」与「已出日账」的差集，逐日补出日账。
// 幂等：`CloseDaily` 依 `UNIQUE(tenant,kind,period)` 幂等，重复补账返回既有账单，
// 故本任务可安全重入、可安全在进程重启后重跑（B-6.6-4）。
// 失败语义：逐租户/逐日独立，单点失败不阻断其余；失败项记入报告并留待下轮重试。

// BackfillReport 缺口扫描结果（观测/日志用）。
type BackfillReport struct {
	Tenants int // 扫描租户数
	Missing int // 发现的缺口日数（账本有用量但未出日账）
	Closed  int // 补出成功数
	Skipped int // 跳过数（冻结租户等）
	Failed  int // 失败数（下轮重试）
}

// tenantDayLister 缺口扫描所需的账本枚举能力。
type tenantDayLister interface {
	Tenants() ([]string, error)
	DaysWithUsage(tenant string) ([]string, error)
}

// BackfillGaps 执行缺口扫描并补账（S-8）。
//
// today: UTC+8 自然日 "YYYY-MM-DD"；仅 **早于 today** 的日子参与（当日仍在累积，不提前出账）。
// lookbackDays: 仅回看最近 N 天（<=0 = 不限）。
//
// 返回报告与「枚举失败」类错误（单日补账失败不返回错误，计入 Failed 以留待重试）。
func (s *BillingService) BackfillGaps(ctx context.Context, today string, lookbackDays int) (BackfillReport, error) {
	var rep BackfillReport
	lister, ok := s.store.Ledger().(tenantDayLister)
	if !ok {
		return rep, nil // 账本不支持枚举 → 无操作（测试替身等）
	}
	from := ""
	if lookbackDays > 0 {
		from = shiftDay(today, -lookbackDays)
	}

	tenants, err := lister.Tenants()
	if err != nil {
		return rep, fmt.Errorf("billing: backfill list tenants: %w", err)
	}

	for _, tenant := range tenants {
		rep.Tenants++
		days, err := lister.DaysWithUsage(tenant)
		if err != nil {
			return rep, fmt.Errorf("billing: backfill days tenant=%s: %w", tenant, err)
		}
		billed, err := s.store.Bills().List(BillQuery{TenantID: tenant, Kind: BillKindDaily})
		if err != nil {
			return rep, fmt.Errorf("billing: backfill billed tenant=%s: %w", tenant, err)
		}
		have := make(map[string]bool, len(billed))
		for _, b := range billed {
			have[b.Period] = true
		}

		for _, day := range days {
			if day >= today { // 当日/未来日不补（仍在累积）
				continue
			}
			if from != "" && day < from { // 超出回看窗口
				continue
			}
			if have[day] {
				continue // 已出账（幂等）
			}
			rep.Missing++
			if _, err := s.CloseDaily(ctx, tenant, day); err != nil {
				if errors.Is(err, ErrFrozen) {
					rep.Skipped++ // 冻结期不出账（B-6.10-3：解冻后由下轮补出）
					continue
				}
				rep.Failed++
				log.Printf("[billing] S-8 补账失败 tenant=%s day=%s: %v", tenant, day, err)
				continue
			}
			rep.Closed++
		}
	}
	return rep, nil
}
