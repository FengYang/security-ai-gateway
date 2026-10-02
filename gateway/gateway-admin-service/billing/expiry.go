// expiry.go — P0-3 Token 计费体系：到期扫描（S-9，§6.4.2 / §6.16）。
//
// 到期提醒（T-30d / T-7d / T-0）经指标 #21 驱动；宽限结束仍逾期再记 anomaly_total
// {kind="plan_expired",severity="critical"}。**不自动降级**（§6.4.2 原则：自动过期 ≠ 自动降级）。
// 去重经 Store.AlertDedup()（(tenant, key) 幂等），使每订阅每阈值只提醒一次。
package billing

import (
	"fmt"
	"time"
)

// nsPerDay 一天的纳秒数。
const nsPerDay = int64(24 * time.Hour)

// expiryThresholds 到期提醒阈值（天；T-30d / T-7d / T-0，§6.4.2）。
var expiryThresholds = []int{30, 7, 0}

// ExpiryReport 到期扫描结果（S-9）。
type ExpiryReport struct {
	Tenants int // 带到期时间的当前订阅租户数
	Days30  int // 本次新触发 T-30 提醒数
	Days7   int // 本次新触发 T-7 提醒数
	Days0   int // 本次新触发 T-0 提醒数
	Expired int // 本次新触发「宽限结束仍逾期」数
}

// ScanExpiries 到期扫描（S-9，§6.4.2）。
//
// 对每个租户的**当前订阅**（effective_at ≤ now 的最新一条，含已过期）：
//   - 剩余 ≤ 30 / ≤ 7 / ≤ 0 天 → 指标 #21 `plan_expiring_total{days=30|7|0}`（每订阅每阈值一次，幂等）
//   - 宽限期（到期后 7 天）结束仍逾期 → 指标 #10 `anomaly_total{kind="plan_expired",severity="critical"}`（幂等）
//
// **不自动降级**：仅提醒 + 告警，降级一律人工（§6.4.2）。
func (s *BillingService) ScanExpiries(now int64) (ExpiryReport, error) {
	var rep ExpiryReport
	subs, err := s.store.Plans().ListSubscriptions(now)
	if err != nil {
		return rep, err
	}
	// 每租户取 effective_at 最大的订阅（当前订阅）
	latest := map[string]Subscription{}
	for _, sub := range subs {
		if cur, ok := latest[sub.TenantID]; !ok || sub.EffectiveAt >= cur.EffectiveAt {
			latest[sub.TenantID] = sub
		}
	}
	dedup := s.store.AlertDedup()
	for _, sub := range latest {
		if sub.ExpiresAt <= 0 {
			continue // 不过期（0 = 永久）
		}
		rep.Tenants++
		days := (sub.ExpiresAt - now) / nsPerDay // 剩余天数（负 = 已逾期）
		base := fmt.Sprintf("expiry:%d", sub.ExpiresAt)
		for _, th := range expiryThresholds {
			if days > int64(th) {
				continue
			}
			fresh, err := dedup.MarkIfNew(sub.TenantID, fmt.Sprintf("%s:%d", base, th), now)
			if err != nil {
				return rep, err
			}
			if !fresh {
				continue // 该订阅该阈值已提醒
			}
			IncPlanExpiring(th) // 指标 #21
			// 通知租户（§6.4.2；与指标同闸（fresh）→ 每订阅每阈值仅一次）
			if s.alertSink != nil {
				s.alertSink(AlertEvent{
					Kind:     "plan_expiring",
					Tenant:   sub.TenantID,
					Days:     th,
					Severity: string(SeverityWarning),
					Period:   dayOfNs(sub.ExpiresAt), // 到期日（UTC+8）
				})
			}
			switch th {
			case 30:
				rep.Days30++
			case 7:
				rep.Days7++
			case 0:
				rep.Days0++
			}
		}
		// 宽限结束仍逾期（到期后 > 7 天）→ 告警升 critical（仍不自动降级）
		if now-sub.ExpiresAt > 7*nsPerDay {
			fresh, err := dedup.MarkIfNew(sub.TenantID, base+":expired", now)
			if err != nil {
				return rep, err
			}
			if fresh {
				IncAnomaly(string(KindPlanExpired), string(SeverityCritical)) // 指标 #10
				rep.Expired++
			}
		}
	}
	return rep, nil
}
