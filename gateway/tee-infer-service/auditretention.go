// 审计/日志留存期声明（合规口径：默认 12 个月，法定下限 6 个月）。
//
// 设计要点（两条纪律，与 contentlabel.go 一致）：
//   - **声明式**：本配置只声明留存期（暴露于启动日志 / GET /config / 指标），
//     服务**不删除任何审计数据**——审计链为只追加（WORM），就地裁剪会破坏哈希链
//     完整性（`audit-verify` 无法从创世重算）。删除动作由**存储层生命周期策略**
//     按本声明值执行，二者应保持一致（"声明—执行"可核验对）。
//   - 校验 fail-closed：取值 <0，或落在 (0, minAuditRetentionDays) 区间 → 启动失败
//     （法定硬底不可下探）；**0 = 显式不声明**（启动告警，检查/备案时须说明留存策略）。
package main

import "fmt"

const (
	// defaultAuditRetentionDays 缺省声明值＝365 天（对应 12 个月的合规口径）。
	defaultAuditRetentionDays = 365
	// minAuditRetentionDays 法定硬底＝180 天（"不少于六个月"，按 180 天计）。
	// 依据：《中华人民共和国网络安全法》（2025 年修正）第二十三条第(三)项。
	minAuditRetentionDays = 180
)

// validateAuditRetentionDays 校验留存期声明（单位：天）；非法即返回错误（启动期 fail-closed）。
func validateAuditRetentionDays(days int) error {
	if days < 0 {
		return fmt.Errorf("audit-retention-days=%d 非法（不可为负；0=不声明）", days)
	}
	if days > 0 && days < minAuditRetentionDays {
		return fmt.Errorf("audit-retention-days=%d 低于法定硬底 %d 天"+
			"（《网络安全法》第二十三条第(三)项：网络日志留存不少于六个月）；如需不声明请显式设 0", days, minAuditRetentionDays)
	}
	return nil
}

// ---- P1-7 T5（MOD4 分层声明，§7.5）----

// RetentionPolicy 热/温/冷分层与未命中采样声明（声明式，服务不删除数据，C-4）。
type RetentionPolicy struct {
	HotDays        int // 热层留存天数（本地 WORM，检索快）
	WarmDays       int // 温层留存天数（对象存储，全量归档）
	ColdDays       int // 冷层留存天数（对象存储，仅命中事件）
	SampleMissRate int // 读取/导出侧未命中降采样率（0–100，0=不采样；合规档默认 0）
}

// defaultRetentionPolicy 缺省分层（热 7d / 温 30d / 冷 180d；合计 ≥180 硬底，C-8）。
var defaultRetentionPolicy = RetentionPolicy{HotDays: 7, WarmDays: 30, ColdDays: 180, SampleMissRate: 0}

// validateRetentionPolicy 校验分层声明（fail-closed，§7.5 T5）：
//   - HotDays ≥ 1
//   - WarmDays > HotDays
//   - ColdDays ≥ WarmDays
//   - HotDays+WarmDays+ColdDays ≥ 180（C-8 法定硬底）
//   - 0 ≤ SampleMissRate ≤ 100
func validateRetentionPolicy(p RetentionPolicy) error {
	if p.HotDays < 1 {
		return fmt.Errorf("retention: HotDays=%d 必须 ≥ 1", p.HotDays)
	}
	if p.WarmDays <= p.HotDays {
		return fmt.Errorf("retention: WarmDays=%d 必须 > HotDays=%d", p.WarmDays, p.HotDays)
	}
	if p.ColdDays < p.WarmDays {
		return fmt.Errorf("retention: ColdDays=%d 必须 ≥ WarmDays=%d", p.ColdDays, p.WarmDays)
	}
	if p.HotDays+p.WarmDays+p.ColdDays < minAuditRetentionDays {
		return fmt.Errorf("retention: 合计 %d 天低于法定硬底 %d 天（C-8）", p.HotDays+p.WarmDays+p.ColdDays, minAuditRetentionDays)
	}
	if p.SampleMissRate < 0 || p.SampleMissRate > 100 {
		return fmt.Errorf("retention: SampleMissRate=%d 必须 ∈ [0,100]", p.SampleMissRate)
	}
	return nil
}
