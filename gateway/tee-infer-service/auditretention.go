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
