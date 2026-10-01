// Package billing — 控制面账务域（gateway-admin-service 子系统）。
//
// 定位：套餐/配额编译/账本/计价/账单/异常/冻结/查询 的统一实现包。
// 信任边界：本包不接触明文内容，输入仅为结构化计数（tenant/model/tokens），
// 单价表为公开商业配置，金额计算不需要内容明文（§3.1.2）。
//
// 默认关闭：billing.enabled=false 时，不注册任何 /billing 端点、不启动任何
// 定时任务、/usage 响应逐字节不变（R-1/M10/附录 F.2.4）。
package billing

import "errors"

// ---------- 同步模式（单写者，A-12/R-30） ----------

const (
	SyncModePull = "pull" // 拉取为唯一账本写入者（默认/权威）；推送仅实时视图
	SyncModePush = "push" // 推送为唯一账本写入者；拉取仅供 L2 对账
)

// ---------- 金额 ----------

// Amount 金额（单位：分，int64）。杜绝浮点。
type Amount int64

// ---------- 错误哨兵 ----------

var (
	// ErrUnique 唯一约束冲突（调用方转 Get 处理幂等，§6.6.1）。
	ErrUnique = errors.New("billing: unique constraint violated")
	// ErrFrozen 租户已冻结（账单不可交付，§6.10.3）。
	ErrFrozen = errors.New("billing: tenant frozen")
	// ErrPricingMissing 单价表缺该模型（拒出账，§6.10.3）。
	ErrPricingMissing = errors.New("billing: pricing missing for model")
	// ErrLedgerAnchorMismatch 账本链尾锚定不符（S-10 关联校验，§7.3）。
	ErrLedgerAnchorMismatch = errors.New("billing: ledger anchor mismatch")
	// ErrAuditAnchorMissing 审计链锚定不存在（§7.3）。
	ErrAuditAnchorMissing = errors.New("billing: audit anchor missing")
)

// IsUnique 判定是否为唯一约束冲突（A-4 收敛，§4.1.8）。
func IsUnique(err error) bool {
	return errors.Is(err, ErrUnique)
}
