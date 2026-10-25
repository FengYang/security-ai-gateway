// Package backup 实现 P2-3 T-2「密钥跨模块协同」的备份/恢复/轮换/销毁能力。
//
// 设计口径唯一源：P2-3 主线文档 §6.2.5「密钥备份/恢复」与 D-9/D-13/D-20：
//   - 备份/恢复只走可选 KeyBackupBackend；**禁止明文导出**；禁止 WrapKey 用于长期密钥；
//     禁止软件加密备份（密钥材料仍出模块，密评风险）；不做 KMIP。
//   - backup_id 由备份库分配并回填；admin/控制面只传 key_id/backup_id，不接触 blob。
//   - 销毁必须同时清 HSM 对象 + 成员本地备份 + 备份库 blob（或 crypto-shred），
//     tombstone 后 restore 必须失败；只删 HSM 对象不删备份不算销毁。
//
// 本包为 **Wave B 代码研发**产物：接口与编排不依赖第三方硬件，可对着内存备份库与
// mock 成员开发验证；真实厂商 wrap/克隆能力核验（§15.3 MUST-4）与真机验收仍挂起，
// 因此本包**不宣称真机通过、不宣称 S3-b/密评、不宣称 G-0 闭合**。
package backup

import (
	"errors"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
)

// 备份/恢复相关错误（对齐 §6.2.5 / §6.5 错误码口径）。
var (
	// ErrBackupUnsupported 交叉校验 Vendor/Model/Mechanism/KEKID 不匹配：
	// 不得尝试软件解包（§6.2.5）。
	ErrBackupUnsupported = errors.New("group_key_backup_unsupported")
	ErrBackupNotFound    = errors.New("backup_not_found")
	// ErrBackupTombstoned 目标对象已 tombstone：restore 必须失败（§6.2.5 销毁语义）。
	ErrBackupTombstoned = errors.New("backup_tombstoned")
	ErrApprovalRequired = errors.New("group_approval_required")
	ErrApprovalNotFound = errors.New("approval_not_found")
	ErrApprovalConsumed = errors.New("approval_consumed")
	ErrApprovalDigest   = errors.New("approval_digest_mismatch")
	ErrApprovalExpired  = errors.New("approval_expired")
	// ErrQuorumUnmet key_replication=quorum/all 下副本未达阈值：
	// 目录置 degraded，**不得宣称 RPO=0**（D-13/§6.2.3）。
	ErrQuorumUnmet = errors.New("backup_quorum_unmet")
	// ErrCrossCheckMismatch 恢复前交叉校验（Vendor/Model/Mechanism/KEKID/checksum）不通过。
	ErrCrossCheckMismatch = errors.New("backup_crosscheck_mismatch")
	// ErrDestroyPending 销毁未完全生效（副本不可达或 blob 删除失败）：保持告警态。
	ErrDestroyPending = errors.New("backup_destroy_pending")
)

// WrappedKey 成员本地 wrap 产物的元数据 + blob。
//
// Blob **禁止**写入控制存储/日志/审计/指标；只经由 KeyBackupStore.Put 落备份库，
// 控制面与 admin 只流转 backup_id（§6.2.5）。
type WrappedKey struct {
	BackupID    string // 由备份库分配并回填；成员不得自行编造
	KeyID       string
	Member      string
	KEKID       string
	Blob        []byte // wrap 产物本体；不得序列化进控制面
	Checksum    []byte // blob 校验和，恢复前必校
	WrappedSize int64
	Vendor      string // 交叉校验用：厂商/型号/机制（§6.2.5）
	Model       string
	Mechanism   string
	CreatedAt   time.Time
	State       string // ready|destroy_pending|destroyed
}

// BackupMeta 备份库回执：控制面/审计只放这些字段，**不放 blob**。
type BackupMeta struct {
	BackupID    string
	Checksum    []byte
	WrappedSize int64
	CreatedAt   time.Time
	State       string
}

// KeyBackupBackend 成员侧 wrap/unwrap 能力（模块内完成，密钥明文不出模块）。
//
// 语义对齐 §6.2.5：
//   - ExportWrapped 只能由具备 CKA_WRAP 白名单的 KEK 执行，仅当前组主可调用；
//   - ImportWrapped 在目标模块内直接建对象（CKA_SENSITIVE=true/CKA_EXTRACTABLE=false），
//     失败不得留下半成品（审计 orphan 并尝试 DestroyKey）；
//   - DestroyWrapped 删除成员本地/厂商备份对象，备份库 blob 删除走 KeyBackupStore.Delete。
type KeyBackupBackend interface {
	ExportWrapped(keyRef module.KeyRef, kekID string) (WrappedKey, error)
	ImportWrapped(wrapped WrappedKey, kekID string, alias string) (module.KeyRef, error)
	DestroyWrapped(backupID string) error
}

// KeyBackupStore 备份库客户端契约（成员侧用 mTLS 连接；§6.2.5）。
//
// backup_id 必须绑定 gid/key_id/member/KEKID，跨组/跨密钥/跨成员复用即拒绝；
// 服务端始终以 BackupMeta.BackupID 为权威值回填。
type KeyBackupStore interface {
	Put(gid, keyID, member, kekID string, w WrappedKey) (BackupMeta, error)
	Get(gid, keyID, backupID string) (WrappedKey, BackupMeta, error)
	Delete(gid, keyID, backupID string) error
}

// Approval 双签审批单（§6.2.6 / §7.2：rotate/destroy/backup/restore 等高危操作需双签）。
type Approval struct {
	ApprovalID string
	GroupID    string
	Action     string // backup|restore|clone|destroy（真轮换走 ModuleGroup.RotateKey，不经审批单）
	Target     string // key_id
	Digest     string // 动作摘要 SHA-256，Consume 时校验
	Initiator  string
	Confirmer  string
	CreatedAt  time.Time
	ExpiresAt  time.Time
}

// ApprovalStore 审批单存储。
type ApprovalStore interface {
	Create(a Approval) error
	Get(groupID, approvalID string) (Approval, error)
	// Consume 校验 digest 一致、未消费、未过期后标记消费；任一项不满足返回对应错误。
	Consume(groupID, approvalID, digest string) error
}

// KeyOpStep 按成员执行的编排步骤（backup/restore/rotate/destroy 均为 KeyOpStep）。
//
// Result 只放 BackupMeta（backup_id/checksum/wrapped_size），**不放 blob**（§6.2.5）。
type KeyOpStep struct {
	OpID    string
	Member  string
	Action  string // backup|backup_store|restore|restore_import|destroy|rotate
	Version int64
	Status  string // pending|running|succeeded|failed
	Result  BackupMeta
	Err     string
}

// KeyOpStepStore 步骤存储：状态迁移必须 CAS，禁止无条件覆盖。
//
// 注意：同一成员在同一 KeyOp 下可有**多个不同 action 的步骤**
// （如 backup → backup_store），故 CAS/Get 的键包含 action。
type KeyOpStepStore interface {
	Create(step KeyOpStep) (int64, error)
	CAS(opID, member, action string, expectedVersion int64, expectedStatus string, step KeyOpStep) (int64, error)
	Get(opID, member, action string) (KeyOpStep, int64, error)
	List(opID string) ([]KeyOpStep, error)
}

// quorumFor 按 D-13 计算 quorum 阈值：2 成员→2，3 成员→2，4 成员→3（即 n/2+1）。
//
// 注意：quorum 达成只代表"已同步到 quorum 的写"；全副本丢失/站点隔离仍走灾难恢复，
// 不得据此宣称 RPO=0（D-13 原文）。
func quorumFor(memberCount int) int {
	if memberCount <= 0 {
		return 0
	}
	return memberCount/2 + 1
}

// replicationTarget 按 key_replication 与成员数计算需要成功的副本数。
// single=1；quorum=quorumFor(n)；all=n。isolated 模式只能 single（D-13）。
func replicationTarget(replication string, memberCount int) int {
	switch replication {
	case "single":
		return 1
	case "all":
		return memberCount
	default: // quorum（shared 默认）
		return quorumFor(memberCount)
	}
}
