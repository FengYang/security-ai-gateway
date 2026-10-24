package poc

// 控制存储类型（与本体 §6.2.6 / §6.2.7 同名结构对齐；poc 为独立参考实现）。

import "time"

// OwnerState 持久 epoch 与当前租约（供观测；不得用于"先判后写"）。
type OwnerState struct {
	Epoch           uint64
	LastOwner       string
	LastOwnerBootID string
	LastDC          string
	DesiredVersion  uint64
	Lease           *LeaseStatus
	StoreRevision   int64
}

// Promotion 已确认的人工切换（双签审批）。
type Promotion struct {
	TargetMember  string
	ExpectedEpoch uint64
	ApprovalID    string
	Digest        string
}

// OwnerAcquireRequest 组主获取请求。
//
// last_owner/last_owner_dc 不在请求中由调用方提供：store 必须在同一 txn 内读取
// /epoch 与 /lease，避免调用方用陈旧值做 TOCTOU 判定（§3.1.1 算法 2）。
type OwnerAcquireRequest struct {
	Member                 string
	DC                     string
	BootID                 string
	ExpectedEpoch          uint64
	ExpectedDesiredVersion uint64
	AllowBootstrap         bool
	AllowAutoIntraDC       bool
	Promotion              *Promotion
	BootstrapOwner         string // 来自 leader.bootstrap_owner
	TTL                    time.Duration
}

// LeaseStatus 当前组主租约。
type LeaseStatus struct {
	Holder        string
	HolderBootID  string
	DC            string
	Epoch         uint64
	ExpiresAt     time.Time
	StoreRevision int64
}

// KeyOp 组级生命周期命令（字段子集，覆盖本 POC 所需）。
type KeyOp struct {
	OpID          string
	Action        string
	Version       int64
	StoreRevision int64
	Status        string // pending|running|succeeded|failed|destroy_pending|cancelled
	ClaimOwner    string
	ClaimEpoch    uint64
}

// Approval 双签审批（§6.2.6）。
type Approval struct {
	ApprovalID string
	GroupID    string
	Action     string
	Target     string
	Digest     string
	Initiator  string
	Confirmer  string
	ExpiresAt  time.Time
}

// 控制存储错误（与 testkit 同名错误同义，消息前缀不同以便区分实现）。
var (
	ErrGroupStaleEpoch   = errString("poc: group_stale_epoch")
	ErrGroupNoLeader     = errString("poc: group_no_leader")
	ErrGroupCASConflict  = errString("poc: group_idempotency_conflict")
	ErrGroupFenced       = errString("poc: group_fenced")
	ErrApprovalNotFound  = errString("poc: approval_not_found")
	ErrApprovalConsumed  = errString("poc: approval_consumed")
	ErrApprovalDigestBad = errString("poc: approval_digest_mismatch")
)

type errString string

func (e errString) Error() string { return string(e) }
