package testkit

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

// 本文件给出《P2--HSM集成》§6.2.6 GroupControlStore 的**内存参考实现**（测试基座），
// 用于锁定 R3-P0-01 / D-17 的并发与 CAS 语义：
//   - AcquireOwner 必须在**单个临界区（等价单 txn）**内比较 epoch/desired/lease，
//     禁止调用方在外部先判定后写入（TOCTOU）；
//   - 所有 CAS* 必须带 expectedVersion/expectedStatus，旧主/旧 step 不得覆盖新终态；
//   - Watch* 必须支持 fromRevision 续传，切换窗口不丢事件。
//
// 注意：内存实现不提供跨进程/跨 Pod 语义，仅用于契约断言，不得用于生产。

// ErrGroupStaleEpoch 竞争窗口内 epoch/desired/lease 发生变化（§3.1.1 算法 2）。
var ErrGroupStaleEpoch = errors.New("testkit: group_stale_epoch")

// ErrGroupNoLeader 无组主租约（生命周期写被拒）。
var ErrGroupNoLeader = errors.New("testkit: group_no_leader")

// ErrGroupCASConflict 版本/状态不匹配，CAS 失败（不得覆盖新终态）。
var ErrGroupCASConflict = errors.New("testkit: group_idempotency_conflict")

// ErrGroupFenced 本地租约/fence 已失效或 boot_id 不匹配。
var ErrGroupFenced = errors.New("testkit: group_fenced")

// OwnerState / OwnerAcquireRequest / LeaseStatus 与本体 §6.2.6 同名结构对齐。
type OwnerState struct {
	Epoch           uint64
	LastOwner       string
	LastOwnerBootID string
	LastDC          string
	DesiredVersion  uint64
	Lease           *LeaseStatus
	StoreRevision   int64
}

type Promotion struct {
	TargetMember  string
	ExpectedEpoch uint64
	ApprovalID    string
	Digest        string
}

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

type LeaseStatus struct {
	Holder        string
	HolderBootID  string
	DC            string
	Epoch         uint64
	ExpiresAt     time.Time
	StoreRevision int64
}

// KeyOp 组级生命周期命令（字段子集，覆盖本契约测试所需）。
type KeyOp struct {
	OpID          string
	Action        string
	Version       int64
	StoreRevision int64
	Status        string // pending|running|succeeded|failed|destroy_pending|cancelled
	ClaimOwner    string
	ClaimEpoch    uint64
}

// DesiredState 简化版（仅承载 version，用于判定 CAS 条件）。
type DesiredState struct {
	Version uint64
}

// MemoryControlStore 内存实现：所有状态迁移在单个互斥锁内完成，等价"单 txn"原子性。
type MemoryControlStore struct {
	mu sync.Mutex

	gid      string
	epoch    uint64
	lastOwn  string
	lastDC   string
	lastBoot string
	hasEpoch bool
	lease    *LeaseStatus

	desired DesiredState

	ops    map[string]KeyOp
	dirs   map[string]KeyDirectory
	dirVer map[string]int64

	rev int64 // 单调递增的 store revision
}

func NewMemoryControlStore(gid string) *MemoryControlStore {
	return &MemoryControlStore{
		gid: gid, ops: map[string]KeyOp{}, dirs: map[string]KeyDirectory{}, dirVer: map[string]int64{},
	}
}

func (s *MemoryControlStore) nextRev() int64 {
	s.rev++
	return s.rev
}

// GetOwnerState 返回持久 epoch 与当前租约（供调用方观察，不得用于"先判后写"）。
func (s *MemoryControlStore) GetOwnerState() OwnerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := OwnerState{
		Epoch: s.epoch, LastOwner: s.lastOwn, LastOwnerBootID: s.lastBoot,
		LastDC: s.lastDC, DesiredVersion: s.desired.Version, Lease: s.lease, StoreRevision: s.rev,
	}
	if s.lease != nil {
		cp := *s.lease
		st.Lease = &cp
	}
	return st
}

// SetDesired 由 admin 写入期望状态（版本 +1）。
func (s *MemoryControlStore) SetDesired() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.desired.Version++
	s.nextRev()
	return s.desired.Version
}

func (s *MemoryControlStore) DesiredVersion() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.desired.Version
}

// AcquireOwner 在单个临界区内完成全部判定与写入（§3.1.1 算法 2 / D-17）。
//
// 允许条件（三者之一）：
//
//	① promotion.target == self 且 promotion.ExpectedEpoch == 当前 epoch 且审批非空；
//	② 无 promotion 且已存在 last_owner 且 self.dc == last_dc 且 AllowAutoIntraDC（同 DC 自动接管）；
//	③ 首次（尚无 epoch）且 AllowBootstrap 且 bootstrap_owner == self。
func (s *MemoryControlStore) AcquireOwner(req OwnerAcquireRequest) (LeaseStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 单 txn 内比较：epoch 与 desired 版本任一不符即 group_stale_epoch。
	if s.hasEpoch && req.ExpectedEpoch != s.epoch {
		return LeaseStatus{}, fmt.Errorf("%w: epoch 期望 %d 实际 %d", ErrGroupStaleEpoch, req.ExpectedEpoch, s.epoch)
	}
	if req.ExpectedDesiredVersion != s.desired.Version {
		return LeaseStatus{}, fmt.Errorf("%w: desired 版本期望 %d 实际 %d", ErrGroupStaleEpoch, req.ExpectedDesiredVersion, s.desired.Version)
	}
	// 租约存在且未过期则不可抢占（不得仅凭本地 expires_at 抢）。
	if s.lease != nil && time.Now().Before(s.lease.ExpiresAt) {
		return LeaseStatus{}, fmt.Errorf("%w: 已存在组主 %s(epoch=%d)", ErrGroupStaleEpoch, s.lease.Holder, s.lease.Epoch)
	}

	switch {
	case req.Promotion != nil:
		if req.Promotion.TargetMember != req.Member {
			return LeaseStatus{}, fmt.Errorf("%w: promotion 目标不是本成员", ErrGroupStaleEpoch)
		}
		if req.Promotion.ExpectedEpoch != s.epoch {
			return LeaseStatus{}, fmt.Errorf("%w: promotion expected_epoch 不匹配", ErrGroupStaleEpoch)
		}
		if req.Promotion.ApprovalID == "" || req.Promotion.Digest == "" {
			return LeaseStatus{}, fmt.Errorf("%w: promotion 缺双签审批", ErrGroupStaleEpoch)
		}
	case s.hasEpoch && s.lastOwn != "":
		// 同 DC 自动接管；跨 DC 必须 promotion。
		if !req.AllowAutoIntraDC {
			return LeaseStatus{}, fmt.Errorf("%w: 未开启同 DC 自动接管", ErrGroupStaleEpoch)
		}
		if req.DC != s.lastDC {
			return LeaseStatus{}, fmt.Errorf("%w: 跨 DC 切换必须人工 promotion（禁止自动）", ErrGroupStaleEpoch)
		}
	default:
		// 首次建主
		if !req.AllowBootstrap {
			return LeaseStatus{}, fmt.Errorf("%w: 首次建主需 AllowBootstrap", ErrGroupStaleEpoch)
		}
		if req.BootstrapOwner == "" || req.BootstrapOwner != req.Member {
			return LeaseStatus{}, fmt.Errorf("%w: bootstrap_owner 必须是本成员", ErrGroupStaleEpoch)
		}
	}

	ttl := req.TTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	s.epoch++
	s.hasEpoch = true
	s.lastOwn = req.Member
	s.lastDC = req.DC
	s.lastBoot = req.BootID
	rev := s.nextRev()
	s.lease = &LeaseStatus{
		Holder: req.Member, HolderBootID: req.BootID, DC: req.DC,
		Epoch: s.epoch, ExpiresAt: time.Now().Add(ttl), StoreRevision: rev,
	}
	return *s.lease, nil
}

// RenewOwner 续租：boot_id 与 epoch 必须同时匹配，缺失/不一致即失败（D-17）。
func (s *MemoryControlStore) RenewOwner(member, bootID string, epoch uint64, ttl time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lease == nil || s.lease.Holder != member {
		return fmt.Errorf("%w: 当前无本成员持有的租约", ErrGroupFenced)
	}
	if s.lease.HolderBootID != bootID {
		return fmt.Errorf("%w: boot_id 不匹配（期望 %s 实际 %s）", ErrGroupFenced, s.lease.HolderBootID, bootID)
	}
	if s.lease.Epoch != epoch {
		return fmt.Errorf("%w: epoch 不匹配（期望 %d 实际 %d）", ErrGroupFenced, s.lease.Epoch, epoch)
	}
	s.lease.ExpiresAt = time.Now().Add(ttl)
	s.lease.StoreRevision = s.nextRev()
	return nil
}

// ReleaseOwner 主动释放（仅持有者本人且 epoch/boot_id 匹配）。
func (s *MemoryControlStore) ReleaseOwner(member, bootID string, epoch uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lease == nil || s.lease.Holder != member || s.lease.HolderBootID != bootID || s.lease.Epoch != epoch {
		return fmt.Errorf("%w: 非持有者或 boot_id/epoch 不匹配", ErrGroupFenced)
	}
	s.lease = nil
	s.nextRev()
	return nil
}

// ExpireLeaseForTest 强制让租约到期（模拟 TTL 过期/KeepAlive 失败）。
func (s *MemoryControlStore) ExpireLeaseForTest() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.lease != nil {
		s.lease.ExpiresAt = time.Now().Add(-time.Second)
	}
}

// CreateKeyOp 创建 KeyOp（版本从 1 开始）。
func (s *MemoryControlStore) CreateKeyOp(op KeyOp) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ops[op.OpID]; ok {
		return 0, fmt.Errorf("%w: KeyOp %s 已存在", ErrGroupCASConflict, op.OpID)
	}
	op.Version = 1
	op.StoreRevision = s.nextRev()
	s.ops[op.OpID] = op
	return op.StoreRevision, nil
}

// CASKeyOp 比较并交换；expectedVersion/expectedStatus 任一不符即失败，
// 保证旧主（旧 claim）不得覆盖新终态。
func (s *MemoryControlStore) CASKeyOp(opID string, expectedVersion int64, expectedStatus string, op KeyOp) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, ok := s.ops[opID]
	if !ok {
		return 0, fmt.Errorf("%w: KeyOp %s 不存在", ErrGroupCASConflict, opID)
	}
	if cur.Version != expectedVersion || cur.Status != expectedStatus {
		return 0, fmt.Errorf("%w: KeyOp %s 版本/状态不匹配（期望 v%d/%s 实际 v%d/%s）",
			ErrGroupCASConflict, opID, expectedVersion, expectedStatus, cur.Version, cur.Status)
	}
	op.Version = cur.Version + 1
	op.StoreRevision = s.nextRev()
	s.ops[opID] = op
	return op.StoreRevision, nil
}

func (s *MemoryControlStore) GetKeyOp(opID string) (KeyOp, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	op, ok := s.ops[opID]
	if !ok {
		return KeyOp{}, 0, fmt.Errorf("%w: KeyOp %s 不存在", ErrGroupCASConflict, opID)
	}
	return op, op.Version, nil
}

// WatchKeyOps 返回 revision > fromRevision 的 KeyOp（切换窗口续传，不丢事件）。
func (s *MemoryControlStore) WatchKeyOps(fromRevision int64) []KeyOp {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]KeyOp, 0)
	for _, op := range s.ops {
		if op.StoreRevision > fromRevision {
			out = append(out, op)
		}
	}
	return out
}

// CASKeyDirectory 目录写入：版本 + writer_epoch/boot_id 双重校验（§6.2.2）。
func (s *MemoryControlStore) CASKeyDirectory(keyID string, expectedVersion int64, writerEpoch uint64, writerBootID string, kd KeyDirectory) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	curVer := s.dirVer[keyID]
	if curVer != expectedVersion {
		return 0, fmt.Errorf("%w: 目录 %s 版本不匹配（期望 %d 实际 %d）", ErrGroupCASConflict, keyID, expectedVersion, curVer)
	}
	if s.lease == nil || s.lease.Epoch != writerEpoch || s.lease.HolderBootID != writerBootID {
		return 0, fmt.Errorf("%w: 目录写者非当前组主（writer_epoch/boot_id 不匹配）", ErrGroupCASConflict)
	}
	kd.Version = curVer + 1
	s.dirs[keyID] = kd
	s.dirVer[keyID] = kd.Version
	s.nextRev()
	return kd.Version, nil
}

func (s *MemoryControlStore) GetKeyDirectory(keyID string) (KeyDirectory, int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dirs[keyID], s.dirVer[keyID]
}
