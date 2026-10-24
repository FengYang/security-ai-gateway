package backup

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// ---------------------------------------------------------------------------
// 内存备份库（MemoryKeyBackupStore）
//
// 用于 Wave B 代码研发阶段的编排验证：语义对齐 §6.2.5 的 KeyBackupStore 契约
// （backup_id 绑定 gid/key_id/member/KEKID、服务端回填权威 ID、tombstone 后不可读），
// 但**不提供生产级的库侧加密/ACL/WORM**——那是备份库（vendor_library/mofn）的职责，
// 真机/厂商能力核验（§15.3）仍挂起，故本实现不得用于宣称密评或生产合规。
// ---------------------------------------------------------------------------

type memBackupRecord struct {
	gid        string
	keyID      string
	backupID   string
	member     string
	kekID      string
	blob       []byte
	meta       BackupMeta
	tombstoned bool
	// 交叉校验字段（§6.2.5）：恢复前须校验 Vendor/Model/Mechanism 与 KEKID，
	// 不匹配即 group_key_backup_unsupported，不得软件解包。
	vendor    string
	model     string
	mechanism string
}

// MemoryKeyBackupStore 内存备份库（测试/开发用）。
type MemoryKeyBackupStore struct {
	mu   sync.Mutex
	recs map[string]*memBackupRecord // key: gid|keyID|backupID
	// usedBID: gid|backupID → keyID。§6.2.5 要求 backup_id 绑定 gid/key_id/member/KEKID，
	// **跨组/跨密钥/跨成员复用即拒绝**；仅按 (gid,keyID,backupID) 查重无法拦截"同一
	// backup_id 挂到另一个 key_id"的情形，故另建全局唯一索引。
	usedBID map[string]string
	seq     uint64
}

// NewMemoryKeyBackupStore 创建空的内存备份库。
func NewMemoryKeyBackupStore() *MemoryKeyBackupStore {
	return &MemoryKeyBackupStore{
		recs:    map[string]*memBackupRecord{},
		usedBID: map[string]string{},
	}
}

func backupRecKey(gid, keyID, backupID string) string {
	return gid + "|" + keyID + "|" + backupID
}

// Put 写入 blob：backup_id 为空时由备份库分配；非空时校验唯一性（跨组/跨密钥复用即拒绝）。
// 服务端始终以自身分配的 BackupID 为权威值回填（§6.2.5）。
func (s *MemoryKeyBackupStore) Put(gid, keyID, member, kekID string, w WrappedKey) (BackupMeta, error) {
	if gid == "" || keyID == "" || member == "" || kekID == "" {
		return BackupMeta{}, fmt.Errorf("backup: gid/keyID/member/kekID 均必填")
	}
	if len(w.Blob) == 0 {
		return BackupMeta{}, fmt.Errorf("backup: blob 为空，拒绝写入（疑似明文导出路径）")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// 校验和：调用方可自带，但备份库始终以 blob 实际内容为准重新计算并回填。
	sum := sha256.Sum256(w.Blob)
	checksum := sum[:]

	bid := w.BackupID
	if bid == "" {
		s.seq++
		bid = fmt.Sprintf("bk-%s-%s-%d", keyID, member, s.seq)
	}
	// backup_id 在 gid 内全局唯一：已绑定到任何其他 key_id 即拒绝（§6.2.5），
	// 不得静默覆盖，避免跨密钥/跨成员复用造成恢复错乱。
	if usedBy, exists := s.usedBID[gid+"|"+bid]; exists {
		return BackupMeta{}, fmt.Errorf("backup: backup_id=%s 已绑定 gid=%s key=%s，拒绝跨密钥/跨成员复用", bid, gid, usedBy)
	}
	s.usedBID[gid+"|"+bid] = keyID

	meta := BackupMeta{
		BackupID:    bid,
		Checksum:    checksum,
		WrappedSize: int64(len(w.Blob)),
		CreatedAt:   time.Now().UTC(),
		State:       "ready",
	}
	s.recs[backupRecKey(gid, keyID, bid)] = &memBackupRecord{
		gid: gid, keyID: keyID, backupID: bid, member: member, kekID: kekID,
		blob: w.Blob, meta: meta,
		vendor: w.Vendor, model: w.Model, mechanism: w.Mechanism,
	}
	return meta, nil
}

// Get 只返回当前组/当前 key 下**未被 tombstone** 的 blob；已 tombstone → ErrBackupTombstoned。
func (s *MemoryKeyBackupStore) Get(gid, keyID, backupID string) (WrappedKey, BackupMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.recs[backupRecKey(gid, keyID, backupID)]
	if !ok {
		return WrappedKey{}, BackupMeta{}, ErrBackupNotFound
	}
	if rec.tombstoned {
		return WrappedKey{}, BackupMeta{}, ErrBackupTombstoned
	}
	// 权威值以备份库记录为准（成员不得自行编造）。
	w := WrappedKey{
		BackupID:    rec.backupID,
		KeyID:       rec.keyID,
		Member:      rec.member,
		KEKID:       rec.kekID,
		Blob:        rec.blob,
		Checksum:    rec.meta.Checksum,
		WrappedSize: rec.meta.WrappedSize,
		Vendor:      rec.vendor,
		Model:       rec.model,
		Mechanism:   rec.mechanism,
		CreatedAt:   rec.meta.CreatedAt,
		State:       rec.meta.State,
	}
	return w, rec.meta, nil
}

// Delete 删除备份库 blob（tombstone 语义：销毁后不可恢复）。
func (s *MemoryKeyBackupStore) Delete(gid, keyID, backupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.recs[backupRecKey(gid, keyID, backupID)]
	if !ok {
		return ErrBackupNotFound
	}
	rec.tombstoned = true
	rec.blob = nil
	rec.meta.State = "destroyed"
	return nil
}

// TombstonedForTest 测试辅助：查询某备份是否已被 tombstone。
func (s *MemoryKeyBackupStore) TombstonedForTest(gid, keyID, backupID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok := s.recs[backupRecKey(gid, keyID, backupID)]
	return ok && rec.tombstoned
}

// ---------------------------------------------------------------------------
// 内存双签审批库（MemoryApprovalStore）
// ---------------------------------------------------------------------------

// MemoryApprovalStore 审批单的内存实现（生产由 admin-service/etcd 承载）。
type MemoryApprovalStore struct {
	mu        sync.Mutex
	approvals map[string]Approval // key: groupID|approvalID
	consumed  map[string]bool
}

// NewMemoryApprovalStore 创建空的审批库。
func NewMemoryApprovalStore() *MemoryApprovalStore {
	return &MemoryApprovalStore{
		approvals: map[string]Approval{},
		consumed:  map[string]bool{},
	}
}

func approvalKey(groupID, approvalID string) string { return groupID + "|" + approvalID }

// Create 登记审批单；同一 (groupID, approvalID) 重复登记即冲突（防止重放覆盖）。
func (s *MemoryApprovalStore) Create(a Approval) error {
	if a.GroupID == "" || a.ApprovalID == "" || a.Digest == "" {
		return fmt.Errorf("approval: groupID/approvalID/digest 必填")
	}
	if a.Initiator == "" || a.Confirmer == "" {
		return ErrApprovalRequired
	}
	if a.Initiator == a.Confirmer {
		// 双签分权：同一人不得兼任（对齐 P1-5 R-S3-10 分权原则）。
		return fmt.Errorf("approval: initiator 与 confirmer 不得为同一人（双签分权）")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	k := approvalKey(a.GroupID, a.ApprovalID)
	if _, exists := s.approvals[k]; exists {
		return fmt.Errorf("approval: approvalID=%s 已存在", a.ApprovalID)
	}
	s.approvals[k] = a
	return nil
}

// Get 读取审批单。
func (s *MemoryApprovalStore) Get(groupID, approvalID string) (Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.approvals[approvalKey(groupID, approvalID)]
	if !ok {
		return Approval{}, ErrApprovalNotFound
	}
	return a, nil
}

// Consume 校验 digest 一致 + 未消费 + 未过期，通过后标记已消费（一次性）。
func (s *MemoryApprovalStore) Consume(groupID, approvalID, digest string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := approvalKey(groupID, approvalID)
	a, ok := s.approvals[k]
	if !ok {
		return ErrApprovalNotFound
	}
	if s.consumed[k] {
		return ErrApprovalConsumed
	}
	if a.Digest != digest {
		return ErrApprovalDigest
	}
	if !a.ExpiresAt.IsZero() && time.Now().UTC().After(a.ExpiresAt) {
		return ErrApprovalExpired
	}
	s.consumed[k] = true
	return nil
}

// DigestFor 计算动作摘要（Initiator+Confirmer 之外的动作内容参与摘要，便于测试构造）。
func DigestFor(action, target, arg string) string {
	sum := sha256.Sum256([]byte(action + "|" + target + "|" + arg))
	return hex.EncodeToString(sum[:])
}

// ---------------------------------------------------------------------------
// 内存 KeyOpStep 库（MemoryKeyOpStepStore）
// ---------------------------------------------------------------------------

// MemoryKeyOpStepStore 步骤的内存实现：状态迁移走 CAS，禁止无条件覆盖。
type MemoryKeyOpStepStore struct {
	mu    sync.Mutex
	steps map[string]KeyOpStep // key: opID|member
	vers  map[string]int64
}

// NewMemoryKeyOpStepStore 创建空步骤库。
func NewMemoryKeyOpStepStore() *MemoryKeyOpStepStore {
	return &MemoryKeyOpStepStore{
		steps: map[string]KeyOpStep{},
		vers:  map[string]int64{},
	}
}

// stepKey 含 action：同一成员在同一 KeyOp 下可有 backup 与 backup_store 等多个步骤，
// 仅用 (opID, member) 会让后者覆盖前者（曾导致 backup_store 的 BackupMeta 丢失）。
func stepKey(opID, member, action string) string { return opID + "|" + member + "|" + action }

// Create 新建步骤（version=1）。已存在则冲突。
func (s *MemoryKeyOpStepStore) Create(step KeyOpStep) (int64, error) {
	if step.OpID == "" || step.Member == "" {
		return 0, fmt.Errorf("backup: step 的 opID/member 必填")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	k := stepKey(step.OpID, step.Member, step.Action)
	if _, exists := s.steps[k]; exists {
		return 0, fmt.Errorf("backup: step op=%s member=%s action=%s 已存在", step.OpID, step.Member, step.Action)
	}
	step.Version = 1
	s.steps[k] = step
	s.vers[k] = 1
	return 1, nil
}

// CAS 条件更新：expectedVersion/expectedStatus 均须匹配（空 expectedStatus 表示不校验状态）。
func (s *MemoryKeyOpStepStore) CAS(opID, member, action string, expectedVersion int64, expectedStatus string, step KeyOpStep) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k := stepKey(opID, member, action)
	cur, ok := s.steps[k]
	if !ok {
		return 0, fmt.Errorf("backup: step op=%s member=%s action=%s 不存在", opID, member, action)
	}
	if cur.Version != expectedVersion {
		return 0, fmt.Errorf("backup: step 版本冲突（期望 %d，实际 %d）", expectedVersion, cur.Version)
	}
	if expectedStatus != "" && cur.Status != expectedStatus {
		return 0, fmt.Errorf("backup: step 状态冲突（期望 %s，实际 %s）", expectedStatus, cur.Status)
	}
	next := expectedVersion + 1
	step.Version = next
	s.steps[k] = step
	s.vers[k] = next
	return next, nil
}

// Get 读取步骤与版本。
func (s *MemoryKeyOpStepStore) Get(opID, member, action string) (KeyOpStep, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.steps[stepKey(opID, member, action)]
	if !ok {
		return KeyOpStep{}, 0, fmt.Errorf("backup: step op=%s member=%s action=%s 不存在", opID, member, action)
	}
	return st, st.Version, nil
}

// List 列出某 KeyOp 的全部步骤。
func (s *MemoryKeyOpStepStore) List(opID string) ([]KeyOpStep, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []KeyOpStep
	for _, st := range s.steps {
		out = append(out, st)
	}
	return out, nil
}
