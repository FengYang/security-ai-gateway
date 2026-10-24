package poc

// KeyBackupStore 内存参考实现（V-3 用；生产为 backup.endpoint mTLS 客户端）。
//
// 契约（本体 §6.2.5 / D-9）：
//   - backup_id 为空时由备份库分配，非空时校验唯一性；重复 Put 返回既有 BackupMeta（幂等），
//     不得覆盖原 blob；
//   - backup_id 必须绑定 gid/key_id/member/KEKID，跨组/跨密钥/跨成员复用即拒绝；
//   - Get 只返回当前组、未被 tombstone 的 blob，恢复前校验 checksum；
//   - 服务端始终以 BackupMeta.BackupID 为权威值回填 WrappedKey.BackupID。

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// WrappedKey 模块内 wrap 后的备份对象（不含明文；与本体 §6.2.5 字段逐一对齐）。
//
// 注意：文档未设 Member 字段——member 身份在生产由 mTLS 客户端证书承载，
// POC 以 context 值模拟（见 MemberFromContext）。
type WrappedKey struct {
	Version   uint8  // 当前 0x01
	KeyID     string // 32 位小写 hex（与 GroupKeyRef.key_id 一致）
	KEKID     string // 备份 KEK 逻辑 ID（backup.kek_id）
	BackupID  string // 备份库分配；调用 Put 时可为空，由服务端分配后回填
	Vendor    string // 厂商/型号（交叉导入校验）
	Model     string
	Mechanism string // 如 CKM_AES_KEY_WRAP / CKM_SM4_GCM
	Alias     string // 目标对象别名（不含密钥材料）
	Blob      []byte // 模块内 wrap 后的密文；不含明文
	Checksum  []byte // HMAC-SM3(Blob)，密钥为备份 KEK/独立 MAC 密钥；不得只用裸 SHA-256
}

// BackupMeta 备份库元数据（与本体 §6.2.5 对齐）。
type BackupMeta struct {
	BackupID    string
	KeyID       string
	Member      string
	KEKID       string
	Checksum    []byte
	WrappedSize int64
	CreatedAt   time.Time
	State       string // ready|destroy_pending|destroyed
}

// KeyBackupStore 备份库接口（本体 §6.2.5 四方法）。
type KeyBackupStore interface {
	Put(ctx context.Context, gid, keyID, backupID string, wrapped WrappedKey) (BackupMeta, error)
	Get(ctx context.Context, gid, backupID string) (WrappedKey, BackupMeta, error)
	Delete(ctx context.Context, gid, backupID string) error
	List(ctx context.Context, gid, keyID string) ([]BackupMeta, error)
}

var (
	// ErrBackupNotFound 备份不存在/已删除。
	ErrBackupNotFound = errors.New("poc: backup_not_found")
	// ErrBackupBindingViolation backup_id 跨组/跨密钥/跨成员复用。
	ErrBackupBindingViolation = errors.New("poc: backup_binding_violation")
	// ErrBackupChecksumMismatch checksum 与 blob 不匹配。
	ErrBackupChecksumMismatch = errors.New("poc: backup_checksum_mismatch")
	// ErrBackupOverwrite 禁止用不同内容覆盖既有 backup_id。
	ErrBackupOverwrite = errors.New("poc: backup_overwrite_forbidden")
)

type memberCtxKey struct{}

// WithMember 把成员身份写入 context（生产对应 mTLS 客户端证书 CN）。
func WithMember(ctx context.Context, member string) context.Context {
	return context.WithValue(ctx, memberCtxKey{}, member)
}

// MemberFromContext 读取成员身份；缺失返回空串（Put 将拒绝）。
func MemberFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(memberCtxKey{}).(string); ok {
		return v
	}
	return ""
}

type backupEntry struct {
	wrapped WrappedKey
	meta    BackupMeta
}

// MemBackupStore 进程内备份库（POC 参考实现）。
type MemBackupStore struct {
	mu      sync.Mutex
	entries map[string]backupEntry // key: gid + "/" + backupID
	seq     int
}

// NewMemBackupStore 创建空备份库。
func NewMemBackupStore() *MemBackupStore {
	return &MemBackupStore{entries: map[string]backupEntry{}}
}

func bkKey(gid, backupID string) string { return gid + "/" + backupID }

// Put 写入备份；幂等：同一 backupID + 同一内容返回既有 meta，不同内容拒绝覆盖。
func (s *MemBackupStore) Put(ctx context.Context, gid, keyID, backupID string, wrapped WrappedKey) (BackupMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	member := MemberFromContext(ctx)
	if gid == "" || keyID == "" || member == "" || wrapped.KEKID == "" {
		return BackupMeta{}, fmt.Errorf("%w: gid/key_id/member/KEKID 不得为空", ErrBackupBindingViolation)
	}
	if wrapped.KeyID != "" && wrapped.KeyID != keyID {
		return BackupMeta{}, fmt.Errorf("%w: WrappedKey.KeyID=%s 与 key_id=%s 不一致",
			ErrBackupBindingViolation, wrapped.KeyID, keyID)
	}
	if err := verifyChecksum(wrapped); err != nil {
		return BackupMeta{}, err
	}
	if backupID != "" {
		if old, ok := s.entries[bkKey(gid, backupID)]; ok {
			// 绑定校验：复用必须同组/同密钥/同成员/同 KEK。
			if old.meta.KeyID != keyID || old.meta.Member != member || old.meta.KEKID != wrapped.KEKID {
				return BackupMeta{}, fmt.Errorf("%w: backup_id %s 已绑定 %s/%s/%s",
					ErrBackupBindingViolation, backupID, old.meta.KeyID, old.meta.Member, old.meta.KEKID)
			}
			if string(old.wrapped.Blob) != string(wrapped.Blob) {
				return BackupMeta{}, fmt.Errorf("%w: backup_id %s 已存在且内容不同", ErrBackupOverwrite, backupID)
			}
			return old.meta, nil // 幂等
		}
	} else {
		s.seq++
		backupID = fmt.Sprintf("bk-%06d", s.seq)
	}
	// 唯一性：同一 gid 下 backupID 不得已被其它绑定占用（上面已覆盖同 key 情形）。
	if _, ok := s.entries[bkKey(gid, backupID)]; ok {
		return BackupMeta{}, fmt.Errorf("%w: backup_id %s 已存在", ErrBackupBindingViolation, backupID)
	}
	meta := BackupMeta{
		BackupID: backupID, KeyID: keyID, Member: member, KEKID: wrapped.KEKID,
		Checksum: wrapped.Checksum, WrappedSize: int64(len(wrapped.Blob)),
		CreatedAt: time.Now().UTC(), State: "ready",
	}
	wrapped.BackupID = backupID
	s.entries[bkKey(gid, backupID)] = backupEntry{wrapped: wrapped, meta: meta}
	return meta, nil
}

// Get 返回当前组、未 tombstone 的 blob，并复校 checksum。
func (s *MemBackupStore) Get(_ context.Context, gid, backupID string) (WrappedKey, BackupMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[bkKey(gid, backupID)]
	if !ok {
		return WrappedKey{}, BackupMeta{}, fmt.Errorf("%w: %s/%s", ErrBackupNotFound, gid, backupID)
	}
	if e.meta.State == "destroyed" {
		return WrappedKey{}, BackupMeta{}, fmt.Errorf("%w: %s 已 tombstone", ErrBackupNotFound, backupID)
	}
	if err := verifyChecksum(e.wrapped); err != nil {
		return WrappedKey{}, BackupMeta{}, err
	}
	return e.wrapped, e.meta, nil
}

// Delete 删除备份 blob（幂等：不存在即视为已删除）。
func (s *MemBackupStore) Delete(_ context.Context, gid, backupID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, bkKey(gid, backupID))
	return nil
}

// List 列出该组该密钥的全部备份元数据。
func (s *MemBackupStore) List(_ context.Context, gid, keyID string) ([]BackupMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]BackupMeta, 0, 4)
	for k, e := range s.entries {
		if len(k) > len(gid)+1 && k[:len(gid)+1] == gid+"/" && e.meta.KeyID == keyID {
			out = append(out, e.meta)
		}
	}
	return out, nil
}

// Tombstone 标记备份为已销毁（模拟 DestroyWrapped 后的库侧状态）。
func (s *MemBackupStore) Tombstone(gid, backupID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e, ok := s.entries[bkKey(gid, backupID)]; ok {
		e.meta.State = "destroyed"
		s.entries[bkKey(gid, backupID)] = e
	}
}

// verifyChecksum 用备份 MAC 密钥复校 HMAC-SM3(Blob)。
func verifyChecksum(w WrappedKey) error {
	if len(w.Blob) == 0 {
		return fmt.Errorf("%w: blob 为空", ErrBackupChecksumMismatch)
	}
	if len(w.Checksum) == 0 {
		return fmt.Errorf("%w: checksum 为空（不得只用裸 SHA-256，也不得缺失）", ErrBackupChecksumMismatch)
	}
	want := HMACSM3(backupMACKey(), w.Blob)
	if string(want) != string(w.Checksum) {
		return fmt.Errorf("%w: HMAC-SM3 不匹配", ErrBackupChecksumMismatch)
	}
	return nil
}

// backupMACKey 备份库侧 MAC 密钥（真实环境为独立备份 MAC 密钥，非数据 KEK）。
func backupMACKey() []byte {
	return []byte("p2-3-poc-backup-mac-key-32byte")
}

// RestoreFlow 按本体 §6.2.5 的恢复顺序执行：目录状态检查 → Get → 交叉校验 → ImportWrapped。
// 用于断言「restore 对 tombstone 必须失败」。
type RestoreFlow struct {
	Store    KeyBackupStore
	DirState func(keyID string) (state string, ok bool)
	Import   func(w WrappedKey) error
}

// Run 执行恢复流程；任一步失败不得留下半成品（由 Import 实现保证）。
func (r RestoreFlow) Run(ctx context.Context, gid, keyID, backupID string) error {
	if st, ok := r.DirState(keyID); ok && st == "destroyed" {
		return fmt.Errorf("poc: restore 对 tombstone 必须失败（state=destroyed）")
	}
	w, meta, err := r.Store.Get(ctx, gid, backupID)
	if err != nil {
		return err
	}
	if meta.KeyID != keyID {
		return fmt.Errorf("%w: BackupMeta.KeyID=%s 与请求 %s 不一致", ErrBackupBindingViolation, meta.KeyID, keyID)
	}
	// 交叉导入校验 Vendor/Model/Mechanism/KEKID。
	if w.Vendor == "" || w.Model == "" || w.Mechanism == "" {
		return fmt.Errorf("poc: group_key_backup_unsupported: Vendor/Model/Mechanism 缺失，不得尝试软件解包")
	}
	return r.Import(w)
}
