package cryptopmodule

import "time"

// 密钥备份/克隆的契约类型（§6.2.5 / D-9）。
//
// **为何放在 module 包而不是 backup 包**：PKCS#11 后端（本包）要实现
// KeyBackupBackend，若契约类型留在 backup 包，则 module → backup 与
// backup → module 形成循环依赖。故契约下沉到本包，backup 包以类型别名引用
// （对 backup 与 group 的现有调用方完全透明）。
//
// 语义（§6.2.5）：
//   - ExportWrapped 只能由具备 CKA_WRAP 白名单的 KEK 执行，仅当前组主可调用；
//   - ImportWrapped 在目标模块内**直接建持久对象**（CKA_SENSITIVE=true /
//     CKA_EXTRACTABLE=false），失败不得留下半成品（审计 orphan 并销毁）；
//   - DestroyWrapped 删除成员本地/厂商备份对象；备份库 blob 删除走
//     KeyBackupStore.Delete（backup 包）。
//
// Blob 禁止写入控制存储 / 日志 / 审计 / 指标；只经 KeyBackupStore 落备份库，
// 控制面与 admin 只流转 backup_id。

// WrappedKey 成员本地 wrap 产物的元数据 + blob。
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
// 实现方示例：PKCS11Backend（-tags pkcs11，见 pkcs11backup.go）。
type KeyBackupBackend interface {
	ExportWrapped(keyRef KeyRef, kekID string) (WrappedKey, error)
	ImportWrapped(wrapped WrappedKey, kekID string, alias string) (KeyRef, error)
	DestroyWrapped(backupID string) error
}
