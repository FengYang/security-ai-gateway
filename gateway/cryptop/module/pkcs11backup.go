//go:build pkcs11

package cryptopmodule

// PKCS#11 后端的 KeyBackupBackend 绑定（§6.2.5 / D-9）。
//
// 关键语义：**密钥明文不出模块**。
//   - ExportWrapped：对模块内**已有对象**直接 C_WrapKey（不读出明文）；
//   - ImportWrapped：C_UnwrapKey 在目标模块内**直接建持久对象**，
//     属性 CKA_TOKEN=true / CKA_SENSITIVE=true / CKA_EXTRACTABLE=false；
//   - DestroyWrapped：删除成员本地/厂商备份对象（幂等）。
//
// 与 ModuleBackend.WrapKey/UnwrapKey 的区别（重要，勿混用）：
//   - WrapKey(kekRef, dek []byte) 的 dek 是**调用方给的明文**，UnwrapKey 也**返回明文**——
//     两者都让密钥材料经过应用层，只适合"临时包一个外部 DEK"场景；
//   - 本文件的三个方法全程在模块内闭环，才是 §6.2.5 要求的备份/恢复路径。
//
// KEK 口径（D-9）：kekID 即模块内 KEK 对象的 alias（组内独立备份 KEK，
// **不得复用数据 KEK**）；组模式由 backup.kek_id 配置经 group 编排器传入。

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/miekg/pkcs11"
)

// 编译期契约：PKCS#11 后端满足 KeyBackupBackend（契约类型见 wrappedkey.go）。
var _ KeyBackupBackend = (*PKCS11Backend)(nil)

// ExportWrapped 以 KEK 包装模块内已有密钥对象（C_WrapKey），返回 wrap 产物元数据。
//
// blob 只在成员与备份库之间流转，**不得**写入控制存储/日志/审计/指标（§6.2.5）。
func (b *PKCS11Backend) ExportWrapped(keyRef KeyRef, kekID string) (WrappedKey, error) {
	if b == nil || b.cfg == nil || b.ctx == nil {
		return WrappedKey{}, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	if kekID == "" {
		return WrappedKey{}, fmt.Errorf("module: ExportWrapped 缺 kek_id（D-9 要求组内独立备份 KEK）")
	}
	key, err := decodeKeyRef(keyRef, b.slotIndex, b.partition())
	if err != nil {
		return WrappedKey{}, err
	}

	s, err := b.AcquireSession()
	if err != nil {
		return WrappedKey{}, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	kek, err := b.findObjectByLabel(sh, b.keyLabel(kekID))
	if err != nil {
		return WrappedKey{}, fmt.Errorf("module: 定位备份 KEK(alias=%s) 失败: %w", kekID, err)
	}
	ckm, err := b.lookupMechCKM(MechAESKeyWrap)
	if err != nil {
		return WrappedKey{}, err
	}

	blob, err := b.ctx.WrapKey(sh,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)},
		pkcs11.ObjectHandle(kek), pkcs11.ObjectHandle(key))
	if err != nil {
		return WrappedKey{}, fmt.Errorf("%w: C_WrapKey(%s): %v（KEK 用途非 kek？）",
			ErrModuleUnavailable, MechAESKeyWrap, err)
	}

	caps := b.Capabilities()
	sum := sha256.Sum256(blob)
	return WrappedKey{
		KeyID: "", // 由调用方（编排器）回填目录 key_id
		// Member 留空：模块侧不知道组内成员 ID，由组层以成员 ID 回填。
		KEKID:       kekID,
		Blob:        blob,
		Checksum:    sum[:],
		WrappedSize: int64(len(blob)),
		Vendor:      caps.Vendor,
		Model:       caps.Model,
		Mechanism:   MechAESKeyWrap,
		CreatedAt:   time.Now().UTC(),
		State:       "ready",
	}, nil
}

// ImportWrapped 以 KEK 解开 wrap 产物，在模块内**直接建持久对象**并返回其 KeyRef。
//
// 对象属性：CKA_TOKEN=true（持久）/ CKA_SENSITIVE=true / CKA_EXTRACTABLE=false
// （§6.2.5：不可导出；V-4 全属性核验的依据）。
// 失败时**不得留下半成品**：销毁刚建的对象再返回错误。
func (b *PKCS11Backend) ImportWrapped(w WrappedKey, kekID, alias string) (KeyRef, error) {
	if b == nil || b.cfg == nil || b.ctx == nil {
		return nil, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	if kekID == "" {
		return nil, fmt.Errorf("module: ImportWrapped 缺 kek_id（D-9）")
	}
	if len(w.Blob) == 0 {
		return nil, fmt.Errorf("module: ImportWrapped blob 为空")
	}
	if alias == "" {
		return nil, fmt.Errorf("module: ImportWrapped 缺 alias（无法在模块内寻址副本）")
	}

	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	kek, err := b.findObjectByLabel(sh, b.keyLabel(kekID))
	if err != nil {
		return nil, fmt.Errorf("module: 定位备份 KEK(alias=%s) 失败: %w", kekID, err)
	}
	ckm, err := b.lookupMechCKM(MechAESKeyWrap)
	if err != nil {
		return nil, err
	}

	// 不可导出 + 持久 + 敏感（secretKeyTemplate 已置 TOKEN/SENSITIVE）。
	tmpl := secretKeyTemplate(b.keyLabel(alias), 0, false, usageEnc)
	oh, err := b.ctx.UnwrapKey(sh,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)},
		pkcs11.ObjectHandle(kek), w.Blob, tmpl)
	if err != nil {
		return nil, fmt.Errorf("%w: C_UnwrapKey(%s): %v（KEK 不匹配/数据损坏）",
			ErrModuleUnavailable, MechAESKeyWrap, err)
	}
	// 半成品清理：仅在后续编码失败时才需要（UnwrapKey 已成功即对象已建成），
	// 故用命名返回值 + defer 判定。
	ref, err := encodeKeyRef(b.slotIndex, b.partition(), uint(oh))
	if err != nil {
		_ = b.ctx.DestroyObject(sh, oh) // 不留下无法寻址的孤儿对象
		return nil, err
	}
	return ref, nil
}

// DestroyWrapped 删除成员本地/厂商备份对象（幂等：对象不存在即成功）。
//
// 说明：PKCS#11 路径下备份库 blob 由 KeyBackupStore.Delete 删除（backup 包），
// 模块侧只负责清"曾建成的备份对象"；SoftHSM 等无厂商备份对象时本方法无操作。
func (b *PKCS11Backend) DestroyWrapped(backupID string) error {
	if b == nil || b.cfg == nil || b.ctx == nil {
		return fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	if backupID == "" {
		return fmt.Errorf("module: DestroyWrapped 缺 backup_id")
	}
	s, err := b.AcquireSession()
	if err != nil {
		return err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	oh, err := b.findObjectByLabel(sh, b.keyLabel(backupID))
	if err != nil {
		// 对象不存在视为已销毁（幂等）；其它错误上报。
		if isObjectNotFound(err) {
			return nil
		}
		return err
	}
	if err := b.ctx.DestroyObject(sh, pkcs11.ObjectHandle(oh)); err != nil {
		return fmt.Errorf("%w: C_DestroyObject(backup=%s): %v", ErrModuleUnavailable, backupID, err)
	}
	return nil
}

// findObjectByLabel 按标签在模块内查找唯一对象（返回 handle）。
func (b *PKCS11Backend) findObjectByLabel(sh pkcs11.SessionHandle, label string) (pkcs11.ObjectHandle, error) {
	tmpl := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_LABEL, label)}
	if err := b.ctx.FindObjectsInit(sh, tmpl); err != nil {
		return 0, fmt.Errorf("%w: C_FindObjectsInit: %v", ErrModuleUnavailable, err)
	}
	objs, _, err := b.ctx.FindObjects(sh, 8)
	if err != nil {
		_ = b.ctx.FindObjectsFinal(sh)
		return 0, fmt.Errorf("%w: C_FindObjects: %v", ErrModuleUnavailable, err)
	}
	if err := b.ctx.FindObjectsFinal(sh); err != nil {
		return 0, fmt.Errorf("%w: C_FindObjectsFinal: %v", ErrModuleUnavailable, err)
	}
	switch len(objs) {
	case 0:
		return 0, fmt.Errorf("%w: 对象不存在（label=%s）", ErrKeyNotFound, label)
	case 1:
		return objs[0], nil
	default:
		return 0, fmt.Errorf("%w: 标签 %s 匹配到 %d 个对象（歧义，拒绝猜测）",
			ErrModuleUnavailable, label, len(objs))
	}
}

// isObjectNotFound 是否为"对象不存在"类错误（用于幂等销毁判定）。
func isObjectNotFound(err error) bool {
	return err != nil && errors.Is(err, ErrKeyNotFound)
}
