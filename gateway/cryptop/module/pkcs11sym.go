//go:build pkcs11

// pkcs11sym.go —— PKCS#11 对称运算（M4-4b）：Seal/Open/HMAC/WrapKey/
// UnwrapKey/KDF 的 C_* 映射。
//
// 运算与机制的对应（功能验证档，softhsm-generic profile 登记）：
//   - Seal/Open    → C_Encrypt* / C_Decrypt*（CKM_AES_GCM，tag 128bit）
//   - HMAC         → C_SignInit(CKM_SHA256_HMAC) + C_Sign
//   - WrapKey      → 瞬态可导出对象 + C_WrapKey（CKM_AES_KEY_WRAP）
//   - UnwrapKey    → C_UnwrapKey（CKM_AES_KEY_WRAP）→ 持久 enc 对象
//   - KDF          → C_SignInit(CKM_SHA256_HMAC) 迭代计数器派生
//
// 关键设计记录：
//  1. **Seal 输出布局** = ciphertext||tag（16B tag 尾随）——与 mock 后端
//     （Go AEAD Seal 惯例）及上层 keystore 期望一致。
//  2. **CKM_SHA256_KEY_DERIVATION 不可用**：其参数 CK_KEY_DERIVATION_STRING_
//     DATA 是含指针的 C 结构体，miekg/pkcs11 的 Mechanism.Parameter 为裸字节
//     直传（见 vendor types.go cMechanism），Go 侧无法安全构造；且该机制输出
//     固定 32B、母密钥不参与计算。改走 **HMAC 迭代计数器 KDF**：母密钥由
//     CKM_SHA256_HMAC 机制绑定（不读密钥值），block_i = HMAC(parentKey,
//     Z||ctr_i)，Z 构造与 mock（长度前缀）同构，任意 outLen 可分块。
//     与 SM 档（GM/T 0005 SM3-KDF）结构一致、算法不同——功能验证档只验证
//     调用链，跨档逐字节一致是 sm-software↔sm-module 的判据。
//  3. **WrapKey 的瞬态对象**：接口形参 dek 为裸字节，而 C_WrapKey 只接受
//     模块内对象。路径：导入为**会话级**（CKA_TOKEN=false）可导出瞬态对象 →
//     C_WrapKey → 立即销毁（defer 双保险）。瞬态对象不落 token、随会话关闭
//     消失；可导出窗口仅存在于 wrap 调用期间（与 D-20 备份 KEK 路径同构）。
//  4. **用途最小权限**：对象按 spec 用途尾缀开属性组（enc/mac/kek/dek），
//     未开属性的运算在模块内即被拒（CKR_KEY_FUNCTION_NOT_PERMITTED），
//     不经适配层放行。
package cryptopmodule

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/miekg/pkcs11"
)

// GCM 固定参数（对齐 mock：mockNonceSize=12 / Go AEAD 惯例）。
const (
	symNonceSize   = 12 // GCM IV 长度（字节）
	symTagBits     = 128
	symTagSize     = symTagBits / 8
	maxKDFOutLen   = 1024 // KDF 输出上限（防呆；SM3-KDF 实际用途远小于此）
	symWrapTagSize = 8    // AES-KEY-WRAP 完整性校验值长度（RFC 3394）
)

// Seal AES-GCM 加密（C_EncryptInit/Update/Final；输出 ct||tag）。
func (b *PKCS11Backend) Seal(keyRef KeyRef, nonce, plaintext, aad []byte) ([]byte, error) {
	handle, err := decodeKeyRef(keyRef, b.slotIndex, b.partition())
	if err != nil {
		return nil, err
	}
	if len(nonce) != symNonceSize {
		return nil, fmt.Errorf("module: Seal nonce 长度 %d != %d（GCM 标准 IV）", len(nonce), symNonceSize)
	}
	ckm, err := b.lookupMechCKM(MechAESGCM)
	if err != nil {
		return nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, pkcs11.NewGCMParams(nonce, aad, symTagBits))}
	if err := b.ctx.EncryptInit(sh, mech, pkcs11.ObjectHandle(handle)); err != nil {
		return nil, fmt.Errorf("%w: C_EncryptInit(CKM_AES_GCM): %v", ErrModuleUnavailable, err)
	}
	ct, err := b.ctx.EncryptUpdate(sh, plaintext)
	if err != nil {
		return nil, fmt.Errorf("%w: C_EncryptUpdate: %v", ErrModuleUnavailable, err)
	}
	// GCM 语义：Final 输出认证 tag（密文已在 Update 返回）。
	tag, err := b.ctx.EncryptFinal(sh)
	if err != nil {
		return nil, fmt.Errorf("%w: C_EncryptFinal: %v", ErrModuleUnavailable, err)
	}
	if len(tag) != symTagSize {
		return nil, fmt.Errorf("%w: GCM tag 长度 %d != %d（库行为异常）", ErrModuleUnavailable, len(tag), symTagSize)
	}
	return append(ct, tag...), nil
}

// Open AES-GCM 解密（输入 ct||tag；认证失败返回明确错误，对齐 mock 语义）。
func (b *PKCS11Backend) Open(keyRef KeyRef, nonce, ciphertext, aad []byte) ([]byte, error) {
	handle, err := decodeKeyRef(keyRef, b.slotIndex, b.partition())
	if err != nil {
		return nil, err
	}
	if len(nonce) != symNonceSize {
		return nil, fmt.Errorf("module: Open nonce 长度 %d != %d（GCM 标准 IV）", len(nonce), symNonceSize)
	}
	if len(ciphertext) < symTagSize {
		return nil, fmt.Errorf("module: Open 输入长度 %d < tag %d（截断）", len(ciphertext), symTagSize)
	}
	// tag 随密文经 Update 尾随传入（PKCS#11 v3.0 GCM 解密语义，M4-4b 真机验证）。
	ckm, err := b.lookupMechCKM(MechAESGCM)
	if err != nil {
		return nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	mech := []*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, pkcs11.NewGCMParams(nonce, aad, symTagBits))}
	if err := b.ctx.DecryptInit(sh, mech, pkcs11.ObjectHandle(handle)); err != nil {
		return nil, fmt.Errorf("%w: C_DecryptInit(CKM_AES_GCM): %v", ErrModuleUnavailable, err)
	}
	pt, err := b.ctx.DecryptUpdate(sh, ciphertext) // 全量 ct||tag
	if err != nil {
		return nil, fmt.Errorf("%w: C_DecryptUpdate: %v", ErrModuleUnavailable, err)
	}
	// GCM 语义：Final 完成认证校验（SoftHSM tag 不符返回
	// CKR_ENCRYPTED_DATA_INVALID；末块明文中 Final 返回）。
	last, err := b.ctx.DecryptFinal(sh)
	if err != nil {
		var p11err pkcs11.Error
		if asPKCS11Err(err, &p11err) && isGCMAuthFailure(p11err) {
			return nil, fmt.Errorf("module: 解密失败（GCM 认证标签不符）")
		}
		return nil, fmt.Errorf("%w: C_DecryptFinal: %v", ErrModuleUnavailable, err)
	}
	return append(pt, last...), nil
}

// HMAC HMAC-SHA256（C_SignInit(CKM_SHA256_HMAC) + C_Sign 单次）。
func (b *PKCS11Backend) HMAC(keyRef KeyRef, data []byte) ([]byte, error) {
	handle, err := decodeKeyRef(keyRef, b.slotIndex, b.partition())
	if err != nil {
		return nil, err
	}
	ckm, err := b.lookupMechCKM(MechSHA256HMAC)
	if err != nil {
		return nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	if err := b.ctx.SignInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)}, pkcs11.ObjectHandle(handle)); err != nil {
		return nil, fmt.Errorf("%w: C_SignInit(CKM_SHA256_HMAC): %v（密钥用途非 mac？）", ErrModuleUnavailable, err)
	}
	mac, err := b.ctx.Sign(sh, data)
	if err != nil {
		return nil, fmt.Errorf("%w: C_Sign(HMAC): %v", ErrModuleUnavailable, err)
	}
	return mac, nil
}

// WrapKey 以 KEK 包装外部 DEK 字节（C_WrapKey；dek 经瞬态可导出会话对象
// 进入模块，用完即毁——见文件头设计记录 3）。输出 = RFC 3394 wrapped key。
func (b *PKCS11Backend) WrapKey(kekRef KeyRef, dek []byte) ([]byte, error) {
	kek, err := decodeKeyRef(kekRef, b.slotIndex, b.partition())
	if err != nil {
		return nil, err
	}
	if len(dek) == 0 {
		return nil, fmt.Errorf("module: WrapKey DEK 为空")
	}
	ckm, err := b.lookupMechCKM(MechAESKeyWrap)
	if err != nil {
		return nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	// 瞬态对象：会话级（TOKEN=false）+ 可导出（EXTRACTABLE=true）+
	// 敏感（SENSITIVE=true，值不可读）；label 唯一防撞（无 alias 入口）。
	tmpLabel := fmt.Sprintf("%swrap-tmp-%x", b.keyPrefix(), kek)
	tmpTmpl := append(secretKeyTemplate(tmpLabel, 0, true, usageEnc),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, dek))
	// TOKEN=false：会话级瞬态对象（覆盖模板默认值，须在追加 CKA_VALUE 前）。
	tmpTmpl = withAttr(tmpTmpl, pkcs11.CKA_TOKEN, false)
	tmpObj, err := b.ctx.CreateObject(sh, tmpTmpl)
	if err != nil {
		return nil, fmt.Errorf("%w: C_CreateObject(wrap 瞬态对象): %v", ErrModuleUnavailable, err)
	}
	defer func() { _ = b.ctx.DestroyObject(sh, tmpObj) }() // 双保险销毁

	wrapped, err := b.ctx.WrapKey(sh,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)},
		pkcs11.ObjectHandle(kek), tmpObj)
	if err != nil {
		return nil, fmt.Errorf("%w: C_WrapKey(CKM_AES_KEY_WRAP): %v（KEK 用途非 kek？）", ErrModuleUnavailable, err)
	}
	return wrapped, nil
}

// UnwrapKey 以 KEK 解开 wrapped DEK，返回 DEK 字节（接口规约 §6.2：
// mock 同语义）。模块内路径：C_UnwrapKey 造**会话级可读瞬态对象**
// （SENSITIVE=false + EXTRACTABLE=true + TOKEN=false）→ 回读 CKA_VALUE →
// 立即销毁（defer 双保险）。若上层需要持久对象，走 ImportKey 显式登记
// （与 WrapKey 的瞬态对象对称，见文件头设计记录 3）。
func (b *PKCS11Backend) UnwrapKey(kekRef KeyRef, wrapped []byte) ([]byte, error) {
	kek, err := decodeKeyRef(kekRef, b.slotIndex, b.partition())
	if err != nil {
		return nil, err
	}
	if len(wrapped) < 2*symWrapTagSize {
		return nil, fmt.Errorf("module: UnwrapKey 输入长度 %d 非法（RFC 3394 最小 %d）",
			len(wrapped), 2*symWrapTagSize)
	}
	ckm, err := b.lookupMechCKM(MechAESKeyWrap)
	if err != nil {
		return nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	label := fmt.Sprintf("%sunwrap-tmp-%x", b.keyPrefix(), kek)
	tmpl := secretKeyTemplate(label, 0, true, usageEnc) // 可导出：解开结果需回读
	tmpl = withAttr(tmpl, pkcs11.CKA_TOKEN, false)      // 会话级瞬态
	tmpl = withAttr(tmpl, pkcs11.CKA_SENSITIVE, false)  // 可读（瞬态窗口）
	oh, err := b.ctx.UnwrapKey(sh,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)},
		pkcs11.ObjectHandle(kek), wrapped, tmpl)
	if err != nil {
		return nil, fmt.Errorf("%w: C_UnwrapKey(CKM_AES_KEY_WRAP): %v（KEK 用途非 kek 或数据损坏）",
			ErrModuleUnavailable, err)
	}
	defer func() { _ = b.ctx.DestroyObject(sh, oh) }() // 双保险销毁

	// 回读明文值（瞬态可读对象的唯一出口）。
	attr, err := b.ctx.GetAttributeValue(sh, oh,
		[]*pkcs11.Attribute{{Type: pkcs11.CKA_VALUE}})
	if err != nil {
		return nil, fmt.Errorf("%w: C_GetAttributeValue(unwrap): %v", ErrModuleUnavailable, err)
	}
	if len(attr) == 0 || len(attr[0].Value) == 0 {
		return nil, fmt.Errorf("%w: unwrap 结果 CKA_VALUE 为空（库行为异常）", ErrModuleUnavailable)
	}
	return append([]byte(nil), attr[0].Value...), nil
}

// KDF 迭代计数器密钥派生（HMAC-SHA256 分块；见文件头设计记录 2）。
// Z 构造与 mock 同构（长度前缀）；alias 非空时派生结果登记为模块内
// 持久 enc 对象（D-4 的模块内执行位置，S3-b 实测路径）。
func (b *PKCS11Backend) KDF(parentRef KeyRef, salt, info []byte, outLen int, alias string) ([]byte, error) {
	parent, err := decodeKeyRef(parentRef, b.slotIndex, b.partition())
	if err != nil {
		return nil, err
	}
	if outLen <= 0 || outLen > maxKDFOutLen {
		return nil, fmt.Errorf("module: KDF outLen=%d 非法（1..%d）", outLen, maxKDFOutLen)
	}
	ckm, err := b.lookupMechCKM(MechSHA256HMAC)
	if err != nil {
		return nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	// Z = len(salt)||salt||len(info)||info（母密钥经 HMAC 机制绑定，
	// 不入 Z——与 mock 的"secret 前置"差异见设计记录 2）。
	z := make([]byte, 0, 8+len(salt)+len(info))
	var l [4]byte
	binary.BigEndian.PutUint32(l[:], uint32(len(salt)))
	z = append(z, l[:]...)
	z = append(z, salt...)
	binary.BigEndian.PutUint32(l[:], uint32(len(info)))
	z = append(z, l[:]...)
	z = append(z, info...)

	out := make([]byte, 0, outLen+32)
	for ctr := uint32(1); len(out) < outLen; ctr++ {
		if err := b.ctx.SignInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)},
			pkcs11.ObjectHandle(parent)); err != nil {
			return nil, fmt.Errorf("%w: C_SignInit(KDF HMAC): %v（父密钥用途非 dek？）", ErrModuleUnavailable, err)
		}
		block := make([]byte, len(z)+4)
		copy(block, z)
		binary.BigEndian.PutUint32(block[len(z):], ctr)
		mac, err := b.ctx.Sign(sh, block)
		if err != nil {
			return nil, fmt.Errorf("%w: C_Sign(KDF 块 %d): %v", ErrModuleUnavailable, ctr, err)
		}
		out = append(out, mac...)
	}
	out = out[:outLen]

	if alias != "" {
		// D-4：派生结果登记为模块内持久 enc 对象（SENSITIVE=true 不可读出）。
		label := b.keyLabel(alias)
		tmpl := append(secretKeyTemplate(label, 0, false, usageEnc),
			pkcs11.NewAttribute(pkcs11.CKA_VALUE, out))
		if _, err := b.ctx.CreateObject(sh, tmpl); err != nil {
			return nil, fmt.Errorf("%w: C_CreateObject(KDF 登记): %v", ErrModuleUnavailable, err)
		}
	}
	return out, nil
}

// ---- 辅助 ----

// withAttr 在属性列表中设置/覆盖指定类型的属性（用于在模板尾部覆盖
// CKA_TOKEN 等默认值）。
func withAttr(attrs []*pkcs11.Attribute, typ uint, v interface{}) []*pkcs11.Attribute {
	for _, a := range attrs {
		if a.Type == typ {
			a.Value = newAttrValue(v)
			return attrs
		}
	}
	return append(attrs, pkcs11.NewAttribute(typ, v))
}

// newAttrValue 与 pkcs11.NewAttribute 相同值域的字节转换（bool→单字节）。
func newAttrValue(v interface{}) []byte {
	if b, ok := v.(bool); ok {
		if b {
			return []byte{1}
		}
		return []byte{0}
	}
	a := pkcs11.NewAttribute(0, v)
	return a.Value
}

// asPKCS11Err 提取 pkcs11.Error（errors.As；容忍被 fmt.Errorf %w 包装）。
func asPKCS11Err(err error, target *pkcs11.Error) bool {
	return errors.As(err, target)
}

// isGCMAuthFailure GCM 认证失败的 CKR 集合。注意：SoftHSM v2.6 对 GCM
// tag 不符返回 CKR_GENERAL_ERROR(0x5) 而非规范的 CKR_ENCRYPTED_DATA_INVALID
// （M4-4b 真机实测 2026-10-24）；GENERAL_ERROR 仅在**解密 Final 上下文**
// 使用本判定（Init/Update 阶段的真实库错误会更早暴露，不会走到 Final）。
func isGCMAuthFailure(e pkcs11.Error) bool {
	switch uint(e) {
	case pkcs11.CKR_ENCRYPTED_DATA_INVALID, pkcs11.CKR_DATA_INVALID, pkcs11.CKR_SIGNATURE_INVALID, pkcs11.CKR_GENERAL_ERROR:
		return true
	}
	return false
}
