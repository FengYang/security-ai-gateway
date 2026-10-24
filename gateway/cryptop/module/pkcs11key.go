//go:build pkcs11

// pkcs11key.go —— PKCS#11 密钥对象管理（M4-4a）：GenerateKey / ImportKey /
// DestroyKey 及对称密钥 spec 解析。
//
// 定位：把统一语义的密钥对象生命周期映射到 C_GenerateKey / C_CreateObject /
// C_DestroyObject。生产路径的密钥材料始终在模块内（token 对象），适配层只
// 传递瞬态字节（B-6.1-1），不缓存（ImportKey 的 key 形参仅经 NewAttribute
// 的 cgo 副本进入模块，本层不保留引用）。
//
// 安全默认（属性模板）：
//   - CKA_TOKEN=true：持久对象（跨会话/重启有效，会话关闭不丢失）；
//   - CKA_PRIVATE=true：仅登录态可见（本后端 Init 已 token 级登录）；
//   - CKA_SENSITIVE=true / CKA_EXTRACTABLE=false：模块内生成/导入的密钥
//     默认不可读出（C-4/C-5；R-S3-4 导出违规防护）。需要 wrap 的 DEK 在
//     M4-4b 以显式可导出属性/专用 spec 处理，此处不放宽。
//
// 机制映射（B-6.1-2）：CKM 值一律经 MechTable 按机制名查厂商 profile 取得，
// **代码内不硬编码任何 CKM**（PKCS#11 v3.0 无 SM 标准 CKM 值，禁止臆测）。
// profile 未登记该机制 → fail-closed 拒绝（ErrNotImplemented 包装），
// 绝不回退软件实现冒充合规（C-3）。
package cryptopmodule

import (
	"errors"
	"fmt"
	"strings"

	"github.com/miekg/pkcs11"
)

// symSpec 对称密钥规格（parseSymSpec 的输出）。
type symSpec struct {
	mech  string // 机制名（MechTable 查 CKM；如 "aes-key-gen"）
	bytes int    // CKA_VALUE_LEN / 导入密钥长度（字节）
	usage string // 对象用途（属性开关维度）：usageEnc/mac/kek/dek
}

// 密钥对象用途（CKA_* 布尔属性组的最小权限划分）。
const (
	usageEnc = "enc" // Seal/Open（CKA_ENCRYPT/DECRYPT）
	usageMac = "mac" // HMAC（CKA_SIGN/VERIFY）
	usageKek = "kek" // WrapKey/UnwrapKey（CKA_WRAP/UNWRAP）
	usageDek = "dek" // KDF 父密钥（CKA_DERIVE）
)

// IsKnownUsage 用途名是否合法。
func IsKnownUsage(u string) bool {
	switch u {
	case usageEnc, usageMac, usageKek, usageDek:
		return true
	}
	return false
}

// parseSymSpec 解析对称密钥 spec（GenerateKey/ImportKey 的 spec 形参）。
// 格式：<密钥规格>[-<用途>]，密钥规格 ∈ {"", "aes", "aes-128", "aes-256"}，
// 用途 ∈ {enc, mac, kek, dek}（缺省 enc）。
//
// M4-4a 档（功能验证）：aes-* —— SoftHSM 等无 SM 机制环境的运算路径验证
// （softhsm-generic.json 登记的标准机制）。SM 档（sm4-*）随 S3-a 厂商
// profile 启用：届时按厂商文档登记 sm4-key-gen 等机制名后，本函数增加
// 对应分支——**当前明确拒绝**而非把 SM spec 悄悄映射到 AES 冒充合规。
func parseSymSpec(spec string) (symSpec, error) {
	base, usage := spec, usageEnc
	// 尾缀用途识别（-enc/-mac/-kek/-dek）；"aes-256" 的 "-256" 不在用途
	// 集合，不会误切。
	if i := strings.LastIndex(spec, "-"); i > 0 && IsKnownUsage(spec[i+1:]) {
		base, usage = spec[:i], spec[i+1:]
	}
	var sp symSpec
	switch base {
	case "", "aes", "aes-128":
		sp = symSpec{mech: MechAESKeyGen, bytes: 16, usage: usage}
	case "aes-256":
		sp = symSpec{mech: MechAESKeyGen, bytes: 32, usage: usage}
	case "sm4", "sm4-128", "sm4-256":
		return symSpec{}, fmt.Errorf("%w: spec=%q 为国密档，SM 机制 CKM 值待 S3-a 厂商 profile 登记（当前不映射到 AES 冒充合规，C-3）",
			ErrNotImplemented, spec)
	default:
		return symSpec{}, fmt.Errorf("module: 未知对称密钥 spec=%q（可用: aes-128/aes-256，可带用途尾缀 -enc/-mac/-kek/-dek）", spec)
	}
	return sp, nil
}

// keyPrefix / partition nil-safe 配置访问器（未初始化后端 b.cfg == nil 时
// 返回零值；参数校验路径先于设备检查，不得因此 panic）。
func (b *PKCS11Backend) keyPrefix() string {
	if b.cfg == nil {
		return ""
	}
	return b.cfg.KeyPrefix
}

func (b *PKCS11Backend) partition() string {
	if b.cfg == nil {
		return ""
	}
	return b.cfg.Partition
}

// keyLabel 模块内对象标签：module_key_prefix + alias（R-S3-8 分区命名空间）。
// alias 为空时退化为 prefix（句柄 token 仍是权威引用，标签仅供人工检索）。
func (b *PKCS11Backend) keyLabel(alias string) string {
	prefix := b.keyPrefix()
	if alias == "" {
		return prefix
	}
	return prefix + alias
}

// lookupMechCKM 按机制名取 CKM 值（profile 驱动；未登记 fail-closed）。
func (b *PKCS11Backend) lookupMechCKM(name string) (uint, error) {
	if b.mech == nil {
		return 0, fmt.Errorf("%w: 未配置厂商机制 profile（module_mechanism_profile），机制 %q 无 CKM 登记",
			ErrNotImplemented, name)
	}
	e, ok := b.mech.Lookup(name)
	if !ok {
		return 0, fmt.Errorf("%w: 机制 %q 未在厂商 profile 登记（CKM 未知，禁止臆测标准值，B-6.1-2）",
			ErrNotImplemented, name)
	}
	v, err := parseCKM(e.CKM)
	if err != nil {
		return 0, fmt.Errorf("module: profile 机制 %q 的 CKM %q 解析失败: %w", name, e.CKM, err)
	}
	if v == 0 {
		return 0, fmt.Errorf("module: profile 机制 %q 的 CKM 为 0（须按厂商 SDK 文档登记）", name)
	}
	return v, nil
}

// secretKeyTemplate 对称密钥对象属性模板（CKA_* 集合见文件头安全默认）。
// 不含 CKA_VALUE——导入路径由调用方追加（生成路径不设该属性）。
// valueLen <= 0 表示省略 CKA_VALUE_LEN（导入路径必须省略：该属性在
// C_CreateObject 上是只读的，M4-4a 真机实测 CKR_ATTRIBUTE_READ_ONLY 0x10；
// 长度由 CKA_VALUE 字节数自然决定）。
// usage 控制用途布尔属性组（最小权限：enc→ENCRYPT/DECRYPT，mac→SIGN/VERIFY，
// kek→WRAP/UNWRAP，dek→DERIVE；其余不开放的属性不设=库默认 false）与
// **密钥类型**：AES 机制（GCM/KEY-WRAP）要求 CKK_AES；HMAC 机制
// （CKM_SHA256_HMAC，mac 与 dek 用途共用）要求 CKK_GENERIC_SECRET——
// M4-4b 真机实测 CKK_AES 配 HMAC 返回 CKR_KEY_TYPE_INCONSISTENT(0x63)。
// keyType 为 CKK_*（SM 档随厂商 profile 的 CKK 扩展值另行确定——S3-a 选型项）。
func secretKeyTemplate(label string, valueLen int, extractable bool, usage string) []*pkcs11.Attribute {
	keyType := uint(pkcs11.CKK_AES)
	if usage == usageMac || usage == usageDek {
		keyType = pkcs11.CKK_GENERIC_SECRET
	}
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, keyType),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, extractable),
	}
	switch usage {
	case usageEnc:
		attrs = append(attrs,
			pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
			pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true))
	case usageMac:
		attrs = append(attrs,
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true))
	case usageKek:
		attrs = append(attrs,
			pkcs11.NewAttribute(pkcs11.CKA_WRAP, true),
			pkcs11.NewAttribute(pkcs11.CKA_UNWRAP, true))
	case usageDek:
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true))
	default:
		// 未知用途：不设任何用途属性（fail-closed，对象不可用于任何运算）。
	}
	if valueLen > 0 {
		attrs = append(attrs, pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, valueLen))
	}
	return attrs
}

// GenerateKey 模块内生成对称密钥（C_GenerateKey；对象持久化于 token）。
// spec ∈ {"", "aes-128", "aes-256"}（SM 档待 S3-a，见 parseSymSpec）。
func (b *PKCS11Backend) GenerateKey(spec, alias string) (KeyRef, error) {
	// 参数校验优先于设备状态检查（spec 是纯静态校验，快速失败）。
	sp, err := parseSymSpec(spec)
	if err != nil {
		return nil, err
	}
	if b.ctx == nil {
		return nil, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	ckm, err := b.lookupMechCKM(sp.mech)
	if err != nil {
		return nil, err
	}
	label := b.keyLabel(alias)

	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()

	tmpl := secretKeyTemplate(label, sp.bytes, false, sp.usage)
	mech := &pkcs11.Mechanism{Mechanism: ckm}
	oh, err := b.ctx.GenerateKey(pkcs11.SessionHandle(s), []*pkcs11.Mechanism{mech}, tmpl)
	if err != nil {
		return nil, fmt.Errorf("%w: C_GenerateKey(%s, %d bytes): %v",
			ErrModuleUnavailable, sp.mech, sp.bytes, err)
	}
	return encodeKeyRef(b.slotIndex, b.partition(), uint(oh))
}

// ImportKey 导入外部对称密钥字节为模块内对象（C_CreateObject；仪式/静态
// 密钥路径）。字节仅瞬态经适配层进入模块，不缓存（B-6.1-1）；默认
// CKA_EXTRACTABLE=false（R-S3-4：不可再读出）。
func (b *PKCS11Backend) ImportKey(spec string, key []byte, alias string) (KeyRef, error) {
	sp, err := parseSymSpec(spec)
	if err != nil {
		return nil, err
	}
	if len(key) != sp.bytes {
		return nil, fmt.Errorf("module: 导入密钥长度 %d != spec %q 要求 %d", len(key), spec, sp.bytes)
	}
	if b.ctx == nil {
		return nil, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	if _, err := b.lookupMechCKM(sp.mech); err != nil {
		return nil, err // 机制登记校验（C_CreateObject 不依赖 CKM，但能力一致性先行）
	}
	label := b.keyLabel(alias)

	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()

	tmpl := append(secretKeyTemplate(label, 0, false, sp.usage), // valueLen=0：导入路径省略 CKA_VALUE_LEN（只读属性）
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, key))
	oh, err := b.ctx.CreateObject(pkcs11.SessionHandle(s), tmpl)
	if err != nil {
		return nil, fmt.Errorf("%w: C_CreateObject(import, %d bytes): %v",
			ErrModuleUnavailable, sp.bytes, err)
	}
	return encodeKeyRef(b.slotIndex, b.partition(), uint(oh))
}

// DestroyKey 销毁模块内密钥对象（C_DestroyObject）。
// 幂等语义：对象已不存在（CKR_OBJECT_HANDLE_INVALID）视为已达成，返回 nil
// （与 mock 后端"删除不存在的键报 ErrKeyNotFound"的差异在此说明：PKCS#11
// 句柄可能被外部工具/其他会话先行销毁，幂等更贴合运维编排；上层 keystore
// 仍以自身台账为准，R2-06 归档策略在 keystore 层）。
func (b *PKCS11Backend) DestroyKey(keyRef KeyRef) error {
	// 参数（KeyRef 归属）校验优先于设备状态检查。
	handle, err := decodeKeyRef(keyRef, b.slotIndex, b.partition())
	if err != nil {
		return err
	}
	if b.ctx == nil {
		return fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	s, err := b.AcquireSession()
	if err != nil {
		return err
	}
	defer func() { _ = b.ReleaseSession(s) }()

	if err := b.ctx.DestroyObject(pkcs11.SessionHandle(s), pkcs11.ObjectHandle(handle)); err != nil {
		var p11err pkcs11.Error
		if errors.As(err, &p11err) && p11err == pkcs11.Error(pkcs11.CKR_OBJECT_HANDLE_INVALID) {
			return nil // 幂等：已不存在
		}
		return fmt.Errorf("%w: C_DestroyObject(handle=0x%x): %v", ErrModuleUnavailable, handle, err)
	}
	return nil
}
