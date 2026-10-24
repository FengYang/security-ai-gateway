//go:build pkcs11

// pkcs11asym.go —— M4-4c 非对称运算（PKCS#11 后端）。
//
// 功能验证档（非国密）：SoftHSM EC P-256 / ECDSA / ECDH1_DERIVE，机制名
// ec-key-pair-gen / ecdsa / ecdh1-derive / sha256（softhsm-generic.json
// 登记的标准 CKM 值）。SM 档（SM2）随 S3-a 厂商 profile 启用：届时按厂商
// 文档登记 sm2-sign / sm2-ecdh 的 CKM 值与曲线参数后，本文件调用链不变
// （C_GenerateKeyPair/C_SignInit/C_Sign/C_VerifyInit/C_Verify/C_DeriveKey），
// **当前明确拒绝 SM spec 而不映射到 EC 冒充合规**（C-3）。
//
// 跨档语义对齐（mock/软件参照）：
//   - 公钥字节 = 原始非压缩点 0x04||X||Y（65B，P-256）；PKCS#11 侧
//     CKA_EC_POINT 为 DER OCTET STRING 包裹，进出各做一次包裹/解包；
//   - 签名 = ASN.1 DER（接口跨档线格式，与 gmsm SM2 一致）。SoftHSM 实测
//     CKM_ECDSA 走裸 r||s（64B，与规范表述不符）——适配层在 Sign/Verify
//     边界归一（ecdsaRawToDER/ecdsaDERToRaw），对上隐藏厂商差异；
//   - ECDH 共享秘密 = X 坐标 32B（CKD_NULL 派生，与 Go crypto/ecdh 及
//     gmsm ecdh 输出同构）。
package cryptopmodule

import (
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"fmt"
	"math/big"

	"github.com/miekg/pkcs11"
)

const (
	// ecPointLen P-256 原始非压缩点长度（0x04||X32||Y32）。
	ecPointLen = 65
	// ecSharedSecretLen P-256 ECDH 共享秘密（X 坐标）长度。
	ecSharedSecretLen = 32
)

// ecCurveOIDP256 prime256v1/secp256r1 的 DER 编码 OID（CKA_EC_PARAMS 值）：
// 1.2.840.10045.3.1.7 → 06 08 2A 86 48 CE 3D 03 01 07。
var ecCurveOIDP256 = []byte{0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07}

// ---------------------------------------------------------------------------
// 错误码判别（厂商措辞宽松匹配的集合函数；单测覆盖，防误判掩盖真实故障）
// ---------------------------------------------------------------------------

// isKeyFunctionNotPermitted CKR_KEY_FUNCTION_NOT_PERMITTED：对象用途属性
// 不允许该运算（CKA_SIGN/CKA_DERIVE=false）——用途错误，非模块故障。
func isKeyFunctionNotPermitted(e pkcs11.Error) bool {
	return uint(e) == pkcs11.CKR_KEY_FUNCTION_NOT_PERMITTED
}

// isVerifyFailure CKR_SIGNATURE_INVALID：验签失败（数据结论，非模块故障；
// 区别于 ErrModuleUnavailable）。
func isVerifyFailure(e pkcs11.Error) bool {
	return uint(e) == pkcs11.CKR_SIGNATURE_INVALID
}

// ---------------------------------------------------------------------------
// ECDSA 签名线格式归一（裸 r||s ↔ ASN.1 DER）
// ---------------------------------------------------------------------------

// ecdsaSigValue ASN.1 DER ECDSA 签名（SEQUENCE { INTEGER r, INTEGER s }）——
// 与 gmsm SM2 签名线格式一致（接口跨档约定）。
type ecdsaSigValue struct {
	R, S *big.Int
}

// ecdsaRawToDER 裸 r||s（2×32B 大端）→ ASN.1 DER。
// SoftHSM v2.6.1 实测：C_Sign/C_Verify 的 CKM_ECDSA 走裸 r||s（64B），
// 与 PKCS#11 规范"DER 编码"表述不符（2026-10-24 真机测量）——适配层统一
// 归一为 DER 线格式，对上隐藏厂商差异。
func ecdsaRawToDER(raw []byte) ([]byte, error) {
	if len(raw) != 2*ecSharedSecretLen {
		return nil, fmt.Errorf("module: 裸签名长度 %d != %d（r||s 各 32B）", len(raw), 2*ecSharedSecretLen)
	}
	r := new(big.Int).SetBytes(raw[:ecSharedSecretLen])
	s := new(big.Int).SetBytes(raw[ecSharedSecretLen:])
	if err := validateECDSAScalar(r); err != nil {
		return nil, fmt.Errorf("module: 裸签名 r 非法: %w", err)
	}
	if err := validateECDSAScalar(s); err != nil {
		return nil, fmt.Errorf("module: 裸签名 s 非法: %w", err)
	}
	return asn1.Marshal(ecdsaSigValue{R: r, S: s})
}

// ecdsaDERToRaw ASN.1 DER → 裸 r||s（2×32B 大端，左侧补零）。
func ecdsaDERToRaw(der []byte) ([]byte, error) {
	var v ecdsaSigValue
	rest, err := asn1.Unmarshal(der, &v)
	if err != nil {
		return nil, fmt.Errorf("module: 签名 DER 解析失败: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("module: 签名 DER 含 %d 字节尾随数据（格式非法）", len(rest))
	}
	if v.R == nil || v.S == nil {
		return nil, fmt.Errorf("module: 签名 DER 缺 r/s 分量")
	}
	if err := validateECDSAScalar(v.R); err != nil {
		return nil, fmt.Errorf("module: 签名 r 非法: %w", err)
	}
	if err := validateECDSAScalar(v.S); err != nil {
		return nil, fmt.Errorf("module: 签名 s 非法: %w", err)
	}
	raw := make([]byte, 2*ecSharedSecretLen)
	v.R.FillBytes(raw[:ecSharedSecretLen])
	v.S.FillBytes(raw[ecSharedSecretLen:])
	return raw, nil
}

// validateECDSAScalar ECDSA 分量范围校验（1 ≤ x < N；P-256 阶）。
func validateECDSAScalar(x *big.Int) error {
	if x.Sign() == 0 {
		return fmt.Errorf("分量为 0")
	}
	if x.Cmp(ecdsaCurveOrder) >= 0 {
		return fmt.Errorf("分量 ≥ 曲线阶 N")
	}
	return nil
}

// ecdsaCurveOrder P-256 阶 N（预计算常量，避免每调用重建）。
var ecdsaCurveOrder = func() *big.Int {
	n := elliptic.P256().Params().N
	return new(big.Int).Set(n)
}()

// ---------------------------------------------------------------------------
// EC 点 DER 包裹/解包（CKA_EC_POINT ↔ 原始非压缩点）
// ---------------------------------------------------------------------------

// validateRawECPoint 校验原始非压缩 EC 点（0x04||X||Y；P-256 固定 65B）。
func validateRawECPoint(raw []byte) error {
	if len(raw) != ecPointLen {
		return fmt.Errorf("module: EC 点长度 %d != %d（P-256 非压缩点 0x04||X||Y）", len(raw), ecPointLen)
	}
	if raw[0] != 0x04 {
		return fmt.Errorf("module: EC 点首字节 0x%x 非非压缩点标记 0x04", raw[0])
	}
	return nil
}

// wrapECPoint 原始 EC 点 → DER OCTET STRING（CKA_EC_POINT 属性值要求）。
func wrapECPoint(raw []byte) ([]byte, error) {
	if err := validateRawECPoint(raw); err != nil {
		return nil, err
	}
	out := make([]byte, 0, 2+len(raw))
	out = append(out, 0x04) // OCTET STRING 标签
	switch {
	case len(raw) < 0x80:
		out = append(out, byte(len(raw))) // 短形式
	case len(raw) < 0x100:
		out = append(out, 0x81, byte(len(raw)))
	default:
		out = append(out, 0x82, byte(len(raw)>>8), byte(len(raw)))
	}
	return append(out, raw...), nil
}

// unwrapECPoint DER OCTET STRING → 原始 EC 点（CKA_EC_POINT 回读用）。
func unwrapECPoint(der []byte) ([]byte, error) {
	if len(der) < 2 {
		return nil, fmt.Errorf("module: EC 点 DER 长度 %d 非法（<2）", len(der))
	}
	if der[0] != 0x04 {
		return nil, fmt.Errorf("module: EC 点 DER 标签 0x%x 非 OCTET STRING(0x04)", der[0])
	}
	var body []byte
	switch {
	case der[1] < 0x80:
		body = der[2:]
	case der[1] == 0x81:
		if len(der) < 3 {
			return nil, fmt.Errorf("module: EC 点 DER 长形式长度截断")
		}
		body = der[3:]
	case der[1] == 0x82:
		if len(der) < 4 {
			return nil, fmt.Errorf("module: EC 点 DER 长形式长度截断")
		}
		body = der[4:]
	default:
		return nil, fmt.Errorf("module: EC 点 DER 长度形式 0x%x 不支持", der[1])
	}
	if err := validateRawECPoint(body); err != nil {
		return nil, fmt.Errorf("module: EC 点 DER 内容非法: %w", err)
	}
	return body, nil
}

// ---------------------------------------------------------------------------
// 属性模板
// ---------------------------------------------------------------------------

// ecPublicTemplate EC 公钥对象模板（生成路径）。
// derive=true（协商用途）不开 CKA_VERIFY——最小权限（ECDH 只消费私钥的
// CKA_DERIVE，公钥对象仅用于读出 EC 点，读完即毁不落 token）。
func ecPublicTemplate(derive bool) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecCurveOIDP256),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),    // 瞬态：读出 EC 点后即毁
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),  // 公钥无需登录态即可见
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, !derive), // 仅签名用途开放验签
	}
}

// ecPrivateTemplate EC 私钥对象模板（生成路径；落 token 模块内持久，
// 供后续 Sign/ECDH 经 KeyRef 引用）。
// 用途属性**双向显式**：开一组的同时显式关另一组——SoftHSM 实测未指定的
// CKA_SIGN 默认为 true（2026-10-24 真机：协商密钥竟能签名），"不设=默认
// false"的假设不成立，最小权限必须显式负向声明。
func ecPrivateTemplate(derive bool) []*pkcs11.Attribute {
	attrs := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, true),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, true),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, false),
	}
	if derive {
		attrs = append(attrs,
			pkcs11.NewAttribute(pkcs11.CKA_DERIVE, true),
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, false))
	} else {
		attrs = append(attrs,
			pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
			pkcs11.NewAttribute(pkcs11.CKA_DERIVE, false))
	}
	return attrs
}

// verifyPubTemplate 验签瞬态公钥对象模板（由原始公钥字节构造；会话级，
// 用完即毁，不落 token——避免每次验签在 token 上堆积对象）。
func verifyPubTemplate(pointDER []byte) []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, ecCurveOIDP256),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, pointDER),
	}
}

// ecdhDerivedTemplate ECDH 派生秘密的瞬态模板（会话级；与 UnwrapKey
// 同构，M4-4b）：SENSITIVE=false + EXTRACTABLE=true 才能回读 CKA_VALUE
// 返回调用方——共享秘密为三级会话域材料（B-6.1-9），调用方用后零化。
func ecdhDerivedTemplate() []*pkcs11.Attribute {
	return []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
		pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_GENERIC_SECRET),
		pkcs11.NewAttribute(pkcs11.CKA_TOKEN, false),
		pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
		pkcs11.NewAttribute(pkcs11.CKA_SENSITIVE, false),
		pkcs11.NewAttribute(pkcs11.CKA_EXTRACTABLE, true),
		pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, ecSharedSecretLen),
	}
}

// ---------------------------------------------------------------------------
// Hash（免密钥）
// ---------------------------------------------------------------------------

// Hash C_Digest 单次摘要（功能验证档 CKM_SHA256；SM 档 CKM_SM3 调用链相同）。
func (b *PKCS11Backend) Hash(data []byte) ([]byte, error) {
	if b.ctx == nil {
		return nil, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	ckm, err := b.lookupMechCKM(MechSHA256)
	if err != nil {
		return nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	if err := b.ctx.DigestInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)}); err != nil {
		return nil, fmt.Errorf("%w: C_DigestInit(CKM_SHA256): %v", ErrModuleUnavailable, err)
	}
	// 规范用法（vendor 测试同）：C_Digest 单次调用即返回完整摘要。
	sum, err := b.ctx.Digest(sh, data)
	if err != nil {
		return nil, fmt.Errorf("%w: C_Digest: %v", ErrModuleUnavailable, err)
	}
	if len(sum) == 0 {
		return nil, fmt.Errorf("%w: C_Digest 返回空摘要", ErrModuleUnavailable)
	}
	return sum, nil
}

// ---------------------------------------------------------------------------
// GenerateKeyPair / Sign / Verify / ECDH
// ---------------------------------------------------------------------------

// GenerateKeyPair 生成 EC 密钥对（功能验证档 CKM_EC_KEY_PAIR_GEN，P-256）。
// usage ∈ {UsageSign, UsageECDH}；返回 (模块内私钥句柄, 原始公钥字节)。
// 公钥对象为瞬态会话对象：读出 EC 点后立即销毁（调用方只拿原始字节，
// token 上不残留公钥对象）。
func (b *PKCS11Backend) GenerateKeyPair(usage string) (KeyRef, []byte, error) {
	// 参数（usage）校验优先于设备状态检查（M4-4a 裁定）。
	derive := false
	switch usage {
	case UsageSign:
	case UsageECDH:
		derive = true
	default:
		return nil, nil, fmt.Errorf("module: 未知 usage=%q（sign|ecdh）", usage)
	}
	if b.ctx == nil {
		return nil, nil, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	ckm, err := b.lookupMechCKM(MechECKeyGen)
	if err != nil {
		return nil, nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	pubOH, privOH, err := b.ctx.GenerateKeyPair(sh,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)},
		ecPublicTemplate(derive), ecPrivateTemplate(derive))
	if err != nil {
		return nil, nil, fmt.Errorf("%w: C_GenerateKeyPair(CKM_EC_KEY_PAIR_GEN): %v", ErrModuleUnavailable, err)
	}
	point, rerr := b.readECPoint(sh, pubOH)
	_ = b.ctx.DestroyObject(sh, pubOH) // 公钥瞬态：读出即毁
	if rerr != nil {
		_ = b.ctx.DestroyObject(sh, privOH) // 失败不残留半成品私钥对象
		return nil, nil, rerr
	}
	ref, err := encodeKeyRef(b.slotIndex, b.partition(), uint(privOH))
	if err != nil {
		_ = b.ctx.DestroyObject(sh, privOH) // 编码失败同样不残留对象
		return nil, nil, err
	}
	return ref, point, nil
}

// readECPoint 回读公钥对象的 CKA_EC_POINT 并解包为原始点。
func (b *PKCS11Backend) readECPoint(sh pkcs11.SessionHandle, oh pkcs11.ObjectHandle) ([]byte, error) {
	out, err := b.ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{{Type: pkcs11.CKA_EC_POINT}})
	if err != nil {
		return nil, fmt.Errorf("%w: C_GetAttributeValue(CKA_EC_POINT): %v", ErrModuleUnavailable, err)
	}
	if len(out) == 0 || len(out[0].Value) == 0 {
		return nil, fmt.Errorf("%w: 公钥对象 CKA_EC_POINT 为空", ErrModuleUnavailable)
	}
	return unwrapECPoint(out[0].Value)
}

// Sign 以模块内 EC 私钥签名（功能验证档 CKM_ECDSA，签 SHA-256 摘要）。
// uid 仅 SM2 档消费（Z 值计算）；ECDSA 档无算法意义，忽略。
func (b *PKCS11Backend) Sign(privRef KeyRef, msg []byte, uid string) ([]byte, error) {
	// 参数（KeyRef 归属）校验优先于设备状态检查。
	handle, err := decodeKeyRef(privRef, b.slotIndex, b.partition())
	if err != nil {
		return nil, err
	}
	if b.ctx == nil {
		return nil, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	ckm, err := b.lookupMechCKM(MechECDSA)
	if err != nil {
		return nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	if err := b.ctx.SignInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)},
		pkcs11.ObjectHandle(handle)); err != nil {
		var p11err pkcs11.Error
		if asPKCS11Err(err, &p11err) && isKeyFunctionNotPermitted(p11err) {
			return nil, fmt.Errorf("module: 对象非签名用途（CKA_SIGN=false；usage=ecdh 密钥不能签名）")
		}
		return nil, fmt.Errorf("%w: C_SignInit(CKM_ECDSA): %v", ErrModuleUnavailable, err)
	}
	// 功能验证档：CKM_ECDSA 签**摘要**——适配层以 Go crypto/sha256 计算
	// （SM2 档由厂商机制在模块内完成 Z 值与哈希，届时按厂商文档调整）。
	_ = uid
	digest := sha256.Sum256(msg)
	sig, err := b.ctx.Sign(sh, digest[:])
	if err != nil {
		return nil, fmt.Errorf("%w: C_Sign: %v", ErrModuleUnavailable, err)
	}
	if len(sig) == 0 {
		return nil, fmt.Errorf("%w: C_Sign 返回空签名", ErrModuleUnavailable)
	}
	// SoftHSM 实测返回裸 r||s（64B）；归一为 DER 线格式（接口跨档约定，
	// 与 gmsm SM2 一致）。
	der, err := ecdsaRawToDER(sig)
	if err != nil {
		return nil, err
	}
	return der, nil
}

// Verify 以原始公钥字节验签（功能验证档 CKM_ECDSA + SHA-256 摘要）。
// 公钥经瞬态会话对象进入模块（用完即毁，不落 token）。
func (b *PKCS11Backend) Verify(pub, msg, sig []byte, uid string) error {
	// 参数（公钥点格式）校验优先（纯函数）。
	pointDER, err := wrapECPoint(pub)
	if err != nil {
		return err
	}
	if len(sig) == 0 {
		return fmt.Errorf("module: Verify 签名长度 0 非法")
	}
	if b.ctx == nil {
		return fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	ckm, err := b.lookupMechCKM(MechECDSA)
	if err != nil {
		return err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	oh, err := b.ctx.CreateObject(sh, verifyPubTemplate(pointDER))
	if err != nil {
		return fmt.Errorf("%w: C_CreateObject(验签瞬态公钥): %v", ErrModuleUnavailable, err)
	}
	defer func() { _ = b.ctx.DestroyObject(sh, oh) }() // 瞬态：用完即毁
	if err := b.ctx.VerifyInit(sh, []*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, nil)}, oh); err != nil {
		return fmt.Errorf("%w: C_VerifyInit(CKM_ECDSA): %v", ErrModuleUnavailable, err)
	}
	digest := sha256.Sum256(msg)
	// 输入为 DER 线格式（接口跨档约定）；C_Verify 要裸 r||s（SoftHSM 实测）。
	raw, err := ecdsaDERToRaw(sig)
	if err != nil {
		return err
	}
	if err := b.ctx.Verify(sh, digest[:], raw); err != nil {
		var p11err pkcs11.Error
		if asPKCS11Err(err, &p11err) && isVerifyFailure(p11err) {
			return fmt.Errorf("module: 验签失败（CKR_SIGNATURE_INVALID）")
		}
		return fmt.Errorf("%w: C_Verify: %v", ErrModuleUnavailable, err)
	}
	return nil
}

// ECDH 以模块内协商私钥与对端公钥派生共享秘密（CKM_ECDH1_DERIVE +
// CKD_NULL：输出 = X 坐标 32B，与 Go crypto/ecdh / gmsm 输出同构）。
// 派生秘密经瞬态可导出会话对象回读后即毁（B-6.1-9：三级会话域材料，
// 调用方用后零化）。
func (b *PKCS11Backend) ECDH(privRef KeyRef, peerPub []byte) ([]byte, error) {
	// 参数（KeyRef 归属 + 对端公钥格式）校验优先。
	handle, err := decodeKeyRef(privRef, b.slotIndex, b.partition())
	if err != nil {
		return nil, err
	}
	if err := validateRawECPoint(peerPub); err != nil {
		return nil, fmt.Errorf("module: 对端公钥非法: %w", err)
	}
	if b.ctx == nil {
		return nil, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	ckm, err := b.lookupMechCKM(MechECDH1Derive)
	if err != nil {
		return nil, err
	}
	s, err := b.AcquireSession()
	if err != nil {
		return nil, err
	}
	defer func() { _ = b.ReleaseSession(s) }()
	sh := pkcs11.SessionHandle(s)

	params := pkcs11.NewECDH1DeriveParams(pkcs11.CKD_NULL, nil, peerPub)
	oh, err := b.ctx.DeriveKey(sh,
		[]*pkcs11.Mechanism{pkcs11.NewMechanism(ckm, params)},
		pkcs11.ObjectHandle(handle), ecdhDerivedTemplate())
	if err != nil {
		var p11err pkcs11.Error
		if asPKCS11Err(err, &p11err) && isKeyFunctionNotPermitted(p11err) {
			return nil, fmt.Errorf("module: 对象非协商用途（CKA_DERIVE=false；usage=sign 密钥不能协商）")
		}
		return nil, fmt.Errorf("%w: C_DeriveKey(CKM_ECDH1_DERIVE): %v", ErrModuleUnavailable, err)
	}
	defer func() { _ = b.ctx.DestroyObject(sh, oh) }() // 瞬态：读出即毁
	out, err := b.ctx.GetAttributeValue(sh, oh, []*pkcs11.Attribute{{Type: pkcs11.CKA_VALUE}})
	if err != nil {
		return nil, fmt.Errorf("%w: C_GetAttributeValue(CKA_VALUE): %v", ErrModuleUnavailable, err)
	}
	if len(out) == 0 || len(out[0].Value) == 0 {
		return nil, fmt.Errorf("%w: 派生秘密为空", ErrModuleUnavailable)
	}
	if len(out[0].Value) != ecSharedSecretLen {
		return nil, fmt.Errorf("%w: 派生秘密长度 %d != %d（P-256 X 坐标）",
			ErrModuleUnavailable, len(out[0].Value), ecSharedSecretLen)
	}
	return out[0].Value, nil
}

// ---------------------------------------------------------------------------
// RotateKey
// ---------------------------------------------------------------------------

// rotateKind RotateKey 的 spec 分流结果。
type rotateKind int

const (
	rotateSym  rotateKind = iota // 对称密钥（GenerateKey）
	rotatePair                   // 非对称密钥对（GenerateKeyPair）
)

// parseRotateSpec 解析 RotateKey 的 spec。
// 功能验证档：ec-sign/ec-ecdh（密钥对，usage 随返回值）、aes-*/""（对称）。
// SM 档（sm4-*/sm2-*）明确拒绝（ErrNotImplemented）——不映射到 EC/AES
// 冒充合规（C-3）。
func parseRotateSpec(spec string) (rotateKind, string, error) {
	switch spec {
	case "ec-sign":
		return rotatePair, UsageSign, nil
	case "ec-ecdh":
		return rotatePair, UsageECDH, nil
	case "sm2-sign", "sm2-ecdh":
		return 0, "", fmt.Errorf("%w: spec=%q 为国密档，SM2 机制 CKM 值待 S3-a 厂商 profile 登记（当前不映射到 EC 冒充合规，C-3）",
			ErrNotImplemented, spec)
	}
	if _, err := parseSymSpec(spec); err != nil { // aes-*/""/sm4-*（sm4 亦拒绝）/未知
		return 0, "", err
	}
	return rotateSym, "", nil
}

// RotateKey 模块内密钥轮换（GM2-02/R2-06）：生成新对象返回新句柄；
// **旧句柄不销毁**（接口规约：旧句柄按调用方策略归档）。旧引用的归属
// 仍受校验（跨后端/跨分区误用即拒）。
func (b *PKCS11Backend) RotateKey(oldRef KeyRef, spec string) (KeyRef, error) {
	// 参数（spec + 旧引用归属）校验优先于设备状态检查。
	kind, usage, err := parseRotateSpec(spec)
	if err != nil {
		return nil, err
	}
	if _, err := decodeKeyRef(oldRef, b.slotIndex, b.partition()); err != nil {
		return nil, err
	}
	if b.ctx == nil {
		return nil, fmt.Errorf("%w: 后端未初始化", ErrModuleUnavailable)
	}
	if kind == rotatePair {
		ref, _, err := b.GenerateKeyPair(usage)
		return ref, err
	}
	return b.GenerateKey(spec, "")
}
