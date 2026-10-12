// Package cryptop —— 密码原语唯一入口（「国密为设计约束」双轨规划的核心交汇点）。
//
// 定位：所有功能的密码调用收敛到本包，**业务代码不直接 import 具体算法实现**
// （不直接使用 crypto/aes、x/crypto/ecdh、hmac+sha256 等）。
// 目的：算法族可切换（Profile），使功能开发不等待认证密码模块；达标时切换实现与 profile，
// 业务代码零改动。
//
// 合规边界（**必须如实标注，见 Profile.ComplianceNote**）：
//   - intl        ：国际算法（当前实现），不满足密评；
//   - sm-software ：国密算法软件实现，**不满足密评**（密评 FAQ：自研/软件实现无法提供安全性证明
//     即判"不符合"；使用长期无安全问题的开源库可争取"部分符合"），仅用于功能验证与非政企场景；
//   - sm-module   ：国密算法 + 经认证密码模块/密码服务，可用于政企合规声明（仍需密码应用方案评估与密评）。
//
// 规划依据：《GA-国密为设计约束的功能规划与落地策略.md》（内部文档）与《GA-国密与密评可行性评估.md》。
//
// 本轮范围（2026-09-12）：**接口骨架 + intl 实现 + 单测**；不接线任何现有调用点，
// 现有行为零变化。sm-software 实现待国密库选型与许可审查通过后补入。
package cryptop

import "errors"

// Profile 算法族（决定使用的算法实现与合规状态）。
type Profile string

const (
	// ProfileIntl 国际算法（AES-256-GCM / SHA-256 / HMAC-SHA256 / HKDF-SHA256 / X25519 / Ed25519）。
	ProfileIntl Profile = "intl"
	// ProfileSMSW 国密算法软件实现（SM2/SM3/SM4）。**不满足密评**，仅功能验证与过渡。
	ProfileSMSW Profile = "sm-software"
	// ProfileSMModule 国密算法 + 经认证密码模块/密码服务。政企合规声明的唯一允许档。
	ProfileSMModule Profile = "sm-module"
)

var (
	// ErrNotImplemented 该 profile 或该原语尚未实现。
	// （sm-software 已实现；sm-module 的生产路径见 New——厂商 SDK 未接入时返回明确错误。）
	ErrNotImplemented = errors.New("cryptop: 该 profile 或原语尚未实现")
	// ErrUnknownProfile 未知 profile。
	ErrUnknownProfile = errors.New("cryptop: 未知 profile")
	// ErrInvalidKeySize 密钥长度不符合当前 profile 要求（业务代码不得硬编码长度，须用 Provider 的尺寸方法）。
	ErrInvalidKeySize = errors.New("cryptop: 密钥长度不符合当前 profile")
	// ErrDecrypt 解密/解封失败（认证标签不符等）。
	ErrDecrypt = errors.New("cryptop: 解密失败（密文或附加数据被篡改）")
)

// MeetsMPY 该 profile 是否可用于**政企密评合规声明**（仅 sm-module 为真）。
func (p Profile) MeetsMPY() bool { return p == ProfileSMModule }

// ComplianceNote 返回供 /config 快照、metrics 标签、构建物元数据与交付文档使用的如实标注文案。
func (p Profile) ComplianceNote() string {
	switch p {
	case ProfileIntl:
		return "国际算法（AES-GCM/SHA-256/X25519）；不满足密评要求（GB/T 39786-2021 三级），不得用于政企合规声明"
	case ProfileSMSW:
		return "国密算法软件实现（SM2/SM3/SM4）；不满足密评要求（自研/软件实现无法提供安全性证明，密评 FAQ 判不符合），仅限功能验证与非政企场景"
	case ProfileSMModule:
		return "国密算法 + 认证密码模块/密码服务；可用于政企合规声明（仍须密码应用方案评估与密评）"
	default:
		return "未知 profile，禁止用于任何合规声明"
	}
}

// Provider 密码原语唯一入口。
//
// 尺寸方法（SymmetricKeySize/NonceSize/HashSize）用于让业务代码**不硬编码长度**——
// 这是"切换 profile 时代码零改动"的前提（AES-256 密钥 32B vs SM4 16B）。
type Provider interface {
	// Profile 当前算法族。
	Profile() Profile
	// ComplianceNote 合规标注文案（等价于 Profile().ComplianceNote()，便于调用方直接标注）。
	ComplianceNote() string

	// Rand 生成 n 字节随机数（须来自 CSPRNG 或密码模块）。
	Rand(n int) ([]byte, error)

	// SymmetricKeySize 对称密钥长度（字节）。
	SymmetricKeySize() int
	// NonceSize AEAD nonce 长度（字节）。
	NonceSize() int
	// HashSize 哈希输出长度（字节）。
	HashSize() int

	// Seal AEAD 加密：返回密文（含认证标签）。
	Seal(key, nonce, plaintext, aad []byte) ([]byte, error)
	// Open AEAD 解密：失败返回 ErrDecrypt（不得返回部分明文）。
	Open(key, nonce, ciphertext, aad []byte) ([]byte, error)
	// SealWithNonce 便捷封装：内部生成 nonce 并随密文一起返回。
	SealWithNonce(key, plaintext, aad []byte) (nonce, ciphertext []byte, err error)

	// Hash 哈希（intl=SHA-256；sm-*=SM3）。
	Hash(data []byte) []byte
	// HMAC 消息认证码（intl=HMAC-SHA256；sm-*=HMAC-SM3）。
	HMAC(key, data []byte) []byte
	// KDF 密钥派生（intl=HKDF-SHA256；sm-*=基于 SM3 的 KDF）。
	KDF(secret, salt, info []byte, outLen int) ([]byte, error)

	// Keystream 生成确定性密钥流（P0-4 §5.3.2；19→20 方法）。
	//   intl = HMAC-SHA256 PRG（每个 8 字节块 = HMAC-SHA256(key, BE64(counter+k)‖domain) 前 8 字节，
	//          **等价 cipher/mask 现役实现**，保向后兼容与 T-5.3-8 逐字节一致）；
	//   sm   = SM4-CTR keystream（IV = Hash(domain) 前 8 字节 ‖ BE64(counter)，逐块递增）。
	// domain 为域分离标签；counter 为流起点（BE64 块号）；n 为请求字节数（≥0；上限见 §4.3 R-8）。
	// ⚠️ 本原语只产流、不做认证（掩码"打散"用，完整性由上层保证）——不得用于替代 AEAD。
	Keystream(key, domain []byte, counter uint64, n int) ([]byte, error)

	// GenerateECDHKeyPair 生成密钥协商密钥对，返回 (私钥, 公钥) 字节（intl=X25519；sm-*=SM2）。
	GenerateECDHKeyPair() (priv, pub []byte, err error)
	// ECDH 密钥协商（intl=X25519；sm-*=SM2 密钥交换）。
	ECDH(priv, peerPub []byte) ([]byte, error)
	// GenerateSignKeyPair 生成签名密钥对，返回 (私钥, 公钥) 字节（intl=Ed25519；sm-*=SM2）。
	GenerateSignKeyPair() (priv, pub []byte, err error)
	// Sign 签名（intl=Ed25519；sm-*=SM2）。
	Sign(priv, msg []byte) ([]byte, error)
	// Verify 验签；失败返回非 nil error。
	Verify(pub, msg, sig []byte) error

	// WrapKey 用 KEK 封装 DEK（密钥封装；intl=AES-256-GCM；sm-*=SM4-GCM）。
	WrapKey(kek, dek []byte) ([]byte, error)
	// UnwrapKey 解封 DEK；失败返回 ErrDecrypt。
	UnwrapKey(kek, wrapped []byte) ([]byte, error)
}

// New 按 profile 构造 Provider。
//
// 当前实现两档：ProfileIntl（国际算法）与 ProfileSMSW（国密软件实现，依赖 emmansun/gmsm）。
// ProfileSMModule（认证密码模块/密码服务）返回 ErrNotImplemented——**调用方据此如实降级或报错，
// 绝不回退到软件实现冒充合规**。
func New(profile Profile) (Provider, error) {
	switch profile {
	case ProfileIntl:
		return newIntlProvider(), nil
	case ProfileSMSW:
		// 国密软件实现（SM2/SM3/SM4，依赖 github.com/emmansun/gmsm）：**不满足密评**，
		// 仅限功能验证与过渡（见 Profile.ComplianceNote）。
		return newSMProvider(), nil
	case ProfileSMModule:
		// 认证密码模块/密码服务（P1-5 M2）：经 env 配置构造后端（sdf/pkcs11）。
		// 厂商 SDK 未接入/配置缺失/能力不足 → 错误（调用方启动拒），
		// **绝不回退到软件实现冒充合规**（C-3）。
		return newModuleProviderFromEnv()
	default:
		return nil, ErrUnknownProfile
	}
}
