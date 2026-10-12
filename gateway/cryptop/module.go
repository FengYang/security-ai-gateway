package cryptop

// module.go —— sm-module 档 Provider 实现（P1-5 M2，§6.2 映射）。
//
// 定位：moduleProvider 实现 Provider 20 方法，把每个原语映射到 ModuleBackend
// （gateway/cryptop/module 包，M1）；业务侧只见到 Provider 接口——切档零改动（C-2）。
//
// 合规边界（务必如实）：
//   - 生产路径：New(ProfileSMModule) 经 env 配置选择 sdf/pkcs11 后端；厂商 SDK
//     未接入或配置缺失 → 返回错误（调用方启动拒），**绝不回退软件实现冒充合规**（C-3）；
//   - mock 后端仅用于测试与适配层功能验证（NewModuleProviderWithBackend），其
//     ComplianceNote 如实标注"不满足密评"，禁止用于生产合规声明（P4）；
//   - Keystream（掩码 PRG）按 §6.2 例外说明保留软件路径（U-S3-2 待机构确认）；
//     若调用方传入模块 token 而非原始字节，软件路径报错（fail-closed），不静默降级。

import (
	"fmt"

	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

// moduleProvider sm-module 档实现（20 方法 → ModuleBackend）。
type moduleProvider struct {
	backend cryptopmodule.ModuleBackend
	cfg     *cryptopmodule.Config
	keystream *smProvider // Keystream 软件路径例外（§6.2/U-S3-2）
}

// newModuleProvider 以指定后端构造 sm-module Provider（内部）。
//
// Init 失败（R-S3-1 库不可加载 / R-S3-11 能力不足等）→ 错误，由调用方启动拒（C-3）。
func newModuleProvider(b cryptopmodule.ModuleBackend, cfg *cryptopmodule.Config) (*moduleProvider, error) {
	if b == nil || cfg == nil {
		return nil, fmt.Errorf("cryptop: moduleProvider 需要 backend 与配置")
	}
	if err := b.Init(cfg); err != nil {
		return nil, fmt.Errorf("cryptop: sm-module 后端初始化失败（启动拒）: %w", err)
	}
	// R-S3-11 兜底复核（Init 内已校验；双查防后端实现遗漏）。
	if err := cryptopmodule.CheckCapabilities(b.Capabilities(), cfg.RequiredMechanisms); err != nil {
		return nil, fmt.Errorf("cryptop: sm-module 能力校验失败: %w", err)
	}
	return &moduleProvider{backend: b, cfg: cfg, keystream: newSMProvider()}, nil
}

// newModuleProviderFromEnv 生产路径：经 env 配置构造（New(ProfileSMModule) 分派至此）。
func newModuleProviderFromEnv() (Provider, error) {
	cfg := cryptopmodule.LoadConfig()
	if cfg.Backend == cryptopmodule.BackendMock {
		// 生产路径禁止 mock（软件实现冒充合规风险，C-3/P4）。
		return nil, fmt.Errorf("%w: sm-module 生产路径禁止 mock 后端（MODULE_BACKEND=mock）；功能验证请使用 NewModuleProviderWithBackend",
			cryptopmodule.ErrNotImplemented)
	}
	b, err := cryptopmodule.NewBackend(cfg)
	if err != nil {
		return nil, err
	}
	return newModuleProvider(b, cfg)
}

// NewModuleProviderWithBackend 以显式后端构造 sm-module Provider。
//
// 用途：① 适配层功能验证（mock 后端，无硬件环境联调）；② 测试。
// **禁止用于生产合规声明**——mock 后端的 ComplianceNote 已如实标注"不满足密评"。
func NewModuleProviderWithBackend(b cryptopmodule.ModuleBackend, cfg *cryptopmodule.Config) (Provider, error) {
	return newModuleProvider(b, cfg)
}

// ModuleBackendProvider 暴露 sm-module 后端的 Provider 能力（M4 装配用：
// keystore moduleStore / 密封密钥模块路径经此获取后端，无需感知具体类型）。
type ModuleBackendProvider interface {
	Provider
	// ModuleBackend 返回本 Provider 承载的模块后端。
	ModuleBackend() cryptopmodule.ModuleBackend
}

// ModuleBackend 实现 ModuleBackendProvider（M4）。
func (p *moduleProvider) ModuleBackend() cryptopmodule.ModuleBackend { return p.backend }

// ---- Provider 20 方法 ----

func (p *moduleProvider) Profile() Profile       { return ProfileSMModule }
func (p *moduleProvider) SymmetricKeySize() int  { return smSymmetricKeySize }
func (p *moduleProvider) NonceSize() int         { return smNonceSize }
func (p *moduleProvider) HashSize() int          { return smHashSize }

// ComplianceNote 档位标注 + 后端如实标注（P4）：mock 后端显式声明不满足密评。
func (p *moduleProvider) ComplianceNote() string {
	note := ProfileSMModule.ComplianceNote()
	if p.cfg != nil && p.cfg.Backend == cryptopmodule.BackendMock {
		return note + "；⚠ 当前为 mock 后端（软件实现，仅适配层功能验证，不满足密评，禁止用于生产合规声明）"
	}
	if p.cfg != nil {
		return note + "（后端: " + p.cfg.Backend + "）"
	}
	return note
}

func (p *moduleProvider) Rand(n int) ([]byte, error) {
	return p.backend.Rand(n)
}

func (p *moduleProvider) Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	return p.backend.Seal(cryptopmodule.KeyRef(key), nonce, plaintext, aad)
}

func (p *moduleProvider) Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	return p.backend.Open(cryptopmodule.KeyRef(key), nonce, ciphertext, aad)
}

func (p *moduleProvider) SealWithNonce(key, plaintext, aad []byte) ([]byte, []byte, error) {
	nonce, err := p.backend.Rand(smNonceSize)
	if err != nil {
		return nil, nil, err
	}
	ct, err := p.backend.Seal(cryptopmodule.KeyRef(key), nonce, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

func (p *moduleProvider) Hash(data []byte) []byte {
	sum, err := p.backend.Hash(data)
	if err != nil {
		// Hash 无错误返回路径（接口约束）；后端异常时 panic 好过返回错误哈希
		// （调用方一律按成功使用，错误哈希会破坏完整性语义）。
		panic(fmt.Sprintf("cryptop: sm-module Hash 失败: %v", err))
	}
	return sum
}

func (p *moduleProvider) HMAC(key, data []byte) []byte {
	mac, err := p.backend.HMAC(cryptopmodule.KeyRef(key), data)
	if err != nil {
		panic(fmt.Sprintf("cryptop: sm-module HMAC 失败: %v", err))
	}
	return mac
}

func (p *moduleProvider) KDF(secret, salt, info []byte, outLen int) ([]byte, error) {
	return p.backend.KDF(cryptopmodule.KeyRef(secret), salt, info, outLen, "")
}

// Keystream 软件路径例外（§6.2/U-S3-2）：掩码 PRG 不承担认证职责，sm-module 档
// 是否下发模块由 S3-b 实测裁决。若 key 为模块 token（非原始字节），软件路径报错
// （fail-closed），绝不静默产出错误流。
func (p *moduleProvider) Keystream(key, domain []byte, counter uint64, n int) ([]byte, error) {
	return p.keystream.Keystream(key, domain, counter, n)
}

func (p *moduleProvider) GenerateECDHKeyPair() ([]byte, []byte, error) {
	ref, pub, err := p.backend.GenerateKeyPair(cryptopmodule.UsageECDH)
	if err != nil {
		return nil, nil, err
	}
	return []byte(ref), pub, nil
}

func (p *moduleProvider) ECDH(priv, peerPub []byte) ([]byte, error) {
	return p.backend.ECDH(cryptopmodule.KeyRef(priv), peerPub)
}

func (p *moduleProvider) GenerateSignKeyPair() ([]byte, []byte, error) {
	ref, pub, err := p.backend.GenerateKeyPair(cryptopmodule.UsageSign)
	if err != nil {
		return nil, nil, err
	}
	return []byte(ref), pub, nil
}

// sm2UID 签名/验签用户标识（§6.4 module_sm2_uid；GM2-06 跨档一致）。
func (p *moduleProvider) sm2UID() string {
	if p.cfg != nil {
		return p.cfg.SM2UID
	}
	return ""
}

func (p *moduleProvider) Sign(priv, msg []byte) ([]byte, error) {
	return p.backend.Sign(cryptopmodule.KeyRef(priv), msg, p.sm2UID())
}

func (p *moduleProvider) Verify(pub, msg, sig []byte) error {
	return p.backend.Verify(pub, msg, sig, p.sm2UID())
}

func (p *moduleProvider) WrapKey(kek, dek []byte) ([]byte, error) {
	return p.backend.WrapKey(cryptopmodule.KeyRef(kek), dek)
}

func (p *moduleProvider) UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	return p.backend.UnwrapKey(cryptopmodule.KeyRef(kek), wrapped)
}

// 编译期契约保证。
var _ Provider = (*moduleProvider)(nil)
