// 段① 信封国密套件（P0-4 §5.1.2）：suite↔provider 绑死的 SM4-GCM。
//
// 设计不变式（F-P0-3）：**suite（算法身份）必须与 provider（算法实现）一一绑定**。
// v1.0 曾让 `sm4GCMSuite{p}.Seal` 直接复用 `p.Seal`——但 `Provider.Seal` 的算法由 p 的
// profile 决定，在 intl 进程里它会执行 AES-GCM 却对外声明 `SuiteID()==2`（SM4），即
// "贴错标签的密码算法"。故本套件**仅可绑定 sm-* provider**，构造期断言，不符即拒。
package cryptoops

import (
	"fmt"

	"security-ai-gateway/gateway/cryptop"
	protocol "security-ai-gateway/protocol/go"
)

// sm4GCMSuiteKeyLen SM4 分组密钥长度（GB/T 32907，128 位）。
const sm4GCMSuiteKeyLen = 16

// sm4GCMSuite 把 SM4-GCM 落地在 cryptop.Provider 上（suite↔provider 绑死）。
//
// **算法身份 = provider 的 profile**：`p.Seal/Open` 的算法由 p 的 profile 决定，故本 suite
// 仅可由 sm-* provider 构造（`newSM4Suite` 断言）；若在 intl 进程构造，产出的 wire 将
// "标 SM4 实为 AES"——构造期即拒绝，防静默错乱（G-7）。
type sm4GCMSuite struct{ p cryptop.Provider }

// newSM4Suite 构造 SM4-GCM suite；要求 p.Profile() ∈ {sm-software, sm-module}，否则 fail-closed。
func newSM4Suite(p cryptop.Provider) (CryptoSuite, error) {
	if p == nil {
		return nil, fmt.Errorf("envelope: SM4 suite 需要 sm provider，实为 nil")
	}
	switch p.Profile() {
	case cryptop.ProfileSMSW, cryptop.ProfileSMModule:
		return sm4GCMSuite{p: p}, nil
	default:
		return nil, fmt.Errorf("envelope: SM4 suite 仅可绑定 sm-* provider，实际 profile=%q（防 wire 标 SM4 实为 AES）", p.Profile())
	}
}

// RegisterSM4Suite 以 sm provider 构造并注册 SM4-GCM suite（§5.1.2 注册矩阵的装配入口）。
// 套件 ID 进程内唯一：`protocol.SuiteSM4GCM` 已注册则返回错误（`RegisterSuite` 语义）。
// 注：`protocol.SuiteAESGCM` 由本包内置标准库实现默认注册，intl/sm 两档皆可解 AES wire（双读）。
func RegisterSM4Suite(p cryptop.Provider) error {
	s, err := newSM4Suite(p)
	if err != nil {
		return err
	}
	return RegisterSuite(s)
}

func (s sm4GCMSuite) SuiteID() byte { return protocol.SuiteSM4GCM }

// Seal 以 SM4-GCM 封装；key 长度须 = 16B（显式校验，不符返回 cryptop.ErrInvalidKeySize → fail-closed，G-2）。
func (s sm4GCMSuite) Seal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	if len(key) != sm4GCMSuiteKeyLen {
		return nil, fmt.Errorf("envelope: SM4-GCM 密钥长度 %d≠%d: %w", len(key), sm4GCMSuiteKeyLen, cryptop.ErrInvalidKeySize)
	}
	return s.p.Seal(key, nonce, plaintext, aad)
}

// Open 以 SM4-GCM 解封；key 长度须 = 16B（显式校验，不符返回 cryptop.ErrInvalidKeySize → fail-closed）。
func (s sm4GCMSuite) Open(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	if len(key) != sm4GCMSuiteKeyLen {
		return nil, fmt.Errorf("envelope: SM4-GCM 密钥长度 %d≠%d: %w", len(key), sm4GCMSuiteKeyLen, cryptop.ErrInvalidKeySize)
	}
	return s.p.Open(key, nonce, ciphertext, aad)
}
