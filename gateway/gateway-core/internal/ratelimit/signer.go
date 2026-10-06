package ratelimit

import (
	"crypto/subtle"
	"fmt"
	"os"

	"security-ai-gateway/gateway/cryptop"
)

// cryptoProvider 限流表签名/验签所用 Provider（P0-4 §5.4.4 组⑫）：
// profile 取自 `CRYPTO_PROFILE`（§12.3；默认 intl，与现役 HMAC-SHA256 逐字节等价）。
var cryptoProvider = newCryptoProvider()

func newCryptoProvider() cryptop.Provider {
	profile := os.Getenv("CRYPTO_PROFILE")
	if profile == "" {
		profile = string(cryptop.ProfileIntl)
	}
	p, err := cryptop.New(cryptop.Profile(profile))
	if err != nil {
		panic("ratelimit: 初始化 cryptop provider 失败（CRYPTO_PROFILE=" + profile + "）: " + err.Error())
	}
	return p
}

// Signer 限流表签发/验签器（HMAC-SHA256 over CanonicalBytes）。
//
// 与 route.Signer / mcpsec.Signer 同族：由 gateway-core 启动时用**同一 K_rx 密钥**构造
// （main.go 中与路由签名器同源），保证"同一下发通道、同一验签密钥"（设计 v1.1 §4）。
type Signer struct {
	key []byte
}

// NewSigner 构造签发器；密钥须 ≥32 字节（与 route.NewSigner 同约束）。
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("ratelimit: 签名密钥长度不足（%d < 32）", len(key))
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Signer{key: k}, nil
}

// SignTable 对限流表签名并写入 Signature 字段。
func (s *Signer) SignTable(t *Table) error {
	canon, err := t.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("ratelimit: 限流表编码失败: %w", err)
	}
	// MAC 经 cryptop（intl=HMAC-SHA256；sm=HMAC-SM3；§5.4.4 组⑫）。
	t.Signature = cryptoProvider.HMAC(s.key, canon)
	return nil
}

// VerifyTable 校验限流表签名。
func (s *Signer) VerifyTable(t *Table) bool {
	canon, err := t.CanonicalBytes()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(t.Signature, cryptoProvider.HMAC(s.key, canon)) == 1
}
