// Package rxsign —— 路由处方（`X-Otp-Route`）的**签发/验签密码实现**（P0-4 §5.4.4 组⑫）。
//
// **拆包理由（R-11 / §9.1 门禁）**：framing/解析在父包 `rxroute`（零密码，Wasm 插件必须链入）；
// 密码求值（MAC）单独落在本包，**仅 gateway-core 与测试链接**。若把两者合在一起，插件会被迫
// 经 `rxroute` 链入 `crypto/hmac`，违反"Wasm 零密码"（该约束与 `protocol/go` 的 framing/cryptoops
// 拆包同源）。
//
// profile 取自 `CRYPTO_PROFILE`（§12.3 `crypto_profile`；默认 intl，与现役 HMAC-SHA256 逐字节等价）。
package rxsign

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"security-ai-gateway/gateway/cryptop"
	"security-ai-gateway/gateway/rxroute"
)

var cryptoProvider = newCryptoProvider()

func newCryptoProvider() cryptop.Provider {
	profile := os.Getenv("CRYPTO_PROFILE")
	if profile == "" {
		profile = string(cryptop.ProfileIntl)
	}
	p, err := cryptop.New(cryptop.Profile(profile))
	if err != nil {
		panic("rxsign: 初始化 cryptop provider 失败（CRYPTO_PROFILE=" + profile + "）: " + err.Error())
	}
	return p
}

// IssueWith 用给定密钥签发处方（MAC 经 cryptop：intl=HMAC-SHA256，逐字节等价现役实现；sm=HMAC-SM3）。
func IssueWith(key []byte, p *rxroute.RoutePrescription) (string, error) {
	input, err := rxroute.Encode(p)
	if err != nil {
		return "", err
	}
	mac := cryptoProvider.HMAC(key, []byte(input))
	return input + "." + base64.RawURLEncoding.EncodeToString(mac), nil
}

// VerifyWith 校验处方：解析（零密码）→ 常量时间比对 MAC → 时效（**顺序不可颠倒**）。
func VerifyWith(key []byte, token string, now time.Time) (*rxroute.RoutePrescription, error) {
	p, input, sig, err := rxroute.ParseToken(token)
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(sig, cryptoProvider.HMAC(key, []byte(input))) != 1 {
		return nil, errors.New("route: 处方签名无效")
	}
	if err := rxroute.Validate(p, now); err != nil {
		return nil, err
	}
	return p, nil
}

// Signer 便捷封装：以固定密钥完成签发/验签（gateway-core 与测试使用）。
type Signer struct {
	key []byte
}

// NewSigner 构造签名器；key 至少 rxroute.MinKeyLen 字节。
func NewSigner(key []byte) (*Signer, error) {
	if err := rxroute.ValidateKey(key); err != nil {
		return nil, err
	}
	return &Signer{key: key}, nil
}

// Issue 签发一张处方（CreatedAt 为零时取当前时间）。
func (s *Signer) Issue(p *rxroute.RoutePrescription) (string, error) {
	return IssueWith(s.key, p)
}

// Verify 校验处方。
func (s *Signer) Verify(token string, now time.Time) (*rxroute.RoutePrescription, error) {
	return VerifyWith(s.key, token, now)
}
