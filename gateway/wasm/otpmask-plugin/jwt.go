// jwt.go — 插件侧 JWT 校验（C-6 租户鉴权）。
//
// 客户端携带 Authorization: Bearer <token>；插件校验 HS256 签名与过期，
// 以 token 中 tenant 声明覆盖 X-Tenant-ID（防止客户端自声明）。
// 仅校验（签发由 auth-service / 外部 IdP 完成），HS256 用标准库实现（wasm 兼容）。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
)

var jwtB64 = base64.RawURLEncoding

// jwtClaims 租户鉴权声明。
type jwtClaims struct {
	Sub    string `json:"sub"`
	Tenant string `json:"tenant"`
	IAT    int64  `json:"iat"`
	EXP    int64  `json:"exp"`
}

// verifyJWT 校验 HS256 签名与过期时间，返回声明。
func verifyJWT(secret []byte, token string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: 段数不为 3")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := jwtB64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("jwt: 签名无效")
	}
	payload, err := jwtB64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt: 载荷解码失败")
	}
	var c jwtClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errors.New("jwt: 载荷解析失败")
	}
	// RFC 8725 §3.1：exp 必填——缺失（=0）的 token 一律拒绝，防"永不过期"的伪造载荷
	if c.EXP == 0 || c.EXP < time.Now().Unix() {
		return nil, errors.New("jwt: token 缺失 exp 或已过期")
	}
	return &c, nil
}

// bearerToken 提取 Authorization: Bearer <token>（无则返回空串）。
func bearerToken() string {
	v, err := proxywasm.GetHttpRequestHeader("authorization")
	if err != nil {
		return ""
	}
	const prefix = "Bearer "
	if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
		return strings.TrimSpace(v[len(prefix):])
	}
	return ""
}
