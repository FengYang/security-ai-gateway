// jwt.go — HS256 JWT 手写实现（RFC 7515，零依赖）。
// 用于网关插件校验租户声明；生产可替换为外部 IdP 签发，本校验逻辑不变。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Claims JWT 载荷（租户鉴权用）。
type Claims struct {
	Sub    string `json:"sub"`
	Tenant string `json:"tenant"`
	IAT    int64  `json:"iat"`
	EXP    int64  `json:"exp"`
}

var b64 = base64.RawURLEncoding // RFC 7515：base64url 无 padding

// signJWT 签发 HS256 token：header.payload 的 HMAC-SHA256。
func signJWT(secret []byte, tenant string, ttl time.Duration) (string, error) {
	if len(secret) < 16 {
		return "", errors.New("jwt: secret 过短（<16 字节）")
	}
	now := time.Now().Unix()
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	claims, _ := json.Marshal(Claims{
		Sub: tenant, Tenant: tenant, IAT: now, EXP: now + int64(ttl.Seconds()),
	})
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(claims)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + b64.EncodeToString(mac.Sum(nil)), nil
}

// verifyJWT 校验签名与过期时间，返回声明。
func verifyJWT(secret []byte, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: 段数不为 3")
	}
	// 验签（常量时间比较）
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("jwt: 签名无效")
	}
	// 解析载荷
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt: 载荷解码失败")
	}
	var c Claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errors.New("jwt: 载荷解析失败")
	}
	if c.EXP != 0 && c.EXP < time.Now().Unix() {
		return nil, errors.New("jwt: token 已过期")
	}
	return &c, nil
}
