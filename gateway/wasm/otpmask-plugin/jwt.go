// jwt.go — 插件侧 JWT 校验（C-6 租户鉴权，P0-4 零密码改造）。
//
// 客户端携带 Authorization: Bearer <token>；插件校验 HS256 签名与过期，
// 以 token 中 tenant 声明覆盖 X-Tenant-ID（防止客户端自声明）。
// 仅校验（签发由 auth-service / 外部 IdP 完成）；HS256 的 HMAC 求值下沉 cryptop sidecar
// （§5.4.5：jwt.go 的 HMAC+比较 → 经 sidecar），密钥字节恒驻 sidecar（C-5），插件零密码（R-11）。
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
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

// verifyJWT 校验 HS256 签名与过期时间，返回声明（CPS 交付：HMAC 求值经 cryptop sidecar，§5.4.5）。
//
// 保留既有语义：三段校验、签名无效一律拒、载荷解码/解析失败拒、exp 必填（缺失=0 一律拒，RFC 8725 §3.1）。
// keyRef 为 JWT 密钥句柄（§6.3 命名，如 otpmask/jwt/v1）；sidecar 不可用 → 拒绝（fail-closed）。
func verifyJWT(keyRef string, token string, cb func(*jwtClaims, error)) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		cb(nil, errors.New("jwt: 段数不为 3"))
		return
	}
	sig, err := jwtB64.DecodeString(parts[2])
	if err != nil {
		cb(nil, errors.New("jwt: 签名无效"))
		return
	}
	symmetricVerifyMAC(keyRef, []byte(parts[0]+"."+parts[1]), sig, func(ok bool, verr error) {
		if verr != nil {
			cb(nil, fmt.Errorf("jwt: 验签服务不可用: %w", verr))
			return
		}
		if !ok {
			cb(nil, errors.New("jwt: 签名无效"))
			return
		}
		payload, err := jwtB64.DecodeString(parts[1])
		if err != nil {
			cb(nil, errors.New("jwt: 载荷解码失败"))
			return
		}
		var c jwtClaims
		if err := json.Unmarshal(payload, &c); err != nil {
			cb(nil, errors.New("jwt: 载荷解析失败"))
			return
		}
		// RFC 8725 §3.1：exp 必填——缺失（=0）的 token 一律拒绝，防"永不过期"的伪造载荷
		if c.EXP == 0 || c.EXP < time.Now().Unix() {
			cb(nil, errors.New("jwt: token 缺失 exp 或已过期"))
			return
		}
		cb(&c, nil)
	})
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
