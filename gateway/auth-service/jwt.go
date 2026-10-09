// jwt.go — HS256 JWT 手写实现（RFC 7515，零依赖）。
// 用于网关插件校验租户声明；生产可替换为外部 IdP 签发，本校验逻辑不变。
package main

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Claims JWT 载荷（租户鉴权 / API Key）。
type Claims struct {
	Sub    string `json:"sub"`
	Tenant string `json:"tenant"`
	// M3 扩展：role（API Key 场景为 "api"）/ jti（Key 标识，供数据面吊销消费）。
	// 插件侧容忍额外字段（§6.3 D-5：role/jti 不影响验签）。
	Role string `json:"role,omitempty"`
	JTI  string `json:"jti,omitempty"`
	IAT  int64  `json:"iat"`
	EXP  int64  `json:"exp"`
}

var b64 = base64.RawURLEncoding // RFC 7515：base64url 无 padding

// jwtSigner 签名器抽象：本地 secret（兼容）或 CPS KeyRef（§8 依赖 5）。
type jwtSigner interface {
	Sign(signingInput []byte) ([]byte, error)
}

// localSigner 本地密钥签名（经 cryptop provider；兼容既有部署）。
type localSigner struct{ secret []byte }

func (s localSigner) Sign(d []byte) ([]byte, error) {
	if len(s.secret) < 16 {
		return nil, errors.New("jwt: secret 过短（<16 字节）")
	}
	return cryptoProvider.HMAC(s.secret, d), nil
}

// cpsSigner 经 cryptopsvc（CPS）以 KeyRef 签名（密钥字节不落本服务，C-5）。
type cpsSigner struct{ client *cpsClient }

func (s cpsSigner) Sign(d []byte) ([]byte, error) { return s.client.HMAC(d) }

// signJWTClaims 以给定签名器签发（header.payload + 签名器产出 MAC）；exp 必填（RFC 8725 §3.1）。
func signJWTClaims(sg jwtSigner, c Claims) (string, error) {
	if c.EXP == 0 {
		return "", errors.New("jwt: exp 必填")
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(c)
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	mac, err := sg.Sign([]byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.EncodeToString(mac), nil
}

// signJWT 兼容入口：本地密钥 + tenant 主体（既有 /issue 行为）。
func signJWT(secret []byte, tenant string, ttl time.Duration) (string, error) {
	now := time.Now().Unix()
	return signJWTClaims(localSigner{secret}, Claims{
		Sub: tenant, Tenant: tenant, IAT: now, EXP: now + int64(ttl.Seconds()),
	})
}

// verifyJWT 校验签名与过期时间，返回声明（本地密钥入口，保持既有测试契约）。
func verifyJWT(secret []byte, token string) (*Claims, error) {
	return verifyJWTWith(localSigner{secret}, token)
}

// verifyJWTWith 以给定签名器重算 MAC 并常量时间比较（CPS 模式下密钥驻 CPS）。
func verifyJWTWith(sg jwtSigner, token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: 段数不为 3")
	}
	// 验签（常量时间比较）
	mac, err := sg.Sign([]byte(parts[0] + "." + parts[1]))
	if err != nil {
		return nil, err
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil || subtle.ConstantTimeCompare(sig, mac) != 1 {
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
	// RFC 8725 §3.1：exp 必填——缺失（=0）的 token 一律拒绝，防"永不过期"的伪造载荷
	if c.EXP == 0 || c.EXP < time.Now().Unix() {
		return nil, errors.New("jwt: token 缺失 exp 或已过期")
	}
	return &c, nil
}
