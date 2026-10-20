package a2aregistry

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

// allowedAlgs 是签名算法白名单（冻结 §4.1）：默认 ES256/RS256/EdDSA，
// 可选 ES384/ES512；none、HS* 与未知 alg 一律拒绝。
var allowedAlgs = map[string]bool{
	"ES256": true,
	"ES384": true,
	"ES512": true,
	"RS256": true,
	"EdDSA": true,
}

// algAllowed 判断 alg 是否在白名单内。
func algAllowed(alg string) bool { return allowedAlgs[alg] }

// jwk 是 RFC 7517 公钥 JWK 的受控子集（仅公钥字段；私钥/对称材料一律拒绝）。
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// parsePublicJWK 解析 JWK → crypto.PublicKey。
// 拒绝：对称密钥（kty=oct）、私钥材料（d/k 字段）、未知 kty、越界坐标。
func parsePublicJWK(raw string) (crypto.PublicKey, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("JWK 为空")
	}
	// 私钥/对称材料检查：字段存在即拒绝（不读取其值）。
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return nil, fmt.Errorf("JWK 非法 JSON: %w", err)
	}
	for _, forbidden := range []string{"d", "k", "p", "q", "dp", "dq", "qi"} {
		if _, ok := probe[forbidden]; ok {
			return nil, fmt.Errorf("JWK 含私钥/对称材料字段 %q（仅接受公钥）", forbidden)
		}
	}
	var k jwk
	if err := json.Unmarshal([]byte(trimmed), &k); err != nil {
		return nil, fmt.Errorf("JWK 解析失败: %w", err)
	}
	switch k.Kty {
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("不支持的 OKP 曲线 %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("OKP x 解码失败: %w", err)
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("Ed25519 公钥长度非法: %d", len(x))
		}
		return ed25519.PublicKey(x), nil
	case "EC":
		return ecPublicKey(k)
	case "RSA":
		return rsaPublicKey(k)
	case "oct":
		return nil, fmt.Errorf("对称密钥（kty=oct）不被接受")
	case "":
		return nil, fmt.Errorf("JWK 缺 kty")
	default:
		return nil, fmt.Errorf("不支持的 kty %q", k.Kty)
	}
}

// ecPublicKey 由 EC JWK 构造 ECDSA 公钥（坐标须落在曲线上）。
func ecPublicKey(k jwk) (crypto.PublicKey, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("不支持的 EC 曲线 %q", k.Crv)
	}
	xb, err := base64.RawURLEncoding.DecodeString(k.X)
	if err != nil {
		return nil, fmt.Errorf("EC x 解码失败: %w", err)
	}
	yb, err := base64.RawURLEncoding.DecodeString(k.Y)
	if err != nil {
		return nil, fmt.Errorf("EC y 解码失败: %w", err)
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !curve.IsOnCurve(x, y) {
		return nil, fmt.Errorf("EC 公钥坐标不在曲线上")
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// rsaPublicKey 由 RSA JWK 构造 RSA 公钥。
func rsaPublicKey(k jwk) (crypto.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("RSA n 解码失败: %w", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("RSA e 解码失败: %w", err)
	}
	e := new(big.Int).SetBytes(eb)
	if e.BitLen() == 0 || e.BitLen() > 32 {
		return nil, fmt.Errorf("RSA 指数非法")
	}
	if !e.IsInt64() || e.Int64() < 3 {
		return nil, fmt.Errorf("RSA 指数非法")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(e.Int64())}, nil
}

// validatePublicJWK 校验 JWK 可被接受为 pinned 公钥（冻结 §4.2）。
func validatePublicJWK(raw string) error {
	pub, err := parsePublicJWK(raw)
	if err != nil {
		return err
	}
	if pub == nil {
		return fmt.Errorf("JWK 未产出公钥")
	}
	return nil
}

// algMatchesKey 校验签名 alg 与公钥类型相容（防 alg/key 混用）。
func algMatchesKey(alg string, pub crypto.PublicKey) bool {
	switch alg {
	case "ES256":
		k, ok := pub.(*ecdsa.PublicKey)
		return ok && k.Curve == elliptic.P256()
	case "ES384":
		k, ok := pub.(*ecdsa.PublicKey)
		return ok && k.Curve == elliptic.P384()
	case "ES512":
		k, ok := pub.(*ecdsa.PublicKey)
		return ok && k.Curve == elliptic.P521()
	case "RS256":
		_, ok := pub.(*rsa.PublicKey)
		return ok
	case "EdDSA":
		_, ok := pub.(ed25519.PublicKey)
		return ok
	}
	return false
}

// keyFingerprint 计算公钥的审计指纹（冻结 §5.7）。
//
// ⚠️ 只入指纹、**不回显公钥材料**：审计链留 SHA-256 摘要即可定位「换过哪把钥匙」，
// 又不把密钥材料写进 WORM 文件。
func keyFingerprint(publicJWK string) string {
	sum := sha256.Sum256([]byte(publicJWK))
	return "sha256:" + hex.EncodeToString(sum[:])
}
