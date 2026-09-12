// Package rxroute — 路由处方（RoutePrescription，推路径 L1）的**共享实现**。
//
// 为什么独立成包：处方由 gateway-core 签发、由 wasm 数据面插件（otpmask）验签，
// 两端必须使用**同一份**规范编码与验签语义。若各自复制实现，一旦格式演进就会出现
// "签发端改了、验签端静默失败"的双实现漂移（同审计链的教训）。故算法权威实现收敛到本包：
// gateway-core 与插件均调用 IssueWith / VerifyWith（见 internal/route/prescription.go）。
//
// 线上格式：`X-Otp-Route` 头 = JWT 三段式（HS256 + base64 RawURLEncoding）：
//
//	header.payload.sig      header = {"alg":"HS256","typ":"JWT"}
//	payload = base64url(RoutePrescription JSON)
//	sig     = HMAC-SHA256(key, header + "." + payload)
//
// 验签规则（与设计 §6 一致）：签名有效 + 未过期（ExpiresAt）+ 在签发时间窗内
// （|now - CreatedAt| ≤ TimeSkew，覆盖未来时钟偏差与过期倒推）。
package rxroute

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RoutePolicy 处方内的路由策略（引擎偏好 + 成本优先级）。
type RoutePolicy struct {
	PreferredEngine string `json:"preferred_engine,omitempty"` // 首选引擎，如 cmaas
	FallbackEngine  string `json:"fallback_engine,omitempty"`  // 兜底引擎，如 vllm
	CostPriority    string `json:"cost_priority,omitempty"`    // latency | cost | quality
}

// RoutePrescription 路由处方——请求级的路由决策凭证（推路径 L1）。
type RoutePrescription struct {
	PrescriptionID string       `json:"prescription_id"`
	Tenant         string       `json:"tenant"`
	Model          string       `json:"model"`
	CreatedAt      int64        `json:"created_at"`
	ExpiresAt      int64        `json:"expires_at"`
	JTI            string       `json:"jti"` // 一次性消费标识（防重放）
	Policy         *RoutePolicy `json:"policy,omitempty"`
}

// TimeSkew 签名时间窗（秒）：处方签发时间与校验时间差超过该值即拒绝。
const TimeSkew = 30

// MinKeyLen HMAC 密钥最小长度（处方与路由表共用同一 K_rx）。
const MinKeyLen = 32

// ValidateKey 校验密钥长度。两端共用，避免"签发端放宽、验签端收紧"之类不一致。
func ValidateKey(key []byte) error {
	if len(key) < MinKeyLen {
		return fmt.Errorf("route: 签名密钥长度 %d < %d", len(key), MinKeyLen)
	}
	return nil
}

// JWT 三段式编码常量。
var b64 = base64.RawURLEncoding

// IssueWith 用给定密钥签发处方（共享实现，gateway-core 使用）。
func IssueWith(key []byte, p *RoutePrescription) (string, error) {
	if p.Tenant == "" || p.Model == "" {
		return "", errors.New("route: tenant/model 必填")
	}
	if p.CreatedAt == 0 {
		p.CreatedAt = time.Now().Unix()
	}
	if p.ExpiresAt == 0 {
		p.ExpiresAt = p.CreatedAt + TimeSkew
	}
	header := `{"alg":"HS256","typ":"JWT"}`
	h := b64.EncodeToString([]byte(header))
	payload, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("route: 处方编码失败: %w", err)
	}
	pl := b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(h + "." + pl))
	sig := b64.EncodeToString(mac.Sum(nil))
	return h + "." + pl + "." + sig, nil
}

// VerifyWith 用给定密钥校验处方（共享实现，数据面插件使用）：签名 + 过期 + 时间窗。
func VerifyWith(key []byte, token string, now time.Time) (*RoutePrescription, error) {
	parts := splitToken(token)
	if len(parts) != 3 {
		return nil, errors.New("route: token 段数不为 3")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := b64.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("route: 处方签名无效")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("route: 处方载荷解码失败")
	}
	var p RoutePrescription
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, errors.New("route: 处方载荷解析失败")
	}
	nowUnix := now.Unix()
	if p.ExpiresAt != 0 && nowUnix > p.ExpiresAt {
		return nil, errors.New("route: 处方已过期")
	}
	// 时间窗：签发时间与当前时间差绝对值 > 窗口即拒绝（覆盖未来时钟偏差与过期倒推）。
	if p.CreatedAt == 0 || abs(nowUnix-p.CreatedAt) > TimeSkew {
		return nil, errors.New("route: 处方超出签发时间窗")
	}
	return &p, nil
}

// Signer 便捷封装：以固定密钥完成签发/验签（数据面插件与测试使用）。
// gateway-core 因需在同一类型上挂路由表签发方法（SignTable/VerifyTable），
// 保留自己的本地结构体并转调 IssueWith/VerifyWith。
type Signer struct {
	key []byte
}

// NewSigner 构造签名器；key 至少 MinKeyLen 字节。
func NewSigner(key []byte) (*Signer, error) {
	if err := ValidateKey(key); err != nil {
		return nil, err
	}
	return &Signer{key: key}, nil
}

// Issue 签发一张处方（signingTime 可注入：CreatedAt 为零时取当前时间）。
func (s *Signer) Issue(p *RoutePrescription) (string, error) {
	return IssueWith(s.key, p)
}

// Verify 校验处方 JWT。
func (s *Signer) Verify(token string, now time.Time) (*RoutePrescription, error) {
	return VerifyWith(s.key, token, now)
}

// abs 返回 int64 绝对值。
func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// splitToken 切分 JWT 三段。
func splitToken(token string) []string {
	out := make([]string, 0, 3)
	start := 0
	for i := 0; i <= len(token); i++ {
		if i == len(token) || token[i] == '.' {
			out = append(out, token[start:i])
			start = i + 1
		}
	}
	return out
}
