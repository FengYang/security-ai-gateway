// Package route: 路由处方（RoutePrescription）数据模型、签发与验签。
package route

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

// Signer 处方签发与验签器。HMAC-SHA256（对称，与插件共享 K_rx）。
type Signer struct {
	key []byte
}

// NewSigner 构造签名器；key 至少 32 字节。
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("route: 签名密钥长度 %d < 32", len(key))
	}
	return &Signer{key: key}, nil
}

// JWT 三段式编码常量。
var b64 = base64.RawURLEncoding

// Issue 签发一张处方，返回 JWT 段式 token。signingTime 可注入（测试可mock）。
func (s *Signer) Issue(p *RoutePrescription) (string, error) {
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
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write([]byte(h + "." + pl))
	sig := b64.EncodeToString(mac.Sum(nil))
	return h + "." + pl + "." + sig, nil
}

// Verify 校验处方 JWT：签名 + 过期 + 时间窗。返回解析出的处方。
func (s *Signer) Verify(token string, now time.Time) (*RoutePrescription, error) {
	parts := splitToken(token)
	if len(parts) != 3 {
		return nil, errors.New("route: token 段数不为 3")
	}
	mac := hmac.New(sha256.New, s.key)
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