// Package rxroute — 路由处方（RoutePrescription，推路径 L1）的**共享 framing/解析实现（零密码）**。
//
// 为什么独立成包：处方由 gateway-core 签发、由 wasm 数据面插件（otpmask）验签，
// 两端必须使用**同一份**规范编码与校验语义。若各自复制实现，一旦格式演进就会出现
// "签发端改了、验签端静默失败"的双实现漂移（同审计链的教训）。
//
// **拆包（P0-4 §5.4.4 组⑫ / R-11）**：本包**不含任何密码求值**（不得 import `crypto/*`、`gmsm`、
// `cipher/mask`、`cryptoops`）——Wasm 插件必须链入本包做解析，密码求值一律经 cryptop sidecar。
// 签发/验签的**密码实现**在子包 `rxroute/rxsign`（仅 gateway-core 与测试链接）。
//
// 线上格式：`X-Otp-Route` 头 = JWT 三段式（HS256 + base64 RawURLEncoding）：
//
//	header.payload.sig      header = {"alg":"HS256","typ":"JWT"}
//	payload = base64url(RoutePrescription JSON)
//	sig     = HMAC(key, header + "." + payload)
//
// 校验规则（与设计 §6 一致）：MAC 有效 + 未过期（ExpiresAt）+ 在签发时间窗内
// （|now - CreatedAt| ≤ TimeSkew，覆盖未来时钟偏差与过期倒推）。
package rxroute

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// RouteEndpoint 处方内的单个端点配置（多端点权重路由）。
// P0-1 新增：用于描述多端点场景下的权重、优先级、超时等配置。
// 向后兼容：老处方只有 PreferredEngine/FallbackEngine，新处方可带完整端点列表。
type RouteEndpoint struct {
	Name     string  `json:"name"`               // 端点名称，如 "openai-gpt4-main"
	URL      string  `json:"url,omitempty"`      // 端点地址（可选，L1 处方可能只传名称）
	Weight   float64 `json:"weight,omitempty"`   // 权重（0-1），仅在同优先级内有效
	Priority int     `json:"priority,omitempty"` // 优先级（数字越小优先级越高，1=主，2=备1...）
}

// RoutePolicy 处方内的路由策略（引擎偏好 + 成本优先级）。
// 向后兼容：v1 只有 PreferredEngine/FallbackEngine（主备二元）；
// v2 新增 Endpoints 数组（多端点权重）。当 Endpoints 非空时，优先使用 Endpoints；
// 否则回退到 PreferredEngine/FallbackEngine 的二元模式。
type RoutePolicy struct {
	PreferredEngine string `json:"preferred_engine,omitempty"` // 首选引擎，如 cmaas（v1 二元模式）
	FallbackEngine  string `json:"fallback_engine,omitempty"`  // 兜底引擎，如 vllm（v1 二元模式）
	CostPriority    string `json:"cost_priority,omitempty"`    // latency | cost | quality
	Endpoints       []RouteEndpoint `json:"endpoints,omitempty"` // v2 多端点列表（P0-1 新增）
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

// Encode 规范编码处方并返回**参与签名的输入**（`header.payload`）。
// **不含任何密码运算**——MAC 由调用方计算（gateway-core 经 `rxsign`；数据面插件经 sidecar `/v1/hmac`）。
func Encode(p *RoutePrescription) (string, error) {
	if p.Tenant == "" || p.Model == "" {
		return "", errors.New("route: tenant/model 必填")
	}
	if p.CreatedAt == 0 {
		p.CreatedAt = time.Now().Unix()
	}
	if p.ExpiresAt == 0 {
		p.ExpiresAt = p.CreatedAt + TimeSkew
	}
	const header = `{"alg":"HS256","typ":"JWT"}`
	payload, err := json.Marshal(p)
	if err != nil {
		return "", fmt.Errorf("route: 处方编码失败: %w", err)
	}
	return b64.EncodeToString([]byte(header)) + "." + b64.EncodeToString(payload), nil
}

// ParseToken 解析处方令牌（**不做任何密码运算**）：返回处方、参与签名的输入（`header.payload`）与签名原始字节。
//
// 调用方须：① 自行计算并常量时间比较 MAC；② **再**调 `Validate` 做时效校验。
// **顺序不可颠倒**——未验签的载荷不可信。
func ParseToken(token string) (*RoutePrescription, string, []byte, error) {
	parts := splitToken(token)
	if len(parts) != 3 {
		return nil, "", nil, errors.New("route: token 段数不为 3")
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, "", nil, errors.New("route: 处方签名段非 base64url")
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, "", nil, errors.New("route: 处方载荷解码失败")
	}
	var p RoutePrescription
	if err := json.Unmarshal(payload, &p); err != nil {
		return nil, "", nil, errors.New("route: 处方载荷解析失败")
	}
	return &p, parts[0] + "." + parts[1], sig, nil
}

// Validate 校验处方时效（过期 + 签发时间窗）。**必须在 MAC 校验通过后调用**。
func Validate(p *RoutePrescription, now time.Time) error {
	nowUnix := now.Unix()
	if p.ExpiresAt != 0 && nowUnix > p.ExpiresAt {
		return errors.New("route: 处方已过期")
	}
	// 时间窗：签发时间与当前时间差绝对值 > 窗口即拒绝（覆盖未来时钟偏差与过期倒推）。
	if p.CreatedAt == 0 || abs(nowUnix-p.CreatedAt) > TimeSkew {
		return errors.New("route: 处方超出签发时间窗")
	}
	return nil
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
