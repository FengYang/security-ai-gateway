// Package route: 路由处方（RoutePrescription）数据模型、签发与验签。
//
// 分层（P0-4 §5.4.4 组⑫ / R-11 拆包）：
//   - framing/解析（零密码）在共享包 security-ai-gateway/gateway/rxroute——数据面 wasm 插件
//     必须链入它做解析，故该包不得含密码求值；
//   - 密码求值（MAC 签发/验签）在子包 security-ai-gateway/gateway/rxroute/rxsign；
//   - 本文件保留类型别名、常量 TimeSkew，以及本地 Signer（因为 routetable.go 需在同一类型上
//     挂路由表签发方法 SignTable/VerifyTable），其处方签发/验签转调 rxsign。
package route

import (
	"time"

	"security-ai-gateway/gateway/rxroute"
	"security-ai-gateway/gateway/rxroute/rxsign"
)

// RoutePolicy 处方内的路由策略（引擎偏好 + 成本优先级）。
type RoutePolicy = rxroute.RoutePolicy

// RoutePrescription 路由处方——请求级的路由决策凭证（推路径 L1）。
type RoutePrescription = rxroute.RoutePrescription

// TimeSkew 签名时间窗（秒）。
const TimeSkew = rxroute.TimeSkew

// Signer 处方与路由表签发器（K_rx 对称）。
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

// Issue 签发处方（算法在 rxsign，保证与数据面插件一致）。
func (s *Signer) Issue(p *RoutePrescription) (string, error) {
	return rxsign.IssueWith(s.key, p)
}

// Verify 校验处方：MAC + 过期 + 时间窗（算法在 rxsign）。
func (s *Signer) Verify(token string, now time.Time) (*RoutePrescription, error) {
	return rxsign.VerifyWith(s.key, token, now)
}
