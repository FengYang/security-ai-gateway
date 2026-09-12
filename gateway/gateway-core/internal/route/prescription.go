// Package route: 路由处方（RoutePrescription）数据模型、签发与验签。
//
// 算法权威实现已收敛到共享包 security-ai-gateway/gateway/rxroute（数据面 wasm 插件
// 与 gateway-core 必须用同一份规范编码/验签语义，避免双实现漂移）。本文件保留：
//   - 类型别名（RoutePolicy / RoutePrescription）与常量 TimeSkew；
//   - 本地 Signer 结构体（因为 routetable.go 需在同一类型上挂路由表签发方法
//     SignTable/VerifyTable），其处方签发/验签转调共享包算法。
package route

import (
	"time"

	"security-ai-gateway/gateway/rxroute"
)

// RoutePolicy 处方内的路由策略（引擎偏好 + 成本优先级）。
type RoutePolicy = rxroute.RoutePolicy

// RoutePrescription 路由处方——请求级的路由决策凭证（推路径 L1）。
type RoutePrescription = rxroute.RoutePrescription

// TimeSkew 签名时间窗（秒）。
const TimeSkew = rxroute.TimeSkew

// Signer 处方与路由表签发器（HMAC-SHA256，K_rx 对称）。
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

// Issue 签发处方（算法在共享包，保证与数据面插件一致）。
func (s *Signer) Issue(p *RoutePrescription) (string, error) {
	return rxroute.IssueWith(s.key, p)
}

// Verify 校验处方：签名 + 过期 + 时间窗（算法在共享包）。
func (s *Signer) Verify(token string, now time.Time) (*RoutePrescription, error) {
	return rxroute.VerifyWith(s.key, token, now)
}
