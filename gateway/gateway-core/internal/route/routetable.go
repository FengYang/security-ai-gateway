package route

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"fmt"
)

// TableRoute 默认路由表的一条记录：tenant+model → 目标引擎与端点（拉路径 L2 兜底）。
type TableRoute struct {
	Tenant        string `json:"tenant"`
	Model         string `json:"model"`
	DefaultEngine string `json:"default_engine"`
	FallbackEngine string `json:"fallback_engine,omitempty"`
	Target        string `json:"target,omitempty"` // 可选：显式目标端点（缺省用引擎默认）
}

// RouteTable 默认路由表（gateway-core 为事实源，签名后经 GET /routes 下发）。
type RouteTable struct {
	Version   int          `json:"version"`
	UpdatedAt int64        `json:"updated_at"`
	Routes    []TableRoute `json:"routes"`
	Signature []byte       `json:"signature"` // HMAC over canonical(version||updatedAt||routes)
}

// CanonicalBytes 生成不含签名的规范字节序列，用于签发/验签。
// 字段顺序固定，保证 gateway-core 与插件两侧 marshal 一致。
func (t *RouteTable) CanonicalBytes() ([]byte, error) {
	payload := struct {
		Version   int          `json:"version"`
		UpdatedAt int64        `json:"updated_at"`
		Routes    []TableRoute `json:"routes"`
	}{t.Version, t.UpdatedAt, t.Routes}
	return json.Marshal(payload)
}

// SignTable 对路由表签名并写入 Signature 字段。同一 Signer（K_rx）。
func (s *Signer) SignTable(t *RouteTable) error {
	canon, err := t.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("route: 路由表编码失败: %w", err)
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(canon)
	t.Signature = mac.Sum(nil)
	return nil
}

// VerifyTable 校验路由表签名，返回是否有效。
func (s *Signer) VerifyTable(t *RouteTable) bool {
	canon, err := t.CanonicalBytes()
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, s.key)
	_, _ = mac.Write(canon)
	return hmac.Equal(t.Signature, mac.Sum(nil))
}

// Lookup 在路由表中按 tenant+model 精确查找；未命中返回 nil。
func (t *RouteTable) Lookup(tenant, model string) *TableRoute {
	for i := range t.Routes {
		r := &t.Routes[i]
		if r.Tenant == tenant && r.Model == model {
			return r
		}
	}
	return nil
}

// NewRouteTable 构造路由表并返回空实例（routing 由调用方填充）。
func NewRouteTable(version int, nowUnix int64) *RouteTable {
	return &RouteTable{Version: version, UpdatedAt: nowUnix, Routes: []TableRoute{}}
}