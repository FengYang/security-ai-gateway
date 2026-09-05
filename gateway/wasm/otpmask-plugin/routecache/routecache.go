// Package routecache: 网关 wasm 数据面（otpmask 插件）的默认路由表本地缓存。
//
// 职责（拉路径 L2 / 冷启动 L3）：
//   - 保存经 gateway-core 签名下发的 RouteTable；
//   - 只接受签名有效、且版本不低于当前缓存的表（防回滚/防篡改）；
//   - 提供 O(1) 的 tenant+model 查询，供"无处方/验签失败"时兜底路由。
//
// 本包为纯逻辑（无 envoy/wasm 运行时依赖），可独立单测；
// 周期拉取/OnTick 等调度在插件 main.go 侧接入（见 README 或设计文档 Step 2）。
package routecache

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"sync"
)

// TableRoute 路由表条目（与 gateway-core internal/route 的 JSON 对齐）。
type TableRoute struct {
	Tenant         string `json:"tenant"`
	Model          string `json:"model"`
	DefaultEngine  string `json:"default_engine"`
	FallbackEngine string `json:"fallback_engine,omitempty"`
	Target         string `json:"target,omitempty"`
}

// RouteTable 签名路由表（JSON 与网关侧对齐）。
type RouteTable struct {
	Version   int          `json:"version"`
	UpdatedAt int64        `json:"updated_at"`
	Routes    []TableRoute `json:"routes"`
	Signature []byte       `json:"signature"`
}

// canon 生成不含签名的规范字节，用于验签（与网关侧 CanonicalBytes 一致）。
func (t *RouteTable) canon() []byte {
	payload := struct {
		Version   int          `json:"version"`
		UpdatedAt int64        `json:"updated_at"`
		Routes    []TableRoute `json:"routes"`
	}{t.Version, t.UpdatedAt, t.Routes}
	b, _ := json.Marshal(payload)
	return b
}

// Verify 校验表签名（HMAC-SHA256），有效返回 true。失败时必须拒绝该表。
func Verify(key []byte, t *RouteTable) bool {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(t.canon())
	return hmac.Equal(t.Signature, mac.Sum(nil))
}

// Cache 内存路由缓存（读本地缓存、不写所有权状态；写操作仅由拉取/更新触发）。
type Cache struct {
	mu    sync.RWMutex
	key   []byte
	table *RouteTable // 当前生效表（最高已验签版本）
}

// New 构造缓存并注入验签密钥 K_rx（HMAC 对称）。
func New(key []byte) *Cache {
	return &Cache{key: key}
}

// Update 用签名路由表更新缓存。规则：
//   - 签名无效 → 拒绝（返回 false）；
//   - 版本 < 当前缓存 → 拒绝（防回滚）；
//   - 否则替换为更高版本。
func (c *Cache) Update(t *RouteTable) bool {
	if t == nil || !Verify(c.key, t) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.table != nil && t.Version < c.table.Version {
		return false
	}
	c.table = t
	return true
}

// Lookup 查询 tenant+model 的默认路由；未命中或缓存为空返回 nil。
func (c *Cache) Lookup(tenant, model string) *TableRoute {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.table == nil {
		return nil
	}
	for i := range c.table.Routes {
		r := &c.table.Routes[i]
		if r.Tenant == tenant && r.Model == model {
			return r
		}
	}
	return nil
}

// Version 返回当前缓存版本（0 = 未初始化）。
func (c *Cache) Version() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.table == nil {
		return 0
	}
	return c.table.Version
}

// Decision 一次路由决策的结果（引擎标识 + 可选显式目标）。
type Decision struct {
	Engine string // 目标引擎标识，如 cmaas / vllm
	Target string // 可选：显式目标端点；空 = 由调用方映射
}

// Decide 执行路由决策，合并推拉两路径（§6 降级语义）：
//   - rxEngine：处方（推路径 L1）显式指定的引擎，优先采用；
//   - 否则回退缓存默认路由表（拉路径 L2）的 default_engine/target；
//   - 都不命中返回零值，由调用方用 config 默认（单 target 兼容）。
func (c *Cache) Decide(tenant, model, rxEngine string) Decision {
	if rxEngine != "" {
		return Decision{Engine: rxEngine}
	}
	if r := c.Lookup(tenant, model); r != nil {
		return Decision{Engine: r.DefaultEngine, Target: r.Target}
	}
	return Decision{}
}