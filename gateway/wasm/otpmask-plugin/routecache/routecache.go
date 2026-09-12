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
	"time"
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

// Options 缓存行为选项（不设 = 保持既有默认语义）。
type Options struct {
	// MaxStale > 0：缓存表的 UpdatedAt 早于 now-MaxStale 即视为**失效**
	// （Decide 按未命中处理，由调用方走密态 fail-closed，而不是静默使用陈旧路由）。
	// MaxStale <= 0：永不过期，与设计 §6 原文"接受旧版本继续用（可用性优先）"一致。
	MaxStale time.Duration
	// Now 时间源（默认 time.Now；测试可注入）。
	Now func() time.Time
}

// Cache 内存路由缓存（读本地缓存、不写所有权状态；写操作仅由拉取/更新触发）。
type Cache struct {
	mu       sync.RWMutex
	key      []byte
	table    *RouteTable // 当前生效表（最高已验签版本）
	maxStale time.Duration
	now      func() time.Time
}

// New 构造缓存并注入验签密钥 K_rx（HMAC 对称），默认永不过期。
func New(key []byte) *Cache {
	return NewWithOptions(key, Options{})
}

// NewWithOptions 构造缓存（带过期阈值/时间源）。
func NewWithOptions(key []byte, opt Options) *Cache {
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	return &Cache{key: key, maxStale: opt.MaxStale, now: now}
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

// stale 判断当前缓存是否已超过 MaxStale（MaxStale<=0 = 永不过期）。
func (c *Cache) stale() bool {
	if c.maxStale <= 0 {
		return false
	}
	c.mu.RLock()
	tbl := c.table
	c.mu.RUnlock()
	if tbl == nil {
		return false
	}
	return c.now().Sub(time.Unix(tbl.UpdatedAt, 0)) > c.maxStale
}

// DecisionSource 路由决策来源（对应设计 §6 的推/拉阶梯）。
type DecisionSource string

const (
	// SourceNone L1 与 L2 均未命中 → 调用方按模式处理（密态 fail-closed / 测试模式静态直连）。
	SourceNone DecisionSource = "none"
	// SourcePrescription 处方（推路径 L1）。
	SourcePrescription DecisionSource = "L1_prescription"
	// SourceCache 默认路由表缓存（拉路径 L2）——属降级。
	SourceCache DecisionSource = "L2_cache"
)

// Decision 一次路由决策的结果。
type Decision struct {
	Engine string         // 目标引擎标识，如 cmaas / vllm
	Target string         // 可选：显式目标端点；空 = 由调用方映射
	Source DecisionSource // 决策来源（L1 / L2 / 无）
	// Degraded true = 本次走了 L2（处方缺失/失效），需记录降级事件（可观测）。
	Degraded bool
	// Stale true = 命中过缓存但已超 MaxStale，故按未命中返回（SourceNone）。
	Stale bool
}

// Decide 执行路由决策，合并推拉两路径（§6 降级语义）：
//   - rxEngine：处方（推路径 L1）显式指定的引擎，优先采用（不降级）；
//   - 否则查缓存默认路由表（拉路径 L2）的 default_engine/target（**降级**，需可观测）；
//   - 缓存超 MaxStale 视为未命中（Stale=true）；
//   - 都不命中返回 SourceNone，由调用方决定 fail-closed 或静态直连。
func (c *Cache) Decide(tenant, model, rxEngine string) Decision {
	if rxEngine != "" {
		return Decision{Engine: rxEngine, Source: SourcePrescription}
	}
	r := c.Lookup(tenant, model)
	if r == nil {
		return Decision{Source: SourceNone}
	}
	if c.stale() {
		return Decision{Source: SourceNone, Stale: true}
	}
	return Decision{Engine: r.DefaultEngine, Target: r.Target, Source: SourceCache, Degraded: true}
}
