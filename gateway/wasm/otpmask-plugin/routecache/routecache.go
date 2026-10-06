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
	"encoding/json"
	"sync"
	"time"
)

// EndpointAuth 端点凭证配置（与 gateway-core internal/route 对齐）。
type EndpointAuth struct {
	Type      string `json:"type,omitempty"`       // 认证类型：bearer / apikey / none
	SecretRef string `json:"secret_ref,omitempty"` // 密钥引用：km://<path> / file://<path> / env://<name>
}

// TableEndpoint 路由表中的端点配置（P0-1 多端点权重路由）。
// 与 gateway-core internal/route 的 JSON 对齐（签名一致性依赖）。
type TableEndpoint struct {
	Name     string       `json:"name"`
	URL      string       `json:"url,omitempty"`
	Weight   float64      `json:"weight,omitempty"`
	Priority int          `json:"priority,omitempty"`
	Enabled  bool         `json:"enabled,omitempty"`
	Auth     EndpointAuth `json:"auth,omitempty"` // P0 端点凭证配置（§9.2）
}

// RouteCanary 灰度切流配置（与 gateway-core internal/route 对齐）。
type RouteCanary struct {
	Enabled            bool     `json:"enabled,omitempty"`
	TargetEndpoint     string   `json:"target_endpoint,omitempty"`
	TargetWeight       float64  `json:"target_weight,omitempty"`
	RampStep           float64  `json:"ramp_step,omitempty"`
	RampIntervalMs     int64    `json:"ramp_interval_ms,omitempty"`
	RollbackThreshold  float64  `json:"rollback_threshold,omitempty"`
	RollbackMinSamples int64    `json:"rollback_min_samples,omitempty"`
	AllowedTenants     []string `json:"allowed_tenants,omitempty"`
}

// TableRoute 路由表条目（与 gateway-core internal/route 的 JSON 对齐）。
type TableRoute struct {
	Tenant         string          `json:"tenant"`
	Model          string          `json:"model"`
	DefaultEngine  string          `json:"default_engine"`
	FallbackEngine string          `json:"fallback_engine,omitempty"`
	Target         string          `json:"target,omitempty"`
	Endpoints      []TableEndpoint `json:"endpoints,omitempty"` // P0-1 新增：多端点权重配置
	// P0-1 新增：多端点路由策略（priority/weighted/failure-aware）。空 = priority。
	// 与 gateway-core internal/route.TableRoute 的 JSON 严格对齐（签名一致性）。
	Strategy string      `json:"strategy,omitempty"`
	Canary   *RouteCanary `json:"canary,omitempty"` // P0-1 新增：灰度切流配置（§7.5）
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

// CanonicalBytes 导出规范字节（= canon），供**外部签发端/跨模块测试**构造签名
// （字段序与 gateway-core internal/route.CanonicalBytes 严格一致，签名一致性依赖于此）。
func (t *RouteTable) CanonicalBytes() []byte { return t.canon() }

// Verifier 表签名校验接缝（P0-4 §4.7 分层：本包为纯逻辑，**不 import 密码/hostcall**）。
//
// 插件注入经 cryptop sidecar（`/v1/hmac` 出 MAC + 常量时间比较，密钥字节恒驻 sidecar）的实现；
// 单测注入**同步**实现，令 CPS 调用同步完成（同 cryptoseam_test.go 手法）。
type Verifier interface {
	// VerifySym 校验 canon 字节 data 的对称 MAC sig（keyRef = K_rx 句柄，§6.3 命名）。
	// cb(ok, err)：err 非空 = 校验不可用（fail-closed，调用方须拒绝该表）。
	VerifySym(keyRef string, data, sig []byte, cb func(ok bool, err error))
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
	verifier Verifier
	keyRef   string
	table    *RouteTable // 当前生效表（最高已验签版本）
	maxStale time.Duration
	now      func() time.Time
}

// New 构造缓存并注入验签接缝 verifier 与 K_rx 句柄 keyRef（§4.7），默认永不过期。
func New(verifier Verifier, keyRef string) *Cache {
	return NewWithOptions(verifier, keyRef, Options{})
}

// NewWithOptions 构造缓存（带过期阈值/时间源）。
func NewWithOptions(verifier Verifier, keyRef string, opt Options) *Cache {
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	return &Cache{verifier: verifier, keyRef: keyRef, maxStale: opt.MaxStale, now: now}
}

// Update 用签名路由表更新缓存（CPS 交付：签名校验经 §4.7 注入的 verifier，proxy-wasm 无阻塞 HTTP）。
// 规则：
//   - 签名无效 / 校验不可用 → 拒绝（cb(false)）；
//   - 版本 < 当前缓存 → 拒绝（防回滚）；
//   - 否则替换为更高（或同）版本。
func (c *Cache) Update(t *RouteTable, cb func(accepted bool)) {
	if t == nil || c.verifier == nil {
		cb(false)
		return
	}
	c.verifier.VerifySym(c.keyRef, t.canon(), t.Signature, func(ok bool, err error) {
		if err != nil || !ok {
			cb(false)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.table != nil && t.Version < c.table.Version {
			cb(false)
			return
		}
		c.table = t
		cb(true)
	})
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
