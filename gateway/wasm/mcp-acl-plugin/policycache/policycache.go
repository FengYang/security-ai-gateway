// Package policycache: mcp-acl 插件（网关侧工具级 ACL，P2-1 T-4）的数据面缓存。
//
// 职责（本体 §6.3/§7.2）：
//   - 保存 gateway-core 签名下发的 RBACPolicy（tenant×tool 放行表）与 ToolCatalog
//     （工具元数据/命名空间/分轨摘要）；
//   - 只接受验签通过且版本不回退的对象（防篡改/防回滚，reason: bad_signature/replay/
//     too_large）；拉取失败一律**保留旧对象**；任一源从未拉到 → Decide 保守拒绝
//     （fail-closed，R-2）；
//   - Decide(tenant, tool)：`Mcp-Name` 头 × 租户 → RBAC 放行表 × 目录联合校验，
//     default deny；命名空间名优先、裸名回退（C-MCP-1 R-6 兼容窗口）。
//
// 纯逻辑包：无 hostcall / envoy 运行时依赖，验签经注入 Verifier 接缝（生产＝cryptop
// sidecar，§4.7；单测注入同步实现）。canonical 字节与 gateway/mcpsec 逐字节一致
// （单测对 mcpsec 断言，杜绝双份漂移）；硬约束：包内**零密码 import**
// （R-4 / `make wasm-guard`）。
package policycache

import (
	"encoding/json"
	"sync"
	"time"
)

// 工具分轨常量（与 mcpsec.TrackPublic/TrackSecure 同值；空值视同 secure，fail-closed）。
const (
	TrackPublic = "public"
	TrackSecure = "secure"
)

// ---- wire 模型（与 gateway/mcpsec 逐字段/逐 tag 对齐；任何差异即 canonical 漂移）----

// FieldConstraint 工具参数的强校验约束（本插件不消费，仅参与 canonical 编码）。
type FieldConstraint struct {
	Type           string   `json:"type,omitempty"`
	Pattern        string   `json:"pattern,omitempty"`
	Whitelist      []string `json:"whitelist,omitempty"`
	InjectionGuard bool     `json:"injection_guard,omitempty"`
	Sensitive      string   `json:"sensitive,omitempty"`
}

// TableTool 工具目录条目（catalog_owner 不参与授权判定，对齐 mcpsec 评审 O-2）。
type TableTool struct {
	Name              string                      `json:"name"`
	CatalogOwner      string                      `json:"catalog_owner"`
	Track             string                      `json:"track,omitempty"`
	Transport         string                      `json:"transport,omitempty"`
	Schema            map[string]*FieldConstraint `json:"schema,omitempty"`
	Required          []string                    `json:"required,omitempty"`
	ResponseSensitive []string                    `json:"response_sensitive,omitempty"`
	Server            string                      `json:"server,omitempty"`
	Namespace         string                      `json:"namespace,omitempty"`
}

// ToolTrack 有效分轨：空值视同 secure（与 mcpsec 同口径，fail-closed）。
func (t TableTool) ToolTrack() string {
	if t.Track == "" {
		return TrackSecure
	}
	return t.Track
}

// NamespacedName 命名空间名："<namespace>__<name>"；无命名空间为裸名（对齐 mcpsec）。
func (t TableTool) NamespacedName() string {
	if t.Namespace == "" {
		return t.Name
	}
	return t.Namespace + "__" + t.Name
}

// CatalogServer 目录内后端摘要。
type CatalogServer struct {
	ID      string `json:"id"`
	BaseURL string `json:"base_url,omitempty"`
	Track   string `json:"track,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
}

// ToolCatalog 工具目录（gateway-core 签发，GET /tools/policy?kind=catalog）。
type ToolCatalog struct {
	Version   int             `json:"version"`
	UpdatedAt int64           `json:"updated_at"`
	Tools     []TableTool     `json:"tools"`
	Servers   []CatalogServer `json:"servers"`
	Signature []byte          `json:"signature,omitempty"`
}

// CanonicalBytes 生成不含签名的规范字节（与 mcpsec.ToolCatalog.CanonicalBytes 逐字节等价：
// json.Marshal([version, updated_at, tools, servers])）。
func (c *ToolCatalog) CanonicalBytes() ([]byte, error) {
	return json.Marshal([]any{c.Version, c.UpdatedAt, c.Tools, c.Servers})
}

// PolicyBinding 放行规则的附加约束（本插件不消费 deny_params——参数级执行点在 TEE，R-6/D-3）。
type PolicyBinding struct {
	DenyParams []string `json:"deny_params,omitempty"`
}

// RBACPolicy 租户×工具授权策略（MVP 单层 allowing-list，default deny 隐含）。
type RBACPolicy struct {
	Version     int                                  `json:"version"`
	UpdatedAt   int64                                `json:"updated_at"`
	TenantRules map[string]map[string]*PolicyBinding `json:"tenant_rules"`
	Signature   []byte                               `json:"signature,omitempty"`
}

// CanonicalBytes 生成不含签名的规范字节（与 mcpsec.RBACPolicy.CanonicalBytes 逐字节等价：
// json.Marshal([version, updated_at, tenant_rules])）。
func (p *RBACPolicy) CanonicalBytes() ([]byte, error) {
	return json.Marshal([]any{p.Version, p.UpdatedAt, p.TenantRules})
}

// Verifier 签名校验接缝（与 otpmask routecache.Verifier 同型）：生产注入经 cryptop
// sidecar（/v1/hmac 出 MAC + 常量时间比较，密钥字节恒驻 sidecar）的实现；
// 单测注入同步实现。err 非空 = 校验不可用（调用方 fail-closed 拒绝该对象）。
type Verifier interface {
	VerifySym(keyRef string, data, sig []byte, cb func(ok bool, err error))
}

// Options 缓存行为选项。
type Options struct {
	// MaxStale > 0：对象 UpdatedAt 早于 now-MaxStale 即视为失效（Decide 拒绝，
	// reason=policy_stale；保守 fail-closed）。<=0 = 永不过期（失败保留旧策略，可用性优先）。
	MaxStale time.Duration
	// MaxSize > 0：单源对象估算上限（字节，canonical+signature 长度），超限拒绝
	// （防 DoS，保留旧对象）。<=0 = 不限制。
	MaxSize int
	// Now 时间源（测试注入；缺省 time.Now）。
	Now func() time.Time
	// OnReject 拒绝回调（source: policy|catalog；reason: bad_signature|replay|too_large）
	// 供指标/日志；在锁内同步触发。
	OnReject func(source, reason string, newVersion int)
}

// Cache 双源内存缓存（读本地缓存；写仅由拉取/更新触发）。
type Cache struct {
	mu       sync.RWMutex
	verifier Verifier
	keyRef   string
	maxStale time.Duration
	maxSize  int
	now      func() time.Time
	onReject func(source, reason string, newVersion int)

	policy  *RBACPolicy
	catalog *ToolCatalog
}

// New 构造缓存（默认选项）。
func New(verifier Verifier, keyRef string) *Cache {
	return NewWithOptions(verifier, keyRef, Options{})
}

// NewWithOptions 构造缓存（带过期阈值/大小限制/时间源/拒绝回调）。
func NewWithOptions(verifier Verifier, keyRef string, opt Options) *Cache {
	now := opt.Now
	if now == nil {
		now = time.Now
	}
	return &Cache{
		verifier: verifier,
		keyRef:   keyRef,
		maxStale: opt.MaxStale,
		maxSize:  opt.MaxSize,
		now:      now,
		onReject: opt.OnReject,
	}
}

// UpdatePolicy 用签名策略更新缓存。规则（按顺序，全部通过才接受）：
//  1. 签名无效 / 校验不可用 → 拒绝（reason=bad_signature）；
//  2. 版本 < 当前缓存 → 拒绝（防回滚，reason=replay）；
//  3. 大小超限 → 拒绝（防 DoS，reason=too_large）；
//  4. 否则替换（同版本重放允许：语义＝重认最新已签对象）。
func (c *Cache) UpdatePolicy(p *RBACPolicy, cb func(accepted bool)) {
	if p == nil || c.verifier == nil {
		c.reject("policy", "bad_signature", 0)
		cb(false)
		return
	}
	canon, err := p.CanonicalBytes()
	if err != nil {
		c.reject("policy", "bad_signature", p.Version)
		cb(false)
		return
	}
	size := len(canon) + len(p.Signature)
	c.verifier.VerifySym(c.keyRef, canon, p.Signature, func(ok bool, verr error) {
		if verr != nil || !ok {
			c.reject("policy", "bad_signature", p.Version)
			cb(false)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.policy != nil && p.Version < c.policy.Version {
			c.reject("policy", "replay", p.Version)
			cb(false)
			return
		}
		if c.maxSize > 0 && size > c.maxSize {
			c.reject("policy", "too_large", p.Version)
			cb(false)
			return
		}
		c.policy = p
		cb(true)
	})
}

// UpdateCatalog 用签名目录更新缓存（规则同 UpdatePolicy）。
func (c *Cache) UpdateCatalog(t *ToolCatalog, cb func(accepted bool)) {
	if t == nil || c.verifier == nil {
		c.reject("catalog", "bad_signature", 0)
		cb(false)
		return
	}
	canon, err := t.CanonicalBytes()
	if err != nil {
		c.reject("catalog", "bad_signature", t.Version)
		cb(false)
		return
	}
	size := len(canon) + len(t.Signature)
	c.verifier.VerifySym(c.keyRef, canon, t.Signature, func(ok bool, verr error) {
		if verr != nil || !ok {
			c.reject("catalog", "bad_signature", t.Version)
			cb(false)
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.catalog != nil && t.Version < c.catalog.Version {
			c.reject("catalog", "replay", t.Version)
			cb(false)
			return
		}
		if c.maxSize > 0 && size > c.maxSize {
			c.reject("catalog", "too_large", t.Version)
			cb(false)
			return
		}
		c.catalog = t
		cb(true)
	})
}

// PolicyVersion 当前策略版本（0 = 未加载；供拉取层同版本短路与可观测）。
func (c *Cache) PolicyVersion() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.policy == nil {
		return 0
	}
	return c.policy.Version
}

// CatalogVersion 当前目录版本（0 = 未加载）。
func (c *Cache) CatalogVersion() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.catalog == nil {
		return 0
	}
	return c.catalog.Version
}

// Loaded 双源均已加载（任一未加载 → Decide fail-closed）。
func (c *Cache) Loaded() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.policy != nil && c.catalog != nil
}

// Decision 授权判定结果（Reason 仅入日志/指标，**不写入响应**——统一 -32602 防 oracle）。
type Decision struct {
	Allow  bool
	Reason string // policy_unavailable|policy_stale|missing_tenant|missing_name|not_in_catalog|track_denied|not_granted
}

// Decide 执行 `Mcp-Name` × 租户的联合校验（default deny）。
// 判定顺序与 fail-closed 语义见 Decision.Reason 枚举；本函数不读 body（R-6/D-3）。
func (c *Cache) Decide(tenant, name string) Decision {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.policy == nil || c.catalog == nil {
		return Decision{Reason: "policy_unavailable"}
	}
	if c.staleLocked() {
		return Decision{Reason: "policy_stale"}
	}
	if tenant == "" {
		return Decision{Reason: "missing_tenant"}
	}
	if name == "" {
		return Decision{Reason: "missing_name"}
	}
	tool := findTool(c.catalog, name)
	if tool == nil {
		return Decision{Reason: "not_in_catalog"}
	}
	if tool.ToolTrack() != TrackPublic {
		return Decision{Reason: "track_denied"}
	}
	rules := c.policy.TenantRules[tenant]
	if len(rules) == 0 {
		return Decision{Reason: "not_granted"}
	}
	if _, ok := rules[tool.NamespacedName()]; ok {
		return Decision{Allow: true}
	}
	// R-6 兼容窗口：命名空间名未命中时回退裸名（发行端命名空间化前的旧策略）。
	if _, ok := rules[tool.Name]; ok {
		return Decision{Allow: true}
	}
	return Decision{Reason: "not_granted"}
}

// staleLocked 判断任一已加载对象是否超过 MaxStale（MaxStale<=0 = 永不过期）。
func (c *Cache) staleLocked() bool {
	if c.maxStale <= 0 {
		return false
	}
	now := c.now()
	if c.policy != nil && now.Sub(time.Unix(c.policy.UpdatedAt, 0)) > c.maxStale {
		return true
	}
	if c.catalog != nil && now.Sub(time.Unix(c.catalog.UpdatedAt, 0)) > c.maxStale {
		return true
	}
	return false
}

// reject 安全触发拒绝回调（nil 保护）。
func (c *Cache) reject(source, reason string, newVersion int) {
	if c.onReject != nil {
		c.onReject(source, reason, newVersion)
	}
}

// findTool 在目录中解析 Mcp-Name：命名空间名精确匹配优先；未命中回退裸名（R-6）。
// 多重命中（命名空间名冲突 / 裸名多重匹配；发行端已按 U-5 拒绝冲突，此处防御性保守）
// → 返回 nil（判 not_in_catalog 拒绝）。
func findTool(c *ToolCatalog, name string) *TableTool {
	var ns, bare *TableTool
	for i := range c.Tools {
		t := &c.Tools[i]
		if t.Namespace != "" && t.NamespacedName() == name {
			if ns != nil {
				return nil // 歧义：命名空间名多重命中
			}
			ns = t
			continue
		}
		if t.Name == name {
			if bare != nil {
				return nil // 歧义：裸名多重命中
			}
			bare = t
		}
	}
	if ns != nil {
		return ns
	}
	return bare
}
