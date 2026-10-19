// Package mcpsec: MCP 安全治理的共享数据模型与签名基础（Step 1）。
//
// 单一事实源：gateway-core（control plane）用它"签发"，tee-infer/mcpguard
// 用它"验签"，两侧共用同一 canonical 编码，杜绝签名/验签 canonical 双份漂移
// （对照 route 表曾因 wasm 无法 import 而需要在插件侧复制，此处 tee 为普通 Go
// 服务故不再复制）。
//
// 纯标准库、无运行时依赖，可被 gateway-core 与 tee-infer 同时 import。
package mcpsec

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
)

// SensitiveAction 敏感字段处理三态（评审 S-5）。
type SensitiveAction string

const (
	// SensMask 脱敏（片段替换，保留可展示语义）。
	SensMask SensitiveAction = "mask"
	// SensBlock 含敏感即拒绝。
	SensBlock SensitiveAction = "block"
	// SensStrip 移除字段不投递（适合 API key/凭据）。
	SensStrip SensitiveAction = "strip"
)

// 工具分轨（C-MCP-4 / §4.6.1）：public＝Higress MCP Server 非敏感轨（网关侧统一托管）；
// secure＝段①不透明透传 → TEE 内终结并裁决的敏感轨。
//
// **重签说明（C-10）**：为工具设置 `Track` 会改变目录 canonical（`Track` 带 omitempty，
// 仅非空时进 canonical）⇒ 该目录**必须重签**（`SignCatalog`），且 `Version` **单调递增**，
// 否则分发/验签侧 `ValidCatalog` 将拒之。
const (
	// TrackPublic 非敏感轨。
	TrackPublic = "public"
	// TrackSecure 敏感轨（缺省值）。
	TrackSecure = "secure"
)

// FieldConstraint 工具参数的强校验约束（JSON Schema 子集：type/required/pattern/whitelist）。
type FieldConstraint struct {
	Type           string          `json:"type,omitempty"` // string | number | boolean
	Pattern        string          `json:"pattern,omitempty"`
	Whitelist      []string        `json:"whitelist,omitempty"`
	InjectionGuard bool            `json:"injection_guard,omitempty"` // 值级注入检测（Step3 接 guardrail）
	Sensitive      SensitiveAction `json:"sensitive,omitempty"`       // 敏感处理三态
}

// TableTool 工具目录条目：**catalog_owner 仅目录归属，不参与授权判定**（评审 O-2）。
type TableTool struct {
	Name              string                      `json:"name"`
	CatalogOwner      string                      `json:"catalog_owner"`
	Track             string                      `json:"track,omitempty"`     // "public"|"secure"；空值视同 secure（fail-closed）；消费点须经 ToolTrack()
	Transport         string                      `json:"transport,omitempty"` // 对应明文域 MCP Server
	Schema            map[string]*FieldConstraint `json:"schema,omitempty"`
	Required          []string                    `json:"required,omitempty"`
	ResponseSensitive []string                    `json:"response_sensitive,omitempty"` // 响应脱敏字段名（Step3）
	// T-3 目录模型扩展（变更要求，C-MCP-1/C-MCP-3 同步；P2-1 §6.2）：
	Server    string `json:"server,omitempty"`    // 后端注册 id（gateway-core /tools/servers；空 = 未登记来源）
	Namespace string `json:"namespace,omitempty"` // 命名空间（缺省由控制面以 server 前缀命名空间化补全）
}

// ToolTrack 返回工具的有效分轨：空值 ⇒ secure（fail-closed）。
// 消费点**统一经此读取**，禁止直读 Track 字段（保证缺省语义单点）。
func (t TableTool) ToolTrack() string {
	if t.Track == "" {
		return TrackSecure
	}
	return t.Track
}

// NamespacedName 命名空间名：Namespace 非空 ⇒ "<namespace>__<name>"，否则裸名。
// T-3 口径（对齐 C-MCP-1 §6.3 D-3/A-1）：`__` 分隔、访问器命名 NamespacedName()（**禁** Name()）；
// Namespace 不含 `_`（控制面校验）⇒ 首个 `__` 即分隔符，命名空间名可无歧义解析。
// 命名空间缺省以注册域 server 前缀补全；同名冲突裁决按命名空间名去重
// （U-5 默认：前缀命名空间 + 校验拒绝冲突）。
func (t TableTool) NamespacedName() string {
	if t.Namespace == "" {
		return t.Name
	}
	return t.Namespace + "__" + t.Name
}

// CatalogServer 目录内后端摘要（T-3 变更要求：id/baseUrl 摘要/track/prefix；**不含凭据**
// ——baseUrl 已在控制面规范化，禁 userinfo/query/fragment）。Track 空值视同 secure（同工具口径）。
type CatalogServer struct {
	ID      string `json:"id"`
	BaseURL string `json:"base_url,omitempty"`
	Track   string `json:"track,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
}

// ToolCatalog 工具目录（gateway-core 事实源，签名后经 GET /tools/policy 下发）。
type ToolCatalog struct {
	Version   int             `json:"version"`
	UpdatedAt int64           `json:"updated_at"`
	Tools     []TableTool     `json:"tools"`
	Servers   []CatalogServer `json:"servers"`             // T-3：后端摘要（进签名域；非 omitempty 保持 JSON 往返 canonical 稳定）
	Signature []byte          `json:"signature,omitempty"` // HMAC over canonical
}

// PolicyBinding 一条放行规则的附加约束（nil/空 = 仅放行无附加限制）。
type PolicyBinding struct {
	DenyParams []string `json:"deny_params,omitempty"`
}

// RBACPolicy 租户×工具授权策略（MVP 单层 allowing-list，default deny 隐含）。
// TenantRules[tenant][tool]：键存在即放行，值可为绑定（附带约束）。
type RBACPolicy struct {
	Version     int                                  `json:"version"`
	UpdatedAt   int64                                `json:"updated_at"`
	TenantRules map[string]map[string]*PolicyBinding `json:"tenant_rules"`
	Signature   []byte                               `json:"signature,omitempty"`
}

// Signer 对称签名器（HMAC-SHA256，与路由签名同族的对称密钥）。
type Signer struct {
	key []byte
}

// NewSigner 构造签名器；key 至少 32 字节。
func NewSigner(key []byte) (*Signer, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("mcpsec: 签名密钥长度 %d < 32", len(key))
	}
	return &Signer{key: key}, nil
}

// CanonicalBytes 生成不含签名的规范字节，供签发/验签（两侧共用同一实现，天然一致）。
// T-3：Servers 摘要并入签名域（重签生效，版本单调）；Servers 与 Tools 同口径**非
// omitempty**——JSON 往返后空切片不退化（[]≠null），canonical 稳定。
func (c *ToolCatalog) CanonicalBytes() ([]byte, error) {
	return canonicalBytes(c.Version, c.UpdatedAt, c.Tools, c.Servers)
}

// Sign 对目录签名并写入 Signature。
func (s *Signer) SignCatalog(c *ToolCatalog) error {
	canon, err := c.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("mcpsec: 目录编码失败: %w", err)
	}
	c.Signature = sign(s.key, canon)
	return nil
}

// ValidCatalog 校验目录：分轨字段合法 **且** 签名有效。
func (s *Signer) ValidCatalog(c *ToolCatalog) bool {
	if !validTracks(c) {
		return false
	}
	canon, err := c.CanonicalBytes()
	if err != nil {
		return false
	}
	return verify(s.key, canon, c.Signature)
}

// validTracks 校验分轨合法性：空值合法（＝缺省 secure）；非空必须 ∈ {public,secure}。
// T-3：同时覆盖工具条目与 servers[] 摘要（两处同口径）。
func validTracks(c *ToolCatalog) bool {
	for i := range c.Tools {
		switch c.Tools[i].Track {
		case "", TrackPublic, TrackSecure:
		default:
			return false
		}
	}
	for i := range c.Servers {
		switch c.Servers[i].Track {
		case "", TrackPublic, TrackSecure:
		default:
			return false
		}
	}
	return true
}

// CanonicalBytes 生成不含签名的规范字节。
func (p *RBACPolicy) CanonicalBytes() ([]byte, error) {
	return canonicalBytes(p.Version, p.UpdatedAt, p.TenantRules)
}

// Sign 对策略签名并写入 Signature。
func (s *Signer) SignPolicy(p *RBACPolicy) error {
	canon, err := p.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("mcpsec: 策略编码失败: %w", err)
	}
	p.Signature = sign(s.key, canon)
	return nil
}

// Valid 校验策略签名。
func (s *Signer) ValidPolicy(p *RBACPolicy) bool {
	canon, err := p.CanonicalBytes()
	if err != nil {
		return false
	}
	return verify(s.key, canon, p.Signature)
}

// canonicalBytes 任意可 JSON 序列化值的规范编码。字段顺序固定于结构体 tag，
// map 键由 encoding/json 按字典序排序 → 确定性；omitempty 字段缺失时两侧一致。
func canonicalBytes(values ...any) ([]byte, error) {
	return json.Marshal(values)
}

// sign 计算 MAC（经 cryptop：intl=HMAC-SHA256，逐字节等价现役实现；sm=HMAC-SM3）。
func sign(key, data []byte) []byte {
	return cryptoProvider.HMAC(key, data)
}

// verify 常量时间比对签名。
func verify(key, data, sig []byte) bool {
	return subtle.ConstantTimeCompare(sig, sign(key, data)) == 1
}

// NewToolCatalog 构造空目录（空切片而非 nil：canonical 确定性，T-3 servers[] 同口径）。
func NewToolCatalog(version int, nowUnix int64) *ToolCatalog {
	return &ToolCatalog{Version: version, UpdatedAt: nowUnix, Tools: []TableTool{}, Servers: []CatalogServer{}}
}

// NewRBACPolicy 构造空策略（默认 deny：无规则即拒绝）。
func NewRBACPolicy(version int, nowUnix int64) *RBACPolicy {
	return &RBACPolicy{Version: version, UpdatedAt: nowUnix, TenantRules: map[string]map[string]*PolicyBinding{}}
}
