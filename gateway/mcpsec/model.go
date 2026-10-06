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
	Name             string                     `json:"name"`
	CatalogOwner     string                     `json:"catalog_owner"`
	Transport        string                     `json:"transport,omitempty"` // 对应明文域 MCP Server
	Schema           map[string]*FieldConstraint `json:"schema,omitempty"`
	Required         []string                   `json:"required,omitempty"`
	ResponseSensitive []string                  `json:"response_sensitive,omitempty"` // 响应脱敏字段名（Step3）
}

// ToolCatalog 工具目录（gateway-core 事实源，签名后经 GET /tools/policy 下发）。
type ToolCatalog struct {
	Version   int         `json:"version"`
	UpdatedAt int64       `json:"updated_at"`
	Tools     []TableTool `json:"tools"`
	Signature []byte      `json:"signature,omitempty"` // HMAC over canonical
}

// PolicyBinding 一条放行规则的附加约束（nil/空 = 仅放行无附加限制）。
type PolicyBinding struct {
	DenyParams []string `json:"deny_params,omitempty"`
}

// RBACPolicy 租户×工具授权策略（MVP 单层 allowing-list，default deny 隐含）。
// TenantRules[tenant][tool]：键存在即放行，值可为绑定（附带约束）。
type RBACPolicy struct {
	Version     int                             `json:"version"`
	UpdatedAt   int64                           `json:"updated_at"`
	TenantRules map[string]map[string]*PolicyBinding `json:"tenant_rules"`
	Signature   []byte                          `json:"signature,omitempty"`
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
func (c *ToolCatalog) CanonicalBytes() ([]byte, error) {
	return canonicalBytes(c.Version, c.UpdatedAt, c.Tools)
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

// Valid 校验目录签名。
func (s *Signer) ValidCatalog(c *ToolCatalog) bool {
	canon, err := c.CanonicalBytes()
	if err != nil {
		return false
	}
	return verify(s.key, canon, c.Signature)
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

// NewToolCatalog 构造空目录。
func NewToolCatalog(version int, nowUnix int64) *ToolCatalog {
	return &ToolCatalog{Version: version, UpdatedAt: nowUnix, Tools: []TableTool{}}
}

// NewRBACPolicy 构造空策略（默认 deny：无规则即拒绝）。
func NewRBACPolicy(version int, nowUnix int64) *RBACPolicy {
	return &RBACPolicy{Version: version, UpdatedAt: nowUnix, TenantRules: map[string]map[string]*PolicyBinding{}}
}