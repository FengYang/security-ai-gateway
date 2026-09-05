// Package mcpguard: MCP 工具调用安全治理引擎（Step 2，TEE 内决策，纯逻辑可单测）。
//
// 职责（对齐《GA-MCP安全治理设计 v1.1》FR1/FR2/FR5 与评审 S-2/A-2/A-3/D-1/D-2/O-3）：
//   - policycache：策略/目录已验签缓存 + 防回滚（A-2/O-3：拉为主 + 签名 seed 热带）；
//   - rbac：租户×工具授权（默认 deny，FR1）；
//   - schema：工具参数强校验（JSON Schema 子集，FR2）；
//   - sanitize：敏感字段三态 mask|block|strip（S-5）；
//   - engine：编排全流程 → Decision（含绑 tenant+reqID 的 MCPParamsHash，S-2）。
//
// 值级 Guardrail（注入/SQL/PII 检索）与双向流接线在 tee-infer 主包（Step 3）完成，
// 本包不依赖主包，独立可单测。
package mcpguard

import (
	"sync"

	"security-ai-gateway/gateway/mcpsec"
)

// PolicyCache 工具目录 + 授权策略的只读缓存（写仅由拉取/更新触发）。
// 规则：签名无效拒绝；版本 < 当前拒绝（防回滚，A-2）；否则替换为更高版本。
type PolicyCache struct {
	mu    sync.RWMutex
	sig   *mcpsec.Signer
	cat   *mcpsec.ToolCatalog
	pol   *mcpsec.RBACPolicy
	ready bool // 存在有效种子（O-3：由签名 seed 热带进镜像启动即置）
}

// NewCache 构造缓存并注入验签密钥（与 gateway-core 同一 K_rx）。
func NewCache(key []byte) (*PolicyCache, error) {
	sig, err := mcpsec.NewSigner(key)
	if err != nil {
		return nil, err
	}
	return &PolicyCache{sig: sig}, nil
}

// UpdateCatalog 用签名目录更新缓存（版本单调，验签失败拒新）。
func (c *PolicyCache) UpdateCatalog(t *mcpsec.ToolCatalog) bool {
	if t == nil || !c.sig.ValidCatalog(t) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cat != nil && t.Version < c.cat.Version {
		return false
	}
	c.cat = t
	if t.Version > 0 {
		c.ready = true
	}
	return true
}

// UpdatePolicy 用签名策略更新缓存（同样版本单调）。
func (c *PolicyCache) UpdatePolicy(p *mcpsec.RBACPolicy) bool {
	if p == nil || !c.sig.ValidPolicy(p) {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.pol != nil && p.Version < c.pol.Version {
		return false
	}
	c.pol = p
	if p.Version > 0 {
		c.ready = true
	}
	return true
}

// Ready 返回是否已持有有效策略（O-3 就绪门控依据；冷启动未就绪应 503）。
func (c *PolicyCache) Ready() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.ready
}

// Catalog 返回当前目录（只读引用）。
func (c *PolicyCache) Catalog() *mcpsec.ToolCatalog {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.cat
}

// Policy 返回当前策略（只读引用）。
func (c *PolicyCache) Policy() *mcpsec.RBACPolicy {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.pol
}

// Version 返回当前最高目录+策略版本（0 = 未就绪）。
func (c *PolicyCache) Version() (catVersion, polVersion int) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.cat != nil {
		catVersion = c.cat.Version
	}
	if c.pol != nil {
		polVersion = c.pol.Version
	}
	return
}