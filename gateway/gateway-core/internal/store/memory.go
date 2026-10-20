// Package store: gateway-core 的持久化抽象。MVP 用内存，后续可切 Redis/DB。
package store

import (
	"errors"
	"sort"
	"sync"

	"security-ai-gateway/gateway/a2aproxy"
	"security-ai-gateway/gateway/gateway-core/internal/mcpsrv"
	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/mcpsec"
)

// Store 处方存储抽象：MVP 最小集，均全局单实例，安全用读写锁。
type Store interface {
	// Save 保存一张已签发的处方。
	Save(p *route.RoutePrescription) error
	// Get 按 prescriptionID 查询。
	Get(id string) (*route.RoutePrescription, bool)
	// Delete 吊销一张处方。
	Delete(id string)
	// ListByTenant 列出租户下所有处方（含过期，供审计/清理）。
	ListByTenant(tenant string) []*route.RoutePrescription
	// SaveRouteTable 保存签名后的默认路由表。
	SaveRouteTable(t *route.RouteTable)
	// GetRouteTable 返回当前默认路由表。
	GetRouteTable() *route.RouteTable
	// SaveRateLimitTable 保存签名后的限流/预算表（Phase 1 门禁 #7）。
	SaveRateLimitTable(t *ratelimit.Table)
	// GetRateLimitTable 返回当前限流/预算表。
	GetRateLimitTable() *ratelimit.Table
	// SaveACLTable 保存签名后的 A2A ACL 表（P2-2 T-3；独立策略域，R-6）。
	SaveACLTable(t *a2aproxy.ACLTable)
	// GetACLTable 返回当前 A2A ACL 表。
	GetACLTable() *a2aproxy.ACLTable
	// SaveA2ARateLimitTable 保存签名后的 A2A 复合限流表（P2-2 T-3a；独立策略域，R-6）。
	SaveA2ARateLimitTable(t *a2aproxy.RateLimitTable)
	// GetA2ARateLimitTable 返回当前 A2A 复合限流表。
	GetA2ARateLimitTable() *a2aproxy.RateLimitTable
	// SaveToolCatalog 保存签名后的工具目录。
	SaveToolCatalog(c *mcpsec.ToolCatalog)
	// GetToolCatalog 返回当前工具目录。
	GetToolCatalog() *mcpsec.ToolCatalog
	// SaveRBACPolicy 保存签名后的授权策略。
	SaveRBACPolicy(p *mcpsec.RBACPolicy)
	// GetRBACPolicy 返回当前授权策略。
	GetRBACPolicy() *mcpsec.RBACPolicy
	// T-3 联邦目录治理：MCP 后端注册域（gateway-core /tools/servers*）。
	// SaveMCPServer 保存/更新后端注册条目（按 id upsert）。
	SaveMCPServer(sv *mcpsrv.Server)
	// GetMCPServer 按 id 查询（不存在返回 nil）。
	GetMCPServer(id string) *mcpsrv.Server
	// ListMCPServers 列出全部后端注册（id 字典序，确定性输出）。
	ListMCPServers() []*mcpsrv.Server
	// DeleteMCPServer 摘除注册；存在返回 true。
	DeleteMCPServer(id string) bool
}

// ErrDup 处方已存在。
var ErrDup = errors.New("store: 处方已存在")

// Memory 内存实现（MVP）。进程重启丢失，处方量少，重启重发即可。
type Memory struct {
	mu             sync.RWMutex
	byID           map[string]*route.RoutePrescription
	byT            map[string][]string // tenant → prescriptionID 列表
	routeTable     *route.RouteTable
	rateLimitTable *ratelimit.Table
	aclTable       *a2aproxy.ACLTable       // P2-2 T-3：A2A ACL 策略表
	a2aRLTable     *a2aproxy.RateLimitTable // P2-2 T-3a：A2A 复合限流表
	toolCatalog    *mcpsec.ToolCatalog
	rbacPolicy     *mcpsec.RBACPolicy
	mcpServers     map[string]*mcpsrv.Server // T-3：后端注册域
}

// NewMemory 构造内存存储。
func NewMemory() *Memory {
	return &Memory{
		byID:       make(map[string]*route.RoutePrescription),
		byT:        make(map[string][]string),
		mcpServers: make(map[string]*mcpsrv.Server),
	}
}

// Save 实现 Store。同 ID 重复保存返回 ErrDup。
func (m *Memory) Save(p *route.RoutePrescription) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.byID[p.PrescriptionID]; ok {
		return ErrDup
	}
	m.byID[p.PrescriptionID] = p
	m.byT[p.Tenant] = append(m.byT[p.Tenant], p.PrescriptionID)
	return nil
}

// Get 实现 Store。
func (m *Memory) Get(id string) (*route.RoutePrescription, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.byID[id]
	return p, ok
}

// Delete 实现 Store。
func (m *Memory) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	p, ok := m.byID[id]
	if !ok {
		return
	}
	delete(m.byID, id)
	ids := m.byT[p.Tenant]
	for i, v := range ids {
		if v == id {
			m.byT[p.Tenant] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
}

// ListByTenant 实现 Store。
func (m *Memory) ListByTenant(tenant string) []*route.RoutePrescription {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := m.byT[tenant]
	out := make([]*route.RoutePrescription, 0, len(ids))
	for _, id := range ids {
		if p, ok := m.byID[id]; ok {
			out = append(out, p)
		}
	}
	return out
}

// SaveRouteTable 实现 Store。
func (m *Memory) SaveRouteTable(t *route.RouteTable) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.routeTable = t
}

// GetRouteTable 实现 Store。
func (m *Memory) GetRouteTable() *route.RouteTable {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.routeTable
}

// SaveRateLimitTable 实现 Store。
func (m *Memory) SaveRateLimitTable(t *ratelimit.Table) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rateLimitTable = t
}

// GetRateLimitTable 实现 Store。
func (m *Memory) GetRateLimitTable() *ratelimit.Table {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rateLimitTable
}

// SaveACLTable 实现 Store。
func (m *Memory) SaveACLTable(t *a2aproxy.ACLTable) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.aclTable = t
}

// GetACLTable 实现 Store。
func (m *Memory) GetACLTable() *a2aproxy.ACLTable {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.aclTable
}

// SaveA2ARateLimitTable 实现 Store。
func (m *Memory) SaveA2ARateLimitTable(t *a2aproxy.RateLimitTable) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.a2aRLTable = t
}

// GetA2ARateLimitTable 实现 Store。
func (m *Memory) GetA2ARateLimitTable() *a2aproxy.RateLimitTable {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.a2aRLTable
}

// SaveToolCatalog 实现 Store。
func (m *Memory) SaveToolCatalog(c *mcpsec.ToolCatalog) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.toolCatalog = c
}

// GetToolCatalog 实现 Store。
func (m *Memory) GetToolCatalog() *mcpsec.ToolCatalog {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.toolCatalog
}

// SaveRBACPolicy 实现 Store。
func (m *Memory) SaveRBACPolicy(p *mcpsec.RBACPolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rbacPolicy = p
}

// GetRBACPolicy 实现 Store。
func (m *Memory) GetRBACPolicy() *mcpsec.RBACPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rbacPolicy
}

// SaveMCPServer 实现 Store。
func (m *Memory) SaveMCPServer(sv *mcpsrv.Server) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.mcpServers[sv.ID] = sv
}

// GetMCPServer 实现 Store。
func (m *Memory) GetMCPServer(id string) *mcpsrv.Server {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mcpServers[id]
}

// ListMCPServers 实现 Store。
func (m *Memory) ListMCPServers() []*mcpsrv.Server {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*mcpsrv.Server, 0, len(m.mcpServers))
	for _, sv := range m.mcpServers {
		out = append(out, sv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// DeleteMCPServer 实现 Store。
func (m *Memory) DeleteMCPServer(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.mcpServers[id]; !ok {
		return false
	}
	delete(m.mcpServers, id)
	return true
}
