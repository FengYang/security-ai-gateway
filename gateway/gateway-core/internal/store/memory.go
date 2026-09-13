// Package store: gateway-core 的持久化抽象。MVP 用内存，后续可切 Redis/DB。
package store

import (
	"errors"
	"sync"

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
	// SaveToolCatalog 保存签名后的工具目录。
	SaveToolCatalog(c *mcpsec.ToolCatalog)
	// GetToolCatalog 返回当前工具目录。
	GetToolCatalog() *mcpsec.ToolCatalog
	// SaveRBACPolicy 保存签名后的授权策略。
	SaveRBACPolicy(p *mcpsec.RBACPolicy)
	// GetRBACPolicy 返回当前授权策略。
	GetRBACPolicy() *mcpsec.RBACPolicy
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
	toolCatalog    *mcpsec.ToolCatalog
	rbacPolicy     *mcpsec.RBACPolicy
}

// NewMemory 构造内存存储。
func NewMemory() *Memory {
	return &Memory{byID: make(map[string]*route.RoutePrescription), byT: make(map[string][]string)}
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
