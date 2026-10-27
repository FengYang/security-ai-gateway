package confllm

import (
	"fmt"
	"sync"
)

// Registry 编译期/运行期注册表（§2 registry.go）。
type Registry struct {
	mu     sync.RWMutex
	byID   map[string]ConfidentialLLMProvider
	byType map[string]ProviderFactory
}

// NewRegistry 构造空注册表。
func NewRegistry() *Registry {
	return &Registry{
		byID:   make(map[string]ConfidentialLLMProvider),
		byType: make(map[string]ProviderFactory),
	}
}

// Register 注册一个运行期实例（按 ID 查表，handler 经 Lookup 取用）。
func (r *Registry) Register(p ConfidentialLLMProvider) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byID[p.ID()] = p
}

// RegisterType 注册一个类型工厂（init() 插件约定，admin-service 经 NewFromConfig 装配）。
func (r *Registry) RegisterType(t string, f ProviderFactory) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byType[t] = f
}

// Lookup 按 providerID 取运行期实例。
func (r *Registry) Lookup(id string) (ConfidentialLLMProvider, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.byID[id]
	return p, ok
}

// All 返回全部运行期实例（health 聚合用）。
func (r *Registry) All() []ConfidentialLLMProvider {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ConfidentialLLMProvider, 0, len(r.byID))
	for _, p := range r.byID {
		out = append(out, p)
	}
	return out
}

// NewFromConfig 按 cfg.Type 查找工厂并构造实例（admin-service 装配入口）。
func (r *Registry) NewFromConfig(cfg ProviderConfig, opts ...ProviderOption) (ConfidentialLLMProvider, error) {
	if cfg.Type == "" {
		return nil, fmt.Errorf("ProviderConfig.Type 为空，无法选择工厂")
	}
	r.mu.RLock()
	f, ok := r.byType[cfg.Type]
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("未注册 provider 类型 %q", cfg.Type)
	}
	return f(cfg, opts...)
}

// GlobalRegistry 全局注册表（各 provider 的 init() 向其注册工厂）。
var GlobalRegistry = NewRegistry()
