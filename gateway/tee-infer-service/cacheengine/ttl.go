package cacheengine

import "time"

// TTLResolver TTL 维度覆盖解析器。
// 按优先级：租户 > 模型 > 场景 > 默认
type TTLResolver struct {
	cfg *CacheConfig
}

// NewTTLResolver 构造 TTL 解析器。
func NewTTLResolver(cfg *CacheConfig) *TTLResolver {
	return &TTLResolver{cfg: cfg}
}

// TTLFor 解析条目的实际 TTL（纯函数，无 IO）。
// 写入时求值并固化到 Entry.ExpireAt，读时不重算。
func (r *TTLResolver) TTLFor(ctx StoreContext) time.Duration {
	if r.cfg == nil {
		return 3600 * time.Second
	}
	def := r.cfg.Exact.TTL

	var cands []time.Duration
	add := func(v time.Duration, ok bool) {
		if ok {
			cands = append(cands, v)
		}
	}

	// 优先级 1：租户
	if v, ok := r.lookupDuration(r.cfg.TTLPolicy.ByTenant, ctx.TenantID); ok {
		add(v, true)
	}
	// 优先级 2：模型
	if v, ok := r.lookupDuration(r.cfg.TTLPolicy.ByModel, ctx.Model); ok {
		add(v, true)
	}
	// 优先级 3：场景
	if v, ok := r.lookupDuration(r.cfg.TTLPolicy.ByScene, string(ctx.Scene)); ok {
		add(v, true)
	}

	if r.cfg.TTLPolicy.Resolution == "min" {
		m := def
		for _, c := range cands {
			if c < m {
				m = c
			}
		}
		return m
	}

	// specific_first：取第一个命中（按上面的优先级顺序添加，第一个即最高优先级）
	if len(cands) > 0 {
		return cands[0]
	}
	return def
}

// lookupDuration 从 map 中查找 duration 字符串并解析。
func (r *TTLResolver) lookupDuration(m map[string]string, key string) (time.Duration, bool) {
	if m == nil {
		return 0, false
	}
	// 先查具名 key
	if v, ok := m[key]; ok {
		d, err := time.ParseDuration(v)
		if err == nil && d >= time.Second {
			return d, true
		}
	}
	// 再查通配
	if v, ok := m["*"]; ok {
		d, err := time.ParseDuration(v)
		if err == nil && d >= time.Second {
			return d, true
		}
	}
	return 0, false
}
