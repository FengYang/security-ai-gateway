package cacheengine

import (
	"crypto/sha256"
)

// CanaryController 灰度发布控制器（§8）。
// 决定一次请求是否进入缓存路径（读/写）。
// 支持白名单（租户/场景/模型）+ 流量比例 + 只读/只写 模式。
type CanaryController interface {
	// Allowed 判断请求是否允许走缓存完整路径（读+写）。
	Allowed(ctx LookupContext) bool

	// WriteOnly 是否为只写模式（写入但不读取命中，用于预热/灰度观察）。
	WriteOnly() bool

	// Enabled 灰度是否开启。
	Enabled() bool
}

// configCanaryController 基于配置的灰度控制器（默认实现）。
type configCanaryController struct {
	cfg *CacheConfig
}

// NewConfigCanaryController 从配置构造默认灰度控制器。
func NewConfigCanaryController(cfg *CacheConfig) CanaryController {
	return &configCanaryController{cfg: cfg}
}

// Enabled 灰度是否开启。
func (c *configCanaryController) Enabled() bool {
	if c.cfg == nil {
		return false
	}
	return c.cfg.Gray.Enabled
}

// WriteOnly 是否只写模式。
func (c *configCanaryController) WriteOnly() bool {
	if c.cfg == nil {
		return false
	}
	return c.cfg.Gray.Enabled && c.cfg.Gray.WriteOnly
}

// Allowed 判定请求是否进入缓存路径。
// 优先级：白名单(租户/场景/模型) > 流量比例 > 默认拒绝。
func (c *configCanaryController) Allowed(ctx LookupContext) bool {
	if c.cfg == nil || !c.cfg.Gray.Enabled {
		return true
	}

	// 白名单：租户
	for _, t := range c.cfg.Gray.CanaryTenants {
		if t == ctx.TenantID {
			return true
		}
	}
	// 白名单：场景
	for _, s := range c.cfg.Gray.CanaryScenes {
		if s == string(ctx.Scene) {
			return true
		}
	}
	// 白名单：模型
	for _, m := range c.cfg.Gray.CanaryModels {
		if m == ctx.Model {
			return true
		}
	}

	// 流量比例：基于 tenant_id 的稳定 hash，保证同一租户始终在/不在灰度中
	if c.cfg.Gray.TrafficPercent > 0 {
		h := sha256.Sum256([]byte(ctx.TenantID))
		// 取 16 bit 做百分比
		val := int(h[0]) + int(h[1])<<8
		if val%100 < c.cfg.Gray.TrafficPercent {
			return true
		}
	}

	return false
}
