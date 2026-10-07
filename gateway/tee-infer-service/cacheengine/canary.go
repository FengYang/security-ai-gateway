package cacheengine

import (
	"crypto/sha256"
)

// CanaryController 灰度发布控制器（§12.4）。
// 与缓存引擎解耦：只回答"某请求在本阶段是否启用缓存"，不持有 Engine 引用。
type CanaryController interface {
	// Allow 判定本次请求是否在灰度范围内（allow），以及是否"只写不读"（writeOnly，G-0 影子）。
	Allow(tenant string, scene SceneClass, model string) (allow bool, writeOnly bool)

	// Stage 返回当前灰度阶段（G-0..G-5；用于 #36 指标与审计）。
	Stage() string

	// Enabled 灰度是否开启（§12.4 之外的必要补充：仅用于 #36 指标发射门控）。
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
	return c.cfg != nil && c.cfg.Gray.Enabled
}

// Stage 当前灰度阶段（缺省 G-0）。
func (c *configCanaryController) Stage() string {
	if c.cfg == nil || c.cfg.Gray.Stage == "" {
		return "G-0"
	}
	return c.cfg.Gray.Stage
}

// Allow 判定是否进入灰度（§12.4）。
// 未启用灰度 = 全量放行（仍受 mode 约束）；G-0 影子 = 只写不读；
// 维度优先级：租户白名单 ×（场景空或匹配） > 模型白名单 > 稳定流量百分比。
func (c *configCanaryController) Allow(tenant string, scene SceneClass, model string) (bool, bool) {
	if c.cfg == nil || !c.cfg.Gray.Enabled {
		return true, false
	}
	g := c.cfg.Gray
	if g.WriteOnly {
		return true, true // G-0 影子：全部写、一律不读
	}
	if contains(g.CanaryTenants, tenant) &&
		(len(g.CanaryScenes) == 0 || contains(g.CanaryScenes, string(scene))) {
		return true, false
	}
	if len(g.CanaryModels) > 0 && contains(g.CanaryModels, model) {
		return true, false
	}
	return c.hashBucket(tenant)%100 < g.TrafficPercent, false
}

// hashBucket 按租户 ID 稳定分桶（同一租户在同一配置版本内结论恒定，§12.4）。
func (c *configCanaryController) hashBucket(tenant string) int {
	h := sha256.Sum256([]byte(tenant))
	return int(h[0]) + int(h[1])<<8
}
