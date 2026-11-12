// router.go - 双路线路由配置
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"security-ai-gateway/protocol/go"
)

type RouteConfig struct {
	Tenant        map[string]TenantRoute `json:"tenant"`
	Model         map[string]ModelRoute  `json:"model"`
	DefaultEngine string                 `json:"default_engine"`
	RequireQuote  bool                   `json:"require_quote"`
	// Policy 成本优化路由策略（GF.3.3 / D-6）：""（缺省，声明序）/"cost"（价格）/
	// "latency"（延迟）/"quality"（质量）。仅影响候选引擎排序与 failover 顺序，
	// 不改变 ValidateRequest 的准入语义（引擎必须在模型支持列表内）。
	Policy string `json:"policy,omitempty"`
	// Placement 端/云落点扩展点（M9-1/M4-3，技术实现方案 §7.1；可选，缺省 = cloud，
	// 行为与现状一致。仅产出提示，不改变引擎列表语义；端/云动态调度不实现）。
	Placement *PlacementConfig `json:"placement,omitempty"`
}

type TenantRoute struct {
	Engine string `json:"engine"`
	Attest string `json:"attest"`
}

// EngineCost 引擎成本/性能元数据（GF.3.3 成本优化路由 D-6 的排序依据）。
// PricePer1K：¥/千 token（输入+输出综合口径）；LatencyP50：P50 延迟（ms）；
// Quality：0-100 相对质量分（越高越好）。三者按 Policy 择优。
type EngineCost struct {
	Engine     string  `json:"engine"`
	PricePer1K float64 `json:"price_per_1k,omitempty"`
	LatencyP50 float64 `json:"latency_p50_ms,omitempty"`
	Quality    float64 `json:"quality,omitempty"`
}

type ModelRoute struct {
	Engines []string `json:"engines"`
	Tier    string   `json:"tier"`
	// Costs 引擎成本/性能元数据（可选）；缺省时按 Engines 声明序 failover。
	Costs []EngineCost `json:"costs,omitempty"`
}

func (c *RouteConfig) defaultRoute() TenantRoute {
	eng := c.DefaultEngine
	if eng == "" {
		eng = protocol.EngineTypeTEEGPU
	}
	return TenantRoute{Engine: eng, Attest: protocol.AttestTypeQuote}
}

// Resolve 解析租户+模型的最终路由（M9-1/M4-3 扩展点：第 4 返回值 placement 为
// 端/云落点提示，"cloud"|"edge"|"auto"，缺省 cloud；端/云动态调度不实现——
// edge 引擎未注册时自动回退 cloud 并告警，现有引擎列表语义不变，见 routectl.go）。
func (c *RouteConfig) Resolve(tenant, model string) (allowedEngines []string, attest string, placement string, err error) {
	if mr, ok := c.Model[model]; ok {
		allowedEngines = append([]string(nil), mr.Engines...)
	} else {
		allowedEngines = []string{c.defaultRoute().Engine}
	}
	// 租户级覆盖
	if tr, ok := c.Tenant[tenant]; ok {
		if tr.Engine != "" {
			// 租户指定引擎必须在模型支持列表内
			ok2 := false
			for _, e := range allowedEngines {
				if e == tr.Engine {
					ok2 = true
					break
				}
			}
			if !ok2 {
				return nil, "", "", fmt.Errorf("route: 租户 %q 指定引擎 %q 不在模型 %q 支持列表 %v 中", tenant, tr.Engine, model, allowedEngines)
			}
			allowedEngines = []string{tr.Engine}
		}
		if tr.Attest != "" {
			attest = tr.Attest
		}
	}
	if attest == "" {
		attest = c.defaultRoute().Attest
	}
	placement = c.placementHintFor(tenant)
	return allowedEngines, attest, placement, nil
}

// ValidateRequest 校验请求的 engine_type/attest_type 与路由配置，不匹配就拒绝
func (c *RouteConfig) ValidateRequest(tenant, model, engineType, attestType string) error {
	allowed, _, _, err := c.Resolve(tenant, model)
	if err != nil {
		return err
	}
	if engineType == "" {
		engineType = protocol.EngineTypeTEEGPU
	}
	match := false
	for _, e := range allowed {
		if e == engineType {
			match = true
			break
		}
	}
	if !match {
		return fmt.Errorf("route: 引擎 %q 不在模型 %q 支持列表 %v 中", engineType, model, allowed)
	}
	// attest_type 缺省 = token
	if attestType == "" {
		attestType = protocol.AttestTypeToken
	}
	if attestType != protocol.AttestTypeQuote && attestType != protocol.AttestTypeToken {
		return fmt.Errorf("route: 未知 attest_type %q", attestType)
	}
	// 生产强制 quote
	if c.RequireQuote && attestType == protocol.AttestTypeToken {
		return errors.New("route: 生产环境强制 quote 证明（token 模式被拒绝）")
	}
	return nil
}

// OrderedEngines 返回模型候选引擎的 failover 顺序（GF.3.3 / D-6）。
// 以模型允许引擎全集为输入，委托 orderEngines 排序；未知模型回退缺省引擎单元素。
func (c *RouteConfig) OrderedEngines(model string) []string {
	return c.orderEngines(c.baseEngines(model), model)
}

// orderEngines 对给定允许引擎列表按成本策略稳定排序（D-6）。
// 纯函数、不改变引擎集合：仅重排顺序供 failover/择优使用；无元数据或 Policy 为空
// 时保持输入序。排序稳定（同分保持原序），结果可复现。
func (c *RouteConfig) orderEngines(allowed []string, model string) []string {
	if len(allowed) == 0 || c.Policy == "" {
		return append([]string(nil), allowed...)
	}
	costs := make(map[string]EngineCost)
	if mr, ok := c.Model[model]; ok {
		for _, ec := range mr.Costs {
			costs[ec.Engine] = ec
		}
	}
	key := func(engine string) float64 {
		ec, ok := costs[engine]
		if !ok {
			return 0
		}
		switch c.Policy {
		case "latency":
			return ec.LatencyP50
		case "quality":
			return -ec.Quality // 降序
		case "cost":
			return ec.PricePer1K
		default:
			return 0
		}
	}
	// 仅当策略可识别（cost/latency/quality）才重排；未知策略保持原序（保守，防误路由）
	switch c.Policy {
	case "cost", "latency", "quality":
	default:
		return append([]string(nil), allowed...)
	}
	ordered := append([]string(nil), allowed...)
	sort.SliceStable(ordered, func(a, b int) bool {
		return key(ordered[a]) < key(ordered[b])
	})
	return ordered
}

// baseEngines 模型的允许引擎全集（未知模型回退缺省引擎）。
func (c *RouteConfig) baseEngines(model string) []string {
	if mr, ok := c.Model[model]; ok && len(mr.Engines) > 0 {
		return append([]string(nil), mr.Engines...)
	}
	return []string{c.defaultRoute().Engine}
}

func ParseRouteConfig(data []byte) (*RouteConfig, error) {
	var c RouteConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// DefaultRouteConfig 开发环境缺省配置。
// P5：C-MaaS 模型（cmaas-* code）仅 cmaas 引擎；C-MaaS 不支持多模态/联网搜索，
// 引擎能力差异经路由配置声明（引擎能力矩阵入路由，见《GA-路线1发布规划.md》§七）。
func DefaultRouteConfig() *RouteConfig {
	return &RouteConfig{
		Tenant: map[string]TenantRoute{},
		Model: map[string]ModelRoute{
			"qwen2.5-0.5b": {Engines: []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector}, Tier: "small"},
			"qwen2.5-1.5b": {Engines: []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector}, Tier: "small"},
			"glm-4-1.5b":   {Engines: []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector}, Tier: "small"},
			"deepseek-v3":  {Engines: []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector}, Tier: "large-moe"},
			"deepseek-r1":  {Engines: []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector}, Tier: "large-moe"},
			"glm-4":        {Engines: []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector}, Tier: "large"},
			"mock": {Engines: []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector, protocol.EngineTypeCMAAS}, Tier: "small",
				Costs: []EngineCost{
					{Engine: protocol.EngineTypeTEEGPU, PricePer1K: 3.0, LatencyP50: 80, Quality: 95},
					{Engine: protocol.EngineTypeMaskedVector, PricePer1K: 1.5, LatencyP50: 120, Quality: 70},
					{Engine: protocol.EngineTypeCMAAS, PricePer1K: 0.5, LatencyP50: 200, Quality: 60},
				}},
			"cmaas-glm-5.2":                {Engines: []string{protocol.EngineTypeCMAAS}, Tier: "cmaas"},
			"cmaas-deepseek-v4-flash":      {Engines: []string{protocol.EngineTypeCMAAS}, Tier: "cmaas"},
			"cmaas-deepseek-v4-flash-0731": {Engines: []string{protocol.EngineTypeCMAAS}, Tier: "cmaas"},
		},
		DefaultEngine: protocol.EngineTypeTEEGPU,
		RequireQuote:  false,
	}
}
