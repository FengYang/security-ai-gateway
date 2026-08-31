// router.go - 双路线路由配置
package main

import (
	"encoding/json"
	"errors"
	"fmt"

	"security-ai-gateway/protocol/go"
)

type RouteConfig struct {
	Tenant map[string]TenantRoute `json:"tenant"`
	Model  map[string]ModelRoute  `json:"model"`
	DefaultEngine string `json:"default_engine"`
	RequireQuote bool   `json:"require_quote"`
}

type TenantRoute struct {
	Engine string `json:"engine"`
	Attest string `json:"attest"`
}

type ModelRoute struct {
	Engines []string `json:"engines"`
	Tier    string   `json:"tier"`
}

func (c *RouteConfig) defaultRoute() TenantRoute {
	eng := c.DefaultEngine
	if eng == "" {
		eng = protocol.EngineTypeTEEGPU
	}
	return TenantRoute{Engine: eng, Attest: protocol.AttestTypeQuote}
}

// Resolve 解析租户+模型的最终路由
func (c *RouteConfig) Resolve(tenant, model string) (allowedEngines []string, attest string, err error) {
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
				return nil, "", fmt.Errorf("route: 租户 %q 指定引擎 %q 不在模型 %q 支持列表 %v 中", tenant, tr.Engine, model, allowedEngines)
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
	return allowedEngines, attest, nil
}

// ValidateRequest 校验请求的 engine_type/attest_type 与路由配置，不匹配就拒绝
func (c *RouteConfig) ValidateRequest(tenant, model, engineType, attestType string) error {
	allowed, _, err := c.Resolve(tenant, model)
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

func ParseRouteConfig(data []byte) (*RouteConfig, error) {
	var c RouteConfig
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// DefaultRouteConfig 开发环境缺省配置
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
			"mock":         {Engines: []string{protocol.EngineTypeTEEGPU, protocol.EngineTypeMaskedVector}, Tier: "small"},
		},
		DefaultEngine: protocol.EngineTypeTEEGPU,
		RequireQuote:  false,
	}
}
