package mcpguard

import (
	"security-ai-gateway/gateway/mcpsec"
)

// Reason 决策结果原因（供审计 MCPReason，拒绝类入链）。
type Reason string

const (
	ReasonPermission  Reason = "permission"
	ReasonDenyParam   Reason = "deny_param"
	ReasonToolUnknown Reason = "tool_unknown"
	ReasonSchema      Reason = "schema_reject"
	ReasonSensitive   Reason = "sensitive"
	ReasonNotReady    Reason = "not_ready" // 冷启动未就绪（O-3：fail-closed）
	ReasonInjection   Reason = "injection" // Step3 值级注入钩子
)

// Decision 一次 MCP 工具调用的裁决结果。
type Decision struct {
	Allow   bool
	Reason  Reason // 放行时为空字符串
	Tool    string
	Params  map[string]any // 脱敏后参数，仅下游投递用，**禁止持久化**
	ParamsHash string      // 绑 tenant+reqID 的参数 hash（S-2，审计用，无明文）
	PolicyVersion int
}

// Engine MCP 工具调用裁决引擎。pure logic，可单测。
type Engine struct {
	cache *PolicyCache
	// PreInject 可选值级注入钩子（FR3，Step3 由主包接线 guardrail.check）；nil = 不执行。
	PreInject func(tool string, sanitized map[string]any) bool
}

// NewEngine 构造引擎。
func NewEngine(cache *PolicyCache) *Engine { return &Engine{cache: cache} }

// Evaluate 执行裁决全流程：就绪门控 → RBAC(FR1) → deny_params → 工具存在性 →
// schema 强校验(FR2) → 敏感三态(S-5) → 值级注入钩子 → 产 Decision（含参数 hash）。
func (e *Engine) Evaluate(tenant, reqID, toolName string, params map[string]any) Decision {
	if !e.cache.Ready() { // 冷启动未就绪 fail-closed（O-3）
		return deny(tenant, reqID, toolName, params, ReasonNotReady)
	}
	pol := e.cache.Policy()
	rd := EvaluateRBAC(pol, tenant, toolName)
	if !rd.Allowed {
		return deny(tenant, reqID, toolName, params, ReasonPermission)
	}
	if DenyParamsExceeded(rd.Binding, params) {
		return deny(tenant, reqID, toolName, params, ReasonDenyParam)
	}

	var tool *mcpsec.TableTool
	if cat := e.cache.Catalog(); cat != nil {
		tool = findTool(cat, toolName)
		if tool == nil {
			return deny(tenant, reqID, toolName, params, ReasonToolUnknown)
		}
	}

	if tool != nil {
		if err := ValidateSchema(tool, params); err != nil {
			return deny(tenant, reqID, toolName, params, ReasonSchema)
		}
		sanitized, err := sanitizeParams(tool, params)
		if err != nil {
			return deny(tenant, reqID, toolName, params, ReasonSensitive)
		}
		if e.PreInject != nil && e.PreInject(toolName, sanitized) {
			return deny(tenant, reqID, toolName, sanitized, ReasonInjection)
		}
		version, _ := e.cache.Version()
		return Decision{Allow: true, Tool: toolName, Params: sanitized,
			ParamsHash: ParamsHash(tenant, reqID, sanitized), PolicyVersion: version}
	}

	// 无目录（紧凑护栏形态）：仍过 RBAC 与参数 hash，保证可审计。
	version, _ := e.cache.Version()
	return Decision{Allow: true, Tool: toolName, Params: params,
		ParamsHash: ParamsHash(tenant, reqID, params), PolicyVersion: version}
}

func deny(tenant, reqID, toolName string, params map[string]any, r Reason) Decision {
	return Decision{Allow: false, Reason: r, Tool: toolName, ParamsHash: ParamsHash(tenant, reqID, params)}
}

func findTool(cat *mcpsec.ToolCatalog, name string) *mcpsec.TableTool {
	for i := range cat.Tools {
		if cat.Tools[i].Name == name {
			return &cat.Tools[i]
		}
	}
	return nil
}