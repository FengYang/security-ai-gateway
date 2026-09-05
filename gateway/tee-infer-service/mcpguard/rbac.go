package mcpguard

import "security-ai-gateway/gateway/mcpsec"

// RBACDecision 一次授权的判定结果。
type RBACDecision struct {
	Allowed bool
	Binding *mcpsec.PolicyBinding // 允许时的附加约束（deny_params）；无 = 仅放行
}

// EvaluateRBAC 按租户×工具执行授权（FR1，default-deny）。
// 策略 TenantRules[tenant][tool] 键存在即放行（值可为绑定），键缺失即拒绝。
// pol 为 nil 或规则缺失一律拒绝 → fail-closed。
func EvaluateRBAC(pol *mcpsec.RBACPolicy, tenant, tool string) RBACDecision {
	if pol == nil || tenant == "" || tool == "" {
		return RBACDecision{Allowed: false}
	}
	byTenant, ok := pol.TenantRules[tenant]
	if !ok {
		return RBACDecision{Allowed: false}
	}
	binding, ok := byTenant[tool]
	if !ok {
		return RBACDecision{Allowed: false}
	}
	if binding == nil {
		return RBACDecision{Allowed: true}
	}
	return RBACDecision{Allowed: true, Binding: binding}
}

// DenyParamsExceeded 判断调用参数是否命中 deny_params（附加放行约束）。
func DenyParamsExceeded(binding *mcpsec.PolicyBinding, params map[string]any) bool {
	if binding == nil || len(binding.DenyParams) == 0 {
		return false
	}
	for _, k := range binding.DenyParams {
		if _, ok := params[k]; ok {
			return true
		}
	}
	return false
}