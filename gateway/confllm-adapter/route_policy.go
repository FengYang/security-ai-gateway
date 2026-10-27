package confllm

import (
	"fmt"
	"net/http"

	"security-ai-gateway/gateway/confllm-adapter/meta"
)

// classOrder 密态等级序数（A > B > C；unknown 不入序，视为不可信）。
var classOrder = map[string]int{
	meta.ClassA: 3,
	meta.ClassB: 2,
	meta.ClassC: 1,
}

// validMinClass 判断 min 是否为合法等级（{A,B,C}；空单独处理表示不设门槛）。
func validMinClass(min string) bool {
	switch min {
	case meta.ClassA, meta.ClassB, meta.ClassC:
		return true
	}
	return false
}

// SatisfiesMin 按密态等级路由过滤（§7.6 QA-3，定死）。
//
//   - min 为空 → 不过滤（普通流量不设门槛，含 unknown 全放行）。
//   - class 或 min 为 unknown / 未登记 → 一律 false（unknown 对任意 min 不可信）。
//   - 否则按序数比较 oc >= om。
func SatisfiesMin(class, min string) bool {
	if min == "" {
		return true
	}
	if class == "" || class == meta.ClassUnknown {
		return false
	}
	oc, ok1 := classOrder[class]
	om, ok2 := classOrder[min]
	if !ok1 || !ok2 {
		return false
	}
	return oc >= om
}

// FilterProviders 按 minConfidentialityClass 过滤候选上游（§7.6，可判定错误码）。
//
//   - min 为空返回全部（不过滤）；
//   - 非法 min（不在 {A,B,C,空}）→ 错误码 invalid_route_policy（不视为空阈值、不静默放行，QA2-20）；
//   - 无满足项返回错误码 no_provider_satisfies_min（非静默降级、非泛化 500，QA2-21）。
func FilterProviders(providers []ConfidentialLLMProvider, minClass string) ([]ConfidentialLLMProvider, error) {
	if minClass != "" && !validMinClass(minClass) {
		return nil, NewProviderError(CodeInvalidRoutePolicy, http.StatusBadRequest,
			fmt.Sprintf("非法 min_confidentiality_class=%q（必须 ∈ {A,B,C} 或空）（§7.6 QA2-20）", minClass))
	}
	if minClass == "" {
		return providers, nil
	}
	out := make([]ConfidentialLLMProvider, 0, len(providers))
	for _, p := range providers {
		if SatisfiesMin(p.Metadata().ConfidentialityClass, minClass) {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil, NewProviderError(CodeNoProviderSatisfiesMin, http.StatusServiceUnavailable,
			fmt.Sprintf("无满足 min_confidentiality_class=%q 的候选上游：密态等级未确认（unknown）者被 min=%s 过滤（§7.6 QA2-21）", minClass, minClass))
	}
	return out, nil
}
