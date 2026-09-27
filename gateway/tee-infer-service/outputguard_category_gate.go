// 输出侧内容审查 — 类目启停门控（S3-2，技术方案 §4.7 运行时覆盖 / §5.6 P-D8-SET）。
//
// 定位：请求级包装 L1/L2 分类器，按"停用类目集合"过滤命中。命中类目被停用 ⇒ 视为未命中，
// 使 block/flag/mask 三动作在单一分类注入点被抑制——mask 经 slot.action==catActionMask 触发，
// 分类被抑制则动作不会成为 mask（无需另改 mask 路径）。
package main

// categoryGate 停用类目门控分类器。
type categoryGate struct {
	inner    OutputClassifier
	disabled map[string]bool
}

// allowed 空类目（未命中）恒放行；非空命中查停用集合。
func (g categoryGate) allowed(cat string) bool { return cat == "" || !g.disabled[cat] }

// Classify 实现 OutputClassifier：命中类目被停用即返回未命中。
func (g categoryGate) Classify(text string) (string, float64, string) {
	cat, conf, match := g.inner.Classify(text)
	if !g.allowed(cat) {
		return "", 0, ""
	}
	return cat, conf, match
}

// categoryGateEarly 包装同时实现两段式 EarlyOutputClassifier 的分类器，
// 保留级联对 ClassifyWithEarly 的能力（若不实现会退回 Classify，改变 L2 时序）。
type categoryGateEarly struct {
	categoryGate
	early EarlyOutputClassifier
}

// ClassifyWithEarly 实现 EarlyOutputClassifier：终态类目被停用即视为未命中。
// 注：onEarly 轻段仅给 blocked 布尔、无类目，无法在此阶段按类目过滤；
// 默认 L2 未启用，停用集合与真 L2 叠加的边界以终态抑制为准。
func (g categoryGateEarly) ClassifyWithEarly(text string, onEarly func(blocked bool)) (string, float64, string) {
	cat, conf, match := g.early.ClassifyWithEarly(text, onEarly)
	if !g.allowed(cat) {
		return "", 0, ""
	}
	return cat, conf, match
}

// withCategoryGate 按停用集合包装分类器；inner 为 nil 或停用集合为空时原样返回（零包装）。
func withCategoryGate(inner OutputClassifier, disabled map[string]bool) OutputClassifier {
	if inner == nil || len(disabled) == 0 {
		return inner
	}
	base := categoryGate{inner: inner, disabled: disabled}
	if early, ok := inner.(EarlyOutputClassifier); ok {
		return categoryGateEarly{categoryGate: base, early: early}
	}
	return base
}
