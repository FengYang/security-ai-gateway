package cacheengine

import "strings"

// countTokens 简单的 token 计数（按字符/词粗略估计；一期用分词近似，二期接 tiktoken）。
// 对于中文按字符计、英文按词计的简单近似，满足 min_prompt_tokens 的粗过滤。
func countTokens(text string) int {
	if text == "" {
		return 0
	}
	// 简单估算：中文字符按 1 token/字，英文按 1 token/4 字符
	var chinese, other int
	for _, r := range text {
		if r >= '\u4e00' && r <= '\u9fff' {
			chinese++
		} else {
			other++
		}
	}
	return chinese + other/4
}

// cacheabilityEngine 可缓存性判定逻辑。
// 纯函数，无 IO；查询与写入共用，保证两侧一致。
type cacheabilityEngine struct {
	cfg    *CacheConfig
	scene  SceneClassifier
}

func newCacheabilityEngine(cfg *CacheConfig, scene SceneClassifier) *cacheabilityEngine {
	return &cacheabilityEngine{cfg: cfg, scene: scene}
}

// Cacheable 可缓存性判定（§6.0）。
// 任一规则命中即不可缓存。
// 必须在场景分类之后调用（NC-3/NC-7 依赖 ctx.Scene）。
func (c *cacheabilityEngine) Cacheable(ctx *LookupContext) CacheDecision {
	// NC-2：工具/函数调用 —— 强制不可缓存
	if ctx.HasToolCall {
		return CacheDecision{Cacheable: false, Reason: "tool_call"}
	}

	// NC-4：请求级旁路
	if ctx.NoCache {
		return CacheDecision{Cacheable: false, Reason: "bypass"}
	}

	// NC-5：租户策略关闭
	if c.cfg != nil && tenantPolicy(c.cfg, ctx.TenantID) == PolicyOff {
		return CacheDecision{Cacheable: false, Reason: "tenant_off"}
	}

	// NC-7：场景被关停
	if c.cfg != nil && contains(c.cfg.Cacheability.DisabledScenes, string(ctx.Scene)) {
		return CacheDecision{Cacheable: false, Reason: "scene_policy"}
	}

	// NC-1：多轮对话（默认不可缓存）
	if ctx.TurnCount > 1 && c.cfg != nil && !c.cfg.Cacheability.MultiTurn {
		return CacheDecision{Cacheable: false, Reason: "multi_turn"}
	}

	// NC-3：时间敏感
	if ctx.TimeSensitive || (c.cfg != nil && contains(c.cfg.Cacheability.TimeSensitiveScenes, string(ctx.Scene))) {
		return CacheDecision{Cacheable: false, Reason: "time_sensitive"}
	}

	// NC-6：输入过短
	minTokens := 8
	if c.cfg != nil {
		minTokens = c.cfg.Exact.MinPromptTokens
	}
	if countTokens(ctx.PromptText) < minTokens {
		return CacheDecision{Cacheable: false, Reason: "too_short"}
	}

	return CacheDecision{Cacheable: true, Reason: ""}
}

// contains 判断字符串是否在切片中。
func contains(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

// tenantPolicy 获取租户的缓存策略。
func tenantPolicy(cfg *CacheConfig, tenantID string) TenantPolicy {
	if cfg == nil || cfg.Semantic.Vector.TenantPolicy == nil {
		return PolicyDefault
	}
	v, ok := cfg.Semantic.Vector.TenantPolicy[tenantID]
	if !ok {
		return PolicyDefault
	}
	switch v {
	case "off":
		return PolicyOff
	case "exact_only":
		return PolicyExactOnly
	default:
		return PolicyDefault
	}
}

// ===== 场景分类器 =====

// SceneClassifier 场景判定接口。
type SceneClassifier interface {
	Classify(prompt string) SceneClass
}

// ruleSceneClassifier 基于规则的场景分类器（一期默认实现）。
// 语义缓存二期会接入更精确的分类模型。
type ruleSceneClassifier struct{}

// NewRuleSceneClassifier 构造基于规则的场景分类器。
func NewRuleSceneClassifier() SceneClassifier {
	return &ruleSceneClassifier{}
}

// Classify 简单规则分类：
// - 含代码块/函数/类关键字 → code
// - 含数学公式/计算相关 → math
// - 含明确事实问句/列表问句 → factual
// - 其余 → general
func (c *ruleSceneClassifier) Classify(prompt string) SceneClass {
	lower := strings.ToLower(prompt)

	// code 场景
	codeSignals := []string{
		"代码", "函数", "类", "接口", "算法",
		"function", "class", "interface", "struct", "package",
		"import ", "def ", "fn ", "func ", "```",
	}
	for _, sig := range codeSignals {
		if strings.Contains(lower, sig) {
			return SceneCode
		}
	}

	// math 场景
	mathSignals := []string{
		"计算", "等于", "多少", "总和", "平均", "百分比",
		"calculate", "sum", "average", "percent", "math",
		"公式", "方程", "求解",
	}
	for _, sig := range mathSignals {
		if strings.Contains(lower, sig) {
			return SceneMath
		}
	}

	// factual 场景
	factualSignals := []string{
		"什么是", "哪些", "怎么", "如何", "为什么",
		"what is", "how to", "why", "list", "explain",
		"列表", "说明", "介绍", "步骤",
	}
	for _, sig := range factualSignals {
		if strings.Contains(lower, sig) {
			return SceneFactual
		}
	}

	return SceneGeneral
}
