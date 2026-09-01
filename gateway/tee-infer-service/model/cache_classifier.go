// Package model — 语义缓存与语义分类器接入点（GF.4.1 / GF.4.3）
//
// 均为真机依赖项：语义缓存收益需 C-MaaS 真机实测（低 prompt 复用场景，若不达标
// 维持现状并记录）；语义分类器需模型选型。本文件仅定义接口 + 保守的零/规则实现，
// 作为 tee-infer 明文域内的接入点预留（研发计划 GF.4 "接入点预留"）。
package model

import "strings"

// SemanticCache 语义缓存接口（GF.4.1）：以引擎实收内容哈希（transformed_hash）为键，
// 命中则返回缓存文本 + 命中标记。实现要点（真机到位后）：
//   - SSE 流缓存：seq 重放 + 重加密（复用会话信封）；
//   - cache_hit 审计事件（tee-infer 审计链）；
//   - 缓存键基于"改造后内容"（装饰 + 脱敏后），与 Guardrail 执行顺序、租户隔离边界
//     在设计评审中明确（研发计划 GF.4.1 评审注记）。
type SemanticCache interface {
	Get(key string) (text string, hit bool)
	Put(key string, text string)
}

// NullCache 空实现（默认）：永不命中、不落盘，等价于"关闭语义缓存"。
// 保证真机未到位时零行为变化（fail-closed 不引入缓存副作用）。
type NullCache struct{}

// Get 恒 miss。
func (NullCache) Get(key string) (string, bool) { return "", false }

// Put 空操作。
func (NullCache) Put(key string, text string) {}

// Classifier 语义分类器接口（GF.4.3）：Guardrail 规则 → 分类器。
// Classify 返回命中的风险类别与匹配片段；空类别 = 未命中。真机到位后接模型分类器，
// 现阶段以规则分类器（KeywordClassifier）占位，语义与既有 Guardrail 规则一致。
type Classifier interface {
	Classify(text string) (category string, match string)
}

// KeywordClassifier 规则分类器（占位实现，GF.4.3 接入点）：
// 按关键词命中返回类别；先命中先返回（顺序敏感，与规则优先级一致）。
type KeywordClassifier struct {
	rules []keywordRule
}

type keywordRule struct {
	category string
	keyword  string
}

// NewKeywordClassifier 构造规则分类器；rules 为 (类别, 关键词) 列表，按顺序匹配。
func NewKeywordClassifier(rules ...[2]string) *KeywordClassifier {
	c := &KeywordClassifier{}
	for _, r := range rules {
		c.rules = append(c.rules, keywordRule{category: r[0], keyword: r[1]})
	}
	return c
}

// Classify 按规则顺序命中首个关键词；忽略大小写；未命中返回空类别。
func (c *KeywordClassifier) Classify(text string) (string, string) {
	lower := strings.ToLower(text)
	for _, r := range c.rules {
		if kw := strings.ToLower(r.keyword); kw != "" && strings.Contains(lower, kw) {
			return r.category, r.keyword
		}
	}
	return "", ""
}
