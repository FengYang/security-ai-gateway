package cacheengine

import (
	"regexp"
	"sort"
	"strings"
)

// EntityFingerprint 实体指纹（§6.6）。
// 用于严格场景（code/math 等）的语义缓存二次校验：
// 如果 query 和 response 的关键实体集合差异过大，则即使相似度达标也不命中。
//
// 设计原则：
//   - 只提取显著实体（数字、专有名词、代码标识符等）
//   - 计算 Jaccard 相似度，低于阈值则拒绝
//   - 轻量级（不依赖 NLP，纯规则）

// EntitySet 实体集合（去重后的实体列表，已排序）。
type EntitySet struct {
	Entities []string // 已排序、去重
}

// ExtractEntities 从文本中提取实体集合。
// 提取规则：
//   - 数字（含小数、百分比）
//   - 代码标识符（驼峰/下划线风格，长度 >= 4）
//   - 大写缩写（>=2 个连续大写字母）
//   - URL / 文件路径
func ExtractEntities(text string) EntitySet {
	if text == "" {
		return EntitySet{Entities: []string{}}
	}

	set := make(map[string]struct{})

	// 1. 数字（含小数、百分比、千分位）
	numRe := regexp.MustCompile(`\d[\d,\.]*\d%?`)
	for _, m := range numRe.FindAllString(text, -1) {
		// 标准化：去掉千分位逗号，统一小写
		norm := strings.ReplaceAll(m, ",", "")
		set[strings.ToLower(norm)] = struct{}{}
	}

	// 2. 代码标识符（驼峰或下划线，含字母数字，长度 >= 4）
	// 匹配类似 variableName, my_function, CONSTANT_NAME, className123
	identRe := regexp.MustCompile(`\b[a-zA-Z_][a-zA-Z0-9_]{3,}\b`)
	for _, m := range identRe.FindAllString(text, -1) {
		// 过滤纯英文普通单词（简单启发：含下划线或数字或驼峰才算）
		if isLikelyIdentifier(m) {
			set[strings.ToLower(m)] = struct{}{}
		}
	}

	// 3. 大写缩写（2 个及以上连续大写字母）
	abbrRe := regexp.MustCompile(`\b[A-Z]{2,}\b`)
	for _, m := range abbrRe.FindAllString(text, -1) {
		set[strings.ToLower(m)] = struct{}{}
	}

	// 4. 引号内的字符串（函数名、配置键等）
	// 匹配 "xxx" 或 'xxx' 形式，长度 >= 3
	quoteRe := regexp.MustCompile("[\"']([^\"']{3,})[\"']")
	for _, m := range quoteRe.FindAllStringSubmatch(text, -1) {
		if len(m) >= 2 {
			set[strings.ToLower(m[1])] = struct{}{}
		}
	}

	// 转为排序后的切片
	entities := make([]string, 0, len(set))
	for e := range set {
		entities = append(entities, e)
	}
	sort.Strings(entities)

	return EntitySet{Entities: entities}
}

// isLikelyIdentifier 判断是否可能是代码标识符。
func isLikelyIdentifier(s string) bool {
	// 含下划线 → 是
	if strings.Contains(s, "_") {
		return true
	}
	// 含数字 → 是
	if strings.ContainsAny(s, "0123456789") {
		return true
	}
	// 驼峰（同时有大写和小写）→ 是
	hasUpper := false
	hasLower := false
	for _, c := range s {
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		}
		if c >= 'a' && c <= 'z' {
			hasLower = true
		}
	}
	if hasUpper && hasLower {
		return true
	}
	// 全大写且长度 >= 4（可能是常量名）→ 是
	if hasUpper && !hasLower && len(s) >= 4 {
		return true
	}
	return false
}

// Jaccard 计算两个实体集合的 Jaccard 相似度。
// Jaccard(A, B) = |A ∩ B| / |A ∪ B|
// 空集返回 0。
func (e EntitySet) Jaccard(other EntitySet) float64 {
	if len(e.Entities) == 0 || len(other.Entities) == 0 {
		return 0
	}

	// 双指针求交集（两个切片都已排序）
	intersection := 0
	i, j := 0, 0
	for i < len(e.Entities) && j < len(other.Entities) {
		if e.Entities[i] == other.Entities[j] {
			intersection++
			i++
			j++
		} else if e.Entities[i] < other.Entities[j] {
			i++
		} else {
			j++
		}
	}

	union := len(e.Entities) + len(other.Entities) - intersection
	if union == 0 {
		return 0
	}
	return float64(intersection) / float64(union)
}

// Compatible 检查实体集合是否兼容（Jaccard >= 阈值）。
// 用于语义命中后的二次校验：严格场景下实体差异过大则不命中。
func (e EntitySet) Compatible(other EntitySet, threshold float64) bool {
	if threshold <= 0 {
		return true // 阈值为 0 = 不检查
	}
	return e.Jaccard(other) >= threshold
}

// Len 返回实体数量。
func (e EntitySet) Len() int {
	return len(e.Entities)
}
