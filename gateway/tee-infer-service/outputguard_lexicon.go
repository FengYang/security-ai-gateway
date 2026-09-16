// 输出侧内容审查 — L1 词库加载器与 AC 自动机（OG-9：词库/策略供应链）。
//
// 设计对齐技术方案 §4.2.4 词库 JSON Schema（M1 冻结项）：
//   - schema_version / category / version / level / rules[]
//   - 6 条加载期强校验：schema 匹配 / category 合法 / level 一致 / submitter≠reviewer /
//     regex 可编译 / 词条数>0 / sha256 与 manifest 一致
//
// 匹配引擎分层（与规则 type 对应）：
//   - exact    → map[string]rule（归一化后全词匹配，O(1)）
//   - contains → AC 自动机（多模式子串匹配，O(n)）
//   - variant  → AC 自动机（归一化后子串匹配，M2 细化变体生成）
//   - regex    → []*regexp.Regexp（逐条编译，M1 先按顺序匹配）
//
// 命名纪律（§4.2.4 / §5.8 #3）：文件名 = 内部类目 ID（a1-06.json），不用俗名。
// 所有类目 ID 作为「值」使用时大写（A1-06），文件路径/条目 ID 前缀小写。
//
// 注意：M1 骨架期本文件为**单类目词库**加载器；M3 多类目级联时升级为
// lexiconRegistry（持有全部类目词库实例）。
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// 词库 schema 版本（与 JSON 文件 schema_version 对齐；不匹配＝拒加载）。
const lexiconSchemaVersion = "1.0"

// 规则类型（rule.type）。
const (
	ruleTypeExact    = "exact"    // 独立成词（归一化后全匹配）
	ruleTypeContains = "contains" // 子串匹配（AC 自动机）
	ruleTypeVariant  = "variant"  // 变体匹配（归一化后子串匹配；M1 走 contains 路径）
	ruleTypeRegex    = "regex"    // 正则匹配
)

// lexiconRule 单条词库规则（与 JSON schema 对齐）。
type lexiconRule struct {
	ID        string  `json:"id"`
	Keyword   string  `json:"keyword"`
	Type      string  `json:"type"`
	Weight    float64 `json:"weight"`
	AddedAt   string  `json:"added_at"`
	Submitter string  `json:"submitter"`
	Reviewer  string  `json:"reviewer"`
	Comment   string  `json:"comment,omitempty"`
}

// lexiconFile 词库文件顶层结构（JSON schema）。
type lexiconFile struct {
	SchemaVersion string        `json:"schema_version"`
	Category      string        `json:"category"`
	Version       string        `json:"version"`
	Level         string        `json:"level"`
	Rules         []lexiconRule `json:"rules"`
}

// lexiconClassifier 基于词库的 OutputClassifier 实现（L1 规则层）。
// 持有一个类目的全部规则，分层匹配（exact → contains/variant → regex）。
// 命中返回：内部类目 ID / 置信度（= rule.weight）/ 命中词。
type lexiconClassifier struct {
	category string // 内部类目 ID（大写 A1-06）
	version  string // 词库版本

	// exact：归一化后的完整词 → rule（O(1) 查表）
	exactMap map[string]lexiconRule

	// contains/variant：AC 自动机（多模式子串匹配）
	ac *acAutomaton

	// regex：已编译的正则列表（逐条匹配）
	regexList []compiledRegexRule
}

// compiledRegexRule 已编译的正则规则。
type compiledRegexRule struct {
	rule lexiconRule
	re   *regexp.Regexp
}

// newLexiconClassifierFromJSON 从 JSON 字节加载单类目词库并构建匹配引擎。
// 加载失败返回错误（fail-closed：调用方不得静默降级）。
func newLexiconClassifierFromJSON(data []byte) (*lexiconClassifier, error) {
	// 1. JSON 解析
	var f lexiconFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("词库 JSON 解析失败: %v", err)
	}

	// 2. 强校验（§4.2.4 六条规则的前 5 条；第 6 条 sha256 由调用方校验）
	if f.SchemaVersion != lexiconSchemaVersion {
		return nil, fmt.Errorf("schema_version=%q 不匹配（期望 %q）", f.SchemaVersion, lexiconSchemaVersion)
	}
	if !isValidCategory(f.Category) {
		return nil, fmt.Errorf("category=%q 不在附录 A 31 类内", f.Category)
	}
	// level 校验：必须与该类目在附录 A 中的默认级别一致（高/中/低）。
	cat, ok := getCategory(f.Category)
	if !ok {
		return nil, fmt.Errorf("category=%q 查无定义", f.Category)
	}
	levelZh := mapLevelEnToZh(cat.DefaultLevel)
	if f.Level != levelZh {
		return nil, fmt.Errorf("level=%q 与策略默认级别 %q 不一致（类目 %s）", f.Level, levelZh, f.Category)
	}
	if len(f.Rules) == 0 {
		return nil, fmt.Errorf("rules 为空（空数组＝拒加载，防误删清空）")
	}
	if f.Version == "" {
		return nil, fmt.Errorf("version 为空")
	}

	lc := &lexiconClassifier{
		category: f.Category,
		version:  f.Version,
		exactMap: make(map[string]lexiconRule),
	}

	var acPatterns []acPattern
	seenIDs := make(map[string]bool, len(f.Rules))

	for i, r := range f.Rules {
		// 校验必填字段
		if r.ID == "" {
			return nil, fmt.Errorf("rules[%d]: id 为空", i)
		}
		if seenIDs[r.ID] {
			return nil, fmt.Errorf("rules[%d]: id=%q 重复", i, r.ID)
		}
		seenIDs[r.ID] = true
		if r.Keyword == "" {
			return nil, fmt.Errorf("rules[%d] (%s): keyword 为空", i, r.ID)
		}
		if r.Submitter == "" || r.Reviewer == "" {
			return nil, fmt.Errorf("rules[%d] (%s): submitter/reviewer 不能为空", i, r.ID)
		}
		if r.Submitter == r.Reviewer {
			return nil, fmt.Errorf("rules[%d] (%s): submitter=reviewer=%q（必须不同）", i, r.ID, r.Submitter)
		}
		if r.Weight < 0 || r.Weight > 1 {
			return nil, fmt.Errorf("rules[%d] (%s): weight=%f 超出 [0,1]", i, r.ID, r.Weight)
		}
		if r.AddedAt == "" {
			return nil, fmt.Errorf("rules[%d] (%s): added_at 为空", i, r.ID)
		}

		switch r.Type {
		case ruleTypeExact:
			key := normalizeLexicon(r.Keyword)
			if key == "" {
				return nil, fmt.Errorf("rules[%d] (%s): 归一化后关键词为空", i, r.ID)
			}
			lc.exactMap[key] = r

		case ruleTypeContains, ruleTypeVariant:
			// variant M1 按 contains 处理（归一化后子串匹配；M2 细化变体生成）
			pat := normalizeLexicon(r.Keyword)
			if pat == "" {
				return nil, fmt.Errorf("rules[%d] (%s): 归一化后关键词为空", i, r.ID)
			}
			acPatterns = append(acPatterns, acPattern{text: pat, rule: r})

		case ruleTypeRegex:
			re, err := regexp.Compile(r.Keyword)
			if err != nil {
				return nil, fmt.Errorf("rules[%d] (%s): regex 编译失败: %v", i, r.ID, err)
			}
			lc.regexList = append(lc.regexList, compiledRegexRule{rule: r, re: re})

		default:
			return nil, fmt.Errorf("rules[%d] (%s): type=%q 非法（取值：exact|contains|variant|regex）",
				i, r.ID, r.Type)
		}
	}

	// 构建 AC 自动机（仅当有 contains/variant 规则时）
	if len(acPatterns) > 0 {
		lc.ac = newACAutomaton(acPatterns)
	}

	return lc, nil
}

// Classify 实现 OutputClassifier 接口。
// 命中返回（内部类目ID, 置信度=最高权重, 命中片段）；未命中返回 ("", 0, "")。
// 匹配优先级：exact > contains/variant > regex（一旦命中即返回最高优先级结果；
// 同层多个命中取权重最高的）。
func (lc *lexiconClassifier) Classify(text string) (string, float64, string) {
	return lc.classifyNorm(text, normalizeLexicon(text))
}

// classifyNorm 接收原文与其归一化结果：归一化由 lexiconRegistry 在级联入口
// 统一做一次后下传，避免同一文本被 30 个类目重复 normalizeLexicon（M1 性能优化 R7①）。
// raw 供 regex 层使用（正则按原文匹配，不经归一化）。
func (lc *lexiconClassifier) classifyNorm(raw, norm string) (string, float64, string) {
	// 1. exact 匹配（O(1)）
	if r, ok := lc.exactMap[norm]; ok {
		return lc.category, r.Weight, r.Keyword
	}

	// 2. contains/variant（AC 自动机）
	if lc.ac != nil {
		if hit := lc.ac.matchFirst(norm); hit != nil {
			return lc.category, hit.rule.Weight, hit.rule.Keyword
		}
	}

	// 3. regex（逐条匹配，按原文）
	for _, cr := range lc.regexList {
		if cr.re.MatchString(raw) {
			return lc.category, cr.rule.Weight, cr.rule.Keyword
		}
	}

	return "", 0, ""
}

// Version 返回词库版本（供 rule_version 审计与 chunk-meta 用）。
func (lc *lexiconClassifier) Version() string { return lc.version }

// hasRegexRules 该词库是否含 regex 规则。
// 用途：lexiconRegistry 优先级排序（§6.1.1「PII > 正则 > 关键词」——结构化强证据优先）。
func (lc *lexiconClassifier) hasRegexRules() bool { return len(lc.regexList) > 0 }

// Category 返回内部类目 ID。
func (lc *lexiconClassifier) Category() string { return lc.category }

// RuleCount 返回总词条数（含 exact/contains/variant/regex；用于可观测）。
func (lc *lexiconClassifier) RuleCount() int {
	n := len(lc.exactMap) + len(lc.regexList)
	if lc.ac != nil {
		n += lc.ac.patternCount()
	}
	return n
}

// MaxKeywordRunes 返回最长关键词的 rune 数（用于派生 P-WINDOW-CHARS）。
// 仅统计 exact / contains / variant（regex 的"长度"语义不明确，不计入）。
func (lc *lexiconClassifier) MaxKeywordRunes() int {
	max := 0
	for _, r := range lc.exactMap {
		if n := len([]rune(r.Keyword)); n > max {
			max = n
		}
	}
	if lc.ac != nil {
		if m := lc.ac.maxPatternLen(); m > max {
			max = m
		}
	}
	return max
}

// lexiconSHA256 计算词库 JSON 字节的 sha256（供 manifest 校验）。
func lexiconSHA256(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// ---- 归一化（与 guardrail.go normalize 对齐，此处独立实现避免循环引用）----

// normalizeLexicon 词库归一化：全角转半角、**去除零宽字符**、折叠大小写、去空白。
// 与 guardrail.go 的 normalize 语义保持一致（M1 骨架期两份代码并存；
// OG-9 完成后可考虑抽取公用函数）。
//
// 零宽字符属 §4.2.3 规定的混淆防御项（U+200B/200C/200D/FEFF/2060）：字符间插零宽
// 是常见绕过手法，归一化后必须仍能命中（§6.1.4「零宽字符插入 100% 命中」）。
func normalizeLexicon(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if isZeroWidthRune(r) {
			continue
		}
		// 全角 ASCII → 半角（U+FF01–U+FF5E → U+0021–U+007E）
		if r >= 0xFF01 && r <= 0xFF5E {
			r -= 0xFEE0
		}
		// 全角空格 → 半角空格
		if r == 0x3000 {
			r = ' '
		}
		// 折叠大小写
		r = unicode.ToLower(r)
		// 去空白（exact/contains 匹配都不考虑空白差异）
		if unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// isZeroWidthRune 零宽/不可见格式字符（§4.2.3 清单）。
func isZeroWidthRune(r rune) bool {
	switch r {
	case 0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060:
		return true
	}
	return false
}

// mapLevelEnToZh 英文级别名 → 中文级别名（与 JSON 文件 level 字段一致）。
func mapLevelEnToZh(en string) string {
	switch en {
	case catLevelHigh:
		return "高"
	case catLevelMedium:
		return "中"
	case catLevelLow:
		return "低"
	}
	return ""
}
