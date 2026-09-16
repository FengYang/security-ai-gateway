package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// OG-9（词库加载器 & AC 自动机）验收单测。

// 构造一个合法的 A1-06 词库 JSON（最小合法集）。
func buildValidLexiconJSON(t *testing.T, modify func(*lexiconFile)) []byte {
	t.Helper()
	f := lexiconFile{
		SchemaVersion: "1.0",
		Category:      "A1-06",
		Version:       "v2026.09.15",
		Level:         "高",
		Rules: []lexiconRule{
			{
				ID: "kw-a1-06-0001", Keyword: "违禁词甲", Type: "exact", Weight: 1.0,
				AddedAt: "2026-09-15", Submitter: "sec-alice", Reviewer: "sec-bob",
			},
			{
				ID: "kw-a1-06-0002", Keyword: "违规词乙", Type: "contains", Weight: 0.9,
				AddedAt: "2026-09-15", Submitter: "sec-alice", Reviewer: "sec-bob",
			},
			{
				ID: "kw-a1-06-0003", Keyword: `\d{11}`, Type: "regex", Weight: 0.8,
				AddedAt: "2026-09-15", Submitter: "sec-alice", Reviewer: "sec-bob",
			},
		},
	}
	if modify != nil {
		modify(&f)
	}
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return data
}

// TestLexiconLoadValid：合法词库加载成功且分类器正常工作。
func TestLexiconLoadValid(t *testing.T) {
	lc, err := newLexiconClassifierFromJSON(buildValidLexiconJSON(t, nil))
	if err != nil {
		t.Fatalf("合法词库加载失败: %v", err)
	}
	if lc.Category() != "A1-06" {
		t.Fatalf("category 期望 A1-06，实际 %s", lc.Category())
	}
	if lc.Version() != "v2026.09.15" {
		t.Fatalf("version 期望 v2026.09.15，实际 %s", lc.Version())
	}
	if lc.RuleCount() != 3 {
		t.Fatalf("总词条数期望 3，实际 %d", lc.RuleCount())
	}

	// exact 命中
	cat, conf, match := lc.Classify("违禁词甲")
	if cat != "A1-06" || conf != 1.0 || match != "违禁词甲" {
		t.Fatalf("exact 命中不符: cat=%s conf=%f match=%q", cat, conf, match)
	}
	// contains 命中
	cat, conf, match = lc.Classify("前后文违规词乙中间的")
	if cat != "A1-06" || conf != 0.9 || match != "违规词乙" {
		t.Fatalf("contains 命中不符: cat=%s conf=%f match=%q", cat, conf, match)
	}
	// regex 命中
	cat, conf, _ = lc.Classify("号码是13812345678对吗")
	if cat != "A1-06" || conf != 0.8 {
		t.Fatalf("regex 命中不符: cat=%s conf=%f", cat, conf)
	}
	// 未命中
	cat, conf, match = lc.Classify("完全正常的句子")
	if cat != "" || conf != 0 || match != "" {
		t.Fatalf("未命中应返回空值: cat=%q conf=%f match=%q", cat, conf, match)
	}
}

// TestLexiconCaseAndWidthFolding：归一化——大小写折叠 + 全角半角 + 去空白。
func TestLexiconCaseAndWidthFolding(t *testing.T) {
	lc, err := newLexiconClassifierFromJSON(buildValidLexiconJSON(t, func(f *lexiconFile) {
		f.Rules = []lexiconRule{
			{ID: "t1", Keyword: "Hello", Type: "exact", Weight: 1.0,
				AddedAt: "2026-09-15", Submitter: "a", Reviewer: "b"},
			{ID: "t2", Keyword: "关键词", Type: "contains", Weight: 1.0,
				AddedAt: "2026-09-15", Submitter: "a", Reviewer: "b"},
		}
	}))
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}

	// exact：大小写 + 空白 + 全角
	if cat, _, _ := lc.Classify("  h e l l o  "); cat != "A1-06" {
		t.Fatal("exact 大小写+空白归一化失败")
	}
	if cat, _, _ := lc.Classify("ＨＥＬＬＯ"); cat != "A1-06" {
		t.Fatal("exact 全角转半角失败")
	}
	// contains：空白不影响
	if cat, _, _ := lc.Classify("前 关 键 词 后"); cat != "A1-06" {
		t.Fatal("contains 去空白归一化失败")
	}
}

// TestLexiconValidation：强校验——6 条规则全部生效。
func TestLexiconValidation(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*lexiconFile)
	}{
		{"schema_version 不匹配", func(f *lexiconFile) { f.SchemaVersion = "2.0" }},
		{"category 非法", func(f *lexiconFile) { f.Category = "A9-99" }},
		{"category 空", func(f *lexiconFile) { f.Category = "" }},
		{"level 不一致", func(f *lexiconFile) { f.Level = "中" }}, // A1-06 级别=高
		{"空 rules", func(f *lexiconFile) { f.Rules = nil }},
		{"submitter=reviewer", func(f *lexiconFile) {
			f.Rules[0].Submitter = "same"
			f.Rules[0].Reviewer = "same"
		}},
		{"weight 超上限", func(f *lexiconFile) { f.Rules[0].Weight = 1.5 }},
		{"weight 负数", func(f *lexiconFile) { f.Rules[0].Weight = -0.1 }},
		{"非法 type", func(f *lexiconFile) { f.Rules[0].Type = "fuzzy" }},
		{"regex 编译失败", func(f *lexiconFile) {
			f.Rules[0].Type = "regex"
			f.Rules[0].Keyword = "[unclosed"
		}},
		{"空 keyword", func(f *lexiconFile) { f.Rules[0].Keyword = "" }},
		{"重复 id", func(f *lexiconFile) {
			f.Rules[1].ID = f.Rules[0].ID
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := buildValidLexiconJSON(t, tc.mod)
			_, err := newLexiconClassifierFromJSON(data)
			if err == nil {
				t.Fatalf("期望加载失败（%s），实际成功", tc.name)
			}
		})
	}
}

// TestLexiconLevelConsistency：不同类目加载时 level 校验正确。
func TestLexiconLevelConsistency(t *testing.T) {
	// A1-07 默认级别 = 中
	data := buildValidLexiconJSON(t, func(f *lexiconFile) {
		f.Category = "A1-07"
		f.Level = "中"
		for i := range f.Rules {
			f.Rules[i].ID = strings.Replace(f.Rules[i].ID, "a1-06", "a1-07", 1)
		}
	})
	lc, err := newLexiconClassifierFromJSON(data)
	if err != nil {
		t.Fatalf("A1-07 中级别加载失败: %v", err)
	}
	if lc.Category() != "A1-07" {
		t.Fatal("A1-07 类目不符")
	}

	// A1-07 如果填"高"应该失败
	data = buildValidLexiconJSON(t, func(f *lexiconFile) {
		f.Category = "A1-07"
		f.Level = "高" // 错：A1-07 默认 = 中
		for i := range f.Rules {
			f.Rules[i].ID = strings.Replace(f.Rules[i].ID, "a1-06", "a1-07", 1)
		}
	})
	if _, err := newLexiconClassifierFromJSON(data); err == nil {
		t.Fatal("A1-07 填高应失败（默认级别是中）")
	}
}

// TestLexiconMaxKeywordRunes：最长关键词计算正确（用于 P-WINDOW-CHARS 派生）。
func TestLexiconMaxKeywordRunes(t *testing.T) {
	lc, err := newLexiconClassifierFromJSON(buildValidLexiconJSON(t, func(f *lexiconFile) {
		f.Rules = []lexiconRule{
			{ID: "s", Keyword: "短", Type: "exact", Weight: 1.0,
				AddedAt: "2026-09-15", Submitter: "a", Reviewer: "b"},
			{ID: "l", Keyword: "这是一个很长的关键词超过其他", Type: "contains", Weight: 1.0,
				AddedAt: "2026-09-15", Submitter: "a", Reviewer: "b"},
			{ID: "m", Keyword: "中等长度", Type: "variant", Weight: 1.0,
				AddedAt: "2026-09-15", Submitter: "a", Reviewer: "b"},
		}
	}))
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if n := lc.MaxKeywordRunes(); n != 14 {
		t.Fatalf("最长关键词期望 14 runes，实际 %d", n)
	}
}

// TestLexiconSHA256：sha256 计算正确（64 hex 字符）。
func TestLexiconSHA256(t *testing.T) {
	data := []byte(`test`)
	sum := lexiconSHA256(data)
	if len(sum) != 64 {
		t.Fatalf("sha256 hex 长度期望 64，实际 %d", len(sum))
	}
	// 已知值：sha256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
	expected := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
	if sum != expected {
		t.Fatalf("sha256 不匹配:\n期望: %s\n实际: %s", expected, sum)
	}
}

// ---- AC 自动机单测 ----

func buildTestAC(patterns []string) *acAutomaton {
	ps := make([]acPattern, len(patterns))
	for i, p := range patterns {
		ps[i] = acPattern{text: p, rule: lexiconRule{ID: fmtTestID(i), Keyword: p, Weight: 1.0}}
	}
	return newACAutomaton(ps)
}

func fmtTestID(i int) string { return fmt.Sprintf("kw-test-%04d", i) }

// TestACBasicMatch：基础多模式匹配。
func TestACBasicMatch(t *testing.T) {
	ac := buildTestAC([]string{"he", "she", "his", "hers"})
	hit := ac.matchFirst("ahishers")
	if hit == nil {
		t.Fatal("应命中")
	}
	// 第一个命中应该是 "his"（在位置 1 开始匹配）—— 等等，从"ahishers"看：
	// a h i s h e r s
	//  0 1 2 3 4 5 6 7
	// i=1 'h' → 到 he 路径的 h
	// i=2 'i' → 到 his 的 hi → his 匹配
	if hit.rule.Keyword != "his" {
		t.Fatalf("第一个命中期望 his，实际 %q", hit.rule.Keyword)
	}
	if hit.start != 1 || hit.end != 4 {
		t.Fatalf("位置期望 [1,4)，实际 [%d,%d)", hit.start, hit.end)
	}
}

// TestACNoMatch：无命中返回 nil。
func TestACNoMatch(t *testing.T) {
	ac := buildTestAC([]string{"abc", "def"})
	if ac.matchFirst("xyz") != nil {
		t.Fatal("无命中应返回 nil")
	}
}

// TestACChinese：中文模式匹配。
func TestACChinese(t *testing.T) {
	ac := buildTestAC([]string{"违规词", "敏感词"})
	hit := ac.matchFirst("这里有违规词出现")
	if hit == nil {
		t.Fatal("应命中违规词")
	}
	if hit.rule.Keyword != "违规词" {
		t.Fatalf("期望 违规词，实际 %q", hit.rule.Keyword)
	}
}

// TestACEmptyPatterns：空模式列表。
func TestACEmptyPatterns(t *testing.T) {
	ac := buildTestAC(nil)
	if ac.patternCount() != 0 {
		t.Fatal("模式数应为 0")
	}
	if ac.matchFirst("anything") != nil {
		t.Fatal("空模式不应命中")
	}
}

// TestACPatternCountAndNodeCount：计数正确。
func TestACPatternCountAndNodeCount(t *testing.T) {
	ac := buildTestAC([]string{"a", "ab", "abc"})
	if ac.patternCount() != 3 {
		t.Fatalf("模式数期望 3，实际 %d", ac.patternCount())
	}
	if ac.nodeCount() < 3 {
		t.Fatalf("节点数至少 3，实际 %d", ac.nodeCount())
	}
}

// TestACMaxPatternLen：最长模式长度。
func TestACMaxPatternLen(t *testing.T) {
	ac := buildTestAC([]string{"短", "中等长度", "最长的一个模式"})
	if ac.maxPatternLen() != 7 {
		t.Fatalf("最长模式期望 7 runes，实际 %d", ac.maxPatternLen())
	}
}
