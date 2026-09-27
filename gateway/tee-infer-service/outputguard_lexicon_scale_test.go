// 输出侧内容审查 — 官方建设规模档**报告项**（不设达标闸门）。
//
// 口径：TC260-003 §8.1（转化前技术文件，本体 §4.2 已核）——
// 词库总规模不宜少于 10000 个；A.1 每类不宜少于 200 个、A.2 每类不宜少于 100 个。
//
// 为什么只报告不设闸门（D-LLM-4 材料 §2.3③）：建设规模是**内容供给**问题（内容源/采购/交付周期），
// 把未达标设成上线门禁会让版本永远发不出去；故按"如实呈现量级差距"处理，逐类目列示，
// **不得用总均值掩盖弱类目**（§6.1.2 同纪律）。
package main

import (
	"strings"
	"testing"
)

// 官方建设规模口径（仅用于报告与导出对照）。
const (
	lexScaleTotalTarget = 10000
	lexScaleA1PerCat    = 200
	lexScaleA2PerCat    = 100
)

// lexScaleCountExempt A.1 中**不按"词条数"计数**的类目（书面说明，非静默放行）：
//   - A1-07：规则形态为**正则**（迁移自输入侧 guardrail），不与关键词同尺度；
//   - A1-08：兜底类，本体明定不单独建词库（仅作映射落点），加载后不出现。
var lexScaleCountExempt = map[string]string{
	"A1-07": "正则类目（regex/injection.json，迁移自输入侧 guardrail），不按关键词条数计",
}

// TestPolicyLexiconKeywordsSelfClassify 不变式：**任一关键词的文本必归其自身类目**。
//
// 这是"分类目统计与审计归因正确"的底线（§6.1.2 不得用总均值掩盖弱类目）：
// Classify(K) 必须返回 K 所属类目；否则说明存在跨类目抢占（低序类目的短词面抢走长词面）
// 或 regex 类目误抢关键词。覆盖**全部关键词**——黄金集正例受 2000 条上限约束，
// 每类只覆盖前 ~23 条规则，不足以兜住这类缺陷（2026-09-27 由此发现 A4-02 抢 A4-03）。
func TestPolicyLexiconKeywordsSelfClassify(t *testing.T) {
	reg, err := loadPolicyDir(policyDirReal)
	if err != nil {
		t.Fatalf("加载真实 policy/ 失败: %v", err)
	}
	total, bad := 0, 0
	for _, cat := range reg.Categories() {
		for _, r := range allRulesOf(reg.byCategory[cat]) {
			if r.Type == ruleTypeRegex {
				continue // 正则源码不是可输入文本，不参与自归类
			}
			total++
			if got, _, _ := reg.Classify(r.Keyword); got != cat {
				bad++
				if bad <= 10 {
					t.Errorf("关键词未归自身类目：%s（应 %s）→ 实际 %q", r.ID, cat, got)
				}
			}
		}
	}
	if bad > 0 {
		t.Fatalf("共 %d/%d 条关键词被划归他类（跨类目抢占 / regex 误抢）", bad, total)
	}
	t.Logf("关键词自归类不变式通过：%d 条全部归入自身类目", total)
}

// TestLexiconRegexNormalizeModes regex 的**匹配文本档**与输入侧 guardrail 同口径验证
// （2026-09-27 修复：改造前 regex 一律按原文匹配 → 输出侧对全角/空格/连字符分隔的 PII 与全角 SQL 漏检）。
//
//   - A4-06（PII）档 = compact（半角化 ＋ 去空白与连字符）；
//   - A1-07（SQL）档 = fold（半角化 ＋ **保留空白**：`\s+` 依赖空白，不可用去空白的档位）。
func TestLexiconRegexNormalizeModes(t *testing.T) {
	reg, err := loadPolicyDir(policyDirReal)
	if err != nil {
		t.Fatalf("加载真实 policy/ 失败: %v", err)
	}
	cases := []struct {
		name string
		text string
		want string
	}{
		{"PII 全角数字手机号", "我的手机号１３８１２３４５６７８请回电", "A4-06"},
		{"PII 空格分隔银行卡", "卡号 6222 0212 3456 7890 123 已核对", "A4-06"},
		{"PII 连字符分隔身份证", "证件 110105-19491231-002X 已登记", "A4-06"},
		{"SQL 全角 union select", "试试ＵＮＩＯＮ ＳＥＬＥＣＴ 1,2,3", "A1-07"},
		{"SQL 多空白依赖（fold 保留空白）", "第一步执行 drop  table audit_log", "A1-07"},
	}
	for _, tc := range cases {
		got, _, _ := reg.Classify(tc.text)
		if got != tc.want {
			t.Errorf("%s：期望命中 %s，实际 %q（regex 匹配文本档未生效？）", tc.name, tc.want, got)
		}
	}
}

// TestPolicyOutputSideGateNotRegress 输出侧门禁（**不可回退**）：指标取自**输出侧词库 + 题库**自身。
//
//   - output_detect = 黄金正例"归入自身类目"的比例（检出）→ 不得下降；
//   - output_fp     = 黄金负例被任一类目命中的比例（误杀）→ 不得上升。
//
// 与版本门禁的三维（rule_detect / semantic_detect / fp）互补：那三维的评测对象是**输入侧**
// guardrail 分类器，**不覆盖 policy/ 词库内容**（2026-09-27 评审发现）。基线登记在
// `policy/versions/index.json` 的 `baseline.output_detect` / `baseline.output_fp`。
func TestPolicyOutputSideGateNotRegress(t *testing.T) {
	reg, err := loadPolicyDir(policyDirReal)
	if err != nil {
		t.Fatalf("加载真实 policy/ 失败: %v", err)
	}
	_, sets := loadGoldenSets(t)
	pos, neg := sets[goldenKindPositive].Cases, sets[goldenKindNegative].Cases
	if len(pos) == 0 || len(neg) == 0 {
		t.Fatalf("题库不完整：正例 %d 条、负例 %d 条", len(pos), len(neg))
	}
	hit := 0
	for _, c := range pos {
		if got, _, _ := reg.Classify(c.Text); got == c.Category {
			hit++
		}
	}
	fp := 0
	for _, c := range neg {
		if got, _, _ := reg.Classify(c.Text); got != "" {
			fp++
		}
	}
	detect := float64(hit) / float64(len(pos))
	fpRate := float64(fp) / float64(len(neg))
	t.Logf("输出侧实测：detect=%d/%d=%.4f  fp=%d/%d=%.4f",
		hit, len(pos), detect, fp, len(neg), fpRate)

	idx, err := loadPolicyVersionIndex(policyDirReal)
	if err != nil {
		if PolicyLoadErrorKind(err) == policyErrVersionsNotConfigured {
			t.Skipf("版本库未启用（无 %s/%s）：输出侧门禁无基线可比，跳过",
				policyVersionsDirName, policyVersionsIndexName)
		}
		t.Fatalf("读取版本索引失败: %v", err)
	}
	if idx.Baseline == nil || idx.Baseline.OutputDetect == nil || idx.Baseline.OutputFP == nil {
		t.Fatalf("输出侧基线未登记（baseline.output_detect / output_fp）——"+
			"版本门禁的三维只覆盖输入侧分类器，不覆盖词库内容；请先把本次实测值登记入 %s/%s 的 baseline",
			policyVersionsDirName, policyVersionsIndexName)
	}
	if detect < *idx.Baseline.OutputDetect {
		t.Errorf("输出侧检出回退：detect %.4f < 基线 %.4f", detect, *idx.Baseline.OutputDetect)
	}
	if fpRate > *idx.Baseline.OutputFP {
		t.Errorf("输出侧误杀上升：fp %.4f > 基线 %.4f", fpRate, *idx.Baseline.OutputFP)
	}
}

// TestPolicyLexiconScaleReport 官方建设规模档报告项（**不设闸门**）。
func TestPolicyLexiconScaleReport(t *testing.T) {
	reg, err := loadPolicyDir(policyDirReal)
	if err != nil {
		t.Fatalf("加载真实 policy/ 失败: %v", err)
	}

	total, a1Total, a2Total := 0, 0, 0
	var a1Weak, a2Weak []string
	t.Logf("各类目词条数（内部类目 ID = 词库文件）：")
	for _, cat := range reg.Categories() {
		n := reg.byCategory[cat].RuleCount()
		total += n
		switch {
		case strings.HasPrefix(cat, "A1-"):
			a1Total += n
			if _, exempt := lexScaleCountExempt[cat]; exempt {
				t.Logf("  %-8s %5d  （豁免计数：%s）", cat, n, lexScaleCountExempt[cat])
				continue
			}
			if n < lexScaleA1PerCat {
				a1Weak = append(a1Weak, cat)
			}
			t.Logf("  %-8s %5d  （A.1 目标 ≥%d）", cat, n, lexScaleA1PerCat)
		case strings.HasPrefix(cat, "A2-"):
			a2Total += n
			if n < lexScaleA2PerCat {
				a2Weak = append(a2Weak, cat)
			}
			t.Logf("  %-8s %5d  （A.2 目标 ≥%d）", cat, n, lexScaleA2PerCat)
		default:
			t.Logf("  %-8s %5d", cat, n)
		}
	}

	// A.1 官方口径共 8 类：A1-07 豁免计数、A1-08 兜底类无词库（未加载）。
	t.Logf("—— 官方建设规模档对照（报告项，不设闸门）——")
	t.Logf("词库总条数 %d（官方 ≥%d）", total, lexScaleTotalTarget)
	if total < lexScaleTotalTarget {
		t.Logf("  缺口 %d 条：属内容供给量级差（内容源/采购/交付），非工程门禁", lexScaleTotalTarget-total)
	}
	t.Logf("A.1 条数合计 %d（可计数类目 %d/6 类达标 ≥%d；A1-07 豁免计数、A1-08 兜底类无词库）",
		a1Total, 6-len(a1Weak), lexScaleA1PerCat)
	t.Logf("A.2 条数合计 %d（%d/%d 类达标 ≥%d）", a2Total, 9-len(a2Weak), 9, lexScaleA2PerCat)
	if len(a1Weak) > 0 {
		t.Logf("  A.1 未达类目：%s", strings.Join(a1Weak, "、"))
	}
	if len(a2Weak) > 0 {
		t.Logf("  A.2 未达类目：%s", strings.Join(a2Weak, "、"))
	}
}
