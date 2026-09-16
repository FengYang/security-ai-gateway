package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// OG-0 输出侧误杀基线取数（研发计划 M0 首个任务）。
//
// 目的：现有 guardrail 规则是按**输入侧**（用户提问）设计并标定的；
// 输出侧（模型生成内容）文本形态差异极大——Markdown 表格分隔行、代码块、
// JSON 片段、长编号等。本测试把既有语料中的 benign（40）与 known_fp（6）
// 文本按**真实 LLM 输出形态**做确定性变换后复跑现有规则，得出：
//   - 各形态的输出侧误杀率
//   - **形态增量**（形态误杀率 − plain 对照误杀率）＝该形态自身引入的误杀
//   - 逐条明细（哪条文本经哪种形态变换后命中哪个规则族）
//   - 规则族分布（pii / sql_injection / prompt_injection）
//
// 设计要点：`plain` 为**对照组**（恒等变换）。只有减去 plain 基线，才能区分
// 「基础文本本就误杀」与「输出形态引入误杀」——这是后续动作表分级的关键输入。
// `long_number` 是**最坏情形探针**（向每条文本注入 16 位编号），用于量化
// 「银行卡规则对任意 16-19 位数字串无差别命中」的水位，不代表该条文本的真实误杀。
//
// 约束（OG-0 验收）：**不改生产代码、不污染入库语料**——本文件只读 corpus.jsonl，
// 变换在内存中确定性完成，不写回任何语料文件。
//
// 语料缺失 → Skip（与 guardrail_bench_test.go 同语义），避免干净检出即红。
const outformCorpusRelPath = "testdata/guardrail-bench/corpus.jsonl"

// outformKind 输出形态变换器。
type outformKind struct {
	name string
	mk   func(text string) string
}

// outformKinds 真实输出形态（研发计划 OG-0 点名：Markdown 表格/代码块/长编号/JSON 片段）+ plain 对照。
var outformKinds = []outformKind{
	{
		name: "plain", // 对照组：恒等，复现输入侧既有基线
		mk:   func(text string) string { return text },
	},
	{
		// Markdown 表格：分隔行含连续短横（|---|---|），是 SQL 注释规则 `--` 的高危误杀源。
		name: "md_table",
		mk: func(text string) string {
			return "| 项目 | 说明 |\n| --- | --- |\n| 内容 | " + text + " |"
		},
	},
	{
		// 代码块：模型讲解 SQL/代码语法时的常见形态，含 select/from 等词。
		name: "code_block",
		mk: func(text string) string {
			return "```text\n" + text + "\n```"
		},
	},
	{
		// JSON 片段：结构化输出，值内嵌原文。
		name: "json_frag",
		mk: func(text string) string {
			b, _ := json.Marshal(text)
			return `{"status":"ok","message":` + string(b) + `,"trace_id":"20260915T120000Z"}`
		},
	},
	{
		// 长编号（最坏情形探针）：模型给出订单号/时间戳等 16-19 位长数字。
		name: "long_number",
		mk: func(text string) string {
			return text + "\n参考编号：1234567890123456\n时间戳：1757923200123"
		},
	},
}

func TestGuardrailOutformBaseline(t *testing.T) {
	path := filepath.FromSlash(outformCorpusRelPath)
	f, err := os.Open(path)
	if err != nil {
		if strings.EqualFold(os.Getenv("GUARDRAIL_BENCH"), "skip") {
			t.Skipf("GUARDRAIL_BENCH=skip：显式跳过输出侧基线（语料未生成，期望文件：%s）", path)
		}
		t.Fatalf("基准语料缺失，输出侧基线未执行：%s\n标准做法：先运行 scripts/build-guardrail-bench.ps1 生成语料。", path)
	}
	defer f.Close()

	// 收集 benign（含 known_fp）基础文本。
	type baseCase struct {
		id      string
		text    string
		knownFP bool
	}
	var bases []baseCase
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var c benchCase
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatalf("语料解析失败（%s）：%v", line, err)
		}
		if c.Scope == "benign" && c.Expect == "allow" {
			bases = append(bases, baseCase{id: c.ID, text: c.Text, knownFP: c.KnownFP})
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("读取语料失败：%v", err)
	}
	if len(bases) == 0 {
		t.Fatalf("语料不含 benign 基础文本（scope=benign & expect=allow）")
	}

	g := newGuardrail()

	type formStat struct {
		benignTotal, benignFP        int // benign（非 known_fp）
		knownFPTotal, knownFPFlagged int
	}
	byForm := map[string]*formStat{}
	byFamily := map[string]int{}   // 规则族分布（命中条数，全部形态合计）
	fpByFamily := map[string]int{} // benign（非 known_fp）误杀按族分布
	var benignFPRow []string       // 仅 benign 误杀明细

	for _, mk := range outformKinds {
		st := &formStat{}
		byForm[mk.name] = st
		for _, b := range bases {
			hit := g.check(mk.mk(b.text))
			if b.knownFP {
				st.knownFPTotal++
			} else {
				st.benignTotal++
			}
			if hit == nil {
				continue
			}
			byFamily[hit.Category]++
			if b.knownFP {
				st.knownFPFlagged++
				continue
			}
			st.benignFP++
			fpByFamily[hit.Category]++
			benignFPRow = append(benignFPRow, fmt.Sprintf("%s [%-11s] 族=%-16s 命中=%q", b.id, mk.name, hit.Category, hit.Match))
		}
	}

	// ---- 报告 ----
	t.Logf("OG-0 输出侧误杀基线：基础文本 %d 条 × 形态 %d 种（语料 %s）", len(bases), len(outformKinds), path)
	t.Logf("  benign 基础文本 = %d 条；known_fp = %d 条", byForm["plain"].benignTotal, byForm["plain"].knownFPTotal)

	forms := make([]string, 0, len(byForm))
	for k := range byForm {
		forms = append(forms, k)
	}
	sort.Strings(forms)

	base := byForm["plain"]
	t.Logf("  %-12s %-10s %-14s %-10s", "形态", "benign误杀", "误杀率", "形态增量")
	for _, name := range forms {
		st := byForm[name]
		delta := st.benignFP - base.benignFP
		t.Logf("  %-12s %-10s %-14s %+-10d", name,
			fmt.Sprintf("%d/%d", st.benignFP, st.benignTotal), fmt.Sprintf("%.1f%%", pct(st.benignFP, st.benignTotal)), delta)
	}
	t.Logf("known_fp（规则固有误报水位，逐形态）：")
	for _, name := range forms {
		st := byForm[name]
		t.Logf("  %-12s %d/%d", name, st.knownFPFlagged, st.knownFPTotal)
	}

	fams := make([]string, 0, len(byFamily))
	for k := range byFamily {
		fams = append(fams, k)
	}
	sort.Strings(fams)
	for _, cat := range fams {
		t.Logf("规则族分布（全形态合计）%-16s 命中 %-4d 条（其中 benign 误杀 %d 条）", cat, byFamily[cat], fpByFamily[cat])
	}

	for _, d := range benignFPRow {
		t.Logf("  误杀：%s", d)
	}

	if base.benignTotal == 0 {
		t.Fatalf("benign 用例为 0，基线未取到数据")
	}
}

func pct(n, d int) float64 {
	if d == 0 {
		return 0
	}
	return float64(n) / float64(d) * 100
}
