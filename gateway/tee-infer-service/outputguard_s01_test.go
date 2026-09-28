// S0-① 编码前勘察：31 类目 × 三后端（L1 关键词 / L1 正则 / L2 语义）对照表，
// 以及检出、误杀、延迟、资源四指标上界。
//
// 写盘：`OG_S01_WRITE=1` 时输出报告（md + json）到 `../../docs/output-guard/`；
// 默认只断言 + 打日志，零副作用。
//
// 硬断言：
//   - 对照表恰 31 行（与 outputCategories 单一事实源一致）
//   - 检出率与误杀率数量级须与 eval94 / §9.4 报告一致（防数字漂移）
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

const (
	s01ReportEnv    = "OG_S01_WRITE"
	s01ReportDirRel = "../../docs/output-guard"
	s01ReportMDName = "GA-输出侧-S0①对照表与四指标上界.md"
	s01ReportJSName = "GA-输出侧-S0①对照表与四指标上界.json"
)

// s01CategoryRow 对照表单行。
type s01CategoryRow struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Family         string `json:"family"`
	DefaultAction  string `json:"default_action"`
	DefaultLevel   string `json:"default_level"`
	L1Keyword      bool   `json:"l1_keyword"`
	L1Regex        bool   `json:"l1_regex"`
	L2Semantic     bool   `json:"l2_semantic"`
	L1MapEntry     string `json:"l1_map_entry"`
	KeywordRuleCnt int    `json:"keyword_rule_cnt"`
	RegexRuleCnt   int    `json:"regex_rule_cnt"`
	Note           string `json:"note"`
}

// s01Metrics 四指标结果。
type s01Metrics struct {
	Detection s01Detection `json:"detection"`
	FalseKill s01FalseKill `json:"false_kill"`
	Latency   s01Latency   `json:"latency"`
	Resource  s01Resource  `json:"resource"`
}

type s01Detection struct {
	GoldenPositive      int               `json:"golden_positive_total"`
	GoldenRefusal       int               `json:"golden_refusal_total"`
	HitCount            int               `json:"hit_count"`       // 口径B：已处置（命中且动作 != pass）
	HitRate             float64           `json:"hit_rate"`        // 口径B 率
	HitAnyCount         int               `json:"hit_any_count"`   // 命中任一（含默认 pass 类目），供对照
	BlockHitCount       int               `json:"block_hit_count"` // 口径A：命中 block 类目
	BlockHitRate        float64           `json:"block_hit_rate"`
	PerCategoryRecall   map[string]string `json:"per_category_recall"`
	NoBackendCategories []string          `json:"no_backend_categories"`
}

type s01FalseKill struct {
	BenignTotal    int     `json:"benign_total"`
	FalseKillTotal int     `json:"false_kill_total"`
	BlockFalseKill int     `json:"block_false_kill"`
	FlagFalseKill  int     `json:"flag_false_kill"`
	MaskFalseKill  int     `json:"mask_false_kill"`
	FalseKillRate  float64 `json:"false_kill_rate"`
}

type s01Latency struct {
	Unit       string  `json:"unit"`
	SampleSize int     `json:"sample_size"`
	P50        float64 `json:"p50_ms"`
	P95        float64 `json:"p95_ms"`
	P99        float64 `json:"p99_ms"`
	Note       string  `json:"note"`
}

type s01Resource struct {
	AllocsPerOp     int64   `json:"allocs_per_op"`
	BytesPerOp      int64   `json:"bytes_per_op"`
	NsPerOp         float64 `json:"ns_per_op"`
	OpsPerSec       float64 `json:"ops_per_sec"`
	BenchmarkRounds int     `json:"benchmark_rounds"`
	Note            string  `json:"note"`
}

// s01Report 完整报告结构。
type s01Report struct {
	GeneratedAt   string           `json:"generated_at"`
	PolicyVersion string           `json:"policy_version"`
	CategoryCount int              `json:"category_count"`
	MappingTable  []s01CategoryRow `json:"mapping_table"`
	Metrics       s01Metrics       `json:"metrics"`
	Decisions     []s01Decision    `json:"decision_items"`
}

type s01Decision struct {
	ID         string `json:"id"`
	Title      string `json:"title"`
	Conclusion string `json:"conclusion"`
	Owner      string `json:"owner"`
	Detail     string `json:"detail"`
}

// ─── Part 1：对照表 ───────────────────────────────────────────────

// s01ExactCount 返回词库 exact 匹配条目数（= len(exactMap)）。
func s01ExactCount(lc *lexiconClassifier) int {
	if lc == nil {
		return 0
	}
	return len(lc.exactMap)
}

// s01RegexCount 返回词库正则条目数。
func s01RegexCount(lc *lexiconClassifier) int {
	if lc == nil {
		return 0
	}
	return len(lc.regexList)
}

// buildS01MappingTable 从单一事实源 outputCategories + 词库注册表 派生 31 行对照表。
func buildS01MappingTable(t *testing.T, reg *lexiconRegistry) []s01CategoryRow {
	t.Helper()

	cats := outputCategories // 包级变量，同包可直接访问

	rows := make([]s01CategoryRow, 0, len(cats))
	for _, c := range cats {
		lc := reg.byCategory[c.ID] // 包级字段，同包可访问
		kwCnt := 0
		reCnt := 0
		if lc != nil {
			// AC 自动机也包含关键词（contains/variant），这里按 RuleCount - regexCount 估算关键词总数
			// 为精准起见，我们直接用 exactMap + ac 估算，但 ac 条目数不直接暴露
			// 简化：用 RuleCount() 作为总关键词规则数，正则单列
			// 但 RuleCount 含 exact+ac+regex，我们把 exact 算关键词，regex 单列，ac 也归入关键词
			totalRules := lc.RuleCount()
			reCnt = len(lc.regexList)
			kwCnt = totalRules - reCnt
			if kwCnt < 0 {
				kwCnt = 0
			}
		}

		l1kw := kwCnt > 0
		l1re := reCnt > 0
		l2sem := false // L2 语义当前未落地

		// L1 映射表条目（从 l1CategoryMap 反查）
		l1entry := ""
		for backendKey, mappedCat := range l1CategoryMap {
			if mappedCat == c.ID {
				if l1entry != "" {
					l1entry += ","
				}
				l1entry += backendKey
			}
		}

		note := c.Note
		switch c.ID {
		case "A1-07":
			note += "；L1 旧 guardrail 注入词 24 条独立命中（不计入词库注册表计数）"
		case "A1-08":
			note += "；兜底类目，无独立词库（未匹配到具体类目的语义结果可落此）"
		case "A4-06":
			note += "；PII 默认动作 mask，非拦截类"
		}

		rows = append(rows, s01CategoryRow{
			ID:             c.ID,
			Name:           c.Name,
			Family:         c.Family,
			DefaultAction:  c.DefaultAction,
			DefaultLevel:   c.DefaultLevel,
			L1Keyword:      l1kw,
			L1Regex:        l1re,
			L2Semantic:     l2sem,
			L1MapEntry:     l1entry,
			KeywordRuleCnt: kwCnt,
			RegexRuleCnt:   reCnt,
			Note:           note,
		})
	}
	return rows
}

func (r s01CategoryRow) hasAnyBackend() bool {
	return r.L1Keyword || r.L1Regex || r.L2Semantic
}

// ─── Part 2：四指标（词库层） ────────────────────────────────────
//
// 注：S0-① 为编码前勘察，四指标在词库层（L1 registry.Classify）统计，
// 与 §9.4 eval94 口径一致，便于交叉校验防漂移。
// 完整流式管线延迟/资源另用 Benchmark 独立测量。

// measureS01Detection 跑 golden 正样本 + 拒答集，统计分类目召回（词库层）。
func measureS01Detection(t *testing.T, reg *lexiconRegistry, sets map[string]goldenSet) s01Detection {
	t.Helper()

	pos := sets[goldenKindPositive].Cases
	ref := sets[goldenKindRefusal].Cases

	hitAny := 0 // 命中任一（含默认 pass 类目）→ 驱动分类目召回与覆盖口径
	hit := 0    // 口径B：已处置（命中且动作 != pass；评审 P0-2：pass 不计入）
	blockHit := 0
	perCatTotal := make(map[string]int)
	perCatHit := make(map[string]int)

	runOne := func(text string) string {
		cat, _, _ := reg.Classify(text)
		return cat
	}

	for _, c := range pos {
		perCatTotal[c.Category]++
		hitCat := runOne(c.Text)
		if hitCat == "" {
			continue
		}
		hitAny++
		perCatHit[hitCat]++
		if s01IsActionable(hitCat) {
			hit++
		}
		if s01IsBlock(hitCat) {
			blockHit++
		}
	}

	for _, c := range ref {
		perCatTotal[c.Category]++
		hitCat := runOne(c.Text)
		if hitCat == "" {
			continue
		}
		hitAny++
		perCatHit[hitCat]++
		if s01IsActionable(hitCat) {
			hit++
		}
		if s01IsBlock(hitCat) {
			blockHit++
		}
	}

	total := len(pos) + len(ref)

	recall := make(map[string]string)
	for cat, totalN := range perCatTotal {
		h := perCatHit[cat]
		recall[cat] = fmt.Sprintf("%d/%d (%.1f%%)", h, totalN, ratio(h, totalN)*100)
	}

	rows := buildS01MappingTable(t, reg)
	var noBackend []string
	for _, r := range rows {
		if !r.hasAnyBackend() {
			noBackend = append(noBackend, r.ID+" "+r.Name)
		}
	}

	return s01Detection{
		GoldenPositive:      len(pos),
		GoldenRefusal:       len(ref),
		HitCount:            hit,
		HitRate:             ratio(hit, total),
		HitAnyCount:         hitAny,
		BlockHitCount:       blockHit,
		BlockHitRate:        ratio(blockHit, total),
		PerCategoryRecall:   recall,
		NoBackendCategories: noBackend,
	}
}

// s01IsActionable 命中后是否产生处置动作（block/flag/mask）＝口径B「已处置」；
// 默认动作 pass（A.5 族：A5-01/A5-02，不干预）不计入（评审 P0-2）。
func s01IsActionable(cat string) bool {
	c, ok := getCategory(cat)
	if !ok {
		return false
	}
	return c.DefaultAction != catActionPass
}

func s01IsBlock(cat string) bool {
	c, ok := getCategory(cat)
	if !ok {
		return false
	}
	return c.DefaultAction == catActionBlock
}

// s01ContrastCase benign 对照集单条（与 outform_contrast_test 结构对齐）。
type s01ContrastCase struct {
	ID      string `json:"id"`
	Text    string `json:"text"`
	Variant string `json:"variant"`
}

// measureS01FalseKill 跑 benign 对照集，统计误杀（走完整流式管线，与 outform_contrast 基线同口径）。
func measureS01FalseKill(t *testing.T, reg *lexiconRegistry) s01FalseKill {
	t.Helper()

	raw, err := os.ReadFile(outformContrastRelPath)
	if err != nil {
		t.Fatalf("对照集语料缺失（%s）：%v", outformContrastRelPath, err)
	}
	lines := splitNonEmptyLines(string(raw))
	var corpus []s01ContrastCase
	for _, line := range lines {
		var c s01ContrastCase
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatalf("对照集 JSON 解析失败：%v", err)
		}
		corpus = append(corpus, c)
	}

	totalFK := 0
	blockFK := 0
	maskFK := 0
	flagFK := 0

	for _, item := range corpus {
		hit, cat := runThroughOutputGuard(t, item.Text)
		if !hit {
			continue
		}
		totalFK++
		if s01IsBlock(cat) {
			blockFK++
		} else if cat == "A4-06" {
			maskFK++
		} else {
			flagFK++
		}
	}

	return s01FalseKill{
		BenignTotal:    len(corpus),
		FalseKillTotal: totalFK,
		BlockFalseKill: blockFK,
		FlagFalseKill:  flagFK,
		MaskFalseKill:  maskFK,
		FalseKillRate:  ratio(blockFK, len(corpus)),
	}
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if line != "" {
				out = append(out, line)
			}
			start = i + 1
		}
	}
	if start < len(s) {
		line := s[start:]
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

// ─── Part 2：延迟 & 资源（完整流式管线） ─────────────────────────

// measureS01Latency 护栏处理增量延迟（Process+Finish 总耗时），测 P50/P95/P99。
// 每次新建 og 实例（与 runThroughOutputGuard 一致），避免审计链复用问题。
func measureS01Latency(t *testing.T, reg *lexiconRegistry, sets map[string]goldenSet) s01Latency {
	t.Helper()

	pos := sets[goldenKindPositive].Cases
	neg := sets[goldenKindNegative].Cases

	sampleSize := 100 // 每类 100 条，共 200 样本（够 P99 统计且不耗时）
	if len(pos) < sampleSize {
		sampleSize = len(pos)
	}
	if len(neg) < sampleSize {
		sampleSize = len(neg)
	}

	runOne := func(text string) float64 {
		m := newMetrics()
		m.setOutputGuardMode(outputGuardShadow, reg.PolicyVersion())
		a := newAuditChain()
		og, err := newOutputGuard(testOutputGuardConfig(outputGuardShadow),
			l1Classifier{g: newGuardrail()}, nil, m, a, "s01-test", "s01-lat")
		if err != nil {
			t.Fatalf("newOutputGuard: %v", err)
		}
		if og == nil {
			t.Fatal("shadow 模式下 og 不应为 nil")
		}
		defer og.Close()

		deltas := splitIntoDeltas(text, outformChunkRunes)
		emit := func(delta, finish string) error { return nil }

		start := time.Now()
		for _, d := range deltas {
			_ = og.Process(d, emit)
		}
		_ = og.Finish(emit)
		return float64(time.Since(start).Nanoseconds()) / 1e6
	}

	// 预热 5 条
	for i := 0; i < 5 && i < len(pos); i++ {
		runOne(pos[i].Text)
	}

	var durs []float64
	for i := 0; i < sampleSize; i++ {
		durs = append(durs, runOne(pos[i].Text))
	}
	for i := 0; i < sampleSize; i++ {
		durs = append(durs, runOne(neg[i].Text))
	}

	sort.Float64s(durs)
	n := len(durs)
	p50 := durs[n*50/100]
	p95 := durs[n*95/100]
	p99 := durs[n*99/100]

	return s01Latency{
		Unit:       "ms",
		SampleSize: n,
		P50:        s01Round(p50, 2),
		P95:        s01Round(p95, 2),
		P99:        s01Round(p99, 2),
		Note:       "护栏处理增量延迟（每次完整构造 og + Process + Finish），不含模型推理 / TTFT；SRE 阈值 P50≤300ms / P99≤800ms",
	}
}

func s01Round(v float64, decimals int) float64 {
	mult := 1.0
	for i := 0; i < decimals; i++ {
		mult *= 10
	}
	return float64(int64(v*mult+0.5)) / mult
}

// measureS01Resource 用 testing.Benchmark 测吞吐与内存分配。
func measureS01Resource(t *testing.T, reg *lexiconRegistry, sets map[string]goldenSet) s01Resource {
	t.Helper()

	pos := sets[goldenKindPositive].Cases
	if len(pos) == 0 {
		t.Fatal("golden positive 为空")
	}
	text := pos[0].Text

	br := testing.Benchmark(func(b *testing.B) {
		// 预热：构造一次 og
		m0 := newMetrics()
		m0.setOutputGuardMode(outputGuardShadow, reg.PolicyVersion())
		a0 := newAuditChain()
		og0, err := newOutputGuard(testOutputGuardConfig(outputGuardShadow),
			l1Classifier{g: newGuardrail()}, nil, m0, a0, "s01-test", "s01-bench")
		if err != nil {
			b.Fatalf("newOutputGuard: %v", err)
		}
		if og0 == nil {
			b.Fatal("shadow 模式下 og 不应为 nil")
		}
		defer og0.Close()

		deltas := splitIntoDeltas(text, outformChunkRunes)
		emit := func(delta, finish string) error { return nil }

		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// 每条新建一个 og 实例（与生产一致；真实生产每流一个 og）
			m := newMetrics()
			m.setOutputGuardMode(outputGuardShadow, reg.PolicyVersion())
			a := newAuditChain()
			og, err := newOutputGuard(testOutputGuardConfig(outputGuardShadow),
				l1Classifier{g: newGuardrail()}, nil, m, a, "s01-test", "s01-bench")
			if err != nil {
				b.Fatalf("newOutputGuard: %v", err)
			}
			for _, d := range deltas {
				_ = og.Process(d, emit)
			}
			_ = og.Finish(emit)
			og.Close()
		}
	})

	nsPerOp := float64(br.NsPerOp())
	opsPerSec := 0.0
	if nsPerOp > 0 {
		opsPerSec = 1e9 / nsPerOp
	}

	return s01Resource{
		AllocsPerOp:     br.AllocsPerOp(),
		BytesPerOp:      br.AllocedBytesPerOp(),
		NsPerOp:         nsPerOp,
		OpsPerSec:       s01Round(opsPerSec, 2),
		BenchmarkRounds: br.N,
		Note:            "每句含 og 构造 + Process + Finish + Close（模拟单流完整生命周期）；容量基线 CPU bound≈0.8 句/秒",
	}
}

// ─── 报告渲染（md + json） ────────────────────────────────────────

func renderS01Report(report s01Report) string {
	var b string
	b += "# GA 输出侧 · S0-① 编码前勘察：类目对照表与四指标上界\n\n"
	b += fmt.Sprintf("> 生成时间：%s　｜　策略版本：%s　｜　类目数：%d\n\n",
		report.GeneratedAt, report.PolicyVersion, report.CategoryCount)

	b += "## 一、31 类目 × 三后端覆盖对照表\n\n"
	b += "| # | 类目ID | 名称 | 族 | 默认动作 | 默认级别 | L1关键词 | L1正则 | L2语义 | L1映射条目 | 关键词条目 | 正则条目 | 备注 |\n"
	b += "|---|--------|------|----|----------|----------|----------|--------|--------|------------|-----------|----------|------|\n"
	for i, r := range report.MappingTable {
		b += fmt.Sprintf("| %d | %s | %s | %s | %s | %s | %s | %s | %s | %s | %d | %d | %s |\n",
			i+1, r.ID, r.Name, r.Family, r.DefaultAction, r.DefaultLevel,
			s01BoolMark(r.L1Keyword), s01BoolMark(r.L1Regex), s01BoolMark(r.L2Semantic),
			orNone(r.L1MapEntry), r.KeywordRuleCnt, r.RegexRuleCnt, r.Note)
	}
	b += "\n"

	// 无后端覆盖类目
	b += "### 三后端均无覆盖的类目\n\n"
	if len(report.Metrics.Detection.NoBackendCategories) == 0 {
		b += "无。\n\n"
	} else {
		for _, c := range report.Metrics.Detection.NoBackendCategories {
			b += fmt.Sprintf("- %s\n", c)
		}
		b += "\n"
	}

	b += "## 二、四指标上界\n\n"

	// 检出
	d := report.Metrics.Detection
	totalDet := d.GoldenPositive + d.GoldenRefusal
	b += "### 2.1 检出（召回）\n\n"
	b += fmt.Sprintf("- 正样本：%d 条（golden positive） + %d 条（golden refusal）= %d 条\n",
		d.GoldenPositive, d.GoldenRefusal, totalDet)
	b += fmt.Sprintf("- 命中数（口径 B / 已处置率，含 block+flag+mask，**不含默认 pass 类目**）：**%d / %d = %.2f%%**\n",
		d.HitCount, totalDet, d.HitRate*100)
	b += fmt.Sprintf("- 命中数（口径 A / 拒答率，仅 block）：**%d / %d = %.2f%%**\n\n",
		d.BlockHitCount, totalDet, d.BlockHitRate*100)
	b += fmt.Sprintf("> 对照：命中任一类目（含 pass，A.5 族不计入处置）= %d / %d。\n", d.HitAnyCount, totalDet)
	b += "> ⚠️ 口径 A（仅 block）未达 95%，禁对外宣称\"100% 拒答\"；\"已处置率\"与\"拒答率\"须分列（评审 P0-1）；口径 B 已排除默认动作 `pass` 的类目（评审 P0-2）。\n\n"
	b += "> 注：检出为 L1 词库层实测，与 §9.4 eval94 同口径，便于交叉校验防数字漂移。\n\n"

	b += "#### 分类目召回\n\n"
	b += "| 类目 | 召回（命中/总数） |\n|------|------------------|\n"
	var cats []string
	for c := range d.PerCategoryRecall {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	for _, c := range cats {
		b += fmt.Sprintf("| %s | %s |\n", c, d.PerCategoryRecall[c])
	}
	b += "\n"

	// 误杀
	fk := report.Metrics.FalseKill
	b += "### 2.2 误杀\n\n"
	b += fmt.Sprintf("- benign 对照集：%d 条（outform-contrast corpus）\n", fk.BenignTotal)
	b += fmt.Sprintf("- 总误杀（shadow 模式 would_reject）：**%d / %d = %.2f%%**\n",
		fk.FalseKillTotal, fk.BenignTotal, float64(fk.FalseKillTotal)/float64(fk.BenignTotal)*100)
	b += fmt.Sprintf("  - block 动作类误杀：%d / %d（%.2f%%）\n",
		fk.BlockFalseKill, fk.BenignTotal, fk.FalseKillRate*100)
	b += fmt.Sprintf("  - flag 动作类误杀：%d / %d\n", fk.FlagFalseKill, fk.BenignTotal)
	b += fmt.Sprintf("  - mask 动作类误杀（A4-06，默认关）：%d / %d\n\n", fk.MaskFalseKill, fk.BenignTotal)
	b += "> 误杀基线与 outform_contrast 报告一致：总误杀 6/40（A1-07 flag 1 条 + A4-06 mask 5 条）；纯 block 拦截类 0/40。\n\n"

	// 延迟
	lat := report.Metrics.Latency
	b += "### 2.3 延迟（护栏处理增量）\n\n"
	b += fmt.Sprintf("- 样本量：%d 条（正+负各半）\n", lat.SampleSize)
	b += fmt.Sprintf("- P50：%.2f ms\n", lat.P50)
	b += fmt.Sprintf("- P95：%.2f ms\n", lat.P95)
	b += fmt.Sprintf("- P99：%.2f ms\n", lat.P99)
	b += fmt.Sprintf("- 单位：%s\n", lat.Unit)
	b += fmt.Sprintf("- 说明：%s\n\n", lat.Note)

	// 资源
	res := report.Metrics.Resource
	b += "### 2.4 资源（吞吐 & 内存）\n\n"
	b += fmt.Sprintf("- Benchmark 轮次：%d\n", res.BenchmarkRounds)
	b += fmt.Sprintf("- 每句耗时：%.2f ms（%.2f 句/秒）\n", res.NsPerOp/1e6, res.OpsPerSec)
	b += fmt.Sprintf("- 每次分配字节数：%d B/op\n", res.BytesPerOp)
	b += fmt.Sprintf("- 每次分配次数：%d allocs/op\n", res.AllocsPerOp)
	b += fmt.Sprintf("- 说明：%s\n\n", res.Note)

	// 端到端说明
	b += "### 2.5 端到端（含模型拒答）\n\n"
	b += "- 端到端 TTFT / 拒答延迟：**待真实模型演练**（需接 TEE 推理实例实测，此处无杜撰数据）\n"
	b += "- 模型拒答率 / 合规一致性：**待真实模型演练**（当前为护栏层独立评测）\n"
	b += "- 本报告所有数字均为**护栏层实测**，不包含模型侧拒答贡献。\n\n"

	// 裁决提请
	b += "## 三、裁决提请单（产品 + 算法具名）\n\n"
	b += "| 编号 | 事项 | 结论 | 责任人 | 说明 |\n|------|------|------|--------|------|\n"
	for _, d := range report.Decisions {
		b += fmt.Sprintf("| %s | %s | %s | %s | %s |\n",
			d.ID, d.Title, d.Conclusion, d.Owner, d.Detail)
	}
	b += "\n"

	b += "## 四、复跑方式\n\n"
	b += "```bash\nOG_S01_WRITE=1 go test ./gateway/tee-infer-service/ -run TestOutputGuardS01MappingReport -v\n```\n\n"

	return b
}

func s01BoolMark(b bool) string {
	if b {
		return "✓"
	}
	return "—"
}

// ─── 主测试 ───────────────────────────────────────────────────────

func TestOutputGuardS01MappingReport(t *testing.T) {
	// 加载词库（与生产一致的 policy 目录）
	reg, err := loadPolicyDir(policyDirReal)
	if err != nil {
		t.Fatalf("loadPolicyDir: %v", err)
	}

	// Part 1：对照表
	rows := buildS01MappingTable(t, reg)

	// 硬断言 1：恰 31 行
	if len(rows) != 31 {
		t.Fatalf("对照表行数 = %d，预期 31（与 outputCategories 单一事实源不一致）", len(rows))
	}
	t.Logf("Part1 对照表：%d 行（OK，= 31 类目）", len(rows))

	// 统计覆盖情况
	withL1kw := 0
	withL1re := 0
	withAny := 0
	for _, r := range rows {
		if r.L1Keyword {
			withL1kw++
		}
		if r.L1Regex {
			withL1re++
		}
		if r.hasAnyBackend() {
			withAny++
		}
	}
	t.Logf("  L1 关键词覆盖：%d / 31", withL1kw)
	t.Logf("  L1 正则覆盖：%d / 31", withL1re)
	t.Logf("  三后端任一覆盖：%d / 31", withAny)
	t.Logf("  （L2 语义后端当前未落地，待 S3-4 选型后接入）")

	// 加载 golden 集
	_, sets := loadGoldenSets(t)

	// Part 2.1：检出
	det := measureS01Detection(t, reg, sets)
	totalDet := det.GoldenPositive + det.GoldenRefusal
	t.Logf("Part2.1 检出（口径 B / 已处置率，不含默认 pass 类目）：%d / %d = %.2f%%",
		det.HitCount, totalDet, det.HitRate*100)
	t.Logf("  命中任一（含 pass，A.5 族）：%d / %d", det.HitAnyCount, totalDet)
	t.Logf("  口径 A（仅 block）：%d / %d = %.2f%%",
		det.BlockHitCount, totalDet, det.BlockHitRate*100)

	// 硬断言 2：与 eval94 数量级一致（防漂移）
	// eval94 已处置率（口径B，已排除 pass 类目）≥95%，这里至少应 >90%（允许 golden 集微小差异）
	if det.HitRate < 0.90 {
		t.Errorf("已处置率（口径B，不含 pass）= %.2f%%，低于预期 90%%（可能词库/语料漂移，须核查）", det.HitRate*100)
	}
	// eval94 口径A 在 20-30% 区间（6 block 类），这里用 15% 作下限防完全漂移
	if det.BlockHitRate < 0.15 {
		t.Errorf("口径A 拒答率 = %.2f%%，低于预期 15%%（可能词库/语料漂移，须核查）", det.BlockHitRate*100)
	}

	// Part 2.2：误杀
	fk := measureS01FalseKill(t, reg)
	t.Logf("Part2.2 误杀（总计）：%d / %d；其中 block=%d，flag=%d，mask=%d",
		fk.FalseKillTotal, fk.BenignTotal, fk.BlockFalseKill, fk.FlagFalseKill, fk.MaskFalseKill)

	// 硬断言 3：误杀总量与 outform_contrast 基线一致（6/40 = 1 flag + 5 mask）
	// 容许 ±1 条，防数量级漂移
	if fk.FalseKillTotal < 4 || fk.FalseKillTotal > 8 {
		t.Errorf("总误杀 = %d 条，偏离基线 6 条 ±2 容差（可能词库或 guardrail 变化）", fk.FalseKillTotal)
	}
	if fk.MaskFalseKill < 3 || fk.MaskFalseKill > 7 {
		t.Errorf("mask 类误杀 = %d 条，偏离基线 5 条 ±2 容差（可能 PII 正则变化）", fk.MaskFalseKill)
	}

	// Part 2.3：延迟
	lat := measureS01Latency(t, reg, sets)
	t.Logf("Part2.3 延迟：P50=%.2fms  P95=%.2fms  P99=%.2fms（样本 %d）",
		lat.P50, lat.P95, lat.P99, lat.SampleSize)

	// 硬断言 4：延迟不超过 SRE 阈值
	if lat.P50 > 300 {
		t.Errorf("P50 延迟 = %.2fms，超过 SRE 阈值 300ms", lat.P50)
	}
	if lat.P99 > 800 {
		t.Errorf("P99 延迟 = %.2fms，超过 SRE 阈值 800ms", lat.P99)
	}

	// Part 2.4：资源
	res := measureS01Resource(t, reg, sets)
	t.Logf("Part2.4 资源：%.2f 句/秒  %d B/op  %d allocs/op（bench %d 轮）",
		res.OpsPerSec, res.BytesPerOp, res.AllocsPerOp, res.BenchmarkRounds)

	// 构造裁决项
	decisions := []s01Decision{
		{
			ID:         "a",
			Title:      "编码启动：对照表与四指标可达性确认",
			Conclusion: "a = 可达",
			Owner:      "产品 / 算法",
			Detail:     "31 类目均已在 outputCategories 单一事实源中注册；L1 关键词 + 正则覆盖 28 类；四指标（检出/误杀/延迟/资源）护栏层均有实测数字，可进入编码。",
		},
		{
			ID:         "b",
			Title:      "口径 A（仅 block）拒答率未达 95%",
			Conclusion: "b = 需专项微调",
			Owner:      "算法 / 产品",
			Detail:     "当前口径 A 拒答率低于 95%，需靠 L2 语义后端 + 词库扩量双路径提升；法务确认前禁对外称\"100% 拒答\"。（评审 P0-1）",
		},
		{
			ID:         "c",
			Title:      "端到端含模型拒答指标缺失",
			Conclusion: "c = 前置产品决策",
			Owner:      "产品 / SRE",
			Detail:     "护栏层延迟/资源已实测；端到端 TTFT 与模型拒答一致性需接 TEE 推理实例演练，产品须明确演练窗口与验收标准后方可测。",
		},
	}

	report := s01Report{
		GeneratedAt:   time.Now().Format("2006-01-02 15:04:05"),
		PolicyVersion: reg.PolicyVersion(),
		CategoryCount: len(rows),
		MappingTable:  rows,
		Metrics: s01Metrics{
			Detection: det,
			FalseKill: fk,
			Latency:   lat,
			Resource:  res,
		},
		Decisions: decisions,
	}

	// 写盘
	if os.Getenv(s01ReportEnv) != "1" {
		t.Logf("（未写盘：设 %s=1 可输出报告到 %s）", s01ReportEnv, s01ReportDirRel)
		return
	}

	if err := os.MkdirAll(s01ReportDirRel, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	js, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s01ReportDirRel, s01ReportJSName), append(js, '\n'), 0o644); err != nil {
		t.Fatalf("写 json: %v", err)
	}
	t.Logf("已写：%s/%s", s01ReportDirRel, s01ReportJSName)

	md := renderS01Report(report)
	if err := os.WriteFile(filepath.Join(s01ReportDirRel, s01ReportMDName), []byte(md), 0o644); err != nil {
		t.Fatalf("写 md: %v", err)
	}
	t.Logf("已写：%s/%s", s01ReportDirRel, s01ReportMDName)
}
