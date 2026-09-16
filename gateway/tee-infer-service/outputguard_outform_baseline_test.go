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

// OG-0 输出侧误杀基线取数（走完整 outputGuard 流式管线）。
//
// 与 guardrail_outform_baseline_test.go 的区别：
//   - 前者直接调 guardrail.check()（整块文本一次性判定，模拟输入侧）
//   - 本测试把文本按 token 粒度拆成 delta 序列，经 outputGuard.Process/Finish
//     走完整的流式缓冲 → 按句切分 → L1 判定 → 映射 → 指标/审计 管线
//     （模拟真实输出侧的逐 token 下发路径）
//
// 两者对照可得出：
//   - 「切句行为」引入的误杀变化（句子边界对命中的影响）
//   - 「形态变换 × 切句」的联合误杀率（真正的输出侧基线）
//
// 约束（OG-0 验收）：不改生产代码、不污染入库语料——变换在内存中确定性完成。
// 语料缺失 → Skip（与 guardrail_bench_test.go 同语义）。
const outformPipeCorpusRelPath = "testdata/guardrail-bench/corpus.jsonl"

// chunkSize 模拟每个 delta 的 token 数（按 rune 数近似；真实 token 大小不定，
// 此处取保守值 4 runes/delta，足以触发缓冲器的「跨 delta 切句」路径）。
const outformChunkRunes = 4

// splitIntoDeltas 把文本按 rune 粒度拆成定长 delta 序列（模拟逐 token 下发）。
func splitIntoDeltas(text string, chunkRunes int) []string {
	if text == "" {
		return nil
	}
	rs := []rune(text)
	var out []string
	for i := 0; i < len(rs); i += chunkRunes {
		end := i + chunkRunes
		if end > len(rs) {
			end = len(rs)
		}
		out = append(out, string(rs[i:end]))
	}
	return out
}

// runThroughOutputGuard 走完整 outputGuard 管线，返回是否命中（would_reject 事件数 > 0）及首个命中级目。
func runThroughOutputGuard(t *testing.T, text string) (hit bool, category string) {
	t.Helper()
	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()
	og, err := newOutputGuard(testOutputGuardConfig(outputGuardShadow),
		l1Classifier{g: newGuardrail()}, nil, m, a, "og0-test", "og0-"+t.Name())
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	if og == nil {
		t.Fatal("shadow 模式下 og 不应为 nil")
	}
	defer og.Close()

	deltas := splitIntoDeltas(text, outformChunkRunes)
	emit := func(delta, finish string) error { return nil }
	for _, d := range deltas {
		if err := og.Process(d, emit); err != nil {
			t.Fatalf("Process: %v", err)
		}
	}
	if err := og.Finish(emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	n := a.countByAction("output_would_reject")
	if n == 0 {
		return false, ""
	}
	// 取首个 would_reject 事件的类目。
	evs := a.query("og0-test")
	for _, ev := range evs {
		if ev.Action == "output_would_reject" {
			return true, ev.OGCategory
		}
	}
	return true, "" // 理论上不可达
}

func TestOutputGuardOutformBaseline(t *testing.T) {
	path := filepath.FromSlash(outformPipeCorpusRelPath)
	f, err := os.Open(path)
	if err != nil {
		if strings.EqualFold(os.Getenv("GUARDRAIL_BENCH"), "skip") {
			t.Skipf("GUARDRAIL_BENCH=skip：显式跳过输出侧管线基线（语料未生成，期望文件：%s）", path)
		}
		t.Fatalf("基准语料缺失，输出侧管线基线未执行：%s\n标准做法：先运行 scripts/build-guardrail-bench.ps1 生成语料。", path)
	}
	defer f.Close()

	type baseCase struct {
		id      string
		text    string
		scope   string
		expect  string
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
		// 收集 benign（测误杀）+ rule（测检出率）；排除语义/公开集（L1 不覆盖，只报告）。
		if c.Scope == "benign" || c.Scope == "rule" {
			bases = append(bases, baseCase{id: c.ID, text: c.Text, scope: c.Scope, expect: c.Expect, knownFP: c.KnownFP})
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("读取语料失败：%v", err)
	}
	if len(bases) == 0 {
		t.Fatalf("语料不含 baseline 文本（scope=benign|rule）")
	}

	// 按 scope × 是否 known_fp 统计。
	type stat struct {
		total, flagged int
	}
	byScope := map[string]*stat{}
	byCategory := map[string]int{}   // 命中按内部类目分布
	var fpDetail []string             // 误杀明细（benign + 非 known_fp）

	for _, b := range bases {
		hit, cat := runThroughOutputGuard(t, b.text)

		key := b.scope
		if b.scope == "benign" && b.knownFP {
			key = "benign_knownfp"
		}
		if byScope[key] == nil {
			byScope[key] = &stat{}
		}
		byScope[key].total++
		if hit {
			byScope[key].flagged++
			if cat != "" {
				byCategory[cat]++
			}
		}

		// 误杀明细：scope=benign + expect=allow + 非 known_fp + 命中。
		if b.scope == "benign" && b.expect == "allow" && !b.knownFP && hit {
			fpDetail = append(fpDetail, fmt.Sprintf("%-16s cat=%-6s text=%q", b.id, cat, b.text))
		}
	}

	// ---- 报告 ----
	t.Logf("OG-0 输出侧管线基线：%d 条文本 × 流式逐 delta（%d runes/delta）", len(bases), outformChunkRunes)
	t.Logf("  （走完整 outputGuard 管线：缓冲→按句切分→L1判定→映射→审计）")

	// 按 scope 输出。
	scopes := make([]string, 0, len(byScope))
	for k := range byScope {
		scopes = append(scopes, k)
	}
	sort.Strings(scopes)
	t.Logf("  %-18s %-10s %-12s", "scope", "命中/总数", "率")
	for _, s := range scopes {
		st := byScope[s]
		t.Logf("  %-18s %-10s %-12s", s,
			fmt.Sprintf("%d/%d", st.flagged, st.total),
			fmt.Sprintf("%.1f%%", pct(st.flagged, st.total)))
	}

	// 类目分布。
	cats := make([]string, 0, len(byCategory))
	for k := range byCategory {
		cats = append(cats, k)
	}
	sort.Strings(cats)
	t.Logf("  命中类目分布（内部 ID）：")
	for _, c := range cats {
		t.Logf("    %-8s %d", c, byCategory[c])
	}

	if len(fpDetail) > 0 {
		t.Logf("  误杀明细（benign + 非 known_fp）：%d 条", len(fpDetail))
		for _, d := range fpDetail {
			t.Logf("    %s", d)
		}
	} else {
		t.Logf("  误杀明细（benign + 非 known_fp）：0 条 ✅")
	}
}
