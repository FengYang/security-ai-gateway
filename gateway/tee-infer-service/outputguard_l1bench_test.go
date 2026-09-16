package main

// OG-1（M0）L1 规则层延迟/资源标定与级联占比诊断基线。
//
// 对应技术方案 §4.3.2 性能预算分解中「现在可定 target」的三个分量：
//
//	① 归一化 + L1 单句检测：target P50 < 1ms / P99 < 5ms —— BenchmarkL1Classify
//	② 序列化与封帧：       target < 1ms/帧          —— BenchmarkFrameMarshal / BenchmarkFrameSeal
//	⑥ 缓冲上限保护：       强切副作用 < 5ms          —— BenchmarkForcedSplitOverhead
//
// 分量③首句凑齐等待 / ④L2 推理 / ⑤排队 不在本机标定范围（OG-0b 仿真已给算术结论，
// 真实值待 M3 OG-13 侧车接入浸泡实测）。L1 为纯 Go in-process 组件，①②⑥ 与
// {Gen,Stream}×{CPU,GPU} 四象限中的后端形态无关：Stream 按句调用（本文件主口径），
// Gen 整段判定等价于 clean-maxunit（500 rune）档；CPU/GPU 差异仅存在于分量④。
//
// 级联占比诊断基线（不设闸门，OG-1 验收）：TestL1CascadeBaseline，消费
// testdata/guardrail-bench/corpus.jsonl（与门禁①同一语料，267 条）。
//
// 运行：
//
//	go test -mod=mod -run '^TestL1CascadeBaseline$' -v .
//	go test -mod=mod -run '^$' -bench 'L1|Frame|ForcedSplit' -benchtime=200000x .

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/protocol/go"
)

// 分位数采样：500 批 × 100 次/批 = 50000 次调用。
// 采用「批量计时再均摊」而非单次计时：Windows QPC 在本机对 μs 级单次调用
// 存在量化（单次 <1 tick 记 0），批量法测得稳态每次成本，P50/P95/P99 为
// 「批次平均延迟」的分布（摊薄了测量扰动；GC/调度造成的单次真实尾延由
// 最慢档的单条观测与 B/op 分配率在标定报告中另行评估）。
const (
	benchLatencyBatches = 500
	benchLatencyBatchN  = 100
)

// benchLoadPolicy 加载生产策略目录（manifest 校验 + 全量词库），失败即终止。
func benchLoadPolicy(b testing.TB) *lexiconRegistry {
	b.Helper()
	reg, err := loadPolicyDir(policyDirReal)
	if err != nil {
		b.Fatalf("loadPolicyDir(%q): %v", policyDirReal, err)
	}
	return reg
}

// benchReportLatency 对 fn 做批量延迟采样，上报 P50/P95/P99/P999（单位 ns/次）。
func benchReportLatency(b *testing.B, fn func()) {
	b.Helper()
	benchReportLatencyN(b, fn, benchLatencyBatches, benchLatencyBatchN)
}

// benchReportLatencyN 可调批量的采样（慢档：整条流 ms 级，减少总调用数）。
func benchReportLatencyN(b *testing.B, fn func(), batches, batchN int) {
	b.Helper()
	b.StopTimer()
	samples := make([]int64, batches)
	for i := range samples {
		t0 := time.Now()
		for j := 0; j < batchN; j++ {
			fn()
		}
		samples[i] = time.Since(t0).Nanoseconds() / int64(batchN)
	}
	sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
	q := func(p float64) float64 {
		return float64(samples[int(float64(len(samples)-1)*p)])
	}
	b.ReportMetric(q(0.50), "p50-ns/i")
	b.ReportMetric(q(0.95), "p95-ns/i")
	b.ReportMetric(q(0.99), "p99-ns/i")
	b.ReportMetric(q(0.999), "p999-ns/i")
}

// L1 标定样本（命中预期在子测启动时显式校验，防词库变更后静默测错路径）。
var (
	// 无命中正常中文句（~38 rune）：最坏路径 = 31 类全部跑完（归一化 ×31 + AC/正则全扫）。
	benchCleanShort = "今天下午三点召开项目评审会议，请各位同事提前准备好相关材料并准时参加。"
	// 无命中 500 rune：P-MAX-UNIT-RUNES 上限，同时等价 Gen 形态整段一次判定的成本量级。
	benchCleanMaxUnit = func() string {
		base := []rune("项目组本周按计划推进接口联调与回归验证工作，各项指标保持稳定。")
		out := make([]rune, 0, 500)
		for len(out) < 500 {
			out = append(out, base...)
		}
		return string(out[:500])
	}()
	// 身份证形态：regex 类（pii）优先级最高，命中即早停。
	benchPIIHit = "经办人证件号 110105198003157892 请核对。"
	// 关键词命中：须先跑完 pii/injection 两个 regex 类与排在 A1-06 前的词库类，
	// 是关键词路径的真实位置（词面取自当前占位词库，仅用于压 AC 路径）。
	benchKeywordHit = "处理结果：【A1-06-示例-0001】请知悉。"
)

// BenchmarkL1Classify 分量①：生产入口 lexiconRegistry.Classify（含每类归一化）。
func BenchmarkL1Classify(b *testing.B) {
	reg := benchLoadPolicy(b)
	cases := []struct {
		name    string
		text    string
		wantHit bool   // 是否预期命中
		wantCat string // 非空时断言精确类目 ID
	}{
		{"clean-short", benchCleanShort, false, ""},
		{"clean-maxunit-500rune", benchCleanMaxUnit, false, ""},
		{"hit-regex-pii", benchPIIHit, true, ""}, // 只断言非空（regex 类目 ID 随词库定）
		{"hit-keyword-a1", benchKeywordHit, true, "A1-06"},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			got, _, _ := reg.Classify(tc.text)
			if !tc.wantHit && got != "" {
				b.Fatalf("样本预期无命中但命中 %q（词库已扩入该词面，请更换干净样本）：%q", got, tc.text)
			}
			if tc.wantHit && got == "" {
				b.Fatalf("样本预期命中但未命中（词库规则可能已变更）：%q", tc.text)
			}
			if tc.wantCat != "" && got != tc.wantCat {
				b.Fatalf("样本预期命中 %q，实际 %q（词库占位词面可能已变更）", tc.wantCat, got)
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(tc.text))) // 吞吐按真实 UTF-8 字节计
			b.ResetTimer()
			for b.Loop() {
				_, _, _ = reg.Classify(tc.text)
			}
			b.StopTimer()
			benchReportLatency(b, func() { _, _, _ = reg.Classify(tc.text) })
		})
	}
}

// benchChunk 生产形态的引擎流式 chunk（OpenAI 兼容内层 JSON）。
type benchChunk struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason any `json:"finish_reason"`
	} `json:"choices"`
}

// BenchmarkFrameMarshal 分量②-a：json.Marshal（网关重组帧时存在；纯透传时无此步）。
func BenchmarkFrameMarshal(b *testing.B) {
	var ch benchChunk
	ch.Choices = make([]struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason any `json:"finish_reason"`
	}, 1)
	ch.Choices[0].Delta.Content = "四个字的增量"
	b.ReportAllocs()
	var sink []byte
	b.ResetTimer()
	for b.Loop() {
		raw, err := json.Marshal(&ch)
		if err != nil {
			b.Fatal(err)
		}
		sink = raw
	}
	_ = sink
}

// BenchmarkFrameSeal 分量②-b：SealEnvelope（AES-GCM）+ hex + SSE 行格式化，
// 对齐 main.go /infer 流式出口 `sealPayload → hex → "data: %s\n\n"`。
// 不含 http.Flusher.Flush（系统调用/网络写，归 M3 e2e 实测）。
func BenchmarkFrameSeal(b *testing.B) {
	key := bytes.Repeat([]byte{0x42}, 32)
	sid := "og1benchsessionid00000000000000" // 32 字符（对齐生产 hex(id) 会话 ID 长度，仅作 AAD）
	chunk := []byte(`{"choices":[{"delta":{"content":"四个字的增量"},"finish_reason":null}]}`)
	var buf bytes.Buffer
	var sink []byte
	b.ReportAllocs()
	b.ResetTimer()
	for n := range b.N {
		wire, err := protocol.SealEnvelope(key, sid, protocol.EndpointInfer, protocol.DirectionS2C, uint64(n+1), chunk)
		if err != nil {
			b.Fatal(err)
		}
		buf.Reset()
		fmt.Fprintf(&buf, "data: %s\n\n", hex.EncodeToString(wire))
		sink = buf.Bytes()
	}
	_ = sink
}

// BenchmarkForcedSplitOverhead 分量⑥：缓冲上限保护（强切）的纯副作用。
//
// 两条流等长（1200 rune、4 rune/delta、共 300 delta，与 OG-0 基线同切 delta 口径），
// 唯一差异：normal 含句末标点（~50 次正常成句、0 次强切）；forced 无任何终止符
// （首句 P-FIRST-UNIT-MAX-RUNES=200 强切 1 次 + P-MAX-UNIT-RUNES=500 强切 1 次；
// 剩余 500 rune 在 Flush 时正常成尾单元，不计强切）。
// 只测 unitBuffer.Push（切分/扫描），不含 L1 判定——判定成本由分量①独立度量，
// 避免「强切流单元数不同」污染差值。
func BenchmarkForcedSplitOverhead(b *testing.B) {
	const runes = 1200
	sentence := "今天下午召开例行项目评审会议，请各位准时到场。" // 24 rune/句
	var normalText strings.Builder
	for normalText.Len() < runes*3 { // UTF-8 字节 ≈ rune×3，循环到足量后按 rune 截断
		normalText.WriteString(sentence)
	}
	normal := string([]rune(normalText.String())[:runes])
	forced := strings.Repeat("甲乙丙丁", runes/4) // 1200 rune，无标点无空格

	pipe := func(text string) {
		buf := newUnitBuffer(resolveOutputGuardParams(outputGuardParams{}), nil)
		for _, d := range splitIntoDeltas(text, outformChunkRunes) {
			_ = buf.Push(d)
		}
		_ = buf.Flush()
	}
	// 前置校验：强切次数符合预期（first_unit×1 + max_unit×1 = 2 次），否则口径错误。
	{
		var reasons []string
		chk := newUnitBuffer(resolveOutputGuardParams(outputGuardParams{}), func(r string) { reasons = append(reasons, r) })
		for _, d := range splitIntoDeltas(forced, outformChunkRunes) {
			_ = chk.Push(d)
		}
		_ = chk.Flush()
		if len(reasons) != 2 || reasons[0] != forcedReasonFirstUnit || reasons[1] != forcedReasonMaxUnit {
			b.Fatalf("强切序列预期 [first_unit max_unit]，实际 %v", reasons)
		}
	}

	for _, tc := range []struct {
		name string
		text string
	}{
		{"normal-1200rune", normal},
		{"forced-1200rune-2split", forced},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				pipe(tc.text)
			}
			b.StopTimer()
			// 整条流 ms 级，用 100 批 ×5 次 = 500 次调用（约 3s 采样窗）。
			benchReportLatencyN(b, func() { pipe(tc.text) }, 100, 5)
		})
	}
}

// TestL1CascadeBaseline OG-1 级联占比诊断基线（无阈值断言；语料缺失同门禁①惯例 Skip）。
//
// 口径：模式 A + T2 默认（L1 未命中全送 L2 复判）下，「L1 放行率」即「L2 级联候选率」
// 的上限——M0 无真实 L2，此处给 L1 单层在 267 条基准语料上的拦截/放行分布；
// 真正的「L2 级联触发率（L1 放行且 L2 命中）/ L2 占比」待 M3 侧车接入后在同一语料
// （及输出侧黄金集）上回填。语料主体是输入侧攻击/正常文本，输出侧语义违规占比
// 不代表生产水位，仅作规则层能力的诊断对照。
func TestL1CascadeBaseline(t *testing.T) {
	path := filepath.FromSlash(benchCorpusRelPath)
	f, err := os.Open(path)
	if err != nil {
		if strings.EqualFold(os.Getenv("GUARDRAIL_BENCH"), "skip") {
			t.Skipf("GUARDRAIL_BENCH=skip：显式跳过级联占比基线（语料未生成，期望文件：%s）", path)
		}
		t.Fatalf("基准语料缺失，级联占比基线未执行：%s\n先运行 scripts/build-guardrail-bench.ps1 生成语料。", path)
	}
	defer f.Close()

	reg := benchLoadPolicy(t)
	type stat struct {
		total, hit int
	}
	byScope := map[string]*stat{}
	byCategory := map[string]int{} // 命中类目（内部 ID / L1 原生标签）分布
	var corpusTotal, corpusHit int
	var totalLatency time.Duration

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
		scope := c.Scope
		if scope == "benign" && c.KnownFP {
			scope = "benign_knownfp"
		}
		st := byScope[scope]
		if st == nil {
			st = &stat{}
			byScope[scope] = st
		}
		st.total++
		corpusTotal++
		t0 := time.Now()
		cat, _, _ := reg.Classify(c.Text)
		totalLatency += time.Since(t0)
		if cat != "" {
			st.hit++
			corpusHit++
			byCategory[cat]++
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("读取语料失败：%v", err)
	}

	pct := func(hit, total int) string {
		if total == 0 {
			return "—"
		}
		return fmt.Sprintf("%.2f%%", float64(hit)/float64(total)*100)
	}
	t.Logf("OG-1 级联占比诊断基线：词库 %d 类 / %d 规则（%s），语料 %d 条（%s）",
		reg.CategoryCount(), reg.RuleCount(), reg.PolicyVersion(), corpusTotal, path)
	t.Logf("  %-16s %8s %8s %10s %16s", "scope", "总数", "L1命中", "L1命中率", "放行(=级联候选)率")
	for _, scope := range []string{"rule", "semantic", "benign", "benign_public", "benign_knownfp"} {
		st := byScope[scope]
		if st == nil {
			continue
		}
		passRate := "—"
		if st.total > 0 {
			passRate = fmt.Sprintf("%.2f%%", float64(st.total-st.hit)/float64(st.total)*100)
		}
		t.Logf("  %-16s %8d %8d %10s %16s", scope, st.total, st.hit, pct(st.hit, st.total), passRate)
	}
	t.Logf("  %-16s %8d %8d %10s %16s", "全语料", corpusTotal, corpusHit,
		pct(corpusHit, corpusTotal),
		fmt.Sprintf("%.2f%%", float64(corpusTotal-corpusHit)/float64(corpusTotal)*100))
	if corpusTotal > 0 {
		t.Logf("  语料混合负载单条均值：%v/条（含解析外的纯 Classify 计时，%d 条总量仅供数量级参考）",
			totalLatency/time.Duration(corpusTotal), corpusTotal)
	}
	cats := make([]string, 0, len(byCategory))
	for c := range byCategory {
		cats = append(cats, c)
	}
	sort.Strings(cats)
	var dist strings.Builder
	for _, c := range cats {
		fmt.Fprintf(&dist, "%s=%d ", c, byCategory[c])
	}
	t.Logf("  命中类目分布：%s", strings.TrimSpace(dist.String()))
	t.Logf("  口径说明：模式 A/T2 下 L1 未命中 → L2 复判；M0 仅 L1 单层，" +
		"「L2 命中占比/级联触发率」待 M3 OG-13 实测回填，本行不设闸门。")
}
