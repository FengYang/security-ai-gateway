package main

// GF.4.3 语义分类器评测跑道。
//
// 目的：Guardrail 的提示词注入检测从关键词规则升级为语义分类器时，需要一个**可复现**的
// 评测口径，使任何候选（本地小模型侧车 / 真实 embedding 混合服务 / 外部内容安全 API 对照）
// 接入后即出同一组指标，避免"各候选各测一套"。
//
// 语料：复用门禁 #1 的同一份基准集（`testdata/guardrail-bench/corpus.jsonl`，
// 由 scripts/build-guardrail-bench.ps1 离线生成、不入库），本跑道记录语料 SHA-256 以保可复现。
//
// 四指标（每个候选一份）：
//  1. 检出率：rule 族（门禁①，阈值 ≥95%）与 semantic 族（公开集语义越狱，关键词基线 ~12%）分列
//  2. 误报率：benign 干净样本（门禁②，阈值 ≤2%）与 benign_public 分列；known_fp 单列（规则缺陷水位）
//  3. 延迟：逐条计时 → mean / P50 / P99（微秒）
//  4. 资源占用：in-process 用 runtime.MemStats 增量；外部候选取响应可选字段 `resources`，
//     缺则如实标注"不可测"（不编造）
//
// 跑法：
//
//	go test -mod=mod ./gateway/tee-infer-service/ -run TestGuardrailEval -v
//
// 外部候选（契约见 model/http_classifier.go）：
//
//	$env:GUARDRAIL_EVAL_SCORER_URL="http://127.0.0.1:19091/classify"
//	$env:GUARDRAIL_EVAL_SCORER_ID="local-guard-8b"   # 可选，用于结果文件名
//	$env:GUARDRAIL_EVAL_SCORER_KEY="..."             # 可选，Bearer
//	go test -mod=mod ./gateway/tee-infer-service/ -run TestGuardrailEvalExternalScorer -v
//
// 结果落盘（**仅在 GUARDRAIL_EVAL_WRITE=1 时写盘**，避免 go test 重写已入库证据）：
// <repo>/docs/benchmark/guardrail-classifier/<scorer-id>.json
// （目录可用 GUARDRAIL_EVAL_OUT 覆盖；默认写入仓库内以便作为门禁证据入库）
// 未开启时只打印指标，不落盘。

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"security-ai-gateway/gateway/tee-infer-service/model"
)

const (
	evalDefaultOutDir = "../../docs/benchmark/guardrail-classifier"
	evalDetailLimit   = 20 // 明细条目上限（漏检/误报各自）
	// evalLatencyNote 延迟口径的如实声明（防读者把 in-process 的 0 误读为"零开销"）。
	evalLatencyNote = "单位微秒；逐条单次计时，受本机时钟粒度影响——in-process 规则基线部分调用 <1µs 记为 0，" +
		"故 P50 可能为 0，请结合 mean 解读；侧车候选为网络往返量级，单次计时足够"
)

// evalFamily 一个语料族的命中统计。
type evalFamily struct {
	Total   int     `json:"total"`
	Blocked int     `json:"blocked"`
	Rate    float64 `json:"rate"`
}

// addDetect 检出族计数：未拦截即漏检（明细用于定位漏掉了哪些攻击）。
func (f *evalFamily) addDetect(blocked bool, id, text string, missed *[]string) {
	f.Total++
	if blocked {
		f.Blocked++
		return
	}
	if missed != nil && len(*missed) < evalDetailLimit {
		*missed = append(*missed, fmt.Sprintf("%s %q", id, truncate(text, 60)))
	}
}

// addFalsePos 误报族计数：拦截即误报（明细用于定位哪些正常文本被拦）。
func (f *evalFamily) addFalsePos(blocked bool, id, text string, falsePos *[]string) {
	f.Total++
	if !blocked {
		return
	}
	f.Blocked++
	if falsePos != nil && len(*falsePos) < evalDetailLimit {
		*falsePos = append(*falsePos, fmt.Sprintf("%s %q", id, truncate(text, 60)))
	}
}

func (f *evalFamily) finalize() {
	if f.Total == 0 {
		f.Rate = 0
		return
	}
	f.Rate = round3(float64(f.Blocked) / float64(f.Total))
}

// evalLatency 延迟指标（微秒：in-process 规则基线在亚毫秒量级，毫秒会大量显示 0.000）。
type evalLatency struct {
	Mean float64 `json:"mean"`
	P50  float64 `json:"p50"`
	P99  float64 `json:"p99"`
}

// evalReport 一次候选评测的完整结果（JSON 落盘 + 控制台摘要共用一个结构）。
type evalReport struct {
	Scorer      string         `json:"scorer"`
	Backend     string         `json:"backend"`
	GeneratedAt string         `json:"generated_at"`
	CorpusPath  string         `json:"corpus_path"`
	CorpusSHA   string         `json:"corpus_sha256"`
	CorpusTotal int            `json:"corpus_total"`
	DetectRule  evalFamily     `json:"detect_rule"`     // 门禁①口径
	DetectSem   evalFamily     `json:"detect_semantic"` // 公开集语义越狱（仅报告）
	FPClean     evalFamily     `json:"false_pos_clean"`
	FPPublic    evalFamily     `json:"false_pos_public"`
	KnownFP     evalFamily     `json:"known_fp_hit"`
	Latency     evalLatency    `json:"latency_us"`
	LatencyNote string         `json:"latency_note"`
	Resources   map[string]any `json:"resources,omitempty"`
	Missed      []string       `json:"missed_rule,omitempty"`     // 规则族漏检明细
	MissedSem   []string       `json:"missed_semantic,omitempty"` // 语义族漏检明细（选型关键证据）
	FalsePos    []string       `json:"false_positives,omitempty"` // 误报明细
	Errors      []string       `json:"errors,omitempty"`          // 候选调用失败（>0 = 该次评测不可用）
}

// evalScorer 候选打分器（评测跑道与候选之间的唯一接口）。
type evalScorer interface {
	ID() string
	Backend() string
	// Begin 在跑语料前调用（in-process 候选用于采样资源基线）。
	Begin()
	// Score 返回是否拦截；error 表示候选不可用（评测据此判失败，**不得**当作放行）。
	Score(text string) (bool, error)
	// Resources 在全部用例跑完后调用；返回 nil = 不可测（如实标注）。
	Resources() map[string]any
}

// keywordEvalScorer 现状 Guardrail（关键词规则）——基线候选，in-process。
type keywordEvalScorer struct {
	g      *guardrail
	before runtime.MemStats
}

func (s *keywordEvalScorer) ID() string      { return "keyword-baseline" }
func (s *keywordEvalScorer) Backend() string { return model.GuardClassifierBackendKeyword }
func (s *keywordEvalScorer) Begin()          { runtime.ReadMemStats(&s.before) }

func (s *keywordEvalScorer) Score(text string) (bool, error) {
	return s.g.check(text) != nil, nil
}

func (s *keywordEvalScorer) Resources() map[string]any {
	var after runtime.MemStats
	runtime.ReadMemStats(&after)
	delta := int64(after.HeapAlloc) - int64(s.before.HeapAlloc)
	if delta < 0 {
		delta = 0 // 期间发生 GC 时差值无意义，按 0 计
	}
	return map[string]any{
		"mode":                "in-process",
		"heap_alloc_delta_kb": delta / 1024,
		"goroutines":          runtime.NumGoroutine(),
		"note":                "关键词规则分类器无模型权重；堆增量含测试框架噪声，仅作数量级参考",
	}
}

// httpEvalScorer 外部候选（本地小模型 sidecar / 真实 embedding 混合服务 / 外部 API 对照）。
// 与运行时使用**同一契约实现**（model.HTTPClassifier），避免评测口径与运行口径漂移。
type httpEvalScorer struct {
	id  string
	c   *model.HTTPClassifier
	mu  sync.Mutex
	res map[string]any
}

func (s *httpEvalScorer) ID() string      { return s.id }
func (s *httpEvalScorer) Backend() string { return model.GuardClassifierBackendHTTP }
func (s *httpEvalScorer) Begin()          {}

func (s *httpEvalScorer) Score(text string) (bool, error) {
	resp, err := s.c.ClassifyWithResources(text)
	if err != nil {
		return false, err
	}
	if resp.Resources != nil {
		s.mu.Lock()
		s.res = resp.Resources
		s.mu.Unlock()
	}
	return resp.Blocked, nil
}

func (s *httpEvalScorer) Resources() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.res == nil {
		return map[string]any{
			"mode": "out-of-process",
			"note": "候选未在响应中提供 resources（契约可选字段）——资源占用不可测，如实标注",
		}
	}
	return s.res
}

// ---------- 跑道实现 ----------

// runGuardrailEval 跑完语料并产出报告（写文件由调用方决定）。
func runGuardrailEval(t *testing.T, sc evalScorer) *evalReport {
	t.Helper()
	path := filepath.FromSlash(benchCorpusRelPath)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("基准语料缺失，评测无法执行：%s\n先运行 scripts/build-guardrail-bench.ps1 生成语料", path)
	}
	sum := sha256.Sum256(raw)
	rep := &evalReport{
		Scorer:      sc.ID(),
		Backend:     sc.Backend(),
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		CorpusPath:  filepath.ToSlash(path),
		CorpusSHA:   hex.EncodeToString(sum[:]),
	}

	var (
		rule, semantic, benignClean, benignPublic, knownFP evalFamily
		durations                                          []float64
		missed, missedSem, falsePos, errs                  []string
	)
	sc.Begin()
	scan := bufio.NewScanner(strings.NewReader(string(raw)))
	scan.Buffer(make([]byte, 0, 1<<20), 1<<20)
	for scan.Scan() {
		line := strings.TrimSpace(scan.Text())
		if line == "" {
			continue
		}
		var c benchCase
		if err := json.Unmarshal([]byte(line), &c); err != nil {
			t.Fatalf("语料解析失败（%s）：%v", line, err)
		}
		rep.CorpusTotal++
		start := time.Now()
		blocked, err := sc.Score(c.Text)
		durations = append(durations, float64(time.Since(start))/float64(time.Microsecond))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", c.ID, err))
			continue
		}
		switch {
		case c.Scope == "rule" && c.Expect == "block":
			rule.addDetect(blocked, c.ID, c.Text, &missed)
		case c.Scope == "semantic":
			semantic.addDetect(blocked, c.ID, c.Text, &missedSem)
		case c.Scope == "benign" && c.Expect == "allow":
			if c.KnownFP {
				knownFP.addFalsePos(blocked, c.ID, c.Text, nil)
			} else {
				benignClean.addFalsePos(blocked, c.ID, c.Text, &falsePos)
			}
		case c.Scope == "benign_public":
			benignPublic.addFalsePos(blocked, c.ID, c.Text, &falsePos)
		default:
			t.Fatalf("未知 scope/expect 组合：id=%s scope=%s expect=%s", c.ID, c.Scope, c.Expect)
		}
	}
	if err := scan.Err(); err != nil {
		t.Fatalf("读取语料失败：%v", err)
	}

	for _, f := range []*evalFamily{&rule, &semantic, &benignClean, &benignPublic, &knownFP} {
		f.finalize()
	}
	rep.DetectRule, rep.DetectSem = rule, semantic
	rep.FPClean, rep.FPPublic, rep.KnownFP = benignClean, benignPublic, knownFP
	rep.Latency = latencyStats(durations)
	rep.LatencyNote = evalLatencyNote
	rep.Resources = sc.Resources()
	rep.Missed, rep.MissedSem = missed, missedSem
	rep.FalsePos, rep.Errors = falsePos, errs
	return rep
}

// latencyStats 计算 mean/P50/P99（最近秩法，单位微秒）。
func latencyStats(durations []float64) evalLatency {
	if len(durations) == 0 {
		return evalLatency{}
	}
	sorted := append([]float64(nil), durations...)
	sort.Float64s(sorted)
	var sum float64
	for _, d := range sorted {
		sum += d
	}
	return evalLatency{
		Mean: round3(sum / float64(len(sorted))),
		P50:  round3(nearestRank(sorted, 0.50)),
		P99:  round3(nearestRank(sorted, 0.99)),
	}
}

func nearestRank(sortedAsc []float64, p float64) float64 {
	idx := int(math.Ceil(p*float64(len(sortedAsc)))) - 1
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sortedAsc) {
		idx = len(sortedAsc) - 1
	}
	return sortedAsc[idx]
}

func round3(v float64) float64 { return math.Round(v*1000) / 1000 }

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// writeEvalReport 落盘报告（目录不存在则创建；返回写入路径）。
func writeEvalReport(t *testing.T, rep *evalReport) string {
	t.Helper()
	// 仅显式触发时写盘（避免 `go test ./gateway/...` 重写已入库的基线证据、弄脏工作区）。
	if os.Getenv("GUARDRAIL_EVAL_WRITE") != "1" {
		t.Logf("（未落盘：设 GUARDRAIL_EVAL_WRITE=1 可写入 %s/%s.json）", filepath.ToSlash(evalDefaultOutDir), rep.Scorer)
		return ""
	}
	dir := filepath.FromSlash(evalDefaultOutDir)
	if override := os.Getenv("GUARDRAIL_EVAL_OUT"); override != "" {
		dir = override
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("创建结果目录失败：%v", err)
	}
	out := filepath.Join(dir, rep.Scorer+".json")
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatalf("报告序列化失败：%v", err)
	}
	if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
		t.Fatalf("报告写入失败：%v", err)
	}
	return out
}

func logEvalSummary(t *testing.T, rep *evalReport, out string) {
	t.Helper()
	t.Logf("候选=%s（backend=%s）语料 %d 条 sha256=%s", rep.Scorer, rep.Backend, rep.CorpusTotal, rep.CorpusSHA[:16])
	t.Logf("  检出① rule        %d/%d = %.2f%%（门禁① ≥95%%）", rep.DetectRule.Blocked, rep.DetectRule.Total, rep.DetectRule.Rate*100)
	t.Logf("  检出② semantic    %d/%d = %.2f%%（公开集语义越狱，仅报告）", rep.DetectSem.Blocked, rep.DetectSem.Total, rep.DetectSem.Rate*100)
	t.Logf("  误报① benign      %d/%d = %.2f%%（门禁② ≤2%%）", rep.FPClean.Blocked, rep.FPClean.Total, rep.FPClean.Rate*100)
	t.Logf("  误报② benign_public %d/%d = %.2f%%（仅报告）", rep.FPPublic.Blocked, rep.FPPublic.Total, rep.FPPublic.Rate*100)
	t.Logf("  已知固有误报      %d/%d（规则缺陷水位，仅报告）", rep.KnownFP.Blocked, rep.KnownFP.Total)
	t.Logf("  延迟 mean=%.1fµs P50=%.1fµs P99=%.1fµs", rep.Latency.Mean, rep.Latency.P50, rep.Latency.P99)
	t.Logf("  资源 %v", rep.Resources)
	if out != "" {
		t.Logf("  结果落盘：%s", out)
	}
}

// ---------- 用例 ----------

// TestGuardrailEvalKeywordBaseline 现状关键词规则基线（默认跑，无外部依赖）。
// 该结果即"不接分类器"的对照水位：门禁①达标，而公开集语义越狱检出率就是 GF.4.3 要抬升的下限。
func TestGuardrailEvalKeywordBaseline(t *testing.T) {
	sc := &keywordEvalScorer{g: newGuardrail()}
	rep := runGuardrailEval(t, sc)
	if len(rep.Errors) > 0 {
		t.Fatalf("基线不应有调用错误：%v", rep.Errors)
	}
	if rep.CorpusTotal == 0 || rep.DetectRule.Total == 0 {
		t.Fatalf("语料不完整：total=%d rule=%d", rep.CorpusTotal, rep.DetectRule.Total)
	}
	out := writeEvalReport(t, rep)
	logEvalSummary(t, rep, out)
}

// TestGuardrailEvalExternalScorer 外部候选评测（需 GUARDRAIL_EVAL_SCORER_URL，否则跳过）。
func TestGuardrailEvalExternalScorer(t *testing.T) {
	url := os.Getenv("GUARDRAIL_EVAL_SCORER_URL")
	if url == "" {
		t.Skip("未配置 GUARDRAIL_EVAL_SCORER_URL —— 外部候选评测跳过（候选就绪后设置该变量即可评）")
	}
	id := os.Getenv("GUARDRAIL_EVAL_SCORER_ID")
	if id == "" {
		id = "external-candidate"
	}
	sc := &httpEvalScorer{
		id: id,
		c:  model.NewHTTPClassifier(url, os.Getenv("GUARDRAIL_EVAL_SCORER_KEY"), 5*time.Second, nil),
	}
	rep := runGuardrailEval(t, sc)
	if len(rep.Errors) > 0 {
		t.Fatalf("候选不可用（%d 次调用失败，首条：%s）——评测结果不可用，不得据以选型",
			len(rep.Errors), rep.Errors[0])
	}
	out := writeEvalReport(t, rep)
	logEvalSummary(t, rep, out)
}

// TestGuardrailEvalContractWithStub 用本地 stub 验证"接候选即出四指标"的链路可用
// （不依赖任何外部资源；stub 语义：含"忽略/jailbreak"即拦截）。
// 报告写入临时目录，不污染 docs/benchmark。
func TestGuardrailEvalContractWithStub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req model.ClassifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		lower := strings.ToLower(req.Text)
		blocked := strings.Contains(lower, "忽略") || strings.Contains(lower, "jailbreak")
		resp := model.ClassifyResponse{Blocked: blocked, Category: "prompt_injection", Match: "stub"}
		if blocked {
			resp.Resources = map[string]any{"mode": "out-of-process", "mem_mb": 128, "device": "cpu"}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("GUARDRAIL_EVAL_OUT", t.TempDir())
	t.Setenv("GUARDRAIL_EVAL_WRITE", "1")
	sc := &httpEvalScorer{id: "stub-candidate", c: model.NewHTTPClassifier(srv.URL, "", 2*time.Second, nil)}
	rep := runGuardrailEval(t, sc)
	if len(rep.Errors) > 0 {
		t.Fatalf("stub 契约不应有调用错误：%v", rep.Errors)
	}
	out := writeEvalReport(t, rep)
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("报告应落盘：%v", err)
	}
	if rep.DetectRule.Total != 61 || rep.DetectSem.Total != 100 {
		t.Errorf("语料族规模应与基准集一致（rule 61 / semantic 100），实际 rule=%d semantic=%d",
			rep.DetectRule.Total, rep.DetectSem.Total)
	}
	if rep.Resources["device"] != "cpu" {
		t.Errorf("候选提供的 resources 应被采集，实际 %v", rep.Resources)
	}
	logEvalSummary(t, rep, out)
}
