// 级联并发控制器单测（OG-13 验收：4 态流转 / 乱序完成与有序下发 / 容量阀 / 超时迟到 /
// 断连收敛 / Finish 排空 / 槽位上限 / P-CONF-BAND 降级 / L1 命中即决不阻塞）。
//
// 全部用进程内 stub 分类器（不启 HTTP server）；HTTP 侧超时/网络错误由
// outputL2HTTPClassifier 的集成测试与 scripts/og12-faultinject.ps1 覆盖。
package main

import (
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
	"time"
)

// stubL2 可控 L2 stub：按文本指定延迟、门控（等待放行）与判定结果，并记录调用顺序。
// S2 两段式扩展：earlys（轻段判定，有值才回调 onEarly）/ earlyGates（早出回调前门控，
// 模拟轻段迟到——如超时先到）。
type stubL2 struct {
	mu         sync.Mutex
	delays     map[string]time.Duration
	gates      map[string]chan struct{}
	verdicts   map[string]stubVerdict
	calls      []string
	earlys     map[string]bool
	earlyGates map[string]chan struct{}
}

type stubVerdict struct {
	cat  string
	conf float64
	fail bool // true → 返回失败哨兵 ("", -1, "")
}

func newStubL2() *stubL2 {
	return &stubL2{
		delays:     make(map[string]time.Duration),
		gates:      make(map[string]chan struct{}),
		verdicts:   make(map[string]stubVerdict),
		earlys:     make(map[string]bool),
		earlyGates: make(map[string]chan struct{}),
	}
}

func (s *stubL2) Classify(text string) (string, float64, string) {
	s.mu.Lock()
	s.calls = append(s.calls, text)
	d, g, v := s.delays[text], s.gates[text], s.verdicts[text]
	s.mu.Unlock()
	return s.settle(d, g, v)
}

// ClassifyWithEarly 实现 EarlyOutputClassifier（S2 两段式）：先记调用（调用已发出），
// 轻段判定（earlys 有值）经 earlyGates 门控后回调 onEarly（模拟"读到响应文档 1"），
// 再按既有 gates/delays/verdicts 返回完整段；未配 earlys 的文本与 Classify 行为一致。
func (s *stubL2) ClassifyWithEarly(text string, onEarly func(blocked bool)) (string, float64, string) {
	s.mu.Lock()
	s.calls = append(s.calls, text)
	eb, has := s.earlys[text]
	eg := s.earlyGates[text]
	d, g, v := s.delays[text], s.gates[text], s.verdicts[text]
	s.mu.Unlock()
	if eg != nil {
		<-eg
	}
	if has && onEarly != nil {
		onEarly(eb)
	}
	return s.settle(d, g, v)
}

// settle 完整段返回逻辑（两个入口共用：门控 → 延迟 → 判定）。
func (s *stubL2) settle(d time.Duration, g chan struct{}, v stubVerdict) (string, float64, string) {
	if g != nil {
		<-g // 门控：由测试决定何时返回（模拟乱序/慢响应）
	}
	if d > 0 {
		time.Sleep(d)
	}
	if v.fail {
		return "", -1, ""
	}
	return v.cat, v.conf, ""
}

func (s *stubL2) callCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.calls)
}

// frameRecorder 并发安全的下发记录器（emit 由级联 goroutine 调用）。
type frameRecorder struct {
	mu     sync.Mutex
	frames []string
	err    error
}

func (r *frameRecorder) emit(delta, finish string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.frames = append(r.frames, delta)
	return r.err
}

func (r *frameRecorder) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.frames))
	copy(out, r.frames)
	return out
}

func (r *frameRecorder) joined() string {
	return strings.Join(r.snapshot(), "")
}

// waitFor 轮询等待条件成立（默认 2s 超时）；用于等待异步下发/指标落定。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("等待超时：%s", what)
}

// newCascadeGuard 构造级联测试用管线（isolated metrics/audit）。
func newCascadeGuard(t *testing.T, casc outputGuardCascadeParams, l1, l2 OutputClassifier) (*outputGuard, *otpmaskMetrics, *auditChain) {
	t.Helper()
	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()
	cfg := outputGuardConfig{
		Mode:          outputGuardShadow,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       casc,
	}
	og, err := newOutputGuard(cfg, l1, l2, m, a, "acme", "req-cascade")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	return og, m, a
}

// cascadeParams 级联测试参数（并发 4、超时 2s；blocking 控制是否按 enforcing 时序阻塞）。
func cascadeParams(blocking bool) outputGuardCascadeParams {
	return outputGuardCascadeParams{
		Timeout:       2 * time.Second,
		Concurrency:   4,
		MaxSlots:      1024,
		Degrade:       degradeFailClosed,
		BlockEmission: blocking,
	}
}

func renderMetrics(m *otpmaskMetrics, auditLen int) string {
	var sb strings.Builder
	m.render(&sb, auditLen)
	return sb.String()
}

// TestCascadeOrderedEmissionUnderOutOfOrderL2：乱序完成 → 严格按生成顺序下发；
// 队头未决时后续句即使已判定也不下发（§3.6.3 按序下发 / 队头阻塞）。
func TestCascadeOrderedEmissionUnderOutOfOrderL2(t *testing.T) {
	l2 := newStubL2()
	gate := make(chan struct{})
	l2.gates["一。"] = gate // 首句门控：模拟"后发先回"
	l2.verdicts["二。"] = stubVerdict{cat: "A2-03", conf: 0.9}
	l2.verdicts["三。"] = stubVerdict{conf: 0} // 未命中

	og, m, _ := newCascadeGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	for _, d := range []string{"一。", "二。", "三。"} {
		if err := og.Process(d, rec.emit); err != nil {
			t.Fatalf("Process(%q): %v", d, err)
		}
	}
	// 首句未决：一帧都不得下发（后两句已判定也不许跳发）
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("队头未决时不应下发任何帧，实际 %v", got)
	}
	waitFor(t, "三句均已提交 L2", func() bool { return l2.callCount() == 3 })

	close(gate) // 放行首句
	waitFor(t, "三帧按序下发", func() bool { return len(rec.snapshot()) == 3 })
	if got := rec.snapshot(); got[0] != "一。" || got[1] != "二。" || got[2] != "三。" {
		t.Fatalf("下发顺序错误（应严格按生成顺序）：%v", got)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	st := og.casc.stats()
	if st.Sentences != 3 || st.L2Calls != 3 {
		t.Fatalf("句数/L2 调用数不符：%+v", st)
	}
	body := renderMetrics(m, 0)
	if !strings.Contains(body, `otpmask_output_guard_l2_call_total{category="A2-03",result="hit"} 1`) {
		t.Fatalf("L2 命中样本缺失\n---\n%s", body)
	}
}

// TestCascadeQueueDepthAggregatedAcrossRequests OG-13 缺陷2 回归：
// 两个请求级 cascade 共享同一进程 metrics，L2 门控挂起时 buffer_queue_depth
// 必须等于全进程在飞总和；一个请求关闭只按自身残留扣减（不覆写全局），
// 其迟到 L2 回调因 l2InFlight 已销账而 settle no-op（不得重复扣减）；另一请求完成后归零。
func TestCascadeQueueDepthAggregatedAcrossRequests(t *testing.T) {
	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()
	cfg := outputGuardConfig{
		Mode:          outputGuardShadow,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       cascadeParams(true),
	}
	newGuard := func(reqID string, l2 OutputClassifier) *outputGuard {
		og, err := newOutputGuard(cfg, fakeL2Classifier{}, l2, m, a, "acme", reqID)
		if err != nil {
			t.Fatalf("newOutputGuard(%s): %v", reqID, err)
		}
		return og
	}
	depth := func() int64 {
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.ogBufferQueueDepth
	}

	l2A, l2B := newStubL2(), newStubL2()
	gA1, gA2 := make(chan struct{}), make(chan struct{})
	gB1, gB2, gB3 := make(chan struct{}), make(chan struct{}), make(chan struct{})
	l2A.gates["a1。"] = gA1
	l2A.gates["a2。"] = gA2
	l2B.gates["b1。"] = gB1
	l2B.gates["b2。"] = gB2
	l2B.gates["b3。"] = gB3

	ogA, ogB := newGuard("reqA", l2A), newGuard("reqB", l2B)
	recA, recB := &frameRecorder{}, &frameRecorder{}
	for _, d := range []string{"a1。", "a2。"} {
		if err := ogA.Process(d, recA.emit); err != nil {
			t.Fatalf("ogA.Process: %v", err)
		}
	}
	for _, d := range []string{"b1。", "b2。", "b3。"} {
		if err := ogB.Process(d, recB.emit); err != nil {
			t.Fatalf("ogB.Process: %v", err)
		}
	}
	waitFor(t, "5 个 L2 调用全部在飞", func() bool { return l2A.callCount()+l2B.callCount() == 5 })
	if d := depth(); d != 5 {
		t.Fatalf("全进程在飞总量应为 5（旧 set 覆写口径只会看到最后写入者的本地值 3），实际 %d", d)
	}

	// A 断连关闭：2 个在飞按残留扣减；B 的 3 个必须保留（旧代码会全局抹 0）
	ogA.Close()
	if d := depth(); d != 3 {
		t.Fatalf("关闭 A 后全局深度应为 3（仅扣 A 残留 2），实际 %d", d)
	}
	// A 的迟到回调返回：l2InFlight 已销账 → settle no-op，不得重复扣减
	close(gA1)
	close(gA2)
	waitFor(t, "A 的 2 个迟到回调记 late", func() bool {
		return strings.Contains(renderMetrics(m, 0), `{category="",result="late"} 2`)
	})
	if d := depth(); d != 3 {
		t.Fatalf("A 迟到回调后深度应仍为 3（销账防双扣），实际 %d", d)
	}

	// B 三句正常完成：各配对 −1，归零
	close(gB1)
	close(gB2)
	close(gB3)
	if err := ogB.Finish(recB.emit); err != nil {
		t.Fatalf("ogB.Finish: %v", err)
	}
	waitFor(t, "B 完成后全局深度归零", func() bool { return depth() == 0 })
	ogB.Close()
	if d := depth(); d != 0 {
		t.Fatalf("收尾后深度应为 0，实际 %d", d)
	}
}

// TestCascadeNonBlockingKeepsByteStream：生产 shadow（BlockEmission=false）→
// 逐 delta 立即放行，字节序列与输入完全一致（阻塞开关关闭时行为与 M2 一致）。
func TestCascadeNonBlockingKeepsByteStream(t *testing.T) {
	l2 := newStubL2()
	gate := make(chan struct{})
	l2.gates["一。"] = gate // 首句 L2 挂住：验证不阻塞下发

	og, _, _ := newCascadeGuard(t, cascadeParams(false), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	deltas := []string{"一。", "二"}
	if err := og.Process(deltas[0], rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Process(deltas[1], rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got := rec.snapshot(); len(got) != 2 || got[0] != "一。" || got[1] != "二" {
		t.Fatalf("非阻塞形态应逐 delta 立即原样放行，实际 %v", got)
	}
	close(gate)
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	if got := rec.joined(); got != strings.Join(deltas, "") {
		t.Fatalf("字节序列改变：%q", got)
	}
}

// TestCascadeTimeoutDegradesAndDiscardsLate：定时器到期 → 按 P-DEGRADE 处置
// （degraded{l2_timeout} + fail-closed 句计数）；迟到结果丢弃并记 l2_call{late}，
// 不回改终态（4 态单向无回退）。
func TestCascadeTimeoutDegradesAndDiscardsLate(t *testing.T) {
	l2 := newStubL2()
	gate := make(chan struct{})
	l2.gates["慢句。"] = gate
	l2.verdicts["慢句。"] = stubVerdict{cat: "A2-03", conf: 0.9}

	p := cascadeParams(true)
	p.Timeout = 50 * time.Millisecond
	og, m, a := newCascadeGuard(t, p, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("慢句。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "槽位超时后按 P-DEGRADE 计数", func() bool { return og.casc.stats().FailClosed == 1 })
	waitFor(t, "degraded{reason=l2_timeout} 落指标", func() bool {
		return strings.Contains(renderMetrics(m, 0), `otpmask_output_guard_degraded_total{backend="l2",reason="l2_timeout"} 1`)
	})
	// 超时后放行 L2：迟到结果必须被丢弃（不改终态、不产生 would_reject）
	close(gate)
	waitFor(t, "迟到结果记 l2_call{late}", func() bool {
		return strings.Contains(renderMetrics(m, 0), `otpmask_output_guard_l2_call_total{category="",result="late"} 1`)
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	if st := og.casc.stats(); st.FailClosed != 1 || st.Sentences != 1 {
		t.Fatalf("超时后计数不符（迟到不得回改终态）：%+v", st)
	}
	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("迟到结果不应产生 would_reject，实际 %d", n)
	}
	if n := a.countByAction("output_guard_degraded"); n != 1 {
		t.Fatalf("应落 1 条 output_guard_degraded（每请求一条），实际 %d", n)
	}
}

// TestCascadeConcurrencyValveNoQueue：提交时超 P-CONCURRENCY → 该句直接按 P-DEGRADE
// （不排队），并记 buffer_full_total + degraded{l2_overload}。
func TestCascadeConcurrencyValveNoQueue(t *testing.T) {
	l2 := newStubL2()
	gate := make(chan struct{})
	l2.gates["甲。"] = gate

	p := cascadeParams(false)
	p.Concurrency = 1
	og, m, a := newCascadeGuard(t, p, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("甲。", rec.emit); err != nil {
		t.Fatalf("Process(甲): %v", err)
	}
	if err := og.Process("乙。", rec.emit); err != nil {
		t.Fatalf("Process(乙): %v", err)
	}
	body := renderMetrics(m, 0)
	for _, want := range []string{
		`otpmask_output_guard_buffer_full_total 1`,
		`otpmask_output_guard_degraded_total{backend="l2",reason="l2_overload"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("容量阀样本缺失 %q\n---\n%s", want, body)
		}
	}
	if st := og.casc.stats(); st.FailClosed != 1 || st.L2Calls != 1 {
		t.Fatalf("超并发句应按 P-DEGRADE 且不发起 L2 调用：%+v", st)
	}
	if n := a.countByAction("output_guard_degraded"); n != 1 {
		t.Fatalf("应落 1 条 output_guard_degraded，实际 %d", n)
	}
	close(gate)
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
}

// TestCascadeMaxSlotsFailClosed：超 P-MAX-SLOTS → 不再建槽位，按 P-DEGRADE 收尾并记指标，
// 该单元 delta 仍下发（shadow 不拦内容）。
func TestCascadeMaxSlotsFailClosed(t *testing.T) {
	p := cascadeParams(false)
	p.MaxSlots = 1
	og, m, _ := newCascadeGuard(t, p, fakeL2Classifier{}, fakeL2Classifier{conf: 0.5})
	rec := &frameRecorder{}

	if err := og.Process("一。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Process("二。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	st := og.casc.stats()
	if st.Sentences != 2 || st.Slots != 1 || st.FailClosed != 1 {
		t.Fatalf("槽位上限未生效：%+v", st)
	}
	body := renderMetrics(m, 0)
	for _, want := range []string{
		`otpmask_output_guard_buffer_full_total 1`,
		`otpmask_output_guard_degraded_total{backend="l2",reason="l2_slots_full"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("槽位上限样本缺失 %q\n---\n%s", want, body)
		}
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	if got := rec.joined(); got != "一。二。" {
		t.Fatalf("shadow 不应丢弃内容：%q", got)
	}
}

// TestCascadeConfidenceMissingDegrades：命中但置信度缺失 → 格式错误 → P-DEGRADE
// （P-CONF-BAND 写死，不做默认猜测）；不产生 would_reject。
func TestCascadeConfidenceMissingDegrades(t *testing.T) {
	// fakeL2Classifier{cat:"A2-03", conf:0} = 命中但未返回置信度
	og, m, a := newCascadeGuard(t, cascadeParams(false), fakeL2Classifier{}, fakeL2Classifier{cat: "A2-03"})
	rec := &frameRecorder{}

	if err := og.Process("某句。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	body := renderMetrics(m, 0)
	for _, want := range []string{
		`otpmask_output_guard_l2_call_total{category="A2-03",result="bad_conf"} 1`,
		`otpmask_output_guard_degraded_total{backend="l2",reason="l2_bad_conf"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("置信度缺失应降级，样本缺失 %q\n---\n%s", want, body)
		}
	}
	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("格式错误不得记 would_reject，实际 %d", n)
	}
	if st := og.casc.stats(); st.FailClosed != 1 {
		t.Fatalf("应计 1 句 fail-closed：%+v", st)
	}
}

// TestCascadeUnmappedDegrades：L2 返回未映射类目 → 格式错误 → P-DEGRADE（§4.2.3），
// 同时记 unmapped 诊断。
func TestCascadeUnmappedDegrades(t *testing.T) {
	og, m, a := newCascadeGuard(t, cascadeParams(false), fakeL2Classifier{}, fakeL2Classifier{cat: "weird_category", conf: 0.95})
	rec := &frameRecorder{}

	if err := og.Process("某句。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	body := renderMetrics(m, 0)
	for _, want := range []string{
		`otpmask_output_guard_unmapped_total{backend="l2",category_raw="weird_category"} 1`,
		`otpmask_output_guard_degraded_total{backend="l2",reason="l2_unmapped"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("未映射应降级，样本缺失 %q\n---\n%s", want, body)
		}
	}
	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("未映射不得记 would_reject，实际 %d", n)
	}
}

// TestCascadeFinishDrainsAndMeasuresFirstFrame：阻塞形态下 Finish 等在飞 L2 收敛后按序排空，
// 首帧延迟增量 = 首次写出 − 首个 delta 进入管线（≥ L2 延迟）。
func TestCascadeFinishDrainsAndMeasuresFirstFrame(t *testing.T) {
	l2 := newStubL2()
	l2.delays["慢句。"] = 40 * time.Millisecond

	og, m, _ := newCascadeGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("慢句。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("阻塞形态下首句未决不应下发，实际 %v", got)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	if got := rec.joined(); got != "慢句。" {
		t.Fatalf("Finish 后应排空下发：%q", got)
	}
	st := og.casc.stats()
	if !st.HasFirstFrame || st.FirstFrameDelay < 30*time.Millisecond {
		t.Fatalf("首帧延迟增量应 ≥ L2 延迟（40ms）：%+v", st)
	}
	body := renderMetrics(m, 0)
	if !strings.Contains(body, "otpmask_output_guard_first_frame_delay_seconds_count 1") {
		t.Fatalf("首帧延迟直方图缺样本\n---\n%s", body)
	}
	if !strings.Contains(body, "otpmask_output_guard_l2_cascade_ratio 1") {
		t.Fatalf("级联占比派生 gauge 应为 1（1 句 / 1 次 L2 调用）\n---\n%s", body)
	}
}

// TestCascadeL1HitDoesNotBlock（方案 2 保留）：L1 命中即决不阻塞下发（即使 L2 很慢），
// L2 仍作为画像调用（结果只留痕、不迁移槽位状态）。
func TestCascadeL1HitDoesNotBlock(t *testing.T) {
	l2 := newStubL2()
	gate := make(chan struct{})
	// L1 命中 sql_injection → A1-07；L2 画像门控挂住（不得阻塞下发）
	l2.gates["请执行 SELECT * FROM users。"] = gate
	l2.verdicts["请执行 SELECT * FROM users。"] = stubVerdict{cat: "A1-07", conf: 0.9}

	og, m, a := newCascadeGuard(t, cascadeParams(true), l1Classifier{g: newGuardrail()}, l2)
	rec := &frameRecorder{}

	const text = "请执行 SELECT * FROM users。"
	if err := og.Process(text, rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	// L1 命中即决：立即下发（不受 L2 画像调用影响）
	waitFor(t, "L1 命中句立即下发", func() bool { return rec.joined() == text })
	waitFor(t, "L2 画像调用已发起", func() bool { return l2.callCount() == 1 })

	close(gate)
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	if n := a.countByAction("output_would_reject"); n != 1 {
		t.Fatalf("L1 与 L2 同类目命中应去重为 1 条 would_reject，实际 %d", n)
	}
	body := renderMetrics(m, 0)
	if !strings.Contains(body, `otpmask_output_guard_l2_call_total{category="A1-07",result="hit"} 1`) {
		t.Fatalf("画像调用应记 l2_call/hit（方案 2）\n---\n%s", body)
	}
	if st := og.casc.stats(); st.FailClosed != 0 {
		t.Fatalf("L1 命中不应计入 fail-closed：%+v", st)
	}
}

// TestCascadeCloseIsIdempotentAndSettlesInflight：Close 幂等；断连后未决槽位置 closed、
// 在飞计数归零；此后到达的 L2 结果按迟到丢弃（不泄漏、不 panic）。
func TestCascadeCloseIsIdempotentAndSettlesInflight(t *testing.T) {
	l2 := newStubL2()
	gate := make(chan struct{})
	l2.gates["甲。"] = gate
	l2.verdicts["甲。"] = stubVerdict{cat: "A2-03", conf: 0.9}

	og, m, a := newCascadeGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("甲。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	og.Close()
	og.Close() // 幂等
	if st := og.casc.stats(); st.FailClosed != 0 {
		t.Fatalf("断连不应计 fail-closed：%+v", st)
	}
	if got := renderMetrics(m, 0); !strings.Contains(got, "otpmask_output_guard_buffer_queue_depth 0") {
		t.Fatalf("断连后队列深度应归零\n---\n%s", got)
	}
	// Close 后 Process 不再缓冲/下发
	if err := og.Process("乙。", rec.emit); err != nil {
		t.Fatalf("Close 后 Process 应静默返回：%v", err)
	}
	close(gate)
	waitFor(t, "断连后在飞结果按迟到丢弃", func() bool {
		return strings.Contains(renderMetrics(m, 0), `otpmask_output_guard_l2_call_total{category="",result="late"} 1`)
	})
	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("断连后不得产命中留痕，实际 %d", n)
	}
}

// ---- OG-13 B2 验收：shadow 字节零变化 + 阻塞预演（§2.3「不改变输出字节」红线）----

// randL2Stub 随机判定 L2 stub：按种子生成随机"判定 + 延迟"，覆盖全部归一化分支
// （未命中 / 命中 / 置信度缺失 / 类目未映射 / 调用失败）与乱序完成。
// RNG 取数在锁内完成、睡眠在锁外（并发安全且不串行化调用）。
type randL2Stub struct {
	mu     sync.Mutex
	rng    *rand.Rand
	jitter time.Duration
}

func newRandL2Stub(seed int64, jitter time.Duration) *randL2Stub {
	return &randL2Stub{rng: rand.New(rand.NewSource(seed)), jitter: jitter}
}

func (s *randL2Stub) Classify(string) (string, float64, string) {
	s.mu.Lock()
	roll := s.rng.Intn(5)
	conf := 0.5 + s.rng.Float64()/2
	var delay time.Duration
	if s.jitter > 0 {
		delay = time.Duration(s.rng.Int63n(int64(s.jitter)))
	}
	s.mu.Unlock()
	if delay > 0 {
		time.Sleep(delay)
	}
	switch roll {
	case 0:
		return "", 0, "" // 未命中
	case 1:
		return "A2-03", conf, "" // 命中
	case 2:
		return "A1-07", 0, "" // 命中但置信度缺失 → P-DEGRADE
	case 3:
		return "未映射类目", conf, "" // 类目未映射 → P-DEGRADE
	default:
		return "", -1, "" // 调用失败 → P-DEGRADE
	}
}

// randDeltas 生成随机 delta 序列：含终止句与未终止片段（覆盖"多个 delta 归属同一槽位"
// 与"delta 无槽位归属"两种形态），含多 rune 字符与空句。
func randDeltas(rng *rand.Rand, n int) []string {
	body := []rune("甲乙丙丁戊己庚辛壬癸")
	tails := []string{"。", "！", "？", "；", "…", "\n", ""}
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var sb strings.Builder
		for j, l := 0, 1+rng.Intn(4); j < l; j++ {
			sb.WriteRune(body[rng.Intn(len(body))])
		}
		sb.WriteString(tails[rng.Intn(len(tails))])
		out = append(out, sb.String())
	}
	return out
}

// fuzzCascadeParams 字节一致性 fuzz 参数：并发/槽位上限放大，让每句都真实走 L2 判定路径
// （而非被容量阀快速降级），从而覆盖全部分支；超时保持默认（避免 fuzz 变成超时测试）。
func fuzzCascadeParams(blocking bool) outputGuardCascadeParams {
	p := cascadeParams(blocking)
	p.Concurrency = 64
	p.MaxSlots = 4096
	return p
}

// assertEmitFrames 逐帧校验下发序列与输入 delta 序列完全一致：
// 帧数相等（不跳发、不合并帧）且逐帧字节相同（原样写出、不改内容）。
func assertEmitFrames(t *testing.T, ctx string, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s：下发帧数 %d ≠ delta 数 %d（跳发或合并帧）\n got=%q\nwant=%q", ctx, len(got), len(want), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s：第 %d 帧字节不符\n got=%q\nwant=%q", ctx, i, got[i], want[i])
		}
	}
}

// runCascadeStream 按给定形态跑一遍流式提交，返回下发帧序列。
func runCascadeStream(t *testing.T, deltas []string, blocking bool, l2 OutputClassifier) []string {
	t.Helper()
	og, _, _ := newCascadeGuard(t, fuzzCascadeParams(blocking), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}
	for _, d := range deltas {
		if err := og.Process(d, rec.emit); err != nil {
			t.Fatalf("blocking=%t Process(%q): %v", blocking, d, err)
		}
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("blocking=%t Finish: %v", blocking, err)
	}
	og.Close()
	return rec.snapshot()
}

// TestCascadeShadowByteStreamFuzz（B2 验收 1）：生产 shadow（BlockEmission=false）下，
// 随机 delta 序列 × 随机 L2 判定/延迟/乱序完成 → 下发帧序列与输入逐帧相同（字节零变化）。
func TestCascadeShadowByteStreamFuzz(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		deltas := randDeltas(rand.New(rand.NewSource(seed)), 40)
		got := runCascadeStream(t, deltas, false, newRandL2Stub(seed, 12*time.Millisecond))
		assertEmitFrames(t, fmt.Sprintf("shadow seed=%d", seed), got, deltas)
	}
}

// TestCascadeBlockingMatchesShadowBytes（B2 验收 2a）：同一输入、同一 L2 随机序列，
// 分别在阻塞预演（BlockEmission=true）与生产 shadow 下跑 → 两形态下发帧序列逐帧相同，
// 且都等于输入（阻塞开关只改时序、不改字节；§3.6.3 末段要求）。
func TestCascadeBlockingMatchesShadowBytes(t *testing.T) {
	for seed := int64(1); seed <= 20; seed++ {
		deltas := randDeltas(rand.New(rand.NewSource(seed)), 40)
		shadow := runCascadeStream(t, deltas, false, newRandL2Stub(seed, 12*time.Millisecond))
		blocking := runCascadeStream(t, deltas, true, newRandL2Stub(seed, 12*time.Millisecond))
		assertEmitFrames(t, fmt.Sprintf("shadow seed=%d", seed), shadow, deltas)
		assertEmitFrames(t, fmt.Sprintf("blocking seed=%d", seed), blocking, deltas)
	}
}

// TestCascadeBlockingStreamingFirstFrameDelay（B2 验收 2b）：阻塞预演下流式提交——
// 首句 L2 慢、后句 L2 快（后发先回）：后句不得越过首句下发；首帧延迟增量 ≈ 首句 L2 延迟
// （§4.3.2 首帧延迟增量口径）；收尾后排空且字节与输入一致。
func TestCascadeBlockingStreamingFirstFrameDelay(t *testing.T) {
	const l2Delay = 60 * time.Millisecond
	l2 := newStubL2()
	l2.delays["首句。"] = l2Delay // 后两句不在 delays 中：立即返回（模拟后发先回）

	og, m, _ := newCascadeGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	deltas := []string{"首句。", "次句。", "末句。"}
	start := time.Now()
	for _, d := range deltas {
		if err := og.Process(d, rec.emit); err != nil {
			t.Fatalf("Process(%q): %v", d, err)
		}
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("首句未决时后句不得越过下发，实际 %v", got)
	}
	waitFor(t, "三帧按序下发", func() bool { return len(rec.snapshot()) == 3 })
	if elapsed := time.Since(start); elapsed < l2Delay {
		t.Fatalf("首帧延迟增量应 ≥ 首句 L2 延迟（%v），实际 %v", l2Delay, elapsed)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	assertEmitFrames(t, "blocking streaming", rec.snapshot(), deltas)

	st := og.casc.stats()
	if !st.HasFirstFrame {
		t.Fatal("未记录首帧时刻（阻塞形态首帧延迟应为真实增量）")
	}
	if st.FirstFrameDelay < l2Delay-10*time.Millisecond {
		t.Fatalf("首帧延迟增量应 ≈ 首句 L2 延迟（%v），实际 %v", l2Delay, st.FirstFrameDelay)
	}
	if body := renderMetrics(m, 0); !strings.Contains(body, "otpmask_output_guard_first_frame_delay_seconds_count 1") {
		t.Fatalf("首帧延迟直方图缺样本\n---\n%s", body)
	}
}

// TestCascadeBlockingReleasesUnclaimedTail（B2 验收 2c）：阻塞形态下，尾部 delta 若始终
// 未构成判定单元（纯空白），Finish 兜底放行后必须真正下发——不得丢字节，
// 也不得让下发游标永久卡住（否则 Finish 永不返回）。
func TestCascadeBlockingReleasesUnclaimedTail(t *testing.T) {
	// 唯一槽位的 L2 立即返回未命中 → 判定完成后无在飞调用（复现"无人在飞"的死锁前提）
	og, _, _ := newCascadeGuard(t, fuzzCascadeParams(true), fakeL2Classifier{}, fakeL2Classifier{conf: 0.5})
	rec := &frameRecorder{}

	deltas := []string{"甲。", "\n", " "}
	for _, d := range deltas {
		if err := og.Process(d, rec.emit); err != nil {
			t.Fatalf("Process(%q): %v", d, err)
		}
	}
	// 等首句判定完成并下发：此后 inFlight=0 且无未决槽位，仅剩两个未认领 delta
	waitFor(t, "首帧下发", func() bool { return len(rec.snapshot()) == 1 })
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	assertEmitFrames(t, "blocking unclaimed tail", rec.snapshot(), deltas)
}

// ---- S2 两段式早出消费（D8 T2/T5；2026-09-19 落地）----
//
// 覆盖：early-pass 首帧放行 / 早出 true held 等完整段定类目 / early-pass 停表
// （完整段迟到不超时）/ held 超时降级兜底 / 早出迟到于超时不回改 / 画像早出不迁移状态。

// S2-1 early-pass 首帧放行（T2）：轻段 false → 槽位提前终态 pass 且立即下发——
// 完整段（gate 未开）未返回时帧已在客户端。
func TestCascadeEarlyPassFirstFrame(t *testing.T) {
	l2 := newStubL2()
	l2.earlys["一。"] = false
	gate := make(chan struct{})
	l2.gates["一。"] = gate // 完整段门控：模拟槽位占用至完整输出（策略 i，E[S]=完整时长）
	og, m, _ := newCascadeGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("一。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "轻段即放行（完整段未返回）", func() bool { return len(rec.snapshot()) == 1 })
	if got := rec.joined(); got != "一。" {
		t.Fatalf("已放行内容错误：%q", got)
	}
	close(gate) // 完整段返回（miss）
	waitFor(t, "完整段 miss 指标", func() bool {
		return strings.Contains(renderMetrics(m, 0), `{category="",result="miss"} 1`)
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	body := renderMetrics(m, 0)
	if strings.Contains(body, "otpmask_output_guard_degraded_total") {
		t.Fatalf("早出放行不应产生降级\n---\n%s", body)
	}
	if strings.Contains(body, "l2_timeout") {
		t.Fatalf("early-pass 槽位不应超时\n---\n%s", body)
	}
}

// S2-2 早出 true → held（策略 i）：轻段无类目不能定动作，完整段命中前零下发；
// 完整段返回后按类目处置（shadow：放行 + would_reject 留痕）。
func TestCascadeEarlyTrueHeldForCategory(t *testing.T) {
	l2 := newStubL2()
	l2.earlys["违规。"] = true
	gate := make(chan struct{})
	l2.gates["违规。"] = gate
	l2.verdicts["违规。"] = stubVerdict{cat: "A1-06", conf: 0.9}
	og, m, a := newCascadeGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("违规。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "L2 调用已发出（轻段已到）", func() bool { return l2.callCount() == 1 })
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("held 期间不得放行（轻段 true 无类目不能定动作），实际 %v", got)
	}
	close(gate)
	waitFor(t, "完整段命中后放行（shadow 原样）", func() bool { return len(rec.snapshot()) == 1 })
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	if n := a.countByAction("output_would_reject"); n != 1 {
		t.Fatalf("shadow 命中应记 1 条 would_reject，实际 %d", n)
	}
	if body := renderMetrics(m, 0); !strings.Contains(body, `{category="A1-06",result="hit"} 1`) {
		t.Fatalf("完整段命中样本缺失\n---\n%s", body)
	}
}

// S2-3 early-pass 停表：槽位提前终态即停表——完整段晚于 P-TIMEOUT 返回也不触发超时降级。
func TestCascadeEarlyPassStopsTimer(t *testing.T) {
	params := cascadeParams(true)
	params.Timeout = 80 * time.Millisecond
	l2 := newStubL2()
	l2.earlys["一。"] = false
	gate := make(chan struct{})
	l2.gates["一。"] = gate
	og, m, _ := newCascadeGuard(t, params, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("一。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "轻段即放行", func() bool { return len(rec.snapshot()) == 1 })
	time.Sleep(150 * time.Millisecond) // 越过 P-TIMEOUT 窗口：完整段仍挂起
	close(gate)                        // 完整段迟到返回（miss）
	waitFor(t, "完整段 miss 指标", func() bool {
		return strings.Contains(renderMetrics(m, 0), `{category="",result="miss"} 1`)
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	body := renderMetrics(m, 0)
	if strings.Contains(body, "l2_timeout") || strings.Contains(body, "result=\"timeout\"") {
		t.Fatalf("early-pass 已停表，完整段迟到不应触发超时降级\n---\n%s", body)
	}
	if strings.Contains(body, "otpmask_output_guard_degraded_total") {
		t.Fatalf("不应有降级\n---\n%s", body)
	}
	if got := rec.joined(); got != "一。" {
		t.Fatalf("应恰一次放行，实际 %q", got)
	}
}

// S2-4 早出 true + 完整段超时 → held 槽位超时降级兜底（l2_timeout + P-DEGRADE；
// 浸泡形态 timeout 照发复刻时序）；迟到的完整段记 late、不回改。
func TestCascadeEarlyTrueHeldTimeoutDegrades(t *testing.T) {
	params := cascadeParams(true)
	params.Timeout = 80 * time.Millisecond
	l2 := newStubL2()
	l2.earlys["违规。"] = true
	gate := make(chan struct{})
	l2.gates["违规。"] = gate // 完整段在超时窗口内不返回
	og, m, _ := newCascadeGuard(t, params, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("违规。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "held 超时降级", func() bool {
		return strings.Contains(renderMetrics(m, 0), `reason="l2_timeout"`)
	})
	close(gate) // 迟到的完整段：槽位已 timeout → late（须先归零在飞，Finish 才不阻塞）
	waitFor(t, "迟到完整段记 late", func() bool {
		return strings.Contains(renderMetrics(m, 0), `{category="",result="late"} 1`)
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	body := renderMetrics(m, 0)
	if !strings.Contains(body, `otpmask_output_guard_degraded_total{backend="l2",reason="l2_timeout"} 1`) {
		t.Fatalf("held 超时应降级 l2_timeout\n---\n%s", body)
	}
	if got := rec.joined(); got != "违规。" {
		t.Fatalf("浸泡模式 timeout 应照发（恰一次），实际 %q", got)
	}
}

// S2-5 早出迟到于超时：槽位已 timeout → 不回改、不迁移、不重复下发（4 态单向无回退）。
func TestCascadeEarlyAfterTimeoutNoRollback(t *testing.T) {
	params := cascadeParams(true)
	params.Timeout = 80 * time.Millisecond
	l2 := newStubL2()
	l2.earlys["一。"] = false
	eg := make(chan struct{})
	l2.earlyGates["一。"] = eg // 轻段挂起：超时先到
	og, m, _ := newCascadeGuard(t, params, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("一。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "槽位超时（轻段未到）", func() bool {
		return strings.Contains(renderMetrics(m, 0), `reason="l2_timeout"`)
	})
	close(eg) // 轻段此时才到：槽位已 timeout → onEarlyVerdict no-op
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	waitFor(t, "完整段返回记 late", func() bool {
		return strings.Contains(renderMetrics(m, 0), `{category="",result="late"} 1`)
	})
	if got := rec.joined(); got != "一。" {
		t.Fatalf("浸泡模式超时照发应恰一次（早出不得重复下发），实际 %q", got)
	}
}

// S2-6 画像调用早出不迁移状态：L1 命中即决放行，画像 L2 的轻段/完整段只留痕。
func TestCascadeProfilingEarlyNoStateChange(t *testing.T) {
	text := "请执行 SELECT * FROM users。"
	l2 := newStubL2()
	l2.earlys[text] = false
	gate := make(chan struct{})
	l2.gates[text] = gate
	l2.verdicts[text] = stubVerdict{cat: "A1-07", conf: 0.9} // 与 L1 同类目（去重）
	og, m, a := newCascadeGuard(t, cascadeParams(true), l1Classifier{g: newGuardrail()}, l2)
	rec := &frameRecorder{}

	if err := og.Process(text, rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "L1 命中即决放行（不等 L2 完整段）", func() bool { return rec.joined() == text })
	waitFor(t, "画像 L2 已发出（轻段已到）", func() bool { return l2.callCount() == 1 })
	close(gate)
	waitFor(t, "画像命中留痕", func() bool {
		return strings.Contains(renderMetrics(m, 0), `{category="A1-07",result="hit"} 1`)
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	if n := a.countByAction("output_would_reject"); n != 1 {
		t.Fatalf("L1 命中应恰记 1 条 would_reject（画像 L2 同类目去重），实际 %d", n)
	}
	if got := rec.joined(); got != text {
		t.Fatalf("放行内容错误：%q", got)
	}
}
