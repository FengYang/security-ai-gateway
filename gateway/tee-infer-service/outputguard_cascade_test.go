// 级联并发控制器单测（OG-13 验收：4 态流转 / 乱序完成与有序下发 / 容量阀 / 超时迟到 /
// 断连收敛 / Finish 排空 / 槽位上限 / P-CONF-BAND 降级 / L1 命中即决不阻塞）。
//
// 全部用进程内 stub 分类器（不启 HTTP server）；HTTP 侧超时/网络错误由
// outputL2HTTPClassifier 的集成测试与 scripts/og12-faultinject.ps1 覆盖。
package main

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// stubL2 可控 L2 stub：按文本指定延迟、门控（等待放行）与判定结果，并记录调用顺序。
type stubL2 struct {
	mu       sync.Mutex
	delays   map[string]time.Duration
	gates    map[string]chan struct{}
	verdicts map[string]stubVerdict
	calls    []string
}

type stubVerdict struct {
	cat  string
	conf float64
	fail bool // true → 返回失败哨兵 ("", -1, "")
}

func newStubL2() *stubL2 {
	return &stubL2{
		delays:   make(map[string]time.Duration),
		gates:    make(map[string]chan struct{}),
		verdicts: make(map[string]stubVerdict),
	}
}

func (s *stubL2) Classify(text string) (string, float64, string) {
	s.mu.Lock()
	s.calls = append(s.calls, text)
	d, g, v := s.delays[text], s.gates[text], s.verdicts[text]
	s.mu.Unlock()
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
