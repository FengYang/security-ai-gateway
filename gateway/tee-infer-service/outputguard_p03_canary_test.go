// P0-3 策略 C 首段门修复（canary 块：门控纳入 L2 ＋ 零漏出挂起 ＋ 底线回挂）测试。
package main

import (
	"strings"
	"testing"
	"time"
)

// p03CascadeParams P0-3 测试级联参数：大并发避免块内补判撞容量阀，超时宽松。
func p03CascadeParams(blocking bool) outputGuardCascadeParams {
	return outputGuardCascadeParams{
		Timeout:       2 * time.Second,
		Concurrency:   8,
		MaxSlots:      1024,
		Degrade:       degradeFailClosed,
		BlockEmission: blocking,
	}
}

// newP03Guard 构造策略 C 管线（P0-3 测试用）。
func newP03Guard(t *testing.T, mode string, blocking bool, l1, l2 OutputClassifier) (*outputGuard, *otpmaskMetrics) {
	t.Helper()
	m := newMetrics()
	m.setOutputGuardMode(mode, defaultPolicyVersion)
	a := newAuditChain()
	cfg := outputGuardConfig{
		Mode:          mode,
		Strategy:      outputStrategyC,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       p03CascadeParams(blocking),
	}
	og, err := newOutputGuard(cfg, l1, l2, m, a, "acme", "req-p03")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	if og == nil {
		t.Fatal("策略 C 下 og 不应为 nil")
	}
	return og, m
}

// waitFirstChunkGate 等待首段门完成判定（以指标文本为持锁快照依据，规避数据竞争）。
func waitFirstChunkGate(t *testing.T, m *otpmaskMetrics) {
	t.Helper()
	waitFor(t, "首段门完成判定", func() bool {
		return strings.Contains(renderMetrics(m, 0), "otpmask_output_guard_c_first_chunk_skip_l2_total")
	})
}

// mustProcess 逐句提交（任一失败即终止测试）。
func mustProcess(t *testing.T, og *outputGuard, rec *frameRecorder, sents ...string) {
	t.Helper()
	for _, s := range sents {
		if err := og.Process(s, rec.emit); err != nil {
			t.Fatalf("Process(%q): %v", s, err)
		}
	}
}

// mustFinish 收尾下发（含在飞 L2 收敛等待）。
func mustFinish(t *testing.T, og *outputGuard, rec *frameRecorder) {
	t.Helper()
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
}

// TestP03CanarySafeBlockFlush canary 探测安全 → 块内挂起成员整块放行（不补判）。
func TestP03CanarySafeBlockFlush(t *testing.T) {
	l2 := newStubL2() // 全部未命中（pass）
	og, m := newP03Guard(t, outputGuardShadow, true, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}
	sents := []string{"一。", "二。", "三。", "四。", "五。", "六。"}

	mustProcess(t, og, rec, sents[0])
	waitFirstChunkGate(t, m) // 首段（L2 有结论且未命中底线）→ 门开
	mustProcess(t, og, rec, sents[1:]...)
	mustFinish(t, og, rec)
	og.Close()

	if got, want := rec.joined(), strings.Join(sents, ""); got != want {
		t.Fatalf("安全块应全部下发，got=%q want=%q", got, want)
	}
	// P0-3 核心：canary 安全时块内成员不补判 —— 仅首段＋探测句走 L2
	if n := l2.callCount(); n != 2 {
		t.Fatalf("canary 安全时应仅首段＋探测走 L2，got %d want 2", n)
	}
	body := renderMetrics(m, 0)
	if !strings.Contains(body, "otpmask_output_guard_canary_probe_total 1") {
		t.Fatalf("应记录 1 次 canary 探测\n---\n%s", body)
	}
	if strings.Contains(body, "otpmask_output_guard_canary_reattach_total") {
		t.Fatalf("安全块不应触发回挂\n---\n%s", body)
	}
}

// TestP03CanaryNonBottomHitNoReattach canary 命中非底线类目（A2 歧视）→ 正常动作表，不回挂。
func TestP03CanaryNonBottomHitNoReattach(t *testing.T) {
	l2 := newStubL2()
	l2.verdicts["六。"] = stubVerdict{cat: "A2-03", conf: 0.9} // 非 12 项底线
	og, m := newP03Guard(t, outputGuardShadow, true, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}
	sents := []string{"一。", "二。", "三。", "四。", "五。", "六。"}

	mustProcess(t, og, rec, sents[0])
	waitFirstChunkGate(t, m)
	mustProcess(t, og, rec, sents[1:]...)
	mustFinish(t, og, rec)
	og.Close()

	if n := l2.callCount(); n != 2 {
		t.Fatalf("非底线命中不应触发块内补判，L2 调用 got %d want 2", n)
	}
	if og.casc.canaryAttached {
		t.Fatal("非底线命中不应闩锁（恢复全级联）")
	}
	if strings.Contains(renderMetrics(m, 0), "otpmask_output_guard_canary_reattach_total") {
		t.Fatal("非底线命中不应回挂")
	}
	if got, want := rec.joined(), strings.Join(sents, ""); got != want {
		t.Fatalf("shadow 下应原样下发，got=%q want=%q", got, want)
	}
}

// TestP03CanaryBottomHitReattachRecheck canary 命中 12 项底线 → 闩锁＋块内成员补跑 L2。
func TestP03CanaryBottomHitReattachRecheck(t *testing.T) {
	l2 := newStubL2()
	l2.verdicts["六。"] = stubVerdict{cat: "A1-06", conf: 0.99} // 底线类目
	og, m := newP03Guard(t, outputGuardShadow, true, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}
	sents := []string{"一。", "二。", "三。", "四。", "五。", "六。"}

	mustProcess(t, og, rec, sents[0])
	waitFirstChunkGate(t, m)
	mustProcess(t, og, rec, sents[1:]...)
	mustFinish(t, og, rec)
	og.Close()

	// 一。＋六。＋块内二。~五。补判（4 句）＝ 6
	if n := l2.callCount(); n != 6 {
		t.Fatalf("底线命中应触发块内 4 句补判，L2 调用 got %d want 6", n)
	}
	if !og.casc.canaryAttached {
		t.Fatal("底线命中应闩锁（本请求恢复全级联）")
	}
	if !strings.Contains(renderMetrics(m, 0), "otpmask_output_guard_canary_reattach_total 1") {
		t.Fatalf("应记录 1 次 canary 回挂\n---\n%s", renderMetrics(m, 0))
	}
	if got, want := rec.joined(), strings.Join(sents, ""); got != want {
		t.Fatalf("补判确认安全的块内句应下发，got=%q want=%q", got, want)
	}
}

// TestP03CanaryInconclusiveFailClosed enforcing 下 canary 无结论（调用失败）→
// fail-closed 闩锁＋块内补判，无结论句按句级 P-DEGRADE 丢弃（零漏出）。
func TestP03CanaryInconclusiveFailClosed(t *testing.T) {
	l2 := newStubL2()
	l2.verdicts["六。"] = stubVerdict{fail: true} // conf=-1 → slotTimeout（无结论）
	og, m := newP03Guard(t, outputGuardEnforcing, true, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	mustProcess(t, og, rec, "一。")
	waitFirstChunkGate(t, m)
	mustProcess(t, og, rec, "二。", "三。", "四。", "五。", "六。", "七。")
	mustFinish(t, og, rec)
	og.Close()

	// 一。＋六。＋块内补判 4 句＋七。（闩锁后全级联）＝ 7
	if n := l2.callCount(); n != 7 {
		t.Fatalf("无结论应 fail-closed 闩锁并补判块内成员，L2 调用 got %d want 7", n)
	}
	if !og.casc.canaryAttached {
		t.Fatal("无结论应闩锁（恢复全级联）")
	}
	if blocked, _ := og.BlockInfo(); blocked {
		t.Fatal("无结论属句级降级，不应整流终止")
	}
	got := rec.joined()
	if strings.Contains(got, "六。") {
		t.Fatalf("无结论句不得下发（零漏出），got=%q", got)
	}
	if !strings.Contains(got, "五。") || !strings.Contains(got, "七。") {
		t.Fatalf("块内已判定安全的句与闩锁后内容应下发，got=%q", got)
	}
}

// TestP03FinishForcesPendingBlockProbe Finish 收尾时尾部挂起块等不到下一探测句 →
// 强制首个挂起成员升级为 canary（取真实 L2 结论，避免静默丢尾/死等）。
func TestP03FinishForcesPendingBlockProbe(t *testing.T) {
	l2 := newStubL2()
	og, m := newP03Guard(t, outputGuardShadow, true, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	mustProcess(t, og, rec, "一。")
	waitFirstChunkGate(t, m)
	// 二。~五。 挂起；六。（seq5）为节奏位 → 探测并安全放行整块
	mustProcess(t, og, rec, "二。", "三。", "四。", "五。", "六。")
	waitFor(t, "安全块放行至六。", func() bool { return len(rec.snapshot()) == 6 })
	// 尾部挂起（seq6~9 均非节奏位）：不得先于探测下发
	mustProcess(t, og, rec, "七。", "八。", "九。", "十。")
	if got := len(rec.snapshot()); got != 6 {
		t.Fatalf("canary 未决时挂起句不得下发，帧数 got %d want 6", got)
	}

	mustFinish(t, og, rec)
	og.Close()

	if n := l2.callCount(); n != 3 { // 一。＋六。＋Finish 强制探测的七。
		t.Fatalf("Finish 应强制尾部首个挂起句走 L2，got %d want 3", n)
	}
	if got, want := rec.joined(), "一。二。三。四。五。六。七。八。九。十。"; got != want {
		t.Fatalf("Finish 应放行尾部全部内容，got=%q want=%q", got, want)
	}
}

// TestP03FirstChunkGateRequiresL2Conclusion P0-3 门控纳入 L2：首段 L1 未命中但 L2 无结论
// 时不得跳过 L2（修复前只看 L1 即跳过）。
func TestP03FirstChunkGateRequiresL2Conclusion(t *testing.T) {
	l2 := newStubL2()
	l2.verdicts["一。"] = stubVerdict{fail: true} // 首段 L2 无结论
	og, m := newP03Guard(t, outputGuardShadow, false, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}
	sents := []string{"一。", "二。", "三。"}

	mustProcess(t, og, rec, sents...)
	mustFinish(t, og, rec)
	og.Close()

	if !og.casc.firstChunkDone {
		t.Fatal("首段门应已完成判定")
	}
	if og.casc.firstChunkSkipL2 {
		t.Fatal("首段 L2 无结论时不得跳过 L2")
	}
	if n := l2.callCount(); n != 3 {
		t.Fatalf("应保持完整级联，L2 调用 got %d want 3", n)
	}
	body := renderMetrics(m, 0)
	if strings.Contains(body, "otpmask_output_guard_c_first_chunk_skip_l2_total") {
		t.Fatalf("门未开启时不应输出首段跳过指标\n---\n%s", body)
	}
	if strings.Contains(body, "otpmask_output_guard_canary_probe_total") {
		t.Fatalf("门未开启时不应有 canary 探测\n---\n%s", body)
	}
}

// TestP03FirstChunkL1HitKeepsFullCascade 首段 L1 命中 → 门不入（行为与策略 B 一致）。
func TestP03FirstChunkL1HitKeepsFullCascade(t *testing.T) {
	l2 := newStubL2() // L2 全空
	og, m := newP03Guard(t, outputGuardShadow, false, fakeL2Classifier{cat: "A1-06", conf: 1.0}, l2)
	rec := &frameRecorder{}
	sents := []string{"一。", "二。", "三。"}

	mustProcess(t, og, rec, sents...)
	mustFinish(t, og, rec)
	og.Close()

	if !og.casc.firstChunkDone || og.casc.firstChunkSkipL2 {
		t.Fatal("首段 L1 命中时 firstChunkSkipL2 应为 false")
	}
	// L1 命中后仍异步跑 L2 画像调用（3 句各 1 次）
	if n := l2.callCount(); n != 3 {
		t.Fatalf("L2 调用 got %d want 3", n)
	}
	if strings.Contains(renderMetrics(m, 0), "otpmask_output_guard_canary_probe_total") {
		t.Fatalf("门未开启时不应有 canary 探测\n---\n%s", renderMetrics(m, 0))
	}
}

// TestP03StrategyANoCanary 策略 A 无首段门 → 不产生 canary 探测/回挂。
func TestP03StrategyANoCanary(t *testing.T) {
	l2 := newStubL2()
	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()
	cfg := outputGuardConfig{
		Mode:          outputGuardShadow,
		Strategy:      outputStrategyA,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       p03CascadeParams(true),
	}
	og, err := newOutputGuard(cfg, fakeL2Classifier{}, l2, m, a, "acme", "req-a")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	rec := &frameRecorder{}
	sents := []string{"一。", "二。", "三。", "四。", "五。", "六。"}

	mustProcess(t, og, rec, sents...)
	mustFinish(t, og, rec)
	og.Close()

	if og.casc.firstChunkSkipL2Enabled {
		t.Fatal("策略 A 不应启用首段门")
	}
	if n := l2.callCount(); n != 6 {
		t.Fatalf("策略 A 每句都走 L2，got %d want 6", n)
	}
	body := renderMetrics(m, 0)
	if strings.Contains(body, "otpmask_output_guard_canary_probe_total") ||
		strings.Contains(body, "otpmask_output_guard_canary_reattach_total") {
		t.Fatalf("策略 A 不应输出 canary 指标\n---\n%s", body)
	}
}

// TestP03EnforcingCanaryBottomTerminatesNoLeak enforcing 下 canary 命中底线 →
// 整流终止，命中句及其后内容一律不下发（零漏出）。
func TestP03EnforcingCanaryBottomTerminatesNoLeak(t *testing.T) {
	l2 := newStubL2()
	l2.verdicts["六。"] = stubVerdict{cat: "A1-06", conf: 0.99}
	og, m := newP03Guard(t, outputGuardEnforcing, true, fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	mustProcess(t, og, rec, "一。")
	waitFirstChunkGate(t, m)
	mustProcess(t, og, rec, "二。", "三。", "四。", "五。", "六。", "七。")
	mustFinish(t, og, rec)
	og.Close()

	blocked, cat := og.BlockInfo()
	if !blocked || cat != "A1-06" {
		t.Fatalf("应整流终止且类目为 A1-06，got blocked=%v cat=%q", blocked, cat)
	}
	got := rec.joined()
	if !strings.Contains(got, "一。") {
		t.Fatalf("首段安全内容应已下发，got=%q", got)
	}
	if strings.Contains(got, "六。") {
		t.Fatalf("命中底线的 canary 句不得下发（零漏出），got=%q", got)
	}
	if strings.Contains(got, "七。") {
		t.Fatalf("终止后内容不得下发（零漏出），got=%q", got)
	}
	if !strings.Contains(renderMetrics(m, 0), "otpmask_output_guard_canary_reattach_total 1") {
		t.Fatalf("应记录 1 次 canary 回挂\n---\n%s", renderMetrics(m, 0))
	}
}
