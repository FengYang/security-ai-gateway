// M4 OG-17 enforcing 语义单测（计划 §七 用例 1-12/16/19；e2e 13/14 在 framewise 侧，
// fail-safe 15 在 policy 侧）。
//
// 覆盖语义裁定：
//   - D1' mask 类目（A4-06）在 block-only 深度下降为 flag+log，流不中断；
//   - D3' 半句跨 delta 泄漏：认领扫描用区间包含谓词，pending 队头持有后续 delta；
//   - D5  slots_full（无槽位可审）→ fail-closed 整流终止，category 空、不发 output_blocked；
//   - D6  同 delta 多认领者 block > pending > timeout > emit；L2 失败的句级丢弃非终止。
package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// newEnforcingGuard 构造 enforcing 级联管线（isolated metrics/audit；默认 fail-closed 参数）。
func newEnforcingGuard(t *testing.T, casc outputGuardCascadeParams, l1, l2 OutputClassifier) (*outputGuard, *otpmaskMetrics, *auditChain) {
	t.Helper()
	m := newMetrics()
	m.setOutputGuardMode(outputGuardEnforcing, defaultPolicyVersion)
	a := newAuditChain()
	cfg := outputGuardConfig{
		Mode:          outputGuardEnforcing,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       casc,
	}
	og, err := newOutputGuard(cfg, l1, l2, m, a, "acme", "req-enforcing")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	return og, m, a
}

// 1. 干净流：逐字节透传，无任何拦截/降级/命中。
func TestEnforcingCleanStreamPassThrough(t *testing.T) {
	og, m, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, newStubL2())
	rec := &frameRecorder{}

	for _, d := range []string{"今天天气。", "真好啊。"} {
		if err := og.Process(d, rec.emit); err != nil {
			t.Fatalf("Process(%q): %v", d, err)
		}
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if got := rec.joined(); got != "今天天气。真好啊。" {
		t.Fatalf("干净流必须逐字节透传，实际 %q", got)
	}
	og.Close()
	if blocked, _ := og.BlockInfo(); blocked {
		t.Fatal("干净流不应置位 blocked")
	}
	if gm := og.BuildGuardMeta(); gm.Detected || gm.Filtered {
		t.Fatalf("干净流 guard meta 应为全否：%+v", gm)
	}
	if body := renderMetrics(m, 0); strings.Contains(body, "blocked_total") {
		t.Fatalf("干净流不应有 blocked 指标：\n%s", body)
	}
}

// 2/10. L1 命中 block 类目：首句即终止，后续 Process/Finish 零字节且不再计句。
func TestEnforcingL1BlockTerminatesZeroBytes(t *testing.T) {
	// L1 桩恒命中 A1-06（显性 block 类目）；不挂 L2（L1 命中即决不送 L2）。
	og, m, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{cat: "A1-06", conf: 1.0}, nil)
	rec := &frameRecorder{}

	if err := og.Process("违规内容。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("命中首句必须零下发，实际 %v", got)
	}
	if err := og.Process("后续内容。", rec.emit); err != nil {
		t.Fatalf("blocked 后 Process 应短路返回 nil，实际 %v", err)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("blocked 后 Finish 应立即返回 nil，实际 %v", err)
	}
	og.Close()

	blocked, cat := og.BlockInfo()
	if !blocked || cat != "A1-06" {
		t.Fatalf("BlockInfo 期望 (true,A1-06)，实际 (%v,%q)", blocked, cat)
	}
	gm := og.BuildGuardMeta()
	if !gm.Detected || !gm.Filtered || gm.Action != catActionBlock || gm.Category != "A1-06" {
		t.Fatalf("guard meta 应为 block/A1-06：%+v", gm)
	}
	// OG-19：output_blocked 审计事件已上移到 streamTextInfer 层发射（以精确计算 filtered_tokens），
	// cascade 层只记指标。此处用指标 + BlockInfo 验证 block 状态，审计事件在 framewise e2e 中断言。
	if body := renderMetrics(m, 0); !strings.Contains(body, `otpmask_output_guard_blocked_total{category="A1-06",mode="enforcing"} 1`) {
		t.Fatalf("blocked 指标缺失：\n%s", body)
	}
}

// 3. L2 门控未决期间零下发；block 判定回来后整流终止、零泄漏。
func TestEnforcingL2GateZeroLeak(t *testing.T) {
	l2 := newStubL2()
	gate := make(chan struct{})
	l2.gates["违规。"] = gate
	l2.verdicts["违规。"] = stubVerdict{cat: "A1-06", conf: 0.9}
	og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("违规。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "L2 已受理该句", func() bool { return l2.callCount() == 1 })
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("L2 未决时必须零下发，实际 %v", got)
	}
	close(gate)
	waitFor(t, "block 判定落定", func() bool {
		b, _ := og.BlockInfo()
		return b
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	if got := rec.joined(); got != "" {
		t.Fatalf("block 句零字节可达，实际下发 %q", got)
	}
	if _, cat := og.BlockInfo(); cat != "A1-06" {
		t.Fatalf("blockCat 期望 A1-06，实际 %q", cat)
	}
}

// 4. 同一 chunk 多句：一句违规整 delta 扣下；全干净则逐字节透传。
func TestEnforcingMultiSentenceSameChunk(t *testing.T) {
	t.Run("违规", func(t *testing.T) {
		l2 := newStubL2()
		l2.verdicts["违规。"] = stubVerdict{cat: "A1-06", conf: 0.9}
		og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
		rec := &frameRecorder{}

		if err := og.Process("违规。干净。", rec.emit); err != nil {
			t.Fatalf("Process: %v", err)
		}
		waitFor(t, "block 判定落定", func() bool {
			b, _ := og.BlockInfo()
			return b
		})
		if err := og.Finish(rec.emit); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		og.Close()
		if got := rec.joined(); got != "" {
			t.Fatalf("同 chunk 含违规必须整扣，实际下发 %q", got)
		}
	})

	t.Run("全干净", func(t *testing.T) {
		og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, newStubL2())
		rec := &frameRecorder{}
		if err := og.Process("干净甲。干净乙。", rec.emit); err != nil {
			t.Fatalf("Process: %v", err)
		}
		if err := og.Finish(rec.emit); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		og.Close()
		if got := rec.joined(); got != "干净甲。干净乙。" {
			t.Fatalf("多句干净流应逐字节透传，实际 %q", got)
		}
	})
}

// 5. 半句跨 delta（D3'）：第一个 delta 无终止符不产生判定单元；
// 违规半句在未认领期间必须扣住，拼出整句被 block 后整流失效。
func TestEnforcingCrossDeltaHalfSentence(t *testing.T) {
	l2 := newStubL2()
	l2.verdicts["违规。"] = stubVerdict{cat: "A1-06", conf: 0.9}
	og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("违规", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("无终止符的半句不得下发，实际 %v", got)
	}
	if err := og.Process("。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "block 判定落定", func() bool {
		b, _ := og.BlockInfo()
		return b
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	if got := rec.joined(); got != "" {
		t.Fatalf("跨 delta 违规半句必须零泄漏，实际下发 %q", got)
	}
	if _, cat := og.BlockInfo(); cat != "A1-06" {
		t.Fatalf("blockCat 期望 A1-06，实际 %q", cat)
	}
}

// 6. 乱序判定不得误杀干净队头：第二句先判 block，首句仍在 pending 时流不得终止；
// 首句随后判干净 → 放行首句，再由第二句终止（D6 pending 优先于 block 的跨 delta 面）。
func TestEnforcingOutOfOrderNoPrematureKill(t *testing.T) {
	l2 := newStubL2()
	gate := make(chan struct{})
	l2.gates["一。"] = gate // 首句挂住；第二句无门控立即返回 block
	l2.verdicts["二。"] = stubVerdict{cat: "A1-06", conf: 0.9}
	og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	for _, d := range []string{"一。", "二。"} {
		if err := og.Process(d, rec.emit); err != nil {
			t.Fatalf("Process(%q): %v", d, err)
		}
	}
	waitFor(t, "两句均已受理 L2", func() bool { return l2.callCount() == 2 })
	// 首句未决：block 已在第二句落定，但第一 delta 的认领面只含首句 pending → 不得终止
	if blocked, _ := og.BlockInfo(); blocked {
		t.Fatal("队头 pending 时不得被后句的 block 提前终止")
	}
	close(gate) // 首句判干净
	waitFor(t, "后句 block 终止整流", func() bool {
		b, _ := og.BlockInfo()
		return b
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	if got := rec.snapshot(); len(got) != 1 || got[0] != "一。" {
		t.Fatalf("仅干净首句可放行，实际 %v", got)
	}
	if _, cat := og.BlockInfo(); cat != "A1-06" {
		t.Fatalf("blockCat 期望 A1-06，实际 %q", cat)
	}
}

// 7. L2 失败句级降级（P-DEGRADE）：该句丢弃，后续干净句照常下发，流不终止、无 output_blocked。
func TestEnforcingDegradedSentenceDroppedNotTerminated(t *testing.T) {
	l2 := newStubL2()
	l2.verdicts["坏。"] = stubVerdict{fail: true}
	og, m, a := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("坏。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "L2 失败回调落定", func() bool { return l2.callCount() == 1 })
	if err := og.Process("好。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "干净句下发", func() bool { return rec.joined() == "好。" })
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	if blocked, _ := og.BlockInfo(); blocked {
		t.Fatal("句级降级不得终止整流")
	}
	if n := a.countByAction("output_blocked"); n != 0 {
		t.Fatalf("句级降级不得发 output_blocked，实际 %d", n)
	}
	if n := a.countByAction("output_guard_degraded"); n != 1 {
		t.Fatalf("期望 1 条 degraded 审计，实际 %d", n)
	}
	if body := renderMetrics(m, a.len()); !strings.Contains(body, `otpmask_output_guard_degraded_total{backend="l2",reason="l2_unavailable"} 1`) {
		t.Fatalf("l2_unavailable 降级指标缺失：\n%s", body)
	}
}

// 8. slots_full（D5）：无槽位可审的内容 fail-closed 整流终止；
// category 为空、不发 output_blocked，但发 slots_full 降级与 buffer_full 计数。
func TestEnforcingSlotsFullTerminates(t *testing.T) {
	casc := cascadeParams(true)
	casc.MaxSlots = 1
	l2 := newStubL2()
	gate := make(chan struct{})
	l2.gates["一。"] = gate
	og, m, a := newEnforcingGuard(t, casc, fakeL2Classifier{}, l2)
	defer close(gate)
	rec := &frameRecorder{}

	if err := og.Process("一。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Process("二。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "slots_full 终止整流", func() bool {
		b, _ := og.BlockInfo()
		return b
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	blocked, cat := og.BlockInfo()
	if !blocked || cat != "" {
		t.Fatalf("slots_full 期望 (true,\"\")，实际 (%v,%q)", blocked, cat)
	}
	gm := og.BuildGuardMeta()
	if !gm.Detected || !gm.Filtered || gm.Action != catActionBlock || gm.Category != "" {
		t.Fatalf("slots_full guard meta 应为 block/空类目：%+v", gm)
	}
	if n := a.countByAction("output_blocked"); n != 0 {
		t.Fatalf("slots_full 不得发 output_blocked，实际 %d", n)
	}
	body := renderMetrics(m, a.len())
	if !strings.Contains(body, `otpmask_output_guard_degraded_total{backend="l2",reason="l2_slots_full"} 1`) {
		t.Fatalf("slots_full 降级指标缺失：\n%s", body)
	}
	if !strings.Contains(body, "otpmask_output_guard_buffer_full_total 1") {
		t.Fatalf("buffer_full 计数缺失：\n%s", body)
	}
}

// 9. block 之后 Finish 立即返回：不等 2s 槽位超时、不接收后续句（后续句不占句数）。
func TestEnforcingFinishReturnsAfterBlock(t *testing.T) {
	l2 := newStubL2()
	l2.verdicts["一。"] = stubVerdict{cat: "A1-06", conf: 0.9}
	og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("一。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "block 判定落定", func() bool {
		b, _ := og.BlockInfo()
		return b
	})
	if err := og.Process("二。", rec.emit); err != nil {
		t.Fatalf("blocked 后 Process 应返回 nil，实际 %v", err)
	}
	if st := og.casc.stats(); st.Sentences != 1 {
		t.Fatalf("blocked 后不再计句，期望 Sentences=1，实际 %d", st.Sentences)
	}
	start := time.Now()
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("blocked 后 Finish 必须立即返回，实际耗时 %v（超时 2s）", d)
	}
	og.Close()
	if got := rec.joined(); got != "" {
		t.Fatalf("blocked 流必须零下发，实际 %q", got)
	}
}

// 11. D1'：mask 类目 A4-06 在 enforcing block-only 深度下降为 flag+log，内容照常下发，流不终止。
func TestEnforcingMaskDowngradedToFlag(t *testing.T) {
	og, m, a := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{cat: "A4-06", conf: 1.0}, nil)
	rec := &frameRecorder{}
	const text = "手机号13800001111。"

	if err := og.Process(text, rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	if got := rec.joined(); got != text {
		t.Fatalf("flag 降档内容必须原样下发，实际 %q", got)
	}
	if blocked, _ := og.BlockInfo(); blocked {
		t.Fatal("mask 降 flag 不得置位 blocked")
	}
	gm := og.BuildGuardMeta()
	if !gm.Detected || gm.Filtered || gm.Action != catActionFlag || gm.Category != "A4-06" {
		t.Fatalf("guard meta 应为 detected/flag/A4-06：%+v", gm)
	}
	if n := a.countByAction("output_blocked"); n != 0 {
		t.Fatalf("降 flag 不得发 output_blocked，实际 %d", n)
	}
	// I3 修复后口径：would_reject 仅 shadow 模式下记录（"本该拦截"=shadow 语义）；
	// enforcing 下 flag 命中只维护 firstHit 状态（BuildGuardMeta 可见），不落 would_reject。
	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("enforcing 下降 flag 不应落 would_reject（口径回归 shadow-only），实际 %d", n)
	}
	if body := renderMetrics(m, a.len()); strings.Contains(body, "blocked_total") {
		t.Fatalf("降 flag 不得计 blocked：\n%s", body)
	}
}

// 12. blockCat 取句序最早的 block 命中：先 flag（A1-07）放行、后 block（A1-06）终止；
// 同一 delta 双 block 时取文本顺序首句的类目（D6 block 取 seq 最小）。
func TestEnforcingBlockCatNotFirstHit(t *testing.T) {
	t.Run("先flag后block", func(t *testing.T) {
		l2 := newStubL2()
		l2.verdicts["假消息。"] = stubVerdict{cat: "A1-07", conf: 0.9}
		l2.verdicts["暴力。"] = stubVerdict{cat: "A1-06", conf: 0.9}
		og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
		rec := &frameRecorder{}

		for _, d := range []string{"假消息。", "暴力。"} {
			if err := og.Process(d, rec.emit); err != nil {
				t.Fatalf("Process(%q): %v", d, err)
			}
		}
		waitFor(t, "block 判定落定", func() bool {
			b, _ := og.BlockInfo()
			return b
		})
		if err := og.Finish(rec.emit); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		og.Close()
		if got := rec.snapshot(); len(got) != 1 || got[0] != "假消息。" {
			t.Fatalf("flag 首句应放行，block 次句应终止，实际 %v", got)
		}
		if _, cat := og.BlockInfo(); cat != "A1-06" {
			t.Fatalf("blockCat 应为 block 句 A1-06，而非首个命中 A1-07，实际 %q", cat)
		}
	})

	t.Run("同delta双block取首句", func(t *testing.T) {
		// 门控消除调度竞态：两句都在判时先放行首句（block），D6 block>pending 立即终止，
		// 类目取触发终止的首句 A1-06；次句迟到回调走 blocked 抑制分支。
		l2 := newStubL2()
		g0, g1 := make(chan struct{}), make(chan struct{})
		l2.gates["暴。"] = g0
		l2.gates["歧。"] = g1
		defer close(g1)
		l2.verdicts["暴。"] = stubVerdict{cat: "A1-06", conf: 0.9}
		l2.verdicts["歧。"] = stubVerdict{cat: "A2-01", conf: 0.9}
		og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
		rec := &frameRecorder{}

		if err := og.Process("暴。歧。", rec.emit); err != nil {
			t.Fatalf("Process: %v", err)
		}
		waitFor(t, "两句均已受理 L2", func() bool { return l2.callCount() == 2 })
		close(g0)
		waitFor(t, "首句 block 终止整流", func() bool {
			b, _ := og.BlockInfo()
			return b
		})
		if err := og.Finish(rec.emit); err != nil {
			t.Fatalf("Finish: %v", err)
		}
		og.Close()
		if got := rec.joined(); got != "" {
			t.Fatalf("同 delta 双 block 必须整扣，实际 %q", got)
		}
		if _, cat := og.BlockInfo(); cat != "A1-06" {
			t.Fatalf("blockCat 应取文本序首句 A1-06，实际 %q", cat)
		}
	})
}

// 16. 慢客户端：干净句 emit 失败（异步回调路径）→ Finish 观测到错误上抛 + Close 幂等；
// blocked 不得被误置位。
func TestEnforcingEmitErrorClosesIdempotently(t *testing.T) {
	og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, newStubL2())
	rec := &frameRecorder{err: errors.New("slow client")}

	// L2 异步判定未决时 Process 同步返回 nil；失败在回调推进游标时发生
	_ = og.Process("好。", rec.emit)
	if err := og.Finish(rec.emit); err == nil {
		t.Fatal("emit 失败必须经 Finish 上抛")
	}
	og.Close()
	og.Close() // 幂等：不得 panic / 双关闭
	if blocked, _ := og.BlockInfo(); blocked {
		t.Fatal("emit 失败不得置位 blocked")
	}
}

// 19. 同一 chunk 多句 + slots_full：首句在判、次句无槽可审 → fail-closed 终止，零下发。
func TestEnforcingMultiSentenceSlotsFull(t *testing.T) {
	casc := cascadeParams(true)
	casc.MaxSlots = 1
	l2 := newStubL2()
	gate := make(chan struct{})
	l2.gates["一。"] = gate
	og, _, _ := newEnforcingGuard(t, casc, fakeL2Classifier{}, l2)
	defer close(gate)
	rec := &frameRecorder{}

	if err := og.Process("一。二。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "slots_full 终止整流", func() bool {
		b, _ := og.BlockInfo()
		return b
	})
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	blocked, cat := og.BlockInfo()
	if !blocked || cat != "" {
		t.Fatalf("期望 (true,\"\")，实际 (%v,%q)", blocked, cat)
	}
	if got := rec.joined(); got != "" {
		t.Fatalf("无槽可审必须零下发，实际 %q", got)
	}
}

// I2 修复验证：enforcing 下尾部纯空白 delta 也 emit 一帧（内容置空），帧计数与 shadow 一致，
// 避免下游依赖逐 delta 帧的逻辑序号跳变。帧内容空白符合 enforcing 语义（未判定单元不下发明文）。
func TestEnforcingTrailingWhitespaceFrameCount(t *testing.T) {
	og, _, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, newStubL2())
	rec := &frameRecorder{}

	// 先发一句完整干净句（构成 1 个 slot），再发一个纯空白 delta（无 slot）
	if err := og.Process("今天天气好。", rec.emit); err != nil {
		t.Fatalf("Process(clean): %v", err)
	}
	if err := og.Process("   \n\t  ", rec.emit); err != nil {
		t.Fatalf("Process(whitespace): %v", err)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	// 2 次 Process = 2 帧（首句帧 + 空白帧），帧计数与 shadow 模式对齐
	frames := rec.snapshot()
	if len(frames) != 2 {
		t.Fatalf("帧计数应为 2（与 shadow 对齐），实际 %d", len(frames))
	}
	// 首帧内容正确；第二帧为空串（gateReleased 置空后下发，保帧计数不保空白内容）
	if frames[0] != "今天天气好。" {
		t.Fatalf("首帧应为 %q，实际 %q", "今天天气好。", frames[0])
	}
	if frames[1] != "" {
		t.Fatalf("空白帧应为空串（gateReleased 置空），实际 %q", frames[1])
	}
}

// I3 修复验证：enforcing 下 block 命中只落 output_blocked，不落 output_would_reject
// （would_reject 口径回归 shadow-only）。
func TestEnforcingBlockNoWouldReject(t *testing.T) {
	l2 := newStubL2()
	l2.verdicts["暴力内容。"] = stubVerdict{cat: "A1-06", conf: 0.95}
	og, m, a := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("暴力内容。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	if blocked, cat := og.BlockInfo(); !blocked || cat != "A1-06" {
		t.Fatalf("应为 blocked/A1-06，实际 (%v,%q)", blocked, cat)
	}
	// I3 核心断言：enforcing 下 block 命中不落 would_reject
	// （output_blocked 审计事件上移到 streamTextInfer 层，cascade 层只记指标）
	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("enforcing 下 block 命中不应落 would_reject（口径 shadow-only），实际 %d", n)
	}
	body := renderMetrics(m, 0)
	if strings.Contains(body, "otpmask_output_guard_would_reject_total") {
		t.Fatalf("enforcing block 不应有 would_reject 指标：\n%s", body)
	}
	if !strings.Contains(body, "otpmask_output_guard_blocked_total") {
		t.Fatalf("enforcing block 应有 blocked 指标：\n%s", body)
	}
}

// ---- S2 两段式早出 × enforcing（D8 T2/T5；2026-09-19 落地）----

// S2-E1 早出 true → held：enforcing 下轻段 true 无类目不能定动作，未决期间零下发；
// 完整段命中 block 类目 → 整流终止、零泄漏、blocked 指标。
func TestEnforcingEarlyTrueHeldThenBlock(t *testing.T) {
	l2 := newStubL2()
	l2.earlys["违规。"] = true
	gate := make(chan struct{})
	l2.gates["违规。"] = gate
	l2.verdicts["违规。"] = stubVerdict{cat: "A1-06", conf: 0.9}
	og, m, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("违规。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "轻段已到（held）", func() bool { return l2.callCount() == 1 })
	if got := rec.snapshot(); len(got) != 0 {
		t.Fatalf("held 期间必须零下发，实际 %v", got)
	}
	close(gate) // 完整段命中 block
	waitFor(t, "整流终止", func() bool {
		b, _ := og.BlockInfo()
		return b
	})
	og.Close()

	blocked, cat := og.BlockInfo()
	if !blocked || cat != "A1-06" {
		t.Fatalf("应为 blocked/A1-06，实际 (%v,%q)", blocked, cat)
	}
	if got := rec.joined(); got != "" {
		t.Fatalf("block 首句必须零泄漏，实际 %q", got)
	}
	if body := renderMetrics(m, 0); !strings.Contains(body, `otpmask_output_guard_blocked_total{category="A1-06",mode="enforcing"} 1`) {
		t.Fatalf("blocked 指标缺失\n---\n%s", body)
	}
}

// S2-E2 early-pass 放行后完整段失败（两段矛盾哨兵）：放行不可撤回（T5：首帧放行只依赖
// 轻段）、不得扩散为句级丢句/整流终止——后续干净句继续放行，仅记 error 指标。
func TestEnforcingEarlyPassFullSegmentFailNoRetroBlock(t *testing.T) {
	l2 := newStubL2()
	l2.earlys["正常一。"] = false
	l2.verdicts["正常一。"] = stubVerdict{fail: true} // 完整段矛盾 → 失败哨兵
	l2.earlys["正常二。"] = false
	l2.verdicts["正常二。"] = stubVerdict{}
	og, m, _ := newEnforcingGuard(t, cascadeParams(true), fakeL2Classifier{}, l2)
	rec := &frameRecorder{}

	if err := og.Process("正常一。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Process("正常二。", rec.emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	waitFor(t, "两句均已早出放行", func() bool { return rec.joined() == "正常一。正常二。" })
	if err := og.Finish(rec.emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()

	if blocked, _ := og.BlockInfo(); blocked {
		t.Fatal("早出已放行的句不可回撤为 block（T5：首帧放行只依赖轻段）")
	}
	body := renderMetrics(m, 0)
	if !strings.Contains(body, `{category="",result="error"} 1`) {
		t.Fatalf("矛盾哨兵应记 error\n---\n%s", body)
	}
	if strings.Contains(body, "otpmask_output_guard_degraded_total") &&
		strings.Contains(body, "reason=\"l2_unavailable\"") {
		t.Fatalf("early-pass 完整段失败不得扩散 fail-closed\n---\n%s", body)
	}
	if strings.Contains(body, "l2_bad_conf") || strings.Contains(body, "l2_timeout") {
		t.Fatalf("early-pass 完整段失败不应记超时/坏置信降级\n---\n%s", body)
	}
}
