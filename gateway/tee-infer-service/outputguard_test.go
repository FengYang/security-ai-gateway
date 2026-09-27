package main

import (
	"bytes"
	"strings"
	"testing"
)

// OG-3（M1 骨架）验收单测：off 零开销、shadow 只记不拦、非法/enforcing 拒绝启动、
// required 指标常驻（门禁 #9）、审计证据字段不进 hash（旧链可复算）。

// newTestOutputGuard 构造 shadow 测试用管线（isolated metrics/audit/guardrail）。
func newTestOutputGuard(t *testing.T, mode, tenant, requestID string) (*outputGuard, *otpmaskMetrics, *auditChain) {
	t.Helper()
	m := newMetrics()
	m.setOutputGuardMode(mode, defaultPolicyVersion)
	a := newAuditChain()
	og, err := newOutputGuard(testOutputGuardConfig(mode), l1Classifier{g: newGuardrail()}, nil, m, a, tenant, requestID)
	if err != nil {
		t.Fatalf("newOutputGuard(mode=%q): %v", mode, err)
	}
	return og, m, a
}

// testOutputGuardConfig 测试用配置（解析后的 D 组默认参数，OG-4）。
func testOutputGuardConfig(mode string) outputGuardConfig {
	return outputGuardConfig{
		Mode:          mode,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
	}
}

// collectThrough 经 og.Process/Finish 逐 delta 下发，返回实际产出。
func collectThrough(t *testing.T, og *outputGuard, deltas []string) string {
	t.Helper()
	var sb strings.Builder
	emit := func(delta, finish string) error {
		sb.WriteString(delta)
		return nil
	}
	for _, d := range deltas {
		if err := og.Process(d, emit); err != nil {
			t.Fatalf("Process(%q): %v", d, err)
		}
	}
	if err := og.Finish(emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	og.Close()
	return sb.String()
}

// TestOutputGuardOffIsNil：off（含未配置空串）→ nil（零开销，调用侧走原路径）。
func TestOutputGuardOffIsNil(t *testing.T) {
	for _, mode := range []string{"", outputGuardOff} {
		og, err := newOutputGuard(testOutputGuardConfig(mode), l1Classifier{g: newGuardrail()}, nil, newMetrics(), newAuditChain(), "t", "r")
		if err != nil {
			t.Fatalf("mode=%q 期望无错误，实际 %v", mode, err)
		}
		if og != nil {
			t.Fatalf("mode=%q 期望 nil（零开销），实际非 nil", mode)
		}
	}
}

// TestOutputGuardRejectsInvalidModes：非法值 → 报错（拒绝启动）；enforcing M4 起合法（仅启动参数）。
func TestOutputGuardRejectsInvalidModes(t *testing.T) {
	for _, mode := range []string{"bogus", "SHADOW", "off "} {
		if err := validateOutputGuardMode(mode); err == nil {
			t.Fatalf("validateOutputGuardMode(%q) 期望报错", mode)
		}
		if _, err := newOutputGuard(testOutputGuardConfig(mode), l1Classifier{g: newGuardrail()}, nil, newMetrics(), newAuditChain(), "t", "r"); err == nil {
			t.Fatalf("newOutputGuard(%q) 期望报错", mode)
		}
	}
	for _, mode := range []string{"", outputGuardOff, outputGuardShadow, outputGuardEnforcing} {
		if err := validateOutputGuardMode(mode); err != nil {
			t.Fatalf("validateOutputGuardMode(%q) 期望通过，实际 %v", mode, err)
		}
	}
}

// TestOutputGuardShadowOnlyRecordsNotBlocks：shadow 命中 → 输出逐字节不变，审计与指标记录（只记不拦）。
// 本用例刻意不给终止符：尾部在 Finish 被作为最后一个判定单元送判（OG-4 flush 路径），
// 验证"末句无终止符"也不逃逸审查。
func TestOutputGuardShadowOnlyRecordsNotBlocks(t *testing.T) {
	og, m, a := newTestOutputGuard(t, outputGuardShadow, "acme", "req-shadow-1")
	deltas := []string{"正常前缀 ", "';--", " 后续文本"}
	got := collectThrough(t, og, deltas)

	if want := strings.Join(deltas, ""); got != want {
		t.Fatalf("shadow 必须原样放行：got %q want %q", got, want)
	}

	// 审计：恰好 1 条 output_would_reject（同请求首个命中只记一次）。
	if n := a.countByAction("output_would_reject"); n != 1 {
		t.Fatalf("期望 1 条 output_would_reject，实际 %d", n)
	}
	evs := a.query("acme")
	if len(evs) != 1 {
		t.Fatalf("期望 1 条 acme 审计事件，实际 %d", len(evs))
	}
	ev := evs[0]
	if ev.Result != "would_reject_A1-07" || ev.OGCategory != "A1-07" {
		t.Fatalf("审计类目不符：Result=%q category=%q", ev.Result, ev.OGCategory)
	}
	if ev.OGMode != outputGuardShadow || ev.OGPolicyVersion != defaultPolicyVersion {
		t.Fatalf("审计 mode/policy_version 不符：mode=%q ver=%q", ev.OGMode, ev.OGPolicyVersion)
	}

	// 指标：requests{mode=shadow}=1、l1_hit / would_reject 按类目各 1（sql_injection → A1-07）。
	var buf bytes.Buffer
	m.render(&buf, a.len())
	body := buf.String()
	for _, want := range []string{
		`otpmask_output_guard_requests_total{mode="shadow"} 1`,
		`otpmask_output_guard_l1_hit_total{category="A1-07"} 1`,
		`otpmask_output_guard_would_reject_total{category="A1-07"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics 缺失样本 %q\n---\n%s", want, body)
		}
	}
}

// TestOutputGuardShadowPerCategoryDedup：同类目跨句只记一次（would_reject/审计去重）；
// 不同类目各记一次（不丢并存命中）；l1_hit 按实际命中次数计数（不去重）。
func TestOutputGuardShadowPerCategoryDedup(t *testing.T) {
	og, m, a := newTestOutputGuard(t, outputGuardShadow, "acme", "req-multi-1")
	// 三个判定单元：sql_injection（"';--。" 引号后注释 → A1-07）、pii（手机号 → A4-06）、sql_injection（";-- 再来一次。" 堆叠注释重复 → A1-07）。
	// 因为 sql_injection 和 prompt_injection 都映射到 A1-07，所以两个 L1 不同类目可能映射到同一内部类目。
	collectThrough(t, og, []string{"';--。", "13812345678。", ";-- 再来一次。"})
	if n := a.countByAction("output_would_reject"); n != 2 {
		t.Fatalf("期望 2 条（A1-07 去重 1 + A4-06 1），实际 %d", n)
	}
	var buf bytes.Buffer
	m.render(&buf, a.len())
	body := buf.String()
	for _, want := range []string{
		`otpmask_output_guard_would_reject_total{category="A1-07"} 1`,
		`otpmask_output_guard_would_reject_total{category="A4-06"} 1`,
		`otpmask_output_guard_l1_hit_total{category="A1-07"} 2`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/metrics 缺失样本 %q\n---\n%s", want, body)
		}
	}
}

// TestOutputGuardShadowBenignNoHit：benign 文本不命中 → 无审计、无 would_reject，但计入 requests_total。
func TestOutputGuardShadowBenignNoHit(t *testing.T) {
	og, m, a := newTestOutputGuard(t, outputGuardShadow, "acme", "req-benign-1")
	got := collectThrough(t, og, []string{"这是一段完全正常的模型输出。"})
	if got != "这是一段完全正常的模型输出。" {
		t.Fatalf("shadow 必须原样放行：got %q", got)
	}
	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("benign 不应落 would_reject，实际 %d", n)
	}
	var buf bytes.Buffer
	m.render(&buf, a.len())
	if !strings.Contains(buf.String(), `otpmask_output_guard_requests_total{mode="shadow"} 1`) {
		t.Fatalf("应计入审查请求数\n---\n%s", buf.String())
	}
	if strings.Contains(buf.String(), "otpmask_output_guard_would_reject_total") {
		t.Fatalf("零命中不应输出 would_reject 样本（零样本不可见）\n---\n%s", buf.String())
	}
}

// TestOutputGuardRequiredMetricsAlwaysRender：门禁 #9 required 指标在 off/shadow 下都必须存在
// （mode / policy_version gauge 常驻；requests_total 预置零值序列）。
func TestOutputGuardRequiredMetricsAlwaysRender(t *testing.T) {
	for _, mode := range []string{outputGuardOff, outputGuardShadow} {
		m := newMetrics()
		m.setOutputGuardMode(mode, defaultPolicyVersion)
		var buf bytes.Buffer
		m.render(&buf, 0)
		body := buf.String()
		for _, name := range []string{
			"otpmask_output_guard_mode",
			"otpmask_output_guard_policy_version",
			"otpmask_output_guard_requests_total",
		} {
			if !strings.Contains(body, name) {
				t.Fatalf("mode=%q：required 指标 %s 缺失（门禁 #9 会 FAIL）\n---\n%s", mode, name, body)
			}
		}
		if !strings.Contains(body, `otpmask_output_guard_mode{mode="`+mode+`"} 1`) {
			t.Fatalf("mode=%q：mode gauge 样本不符\n---\n%s", mode, body)
		}
	}
}

// TestOutputGuardAuditEvidenceNotInHash：新增证据字段不进 hash()——旧链在新代码下仍可复算。
func TestOutputGuardAuditEvidenceNotInHash(t *testing.T) {
	og, _, a := newTestOutputGuard(t, outputGuardShadow, "acme", "req-chain-1")
	collectThrough(t, og, []string{"drop table users"}) // 命中 sql_injection
	if ok, n := a.verify(); !ok || n == 0 {
		t.Fatalf("新增证据字段后审计链应仍可校验：ok=%v n=%d", ok, n)
	}
}

// fakeUnmappedClassifier 始终返回未映射类目（用于测试 P-DEGRADE 路径）。
type fakeUnmappedClassifier struct{ cat string }

func (c fakeUnmappedClassifier) Classify(text string) (string, float64, string) {
	return c.cat, 1.0, "fake-match"
}

// TestOutputGuardUnmappedCategory：后端返回未映射类目 → 记 unmapped 指标，不记 would_reject，
// 不落 output_would_reject 审计（P-DEGRADE：fail-closed 语义下无类目可归）。
func TestOutputGuardUnmappedCategory(t *testing.T) {
	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()
	og, err := newOutputGuard(testOutputGuardConfig(outputGuardShadow),
		fakeUnmappedClassifier{cat: "unknown_cat"}, nil, m, a, "acme", "req-unmapped-1")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	collectThrough(t, og, []string{"随便什么文本。"})

	// 审计：无 output_would_reject（未映射 = 无类目可归 = 不记 would_reject）。
	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("未映射类目不应落 would_reject 审计，实际 %d", n)
	}
	// 指标：unmapped 有计数，would_reject 无计数。
	var buf bytes.Buffer
	m.render(&buf, a.len())
	body := buf.String()
	if !strings.Contains(body, `otpmask_output_guard_unmapped_total{backend="l1",category_raw="unknown_cat"} 1`) {
		t.Fatalf("应记 unmapped 指标\n---\n%s", body)
	}
	if strings.Contains(body, "otpmask_output_guard_would_reject_total") {
		t.Fatalf("未映射类目不应有 would_reject 指标样本\n---\n%s", body)
	}
}
