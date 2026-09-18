package main

import (
	"regexp"
	"strings"
	"testing"
)

// newTestPIIRegexps 构造测试用 PII 正则切片（与 pii_patterns.json 顺序一致：手机/身份证/邮箱/银行卡）。
func newTestPIIRegexps(t *testing.T) []*regexp.Regexp {
	t.Helper()
	patterns := []string{
		`(^|[^0-9])(1[3-9][0-9]{9})([^0-9]|$)`,  // 手机号
		`(^|[^0-9])([0-9]{17}[0-9Xx])([^0-9]|$)`, // 身份证
		`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`, // 邮箱
		`(^|[^0-9])([0-9]{16,19})([^0-9]|$)`,     // 银行卡
	}
	res := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			t.Fatalf("编译第 %d 条正则失败: %v", i, err)
		}
		res[i] = re
	}
	return res
}

func TestMaskPhone(t *testing.T) {
	res := newTestPIIRegexps(t)
	cases := []struct {
		name string
		in   string
		want string
		hits int
	}{
		{"标准手机号", "我的电话是13812345678", "我的电话是138****5678", 1},
		{"手机号带边界", "电话：13999998888。", "电话：139****8888。", 1},
		{"多个手机号", "13811112222 和 13933334444", "138****2222 和 139****4444", 2},
		{"无手机号", "你好世界", "你好世界", 0},
		{"短数字串（非手机号）", "编号是12345", "编号是12345", 0},
		{"空文本", "", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, hits := maskTextPII(c.in, res)
			if got != c.want {
				t.Fatalf("期望 %q，实际 %q", c.want, got)
			}
			if hits != c.hits {
				t.Fatalf("期望命中 %d，实际 %d", c.hits, hits)
			}
			// 等长验证：手机号等长替换，总长度不变
			if len(got) != len(c.in) {
				t.Fatalf("等长替换失败：输入长 %d，输出长 %d", len(c.in), len(got))
			}
		})
	}
}

func TestMaskIDCard(t *testing.T) {
	res := newTestPIIRegexps(t)
	cases := []struct {
		name string
		in   string
		want string
		hits int
	}{
		{"标准18位身份证", "身份证号11010519491231002X", "身份证号110105********002X", 1},
		{"带X的身份证", "证件：11010519491231002x。", "证件：110105********002x。", 1},
		{"多个身份证", "11010519491231002X和310101200001011234", "110105********002X和310101********1234", 2},
		{"无身份证", "正常文本", "正常文本", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, hits := maskTextPII(c.in, res)
			if got != c.want {
				t.Fatalf("期望 %q，实际 %q", c.want, got)
			}
			if hits != c.hits {
				t.Fatalf("期望命中 %d，实际 %d", c.hits, hits)
			}
			if len(got) != len(c.in) {
				t.Fatalf("等长替换失败：输入长 %d，输出长 %d", len(c.in), len(got))
			}
		})
	}
}

func TestMaskEmail(t *testing.T) {
	res := newTestPIIRegexps(t)
	cases := []struct {
		name string
		in   string
		want string
		hits int
	}{
		{"标准邮箱", "联系邮箱 user@example.com", "联系邮箱 u***@example.com", 1},
		{"单字符用户名", "邮箱 a@b.com", "邮箱 ***@b.com", 1},
		{"双字符用户名", "ab@test.org", "a*@test.org", 1},
		{"长用户名", "john.doe+label@mail.example.co.uk", "j*************@mail.example.co.uk", 1},
		{"多个邮箱", "a@b.com 和 test@example.com", "***@b.com 和 t***@example.com", 2},
		{"无邮箱", "没有邮箱地址", "没有邮箱地址", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, hits := maskTextPII(c.in, res)
			if got != c.want {
				t.Fatalf("期望 %q，实际 %q", c.want, got)
			}
			if hits != c.hits {
				t.Fatalf("期望命中 %d，实际 %d", c.hits, hits)
			}
		})
	}
}

func TestMaskBankCard(t *testing.T) {
	res := newTestPIIRegexps(t)
	cases := []struct {
		name string
		in   string
		want string
		hits int
	}{
		{"16位银行卡", "卡号6222021234567890", "卡号622202******7890", 1},
		{"19位银行卡", "卡号6222021234567890123", "卡号622202*********0123", 1},
		{"多个银行卡", "6222021234567890, 6228481234567890123", "622202******7890, 622848*********0123", 2},
		{"无银行卡", "无卡号文本", "无卡号文本", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, hits := maskTextPII(c.in, res)
			if got != c.want {
				t.Fatalf("期望 %q，实际 %q", c.want, got)
			}
			if hits != c.hits {
				t.Fatalf("期望命中 %d，实际 %d", c.hits, hits)
			}
			if len(got) != len(c.in) {
				t.Fatalf("等长替换失败：输入长 %d，输出长 %d", len(c.in), len(got))
			}
		})
	}
}

func TestMaskMixedPII(t *testing.T) {
	res := newTestPIIRegexps(t)
	in := "张三，电话13812345678，身份证11010519491231002X，邮箱 zhang@test.com，银行卡 6222021234567890。"
	got, hits := maskTextPII(in, res)
	if hits != 4 {
		t.Fatalf("期望 4 类各命中 1 次共 4 次，实际 %d", hits)
	}
	// 验证四类都被改写
	if !strings.Contains(got, "138****5678") {
		t.Fatalf("手机号未正确脱敏: %s", got)
	}
	if !strings.Contains(got, "110105********002X") {
		t.Fatalf("身份证未正确脱敏: %s", got)
	}
	if !strings.Contains(got, "z****@test.com") {
		t.Fatalf("邮箱未正确脱敏: %s", got)
	}
	if !strings.Contains(got, "622202******7890") {
		t.Fatalf("银行卡未正确脱敏: %s", got)
	}
	// 原文 PII 不应出现
	if strings.Contains(got, "13812345678") {
		t.Fatalf("手机号明文泄露: %s", got)
	}
	if strings.Contains(got, "11010519491231002X") {
		t.Fatalf("身份证明文泄露: %s", got)
	}
}

func TestMaskEmptyOrNil(t *testing.T) {
	// 空正则切片
	got, hits := maskTextPII("13812345678", nil)
	if got != "13812345678" || hits != 0 {
		t.Fatalf("空正则应不改写，实际 got=%q hits=%d", got, hits)
	}
	// 空文本
	res := newTestPIIRegexps(t)
	got, hits = maskTextPII("", res)
	if got != "" || hits != 0 {
		t.Fatalf("空文本应返回空，实际 got=%q hits=%d", got, hits)
	}
}

// TestEnforcingMaskRewritesDelta 验证 enforcing + mask 启用时，
// 命中 PII 类目的 delta 在下发前被实打马赛克（OG-18）。
func TestEnforcingMaskRewritesDelta(t *testing.T) {
	res := newTestPIIRegexps(t)
	// L1：所有 unit 都命中 A4-06（PII mask 类目，maskEnabled=true 时动作 = mask）
	l1 := fakeL2Classifier{cat: "A4-06", conf: 0.99, match: "13812345678"}
	// L2：不命中（L1 已即决，L2 仅画像，不影响下发）
	l2 := fakeL2Classifier{}

	m := newMetrics()
	m.setOutputGuardMode(outputGuardEnforcing, defaultPolicyVersion)
	a := newAuditChain()

	cfg := outputGuardConfig{
		Mode:          outputGuardEnforcing,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       cascadeParams(true),
		MaskEnabled:   true,
		MaskRegexps:   res,
	}
	og, err := newOutputGuard(cfg, l1, l2, m, a, "acme", "req-mask")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	defer og.Close()

	var got strings.Builder
	emit := func(delta, finish string) error {
		got.WriteString(delta)
		return nil
	}

	input := "我的电话是13812345678，请联系。"
	if err := og.Process(input, emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Finish(emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	output := got.String()
	// 断言 1：手机号明文不得出现在输出中
	if strings.Contains(output, "13812345678") {
		t.Fatalf("手机号明文泄露: %q", output)
	}
	// 断言 2：输出应含脱敏后的手机号
	if !strings.Contains(output, "138****5678") {
		t.Fatalf("手机号未正确脱敏: %q", output)
	}
	// 断言 3：总长度不变（等长替换）
	if len(output) != len(input) {
		t.Fatalf("等长替换失败：输入长 %d，输出长 %d", len(input), len(output))
	}
	// 断言 4：mask 指标有计数
	var sb strings.Builder
	m.render(&sb, a.len())
	if !strings.Contains(sb.String(), "output_guard_masked_total") {
		t.Fatalf("mask 指标缺失:\n%s", sb.String())
	}
	// 断言 5：MaskedCategories 包含 A4-06
	cats := og.MaskedCategories()
	found := false
	for _, c := range cats {
		if c == "A4-06" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("MaskedCategories 应包含 A4-06，实际: %v", cats)
	}
}

// TestEnforcingMaskDisabledNoRewrite 验证 mask 开关关闭时，
// 即使 PII 类目命中也不改写内容（保持原行为 = flag 降级）。
func TestEnforcingMaskDisabledNoRewrite(t *testing.T) {
	res := newTestPIIRegexps(t)
	l1 := fakeL2Classifier{cat: "A4-06", conf: 0.99, match: "13812345678"}
	l2 := fakeL2Classifier{}

	m := newMetrics()
	m.setOutputGuardMode(outputGuardEnforcing, defaultPolicyVersion)
	a := newAuditChain()

	cfg := outputGuardConfig{
		Mode:          outputGuardEnforcing,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       cascadeParams(true),
		MaskEnabled:   false, // 关闭 mask
		MaskRegexps:   res,
	}
	og, err := newOutputGuard(cfg, l1, l2, m, a, "acme", "req-nomask")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	defer og.Close()

	var got strings.Builder
	emit := func(delta, finish string) error {
		got.WriteString(delta)
		return nil
	}

	input := "我的电话是13812345678，请联系。"
	if err := og.Process(input, emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Finish(emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	output := got.String()
	// mask 关闭：PII 明文应保留（A4-06 降为 flag，不拦截不改写）
	if !strings.Contains(output, "13812345678") {
		t.Fatalf("mask 关闭时应保留明文，实际: %q", output)
	}
	// MaskedCategories 应为空（mask 未启用，action 不是 mask）
	if cats := og.MaskedCategories(); len(cats) != 0 {
		t.Fatalf("mask 关闭时 MaskedCategories 应为空，实际: %v", cats)
	}
}

// TestShadowMaskNoRewrite 验证 shadow 模式下即使 mask 开关开启，
// PII 类目仍降为 flag（不改写内容）——与 D1' 决策一致。
// shadow 恒为 flag 是基础约定，不能因 mask 开关而改变。
func TestShadowMaskNoRewrite(t *testing.T) {
	res := newTestPIIRegexps(t)
	l1 := fakeL2Classifier{cat: "A4-06", conf: 0.99, match: "13812345678"}
	l2 := fakeL2Classifier{}

	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()

	cfg := outputGuardConfig{
		Mode:          outputGuardShadow, // shadow 模式
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       cascadeParams(true),
		MaskEnabled:   true, // 即使 mask 开关开
		MaskRegexps:   res,
	}
	og, err := newOutputGuard(cfg, l1, l2, m, a, "acme", "req-shadow-mask")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	defer og.Close()

	var got strings.Builder
	emit := func(delta, finish string) error {
		got.WriteString(delta)
		return nil
	}

	input := "我的电话是13812345678，请联系。"
	if err := og.Process(input, emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Finish(emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	output := got.String()
	// shadow 下恒为 flag：PII 明文应保留（不改写）
	if !strings.Contains(output, "13812345678") {
		t.Fatalf("shadow 模式下即使 mask 开关开也应保留明文（恒为 flag），实际: %q", output)
	}
	// MaskedCategories 应为空（shadow 下 action 是 flag，不是 mask）
	if cats := og.MaskedCategories(); len(cats) != 0 {
		t.Fatalf("shadow 模式下 MaskedCategories 应为空，实际: %v", cats)
	}
}

// TestEnforcingMaskAuditEvent 验证 enforcing + mask 启用时，
// MaskedCategories() 返回正确类目（供上层发射 output_masked 审计）。
// 模拟上层 streamTextInfer 的审计发射逻辑，验证事件构造正确。
func TestEnforcingMaskAuditEvent(t *testing.T) {
	res := newTestPIIRegexps(t)
	l1 := fakeL2Classifier{cat: "A4-06", conf: 0.99, match: "13812345678"}
	l2 := fakeL2Classifier{}

	m := newMetrics()
	m.setOutputGuardMode(outputGuardEnforcing, defaultPolicyVersion)
	a := newAuditChain()

	cfg := outputGuardConfig{
		Mode:          outputGuardEnforcing,
		PolicyVersion: defaultPolicyVersion,
		Params:        resolveOutputGuardParams(defaultOutputGuardParams()),
		Cascade:       cascadeParams(true),
		MaskEnabled:   true,
		MaskRegexps:   res,
	}
	og, err := newOutputGuard(cfg, l1, l2, m, a, "acme", "req-mask-audit")
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	defer og.Close()

	emit := func(delta, finish string) error { return nil }
	input := "电话13812345678，邮箱 user@test.com。"
	if err := og.Process(input, emit); err != nil {
		t.Fatalf("Process: %v", err)
	}
	if err := og.Finish(emit); err != nil {
		t.Fatalf("Finish: %v", err)
	}

	// 模拟上层 streamTextInfer 的审计发射逻辑
	maskedCats := og.MaskedCategories()
	auditEvents := make([]AuditEvent, 0)
	for _, cat := range maskedCats {
		auditEvents = append(auditEvents, AuditEvent{
			TenantID:     "acme",
			RequestID:    "req-mask-audit",
			Action:       "output_masked",
			Result:       "masked_" + cat,
			OGCategory:   cat,
			OGMode:       outputGuardEnforcing,
			MeteringMode: "estimate",
		})
	}

	// 断言：应至少有 1 条 mask 审计（A4-06）
	if len(auditEvents) == 0 {
		t.Fatal("应发射 output_masked 审计事件，实际 0 条")
	}
	// 断言：A4-06 必须在其中
	found := false
	for _, e := range auditEvents {
		if e.OGCategory == "A4-06" && e.Action == "output_masked" &&
			e.Result == "masked_A4-06" && e.OGMode == outputGuardEnforcing {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("未找到 A4-06 的 output_masked 事件，实际: %+v", auditEvents)
	}
}
