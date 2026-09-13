package main

// shadow_test.go — 影子计数引擎/上报队列单测（纯逻辑；宿主无 proxy-wasm hostcall，故置 metricsHostGuard）。
//
// 覆盖（方案 §A.5 判据 1）：窗口计数与命中判定（含窗口翻转、多维度隔离）、缺头不猜测、
// 非影子规则不处理、维度上限淘汰、上报 report_id 确定性、队列溢出丢弃。

import (
	"os"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/ratelimitcache"
)

// TestMain 置位 hostcall 守卫（宿主单测不可调用 proxy-wasm hostcall：计数与日志）。
func TestMain(m *testing.M) {
	hostGuard = true
	os.Exit(m.Run())
}

// shadowRate 构造一条影子 rate 规则。
func shadowRate(id, scope, target string, rpm int64) ratelimitcache.Rule {
	return ratelimitcache.Rule{ID: id, Kind: "rate", Scope: scope, Target: target, RPM: rpm, Action: "shadow", Enabled: true}
}

// engineAt 构造时钟可注入的引擎。
func engineAt(t *testing.T, at time.Time) (*shadowEngine, func(time.Time)) {
	t.Helper()
	e := newShadowEngine()
	cur := at
	e.now = func() time.Time { return cur }
	return e, func(next time.Time) { cur = next }
}

// TestShadowEngine_CountAndWindowStart 计数与窗口起点：rpm=2 → 第 3 次命中；窗口起点对齐到分钟。
func TestShadowEngine_CountAndWindowStart(t *testing.T) {
	at := time.Unix(1789272, 30) // 1789272 秒（分钟序号对齐）
	e, _ := engineAt(t, at)
	rules := []ratelimitcache.Rule{shadowRate("r1", "tenant", "t-a", 2)}

	for i := 1; i <= 2; i++ {
		res := e.observe("t-a", "", "req", rules)
		if res.Hits != 0 {
			t.Fatalf("第 %d 次不应命中（阈值 2）", i)
		}
	}
	res := e.observe("t-a", "", "req", rules)
	if res.Hits != 1 {
		t.Fatalf("第 3 次应命中（observed=3 > 2），实际 %d", res.Hits)
	}
	snap := e.dimsSnapshot()
	wc, ok := snap[dimKey{Scope: "tenant", Target: "t-a", RuleID: "r1"}]
	if !ok {
		t.Fatalf("应建立维度计数: %+v", snap)
	}
	if wc.Observed != 3 || wc.WouldReject != 1 {
		t.Fatalf("计数不符: %+v", wc)
	}
	if wc.WindowStart != windowStartOf(at) {
		t.Fatalf("窗口起点应对齐到分钟: %d vs %d", wc.WindowStart, windowStartOf(at))
	}
	if wc.Threshold != 2 {
		t.Fatalf("阈值应为 2: %+v", wc)
	}
}

// TestShadowEngine_TenantAndApiKeyDims 两维度隔离计数并各自命中。
func TestShadowEngine_TenantAndApiKeyDims(t *testing.T) {
	at := time.Unix(1789272, 0)
	e, _ := engineAt(t, at)
	rules := []ratelimitcache.Rule{
		shadowRate("t-rule", "tenant", "t-a", 1),
		shadowRate("k-rule", "api_key", "consumer-a", 1),
	}
	res := e.observe("t-a", "consumer-a", "req-1", rules)
	if res.Hits != 0 {
		t.Fatalf("首请求不应命中: %+v", res)
	}
	res = e.observe("t-a", "consumer-a", "req-2", rules)
	if res.Hits != 2 {
		t.Fatalf("第 2 请求应两维度同时命中（各阈值 1），实际 %d", res.Hits)
	}
	snap := e.dimsSnapshot()
	if len(snap) != 2 {
		t.Fatalf("应有两个维度计数: %+v", snap)
	}
	for k, wc := range snap {
		if wc.Observed != 2 || wc.WouldReject != 1 {
			t.Fatalf("维度 %+v 计数不符: %+v", k, wc)
		}
	}
}

// TestShadowEngine_MissingHeadSkips 缺头 → 跳过该维度并上报缺失头名（不猜测、不回落其它头）；
// 身份与 rule.Target 不匹配 → 不计数（维度隔离）。
func TestShadowEngine_MissingHeadSkips(t *testing.T) {
	at := time.Unix(1789272, 0)
	e, _ := engineAt(t, at)
	rules := []ratelimitcache.Rule{
		shadowRate("t-rule", "tenant", "t-a", 1),
		shadowRate("k-rule", "api_key", "consumer-a", 1),
	}
	res := e.observe("", "consumer-a", "req", rules)
	if len(res.MissingHeads) != 1 || res.MissingHeads[0] != tenantHeaderName {
		t.Fatalf("应报缺租户头: %+v", res)
	}
	if len(e.dimsSnapshot()) != 1 {
		t.Fatalf("仅 api_key 维度应建计数: %+v", e.dimsSnapshot())
	}
	// 消费者头缺失（值为空）
	res = e.observe("t-a", "", "req", rules)
	if len(res.MissingHeads) != 1 || res.MissingHeads[0] != consumerHeaderName {
		t.Fatalf("应报缺消费者头: %+v", res)
	}
	// 身份与规则目标不匹配 → 既不计数也不报缺头
	res = e.observe("t-other", "consumer-other", "req", rules)
	if len(res.MissingHeads) != 0 || res.Hits != 0 {
		t.Fatalf("不匹配身份不应计数/报缺头: %+v", res)
	}
}

// TestShadowEngine_IgnoresNonShadowRules enforce/预算/禁用/model 维度一律不处理。
func TestShadowEngine_IgnoresNonShadowRules(t *testing.T) {
	at := time.Unix(1789272, 0)
	e, _ := engineAt(t, at)
	enforce := shadowRate("e-rule", "tenant", "t-a", 1)
	enforce.Action = "reject"
	budget := ratelimitcache.Rule{ID: "b-rule", Kind: "budget", Scope: "tenant", Target: "t-a", DailyBudgetTokens: 100, Action: "shadow", Enabled: true}
	disabled := shadowRate("d-rule", "tenant", "t-a", 1)
	disabled.Enabled = false
	modelScope := shadowRate("m-rule", "model", "qwen-plus", 1)

	for i := 0; i < 5; i++ {
		if res := e.observe("t-a", "consumer-a", "req", []ratelimitcache.Rule{enforce, budget, disabled, modelScope}); res.Hits != 0 {
			t.Fatalf("非影子规则不应命中: %+v", res)
		}
	}
	if n := len(e.dimsSnapshot()); n != 0 {
		t.Fatalf("不应建立任何维度计数: %+v", e.dimsSnapshot())
	}
}

// TestShadowEngine_WindowRotationReport 窗口翻转（新请求触发）→ 结算旧窗口并开新窗口。
func TestShadowEngine_WindowRotationReport(t *testing.T) {
	at := time.Unix(1789272, 10)
	e, setNow := engineAt(t, at)
	rules := []ratelimitcache.Rule{shadowRate("r1", "tenant", "t-a", 1)}
	e.observe("t-a", "", "req-1", rules)
	e.observe("t-a", "", "req-2", rules) // observed=2 → would_reject=1

	next := at.Add(60 * time.Second)
	setNow(next)
	res := e.observe("t-a", "", "req-3", rules)
	if len(res.Reports) != 1 {
		t.Fatalf("窗口翻转应结算出 1 条上报: %+v", res)
	}
	rep := res.Reports[0]
	if rep.WindowStart != windowStartOf(at) || rep.Observed != 2 || rep.WouldReject != 1 || rep.Threshold != 1 {
		t.Fatalf("上报内容不符: %+v", rep)
	}
	if rep.Scope != "tenant" || rep.Target != "t-a" || rep.RuleID != "r1" {
		t.Fatalf("上报维度不符: %+v", rep)
	}
	if len(rep.Samples) != 2 || rep.Samples[0] != "req-1" {
		t.Fatalf("样本请求 ID 不符: %+v", rep.Samples)
	}
	// 新窗口从 0 开始（本次请求计入新窗口）
	wc := e.dimsSnapshot()[dimKey{Scope: "tenant", Target: "t-a", RuleID: "r1"}]
	if wc.WindowStart != windowStartOf(next) || wc.Observed != 1 {
		t.Fatalf("新窗口应重新计数: %+v", wc)
	}
}

// TestShadowEngine_CollectExpired 无新请求时由 tick 结算过期窗口；空窗口不产出上报。
func TestShadowEngine_CollectExpired(t *testing.T) {
	at := time.Unix(1789272, 0)
	e, setNow := engineAt(t, at)
	// r2 的目标是 t-b：本次请求身份 t-a 与之不匹配 → 只建立 t-a 维度（维度隔离）
	rules := []ratelimitcache.Rule{shadowRate("r1", "tenant", "t-a", 5), shadowRate("r2", "tenant", "t-b", 5)}
	e.observe("t-a", "", "req-1", rules)

	setNow(at.Add(2 * time.Minute))
	reps := e.collectExpired()
	if len(reps) != 1 {
		t.Fatalf("应只结算 t-a 维度: %+v", reps)
	}
	if rep := reps[0]; rep.Target != "t-a" || rep.RuleID != "r1" || rep.Observed != 1 || rep.WouldReject != 0 {
		t.Fatalf("结算内容不符: %+v", rep)
	}
	if again := e.collectExpired(); len(again) != 0 {
		t.Fatalf("同窗口再次结算应为空: %+v", again)
	}
	// 空窗口（无流量）不产出上报
	setNow(at.Add(3 * time.Minute))
	if reps := e.collectExpired(); len(reps) != 0 {
		t.Fatalf("空窗口不应产出上报: %+v", reps)
	}
}

// TestShadowEngine_ReportIDDeterministic report_id 为确定性键（同窗同维度一致 ⇒ 重试由 tee 侧幂等去重）。
func TestShadowEngine_ReportIDDeterministic(t *testing.T) {
	at := time.Unix(1789272, 0)
	build := func() string {
		e, setNow := engineAt(t, at)
		rules := []ratelimitcache.Rule{shadowRate("r1", "tenant", "t-a", 1)}
		e.observe("t-a", "", "req", rules)
		setNow(at.Add(60 * time.Second))
		res := e.observe("t-a", "", "req", rules)
		if len(res.Reports) != 1 {
			t.Fatalf("应结算 1 条: %+v", res)
		}
		return res.Reports[0].ReportID
	}
	id1, id2 := build(), build()
	if id1 != id2 {
		t.Fatalf("report_id 应确定性一致（幂等键）: %q vs %q", id1, id2)
	}
	if id1 == "" {
		t.Fatal("report_id 不得为空")
	}
}

// TestShadowEngine_CapEviction 维度条目超上限 → 淘汰最旧窗口并计数（含计数者）。
func TestShadowEngine_CapEviction(t *testing.T) {
	at := time.Unix(1789272, 0)
	e, setNow := engineAt(t, at)
	// 先让一个最旧窗口落位（含 1 次计数）
	e.observe("t-old", "", "req", []ratelimitcache.Rule{shadowRate("r1", "tenant", "t-old", 5)})
	setNow(at.Add(60 * time.Second))
	// 填满维度表（每个租户一个维度；规则目标与请求身份一致）
	for i := 0; i < maxShadowDims; i++ {
		target := "t-" + itoa(i)
		e.observe(target, "", "req", []ratelimitcache.Rule{shadowRate("r1", "tenant", target, 5)})
	}
	res := e.observe("t-newest", "", "req", []ratelimitcache.Rule{shadowRate("r1", "tenant", "t-newest", 5)})
	if res.Evicted != 1 {
		t.Fatalf("超上限应淘汰 1 个含计数的维度: %+v", res)
	}
	if n := len(e.dimsSnapshot()); n > maxShadowDims {
		t.Fatalf("维度表不得超上限: %d", n)
	}
}

// TestShadowEngine_ReportIDPerVMTag 不同 VM（worker）的同窗同维度 → report_id 不同
// （否则多 worker 的同窗汇总会被 tee-infer 幂等去重而丢计数——实链已踩到 accepted=2/deduped=8）。
func TestShadowEngine_ReportIDPerVMTag(t *testing.T) {
	at := time.Unix(1789272, 0)
	build := func(tag string) string {
		e, setNow := engineAt(t, at)
		e.tag = tag
		rules := []ratelimitcache.Rule{shadowRate("r1", "tenant", "t-a", 1)}
		e.observe("t-a", "", "req", rules)
		setNow(at.Add(60 * time.Second))
		res := e.observe("t-a", "", "req", rules)
		if len(res.Reports) != 1 {
			t.Fatalf("应结算 1 条: %+v", res)
		}
		return res.Reports[0].ReportID
	}
	id1, id2 := build("vm1"), build("vm2")
	if id1 == id2 {
		t.Fatalf("不同 VM 的 report_id 必须不同: %q", id1)
	}
	if !strings.Contains(id1, "vm1") || !strings.Contains(id2, "vm2") {
		t.Fatalf("report_id 应包含 VM 标识: %q / %q", id1, id2)
	}
}

// TestReportQueue_OverflowDrops 队列溢出丢弃并计数（takeAll 后清空）。
func TestReportQueue_OverflowDrops(t *testing.T) {
	q := newReportQueue(2)
	q.push([]pendingReport{{ReportID: "a"}, {ReportID: "b"}, {ReportID: "c"}})
	if q.length() != 2 {
		t.Fatalf("队列应保持上限 2，实际 %d", q.length())
	}
	got := q.takeAll()
	if len(got) != 2 || got[0].ReportID != "a" || got[1].ReportID != "b" {
		t.Fatalf("FIFO 顺序不符: %+v", got)
	}
	if q.length() != 0 {
		t.Fatalf("takeAll 后应为空，实际 %d", q.length())
	}
}

// itoa 轻量整数转字符串（避免引入 strconv 仅为一处用例）。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
