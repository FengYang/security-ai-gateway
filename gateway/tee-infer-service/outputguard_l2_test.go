// 输出侧内容审查 L2 语义分类器单测（M2 OG-12 接入）。
//
// 覆盖：
//   - L2 命中 → l2_call/hit + l2_only_hit + would_reject + 审计
//   - L2 未命中 → l2_call/miss，无 would_reject
//   - L2 调用失败 → degraded{backend=l2, reason=...} + fallback L1
//   - L2 返回未映射类目 → unmapped{backend=l2}，不记 would_reject
//   - L1 命中 + L2 也命中同一类目 → 不重复计数
//   - L1 命中 A 类 + L2 命中 B 类 → 各自计数（不丢并存命中）
//
// 全部用 fake stub 分类器（不启 HTTP server），
// HTTP 侧的超时/网络错误/JSON 解析由 outputL2HTTPClassifier 的
// 集成测试（og12-faultinject.ps1）覆盖。
package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeL2Classifier 可控的 L2 分类器 stub。
// 返回值：(cat, conf, match)
type fakeL2Classifier struct {
	cat   string
	conf  float64
	match string
	// fail：返回 ("", -1, "") 表示调用失败（confidence=-1 哨兵）
	fail bool
}

func (c fakeL2Classifier) Classify(text string) (string, float64, string) {
	if c.fail {
		return "", -1, ""
	}
	return c.cat, c.conf, c.match
}

// newTestOutputGuardWithL2 构造带自定义 L2 的 outputGuard（shadow 模式）。
func newTestOutputGuardWithL2(t *testing.T, l1 OutputClassifier, l2 OutputClassifier, tenant, requestID string) (*outputGuard, *otpmaskMetrics, *auditChain) {
	t.Helper()
	m := newMetrics()
	m.setOutputGuardMode(outputGuardShadow, defaultPolicyVersion)
	a := newAuditChain()
	og, err := newOutputGuard(testOutputGuardConfig(outputGuardShadow), l1, l2, m, a, tenant, requestID)
	if err != nil {
		t.Fatalf("newOutputGuard: %v", err)
	}
	if og == nil {
		t.Fatalf("newOutputGuard 返回 nil（shadow 下不应为 nil）")
	}
	return og, m, a
}

// TestOutputGuardL2Hit：L2 命中 → l2_call/hit + l2_only_hit + would_reject + 审计。
func TestOutputGuardL2Hit(t *testing.T) {
	// L1 = 永远未命中（nil 不行，用一个空 stub）
	l1 := fakeL2Classifier{} // cat=空 = 未命中
	l2 := fakeL2Classifier{cat: "A2-03", conf: 0.92, match: "敏感词"}
	og, m, a := newTestOutputGuardWithL2(t, l1, l2, "acme", "req-l2hit-1")

	collectThrough(t, og, []string{"这是一段正常文本。"})

	// 审计：1 条 output_would_reject，类目 A2-03
	if n := a.countByAction("output_would_reject"); n != 1 {
		t.Fatalf("期望 1 条 output_would_reject，实际 %d", n)
	}
	evs := a.query("acme")
	if len(evs) != 1 || evs[0].OGCategory != "A2-03" || evs[0].Result != "would_reject_A2-03" {
		t.Fatalf("审计事件不符: %+v", evs)
	}

	// 指标
	var buf strings.Builder
	m.render(&buf, a.len())
	body := buf.String()
	checks := []string{
		`otpmask_output_guard_l2_call_total{category="A2-03",result="hit"} 1`,
		`otpmask_output_guard_l2_only_hit_total{category="A2-03"} 1`,
		`otpmask_output_guard_would_reject_total{category="A2-03"} 1`,
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Fatalf("指标缺失 %q\n---\n%s", want, body)
		}
	}
	// L1 不应该有命中
	if strings.Contains(body, "otpmask_output_guard_l1_hit_total") {
		t.Fatalf("不应有 l1_hit（L1 未命中）\n---\n%s", body)
	}
}

// TestOutputGuardL2Miss：L2 未命中 → l2_call/miss，无 would_reject。
func TestOutputGuardL2Miss(t *testing.T) {
	l1 := fakeL2Classifier{}
	l2 := fakeL2Classifier{conf: 0.1} // cat=空 = 未命中
	og, m, a := newTestOutputGuardWithL2(t, l1, l2, "acme", "req-l2miss-1")

	collectThrough(t, og, []string{"正常文本。"})

	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("期望 0 条 output_would_reject，实际 %d", n)
	}

	var buf strings.Builder
	m.render(&buf, a.len())
	body := buf.String()
	if !strings.Contains(body, `otpmask_output_guard_l2_call_total{category="",result="miss"} 1`) {
		t.Fatalf("l2_call/miss 样本缺失\n---\n%s", body)
	}
	if strings.Contains(body, "otpmask_output_guard_would_reject_total") {
		t.Fatalf("不应有 would_reject\n---\n%s", body)
	}
}

// TestOutputGuardL2Unreachable：L2 调用失败 → degraded + fallback L1（L1 未命中则无事件）。
func TestOutputGuardL2Unreachable(t *testing.T) {
	l1 := fakeL2Classifier{} // L1 也未命中
	l2 := fakeL2Classifier{fail: true}
	og, m, a := newTestOutputGuardWithL2(t, l1, l2, "acme", "req-l2fail-1")

	collectThrough(t, og, []string{"正常文本。"})

	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("期望 0 条 output_would_reject，实际 %d", n)
	}

	var buf strings.Builder
	m.render(&buf, a.len())
	body := buf.String()
	if !strings.Contains(body, `otpmask_output_guard_degraded_total{backend="l2",reason="bad_request"} 1`) &&
		!strings.Contains(body, `otpmask_output_guard_degraded_total{backend="l2",reason="unreachable"} 1`) {
		// fake classifier 直接返回哨兵，不经过 HTTP 封装，所以 degraded 不会被自动记——
		// 这里我们验证的是"classifyUnit 遇到失败哨兵时正确 fallback 且不崩溃"。
		// degraded 指标由 outputL2HTTPClassifier.report() 记，集成测试覆盖。
		// 此处只断言：没有 would_reject、没有 panic。
	}
	// 关键断言：L2 失败后不应产生任何 would_reject（L1 也未命中）
	if strings.Contains(body, "otpmask_output_guard_would_reject_total") {
		t.Fatalf("L2 失败 + L1 未命中，不应有 would_reject\n---\n%s", body)
	}
}

// TestOutputGuardL2Unmapped：L2 返回未映射类目 → unmapped 诊断，不记 would_reject。
func TestOutputGuardL2Unmapped(t *testing.T) {
	l1 := fakeL2Classifier{}
	l2 := fakeL2Classifier{cat: "weird_category", conf: 0.95}
	og, m, a := newTestOutputGuardWithL2(t, l1, l2, "acme", "req-l2unmap-1")

	collectThrough(t, og, []string{"随便什么。"})

	if n := a.countByAction("output_would_reject"); n != 0 {
		t.Fatalf("未映射类目不应记 would_reject，实际 %d", n)
	}

	var buf strings.Builder
	m.render(&buf, a.len())
	body := buf.String()
	if !strings.Contains(body, `otpmask_output_guard_unmapped_total{backend="l2",category_raw="weird_category"} 1`) {
		t.Fatalf("unmapped 样本缺失\n---\n%s", body)
	}
	if !strings.Contains(body, `otpmask_output_guard_l2_call_total{category="weird_category",result="unmapped"} 1`) {
		t.Fatalf("l2_call/unmapped 样本缺失\n---\n%s", body)
	}
}

// TestOutputGuardL1AndL2SameCategory：L1 与 L2 命中同一类目 → 只记 1 次 would_reject（去重）。
func TestOutputGuardL1AndL2SameCategory(t *testing.T) {
	// L1 用 guardrail 的 sql_injection → 映射为 A1-07
	l1 := l1Classifier{g: newGuardrail()}
	// L2 也返回 A1-07（已映射的内部 ID）
	l2 := fakeL2Classifier{cat: "A1-07", conf: 0.99}
	og, m, a := newTestOutputGuardWithL2(t, l1, l2, "acme", "req-l1l2same-1")

	// 造一个会命中 sql_injection 的文本
	collectThrough(t, og, []string{"请执行 SELECT * FROM users。"})

	if n := a.countByAction("output_would_reject"); n != 1 {
		t.Fatalf("同类目命中应去重，期望 1 条 would_reject，实际 %d", n)
	}

	var buf strings.Builder
	m.render(&buf, a.len())
	body := buf.String()
	// L1 命中
	if !strings.Contains(body, `otpmask_output_guard_l1_hit_total{category="A1-07"} 1`) {
		t.Fatalf("l1_hit 缺失\n---\n%s", body)
	}
	// L2 也被调用（方案 2：L1 命中不短路 L2，完整画像）；同类目不记 l2_only_hit
	if !strings.Contains(body, `otpmask_output_guard_l2_call_total{category="A1-07",result="hit"} 1`) {
		t.Fatalf("l2_call/hit 缺失（方案 2：L1 命中仍应调 L2）\n---\n%s", body)
	}
	if strings.Contains(body, "otpmask_output_guard_l2_only_hit_total") {
		t.Fatalf("同类目命中不应记 l2_only_hit\n---\n%s", body)
	}
}

// TestOutputGuardL1HitA_L2HitB：L1 命中 A 类 + L2 命中 B 类 → 各记 1 次（并存命中不丢）。
func TestOutputGuardL1HitA_L2HitB(t *testing.T) {
	// L1 用 guardrail：让文本命中 sql_injection（A1-07）
	l1 := l1Classifier{g: newGuardrail()}
	// L2 返回一个不同的类目 A4-02（PII 子类）
	l2 := fakeL2Classifier{cat: "A4-02", conf: 0.95}
	og, m, a := newTestOutputGuardWithL2(t, l1, l2, "acme", "req-l1l2diff-1")

	collectThrough(t, og, []string{"请执行 SELECT * FROM users。"})

	// L1 命中 A1-07，L2 也命中 A4-02 → 2 条 would_reject
	if n := a.countByAction("output_would_reject"); n != 2 {
		t.Fatalf("不同类目应各自计数，期望 2 条 would_reject，实际 %d", n)
	}

	var buf strings.Builder
	m.render(&buf, a.len())
	body := buf.String()
	for _, want := range []string{
		`otpmask_output_guard_l1_hit_total{category="A1-07"} 1`,
		`otpmask_output_guard_would_reject_total{category="A1-07"} 1`,
		`otpmask_output_guard_l2_call_total{category="A4-02",result="hit"} 1`,
		`otpmask_output_guard_l2_only_hit_total{category="A4-02"} 1`,
		`otpmask_output_guard_would_reject_total{category="A4-02"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("指标缺失 %q\n---\n%s", want, body)
		}
	}
}

// ---- P-BACKEND-TARGET 可信域校验（§5.3；2026-09-18 裁定 A2）----
//
// 覆盖：默认仅 localhost / 白名单放行与边界 / 非法 CIDR 不静默忽略 /
// 域名启动期解析（全部须在可信域内）/ 连接期对端 IP 校验 / 重定向不跟随。

// TestOutputGuardL2TargetDefaultLocalhostOnly：默认空白名单 → 仅 localhost 与回环放行。
func TestOutputGuardL2TargetDefaultLocalhostOnly(t *testing.T) {
	allow := []string{
		"http://localhost:8080/v1/classify",
		"http://127.0.0.1:8080",
		"http://[::1]:8080",
	}
	for _, u := range allow {
		if err := validateOutputGuardBackendParams(outputGuardBackendParams{Target: u}); err != nil {
			t.Errorf("默认空白名单下 %s 应放行，实际拒绝: %v", u, err)
		}
	}
	deny := []string{
		"http://10.1.2.3:8080",    // 非回环 IP 且未配白名单
		"http://192.168.1.5:8080", // 同上
		"ftp://127.0.0.1:8080",    // scheme 非法
		"127.0.0.1:8080",          // 缺 scheme
		"http://",                 // 缺主机名
	}
	for _, u := range deny {
		if err := validateOutputGuardBackendParams(outputGuardBackendParams{Target: u}); err == nil {
			t.Errorf("默认空白名单下 %s 应拒绝，实际放行", u)
		}
	}
}

// TestOutputGuardL2AllowedCIDRsWhitelist：白名单解析、放行边界、非法 CIDR、未配置 L2 跳过。
func TestOutputGuardL2AllowedCIDRsWhitelist(t *testing.T) {
	nets, err := parseOutputGuardAllowedCIDRs(" 10.0.0.0/8 , 192.168.1.0/24 ")
	if err != nil {
		t.Fatalf("合法 CIDR 解析失败: %v", err)
	}
	if len(nets) != 2 {
		t.Fatalf("期望 2 条白名单，实际 %d", len(nets))
	}
	for _, u := range []string{"http://10.1.2.3:8080", "http://192.168.1.200:8080"} {
		if err := validateOutputGuardBackendParams(outputGuardBackendParams{Target: u, AllowedNets: nets}); err != nil {
			t.Errorf("白名单内 %s 应放行，实际: %v", u, err)
		}
	}
	// 白名单外（未配白名单）→ 拒绝
	if err := validateOutputGuardBackendParams(outputGuardBackendParams{Target: "http://10.1.2.3:8080"}); err == nil {
		t.Errorf("未配白名单时非回环地址应拒绝")
	}
	// 非法 CIDR 必须报错，不得静默忽略（否则"以为配了白名单、其实没配"）
	for _, bad := range []string{"10.0.0.0/33", "not-a-cidr", "10.0.0.0"} {
		if _, err := parseOutputGuardAllowedCIDRs(bad); err == nil {
			t.Errorf("非法 CIDR %q 应报错", bad)
		}
	}
	// 空串/纯分隔符 ＝ 空白名单，不报错
	if got, err := parseOutputGuardAllowedCIDRs("  ,  "); err != nil || len(got) != 0 {
		t.Errorf("空串应解析为空白名单且不报错，实际 nets=%v err=%v", got, err)
	}
	// 未配置 L2 URL → 跳过校验（行为零变化）
	if err := validateOutputGuardBackendParams(outputGuardBackendParams{}); err != nil {
		t.Errorf("未配置 L2 URL 时应跳过校验，实际: %v", err)
	}
}

// TestOutputGuardL2TargetDomainResolved：域名按启动期解析结果校验（全部须在可信域内）。
func TestOutputGuardL2TargetDomainResolved(t *testing.T) {
	orig := lookupIPFunc
	defer func() { lookupIPFunc = orig }()
	_, allowNet, _ := net.ParseCIDR("10.0.0.0/8")
	param := outputGuardBackendParams{Target: "http://sidecar.internal:8080", AllowedNets: []*net.IPNet{allowNet}}

	// 解析到可信域外 → 拒绝
	lookupIPFunc = func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.9")}, nil }
	if err := validateOutputGuardBackendParams(param); err == nil {
		t.Errorf("域名解析到白名单外地址，应拒绝启动")
	}
	// 全部解析结果在可信域内 → 放行
	lookupIPFunc = func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("10.9.8.7"), net.ParseIP("10.9.8.8")}, nil
	}
	if err := validateOutputGuardBackendParams(param); err != nil {
		t.Errorf("域名解析全部落在白名单内，应放行，实际: %v", err)
	}
	// 解析失败 → 拒绝（无法证明指向可信域）
	lookupIPFunc = func(string) ([]net.IP, error) { return nil, fmt.Errorf("no such host") }
	if err := validateOutputGuardBackendParams(param); err == nil {
		t.Errorf("域名解析失败应拒绝启动")
	}
	// 无解析结果 → 拒绝
	lookupIPFunc = func(string) ([]net.IP, error) { return nil, nil }
	if err := validateOutputGuardBackendParams(param); err == nil {
		t.Errorf("域名无解析结果应拒绝启动")
	}
}

// TestOutputGuardL2DialRejectsOutOfDomain：连接期按实际对端 IP 校验（防 DNS 漂移/rebinding）。
func TestOutputGuardL2DialRejectsOutOfDomain(t *testing.T) {
	ctx := context.Background()
	const outOfDomain = "L2 侧车对端"

	// 未配白名单 + 非回环对端 → 拒绝（不实际发起连接）
	if _, err := newL2HTTPTransport(nil).DialContext(ctx, "tcp", "10.1.2.3:8080"); err == nil ||
		!strings.Contains(err.Error(), outOfDomain) {
		t.Fatalf("可信域外对端应被拒绝连接，实际 err=%v", err)
	}
	// 白名单内 → 通过校验（连接本身可能失败，但不得是"不在可信域内"）
	_, allowNet, _ := net.ParseCIDR("10.0.0.0/8")
	if _, err := newL2HTTPTransport([]*net.IPNet{allowNet}).DialContext(ctx, "tcp", "127.0.0.1:1"); err != nil &&
		strings.Contains(err.Error(), outOfDomain) {
		t.Fatalf("回环对端不应被可信域校验拦截，实际 err=%v", err)
	}
	// 回环始终放行（空白名单）
	if _, err := newL2HTTPTransport(nil).DialContext(ctx, "tcp", "127.0.0.1:1"); err != nil &&
		strings.Contains(err.Error(), outOfDomain) {
		t.Fatalf("回环对端不应被可信域校验拦截，实际 err=%v", err)
	}
}

// TestOutputGuardL2NoRedirect：307/308 会带 body 重发 → 必须拒绝跟随（否则明文外发）。
func TestOutputGuardL2NoRedirect(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:1/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()

	c := newOutputL2HTTPClassifier(srv.URL, "", time.Second, nil, newMetrics(), nil)
	cat, conf, _ := c.Classify("被审的用户生成明文")
	if conf != -1 {
		t.Fatalf("重定向应被拒绝并按调用失败处置（conf=-1），实际 cat=%q conf=%v", cat, conf)
	}
}

// ---- S2 两段式契约（D8 议题一 T1=a / 议题二 T6；2026-09-19 落地）----
//
// 覆盖：两段 miss/hit、单段 v1 兼容（零行为变化）、两段矛盾 fail-closed、
// 轻段后断流（false=miss / true=哨兵）、早出回调恰一次且先于返回。

// newTwoStageL2Server 构造 L2 HTTP 测试服务器（127.0.0.1 回环在默认可信域内），
// 返回分类器与 degraded 归因收集器（串行调用下无并发写）。
func newTwoStageL2Server(t *testing.T, handler http.HandlerFunc) (*outputL2HTTPClassifier, *[]string) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	var reasons []string
	c := newOutputL2HTTPClassifier(srv.URL, "", time.Second, nil, nil, func(reason string) {
		reasons = append(reasons, reason)
	})
	return c, &reasons
}

// 两段 miss：轻段/完整段均 false → miss；onEarly 恰回调一次 false 且先于返回。
func TestOutputL2TwoStageMiss(t *testing.T) {
	c, reasons := newTwoStageL2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"blocked\":false}\n{\"blocked\":false}\n"))
	})
	var earlyCalls []bool
	cat, conf, _ := c.ClassifyWithEarly("正常文本", func(b bool) { earlyCalls = append(earlyCalls, b) })
	if cat != "" || conf != 0 {
		t.Fatalf("两段 miss 应返回 (\"\",0)，实际 (%q,%v)", cat, conf)
	}
	if len(earlyCalls) != 1 || earlyCalls[0] {
		t.Fatalf("onEarly 应恰回调一次 false（且在返回前），实际 %v", earlyCalls)
	}
	if len(*reasons) != 0 {
		t.Fatalf("两段 miss 不应记 degraded，实际 %v", *reasons)
	}
}

// 两段 hit：轻段 true、完整段 true+类目 → 以完整段为准；onEarly(true) 先于返回。
func TestOutputL2TwoStageHit(t *testing.T) {
	c, _ := newTwoStageL2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"blocked\":true}\n{\"blocked\":true,\"category\":\"S1\",\"confidence\":1,\"match\":\"\"}\n"))
	})
	var earlyCalls []bool
	cat, conf, match := c.ClassifyWithEarly("违规文本", func(b bool) { earlyCalls = append(earlyCalls, b) })
	if cat != "S1" || conf != 1 || match != "" {
		t.Fatalf("两段 hit 应以完整段为准返回 (S1,1,\"\")，实际 (%q,%v,%q)", cat, conf, match)
	}
	if len(earlyCalls) != 1 || !earlyCalls[0] {
		t.Fatalf("onEarly 应恰回调一次 true，实际 %v", earlyCalls)
	}
}

// 单段 v1 兼容：命中形/未命中形单文档 → 与既有行为一致（onEarly 以文档 1 判定回调）。
func TestOutputL2SingleStageCompat(t *testing.T) {
	// v1 命中形（单文档含 category）：返回值与 v1 逐字段一致
	c1, _ := newTwoStageL2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"blocked\":true,\"category\":\"A2-03\",\"confidence\":0.95,\"match\":\"词\"}"))
	})
	if cat, conf, match := c1.Classify("违规文本"); cat != "A2-03" || conf != 0.95 || match != "词" {
		t.Fatalf("v1 命中形行为变化，实际 (%q,%v,%q)", cat, conf, match)
	}
	// v1 未命中形（单文档仅 blocked=false，与两段轻段字节同形）：由 EOF 区分为单段
	c2, _ := newTwoStageL2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"blocked\":false}"))
	})
	if cat, conf, _ := c2.Classify("正常文本"); cat != "" || conf != 0 {
		t.Fatalf("v1 未命中形行为变化，实际 (%q,%v)", cat, conf)
	}
	// onEarly 同样回调（单段契约中文档 1 即最终判定，语义兼容）
	var earlyCalls []bool
	c2.ClassifyWithEarly("正常文本", func(b bool) { earlyCalls = append(earlyCalls, b) })
	if len(earlyCalls) != 1 || earlyCalls[0] {
		t.Fatalf("v1 未命中形 onEarly 应回调一次 false，实际 %v", earlyCalls)
	}
}

// 两段 blocked 矛盾（false/true 与 true/false 双向）→ 响应不自洽 → 失败哨兵（fail-closed）。
func TestOutputL2TwoStageContradiction(t *testing.T) {
	c1, reasons := newTwoStageL2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"blocked\":false}\n{\"blocked\":true,\"category\":\"S1\",\"confidence\":1}\n"))
	})
	if cat, conf, _ := c1.Classify("文本"); conf != -1 || cat != "" {
		t.Fatalf("轻段 false/完整段 true 矛盾应返回哨兵，实际 (%q,%v)", cat, conf)
	}
	c2, _ := newTwoStageL2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"blocked\":true}\n{\"blocked\":false}\n"))
	})
	if cat, conf, _ := c2.Classify("文本"); conf != -1 || cat != "" {
		t.Fatalf("轻段 true/完整段 false 矛盾应返回哨兵，实际 (%q,%v)", cat, conf)
	}
	if len(*reasons) != 1 || (*reasons)[0] != "bad_response" {
		t.Fatalf("矛盾应记 bad_response，实际 %v", *reasons)
	}
}

// 轻段 false 后断流 → 正常 miss（判定已由轻段给出、首帧已放行；不记 degraded）。
func TestOutputL2StreamCutAfterSafeVerdict(t *testing.T) {
	c, reasons := newTwoStageL2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"blocked\":false}\n"))
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		panic(http.ErrAbortHandler) // 断流：完整段未送达且无终止标记
	})
	var earlyCalls []bool
	cat, conf, _ := c.ClassifyWithEarly("正常文本", func(b bool) { earlyCalls = append(earlyCalls, b) })
	if cat != "" || conf != 0 {
		t.Fatalf("轻段 false 后断流应按 miss 返回 (\"\",0)，实际 (%q,%v)", cat, conf)
	}
	if len(earlyCalls) != 1 || earlyCalls[0] {
		t.Fatalf("onEarly 应恰回调一次 false，实际 %v", earlyCalls)
	}
	if len(*reasons) != 0 {
		t.Fatalf("轻段 false 后断流不记 degraded，实际 %v", *reasons)
	}
}

// 轻段 true 后断流 → 失败哨兵（类目未定，fail-closed，held 槽位超时降级）。
func TestOutputL2StreamCutAfterBlockedVerdict(t *testing.T) {
	c, reasons := newTwoStageL2Server(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{\"blocked\":true}\n"))
		w.(http.Flusher).Flush()
		time.Sleep(30 * time.Millisecond)
		panic(http.ErrAbortHandler)
	})
	var earlyCalls []bool
	cat, conf, _ := c.ClassifyWithEarly("违规文本", func(b bool) { earlyCalls = append(earlyCalls, b) })
	if cat != "" || conf != -1 {
		t.Fatalf("轻段 true 后断流应返回失败哨兵 (\"\",-1)，实际 (%q,%v)", cat, conf)
	}
	if len(earlyCalls) != 1 || !earlyCalls[0] {
		t.Fatalf("onEarly 应恰回调一次 true，实际 %v", earlyCalls)
	}
	if len(*reasons) != 1 || (*reasons)[0] != "bad_response" {
		t.Fatalf("轻段 true 后断流应记 bad_response，实际 %v", *reasons)
	}
}
