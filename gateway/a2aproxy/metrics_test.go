package a2aproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/a2a"
)

// T-5 可观测测试：§6.5 数据面指标的语义与文本渲染。

// rendered 返回 /metrics 输出文本。
func rendered(t *testing.T, p *Proxy) string {
	t.Helper()
	rec := httptest.NewRecorder()
	p.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", rec.Code)
	}
	return rec.Body.String()
}

func TestMetricsTaskStateCounter(t *testing.T) {
	h := newHarness(t)
	_, raw := h.invoke(t, "SendMessage", `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-cs","role":"ROLE_USER","parts":[{"text":"hi"}]}}}`, nil)
	if strings.Contains(string(raw), `"error"`) {
		t.Fatalf("基线调用不应出错: %s", raw)
	}
	out := rendered(t, h.proxy)
	if !strings.Contains(out, "a2a_tasks_total{") {
		t.Fatalf("缺少 a2a_tasks_total: %s", out)
	}
	if !strings.Contains(out, `state="completed"`) {
		t.Errorf("期望任务终态 completed 被观测: %s", out)
	}
	if !strings.Contains(out, `tenant="tenant-a"`) || !strings.Contains(out, `agent="test-agent"`) {
		t.Errorf("缺少 tenant/agent 标签: %s", out)
	}
}

// TestMetricsTaskDurationHistogramOnlyWhenStartKnown 覆盖 F-6 D-F6-5/SM-9/SM-10：
// 起点已知才落耗时样本；首见即终态（起点未知）不落样本、不伪造。
func TestMetricsTaskDurationHistogramOnlyWhenStartKnown(t *testing.T) {
	m := NewA2AMetrics()
	now := time.Now().UTC()

	// 终点但起点未知 → 不落样本。
	if _, ok := m.ObserveTerminalTask("t", "a", "task-1", now); ok {
		t.Fatal("起点未知不应落样本（SM-10：不得伪造起点）")
	}
	if strings.Contains(renderMetricsText(m), "a2a_task_duration_seconds_bucket") {
		t.Error("未落样本时不应渲染直方图")
	}

	// 起点 → 终态：落样本并结算毫秒。
	m.TrackTaskStart("t", "a", "task-2", now.Add(-150*time.Millisecond))
	ms, ok := m.ObserveTerminalTask("t", "a", "task-2", now)
	if !ok {
		t.Fatal("起点已知应落样本")
	}
	if ms < 149 || ms > 151 {
		t.Errorf("duration_ms = %d, want ~150", ms)
	}
	out := renderMetricsText(m)
	for _, want := range []string{
		"# TYPE a2a_task_duration_seconds histogram",
		`a2a_task_duration_seconds_bucket{agent="a",le="0.25"} 1`,
		`a2a_task_duration_seconds_bucket{agent="a",le="+Inf"} 1`,
		`a2a_task_duration_seconds_count{agent="a"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("渲染缺少 %q: %s", want, out)
		}
	}
	// start 条目在结算后清除：二次终态不得重复计数。
	if _, ok := m.ObserveTerminalTask("t", "a", "task-2", now.Add(time.Second)); ok {
		t.Error("同一 task 二次终态不应重复结算")
	}
	if strings.Contains(renderMetricsText(m), `a2a_task_duration_seconds_count{agent="a"} 2`) {
		t.Error("重复结算导致 count=2")
	}
}

func TestMetricsTrackStartIsIdempotent(t *testing.T) {
	m := NewA2AMetrics()
	start := time.Now().UTC().Add(-time.Second)
	m.TrackTaskStart("t", "a", "task-x", start)
	// 第二次（更晚）不得覆盖已有起点。
	m.TrackTaskStart("t", "a", "task-x", start.Add(500*time.Millisecond))
	ms, ok := m.ObserveTerminalTask("t", "a", "task-x", start.Add(time.Second))
	if !ok {
		t.Fatal("应落样本")
	}
	if ms < 999 || ms > 1001 {
		t.Errorf("duration_ms = %d, want ~1000（起点应为首次观测）", ms)
	}
}

func TestMetricsAuthzDenyAndRateLimit(t *testing.T) {
	h := newHarness(t)
	// ACL 拒绝：tenant|agent|skill 命中 deny。
	h.gov.deny["tenant-a|test-agent|hello_world"] = true
	_, raw := h.invoke(t, "SendMessage", `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-d","role":"ROLE_USER","parts":[{"text":"hi"}]}}}`, map[string]string{a2a.HeaderSkill: "hello_world"})
	if !strings.Contains(string(raw), a2a.ReasonUnknownSkill) && !strings.Contains(string(raw), "acl_denied") {
		t.Fatalf("期望被拒绝: %s", raw)
	}
	out := rendered(t, h.proxy)
	if !strings.Contains(out, `a2a_authz_denies_total{agent="test-agent",reason="acl_denied"} 1`) {
		t.Errorf("缺少授权拒绝计数: %s", out)
	}
	// 治理顺序：ACL 先于限流，被 ACL 拒绝的请求不应产生限流决策（避免指标虚高）。
	if strings.Contains(out, "a2a_rate_limit_decisions_total") {
		t.Errorf("ACL 拒绝（发生在限流之前）不应产生限流决策指标: %s", out)
	}
}

// TestMetricsRateLimitAllow 正常放行路径应记录 allow 决策。
func TestMetricsRateLimitAllow(t *testing.T) {
	h := newHarness(t)
	_, raw := h.invoke(t, "SendMessage", `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-a","role":"ROLE_USER","parts":[{"text":"hi"}]}}}`, nil)
	if strings.Contains(string(raw), `"error"`) {
		t.Fatalf("基线调用不应出错: %s", raw)
	}
	out := rendered(t, h.proxy)
	if !strings.Contains(out, `a2a_rate_limit_decisions_total{scope="unknown",decision="allow"} 1`) {
		t.Errorf("缺少限流 allow 计数: %s", out)
	}
}

func TestMetricsRateLimitThrottled(t *testing.T) {
	h := newHarness(t)
	h.gov.retry = 30 // 恒定限流
	resp, _ := h.invoke(t, "SendMessage", `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-r","role":"ROLE_USER","parts":[{"text":"hi"}]}}}`, nil)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", resp.StatusCode)
	}
	out := rendered(t, h.proxy)
	if !strings.Contains(out, `a2a_rate_limit_decisions_total{scope="unknown",decision="throttled"} 1`) {
		t.Errorf("缺少限流 throttled 计数: %s", out)
	}
}

// TestRateLimitEngineScope 精确键 / 通配回退 / 无规则三态上报（T-5 scope 维度来源）。
func TestRateLimitEngineScope(t *testing.T) {
	tab := buildRLTable(t, 1,
		RateLimitRule{Tenant: "t", Agent: "a", Skill: "s", RPM: 10},
		RateLimitRule{Tenant: "t", Agent: "a", Skill: WildcardSkill, RPM: 1},
	)
	e := NewRateLimitEngine()
	if err := e.Replace(tab); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if _, err := e.Allow("t", "a", "s"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if got := e.LastRateLimitScope(); got != RateLimitScopeExact {
		t.Errorf("精确键 scope = %q, want %q", got, RateLimitScopeExact)
	}
	if _, err := e.Allow("t", "a", "other"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if got := e.LastRateLimitScope(); got != RateLimitScopeWildcard {
		t.Errorf("通配回退 scope = %q, want %q", got, RateLimitScopeWildcard)
	}
	if _, err := e.Allow("t", "no-such-agent", "s"); err != nil {
		t.Fatalf("allow: %v", err)
	}
	if got := e.LastRateLimitScope(); got != RateLimitScopeNone {
		t.Errorf("无规则 scope = %q, want %q", got, RateLimitScopeNone)
	}
}

// TestStaticGovernanceScopeDelegation 透传：Limiter 支持上报则透传，未接线则为 none。
func TestStaticGovernanceScopeDelegation(t *testing.T) {
	g := &StaticGovernance{Limiter: NewRateLimitEngine()}
	if got := g.LastRateLimitScope(); got != RateLimitScopeUnknown {
		t.Errorf("引擎尚未决策时应为 unknown, got %q", got)
	}
	if _, err := g.RateLimit(nil, "t", "a", "s"); err != nil { //nolint:staticcheck // nil ctx 不影响内置引擎
		t.Fatalf("ratelimit: %v", err)
	}
	if got := g.LastRateLimitScope(); got != RateLimitScopeNone {
		t.Errorf("空表应上报 none, got %q", got)
	}
	empty := &StaticGovernance{}
	if got := empty.LastRateLimitScope(); got != RateLimitScopeNone {
		t.Errorf("Limiter 未接线应为 none, got %q", got)
	}
}

// TestMetricsHandlerRejectsNonGet /metrics 只接受 GET（运维面收敛，避免探测面扩大）。
func TestMetricsHandlerRejectsNonGet(t *testing.T) {
	h := newHarness(t)
	rec := httptest.NewRecorder()
	h.proxy.MetricsHandler().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /metrics status = %d, want 405", rec.Code)
	}
}

// renderMetricsText 渲染给定指标集合为文本（测试辅助）。
func renderMetricsText(m *A2AMetrics) string {
	var sb strings.Builder
	m.Render(&sb)
	return sb.String()
}
