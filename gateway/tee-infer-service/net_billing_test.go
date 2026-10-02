package main

// net_billing_test.go — GA-计费 P0-3 跨服务接线单测：
// ① month 窗口（UTC+8 自然月）；② X-Otpmask-Retry-Attempt 解析；
// ③ aggregateUsage 净量/重试分列（A-27/A-35）。

import (
	"net/http"
	"testing"
	"time"
)

// ---------- ① month 窗口 ----------

func TestQuotaWindowKeyFor_Month(t *testing.T) {
	// 2026-09-14 20:00 UTC = 2026-09-15 04:00 UTC+8 → 月键 2026-09
	utc := time.Date(2026, 9, 14, 20, 0, 0, 0, time.UTC)
	if got := quotaWindowKeyFor(quotaWindowMonth, utc); got != "2026-09" {
		t.Errorf("month key = %q, want 2026-09", got)
	}
	// 跨月边界：2026-09-30 16:00 UTC = 2026-10-01 00:00 UTC+8 → 2026-10
	edge := time.Date(2026, 9, 30, 16, 0, 0, 0, time.UTC)
	if got := quotaWindowKeyFor(quotaWindowMonth, edge); got != "2026-10" {
		t.Errorf("month boundary key = %q, want 2026-10", got)
	}
}

func TestValidQuotaWindow_MonthAccepted(t *testing.T) {
	if !validQuotaWindow(quotaWindowMonth) {
		t.Error("month window should be accepted (P0-3/P-2)")
	}
	if !validQuotaWindow(quotaWindowMinute) || !validQuotaWindow(quotaWindowDay) || !validQuotaWindow(quotaWindowNone) {
		t.Error("existing windows must remain valid")
	}
	if validQuotaWindow("week") {
		t.Error("unknown window must be rejected")
	}
}

func TestQuotaMonthWindow_EnforcesAndRotates(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-m"] = quotaSpec{Limits: []quotaLimit{{Window: quotaWindowMonth, MaxTokens: 100}}}

	if ok, _ := s.reserveQuota("t-m", 60); !ok {
		t.Fatal("first reserve should pass")
	}
	if ok, denied := s.reserveQuota("t-m", 50); ok || denied != quotaWindowMonth {
		t.Fatalf("second reserve should be denied by month window, got ok=%v denied=%q", ok, denied)
	}
	// 模拟跨月：把窗口键改为上一个月的键 → 计数重置
	s.mu.Lock()
	s.quotaWindowKey["t-m|"+quotaWindowMonth] = "1999-01"
	used := s.dimensionUsed("t-m", quotaWindowMonth)
	s.mu.Unlock()
	if used != 0 {
		t.Errorf("month window should reset on rotation, used=%d", used)
	}
}

// ---------- ② 重试头解析 ----------

func TestRetryAttemptFromHeader(t *testing.T) {
	cases := []struct {
		val  string
		want int
	}{
		{"", 0},
		{"0", 0},
		{"-1", 0},
		{"abc", 0},
		{"1", 1},
		{"2", 2},
		{" 3 ", 3},
	}
	for _, c := range cases {
		r, _ := http.NewRequest(http.MethodPost, "/infer", nil)
		if c.val != "" {
			r.Header.Set(retryAttemptHeader, c.val)
		}
		if got := retryAttemptFromHeader(r); got != c.want {
			t.Errorf("retryAttemptFromHeader(%q) = %d, want %d", c.val, got, c.want)
		}
	}
}

// ---------- ③ aggregateUsage 净量/重试分列 ----------

func TestAggregateUsage_NetAndRetrySplit(t *testing.T) {
	// 两条 infer：一条正常（net），一条重试（retry）；deny 不计费
	events := []AuditEvent{
		{EventID: "e1", TenantID: "t1", Action: "infer", TokensIn: 100, TokensOut: 50,
			Timestamp: 1000, EngineType: "tee_gpu", Model: "qwen"},
		{EventID: "e2", TenantID: "t1", Action: "infer", TokensIn: 70, TokensOut: 30,
			Timestamp: 1001, EngineType: "tee_gpu", Model: "qwen", IsRetry: true},
		{EventID: "e3", TenantID: "t1", Action: "deny", Result: "guardrail", Timestamp: 1002},
	}

	out := aggregateUsage(events, 0, 2000)
	inc := out["t1"]
	if inc == nil {
		t.Fatal("tenant t1 missing")
	}
	// 总量（含 retry，向后兼容）
	if inc.TokensIn != 170 || inc.TokensOut != 80 {
		t.Errorf("raw = (%d,%d), want (170,80)", inc.TokensIn, inc.TokensOut)
	}
	// 净量（剔除 retry）
	if inc.TokensInNet != 100 || inc.TokensOutNet != 50 {
		t.Errorf("net = (%d,%d), want (100,50)", inc.TokensInNet, inc.TokensOutNet)
	}
	// 重试 = 70+30
	if inc.RetryTokens != 100 {
		t.Errorf("retry = %d, want 100", inc.RetryTokens)
	}
	// 守恒：raw_in+raw_out == net_in+net_out+retry
	if inc.TokensIn+inc.TokensOut != inc.TokensInNet+inc.TokensOutNet+inc.RetryTokens {
		t.Error("conservation identity violated")
	}
	// 模型维度同口径
	mu := inc.ByModel[modelDimensionKey("tee_gpu", "qwen")]
	if mu == nil {
		t.Fatal("by_model missing")
	}
	if mu.TokensInNet != 100 || mu.TokensOutNet != 50 || mu.RetryTokens != 100 {
		t.Errorf("model net/retry = (%d,%d,%d), want (100,50,100)",
			mu.TokensInNet, mu.TokensOutNet, mu.RetryTokens)
	}
	// deny 不计费
	if inc.Requests != 2 {
		t.Errorf("requests = %d, want 2 (deny excluded)", inc.Requests)
	}
}
