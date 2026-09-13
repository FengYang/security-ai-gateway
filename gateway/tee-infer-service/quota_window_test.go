package main

// S3b 窗口配额测试：
//   - minute 窗口：窗口内累计超限拒绝，窗口翻转自动重置
//   - day 窗口：UTC+8 自然日窗口；翻转自动重置
//   - 回滚同步退回窗口计数（失败请求不白占额度）
//   - 缺省（无 window）= 累计上限，行为不变
//   - 非法 window 一律 400（避免"配了不生效"）

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newQuotaTestServer 构造仅含配额相关状态的最小 teeServer（纯逻辑单测，不起完整服务）。
func newQuotaTestServer() *teeServer {
	return &teeServer{
		usage:            make(map[string]*usageRecord),
		quota:            make(map[string]quotaSpec),
		quotaWindowUsage: make(map[string]int64),
		quotaWindowKey:   make(map[string]string),
	}
}

// TestQuotaWindowMinute 每分钟窗口：超限拒绝、翻转重置、回滚退回。
func TestQuotaWindowMinute(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-a"] = quotaSpec{MaxTokens: 100, Window: quotaWindowMinute}

	if !s.reserveQuota("t-a", 60) {
		t.Fatal("首次 60 token 应放行")
	}
	if s.reserveQuota("t-a", 50) {
		t.Fatal("窗口内累计 110 > 100 应拒绝")
	}
	if got := s.quotaWindowUsed("t-a"); got != 60 {
		t.Fatalf("窗口内已用应为 60，实际 %d", got)
	}
	// 回滚：失败请求退回窗口额度
	s.rollbackQuota("t-a", 60)
	if got := s.quotaWindowUsed("t-a"); got != 0 {
		t.Fatalf("回滚后窗口已用应为 0，实际 %d", got)
	}
	// 窗口翻转：伪造上一窗口标识 → 计数归零
	s.quotaWindowKey["t-a|"+quotaWindowMinute] = "stale-key"
	if !s.reserveQuota("t-a", 90) {
		t.Fatal("窗口翻转后 90 token 应放行")
	}
	if got := s.quotaWindowUsed("t-a"); got != 90 {
		t.Fatalf("翻转后窗口已用应为 90，实际 %d", got)
	}
	// 计量不受窗口影响（累计 TokensIn 照记）
	if rec := s.usage["t-a"]; rec == nil || rec.TokensIn != 90 {
		t.Fatalf("累计计量应照记: %+v", rec)
	}
}

// TestQuotaWindowDayRollover 自然日窗口：跨日（UTC+8）自动重置。
func TestQuotaWindowDayRollover(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-b"] = quotaSpec{MaxTokens: 100, Window: quotaWindowDay}

	if !s.reserveQuota("t-b", 100) {
		t.Fatal("首日 100 token 应放行")
	}
	if s.reserveQuota("t-b", 1) {
		t.Fatal("同日超限应拒绝")
	}
	// 伪造"昨天"的窗口标识 → 今日视为新窗口
	s.quotaWindowKey["t-b|"+quotaWindowDay] = "1999-01-01"
	if !s.reserveQuota("t-b", 100) {
		t.Fatal("跨日后应重置并放行")
	}
	if got := s.quotaWindowUsed("t-b"); got != 100 {
		t.Fatalf("跨日后窗口已用应为 100，实际 %d", got)
	}
}

// TestQuotaWindowKeyFor 窗口标识计算：minute 为分钟序号；day 为 UTC+8 自然日。
func TestQuotaWindowKeyFor(t *testing.T) {
	utc := time.Date(2026, 9, 13, 17, 30, 0, 0, time.UTC)
	// UTC 17:30 = UTC+8 次日 01:30
	if got := quotaWindowKeyFor(quotaWindowDay, utc); got != "2026-09-14" {
		t.Fatalf("UTC+8 自然日应为 2026-09-14，实际 %s", got)
	}
	m1 := quotaWindowKeyFor(quotaWindowMinute, utc)
	m2 := quotaWindowKeyFor(quotaWindowMinute, utc.Add(30*time.Second))
	if m1 != m2 {
		t.Fatalf("同一分钟内标识应相同: %s vs %s", m1, m2)
	}
	if quotaWindowKeyFor(quotaWindowMinute, utc.Add(time.Minute)) == m1 {
		t.Fatal("跨分钟后标识应变化")
	}
	if got := quotaWindowKeyFor(quotaWindowNone, utc); got != "" {
		t.Fatalf("无窗口应为空标识，实际 %q", got)
	}
}

// TestQuotaWindowDefaultCumulative 缺省（无 window）= 累计上限，行为不变。
func TestQuotaWindowDefaultCumulative(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-c"] = quotaSpec{MaxTokens: 100} // Window 为空

	if !s.reserveQuota("t-c", 80) {
		t.Fatal("累计模式 80 应放行")
	}
	// 输出侧记录后累计达 100，再加即拒绝（与 P1 语义一致：使用累计口径而非窗口）
	s.mu.Lock()
	s.usage["t-c"].TokensOut += 20
	s.mu.Unlock()
	if s.reserveQuota("t-c", 1) {
		t.Fatal("累计 100 + 1 > 100 应拒绝")
	}
	if got := s.quotaWindowUsed("t-c"); got != 0 {
		t.Fatalf("累计模式不应有窗口计数，实际 %d", got)
	}
}

// TestHandleQuota_window 管理接口：合法 window 生效；非法 window 400。
func TestHandleQuota_window(t *testing.T) {
	s := newQuotaTestServer()
	mux := http.NewServeMux()
	mux.HandleFunc("/usage/quota", s.handleQuota)
	ts := httptest.NewServer(mux)
	defer ts.Close()

	post := func(body string) (int, map[string]any) {
		resp, err := http.Post(ts.URL+"/usage/quota", "application/json", bytes.NewReader([]byte(body)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	code, out := post(`{"tenant":"t-d","max_tokens":5000,"window":"day"}`)
	if code != http.StatusOK || out["window"] != "day" || out["quota"] != float64(5000) {
		t.Fatalf("day 窗口应生效: code=%d out=%+v", code, out)
	}
	if s.quotaWindowOf("t-d") != quotaWindowDay {
		t.Fatalf("窗口未写入运行态: %q", s.quotaWindowOf("t-d"))
	}
	if code, _ := post(`{"tenant":"t-d","max_tokens":1,"window":"hour"}`); code != http.StatusBadRequest {
		t.Fatalf("非法 window 应 400，实际 %d", code)
	}
	// 解除配额（<=0）：窗口一并清除
	if code, _ := post(`{"tenant":"t-d","max_tokens":0}`); code != http.StatusOK {
		t.Fatalf("解除配额应 200，实际 %d", code)
	}
	if s.quotaWindowOf("t-d") != quotaWindowNone {
		t.Fatal("解除配额后不应残留窗口")
	}
}
