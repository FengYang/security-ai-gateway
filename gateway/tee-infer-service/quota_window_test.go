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
	"strings"
	"testing"
	"time"
)

// newQuotaTestServer 构造仅含配额相关状态的最小 teeServer（纯逻辑单测，不起完整服务）。
func newQuotaTestServer() *teeServer {
	return &teeServer{
		usage:             make(map[string]*usageRecord),
		quota:             make(map[string]quotaSpec),
		quotaWindowUsage:  make(map[string]int64),
		quotaWindowKey:    make(map[string]string),
		shadowWindowUsage: make(map[string]int64),
		shadowWindowKey:   make(map[string]string),
		audit:             newAuditChain(),
		metrics:           newMetrics(),
	}
}

// TestQuotaWindowMinute 每分钟窗口：超限拒绝、翻转重置、回滚退回。
func TestQuotaWindowMinute(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-a"] = quotaSpec{Limits: []quotaLimit{{Window: quotaWindowMinute, MaxTokens: 100}}}

	if ok, _ := s.reserveQuota("t-a", 60); !ok {
		t.Fatal("首次 60 token 应放行")
	}
	if ok, denied := s.reserveQuota("t-a", 50); ok {
		t.Fatal("窗口内累计 110 > 100 应拒绝")
	} else if denied != quotaWindowMinute {
		t.Fatalf("拒绝应归因 window=%q，实际 %q", quotaWindowMinute, denied)
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
	if ok, _ := s.reserveQuota("t-a", 90); !ok {
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
	s.quota["t-b"] = quotaSpec{Limits: []quotaLimit{{Window: quotaWindowDay, MaxTokens: 100}}}

	if ok, _ := s.reserveQuota("t-b", 100); !ok {
		t.Fatal("首日 100 token 应放行")
	}
	if ok, _ := s.reserveQuota("t-b", 1); ok {
		t.Fatal("同日超限应拒绝")
	}
	// 伪造"昨天"的窗口标识 → 今日视为新窗口
	s.quotaWindowKey["t-b|"+quotaWindowDay] = "1999-01-01"
	if ok, _ := s.reserveQuota("t-b", 100); !ok {
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
	s.quota["t-c"] = quotaSpec{Limits: []quotaLimit{{MaxTokens: 100}}} // Window 为空

	if ok, _ := s.reserveQuota("t-c", 80); !ok {
		t.Fatal("累计模式 80 应放行")
	}
	// 输出侧记录后累计达 100，再加即拒绝（与 P1 语义一致：使用累计口径而非窗口）
	s.mu.Lock()
	s.usage["t-c"].TokensOut += 20
	s.mu.Unlock()
	if ok, denied := s.reserveQuota("t-c", 1); ok {
		t.Fatal("累计 100 + 1 > 100 应拒绝")
	} else if denied != quotaWindowNone {
		t.Fatalf("累计维度拒绝应归因 window=\"\"，实际 %q", denied)
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
	// 扁平写法（S3b 兼容）必须等价于单维度 limits —— B 项改造后行为逐字段一致
	if got := s.quota["t-d"].Limits; len(got) != 1 || got[0].Window != quotaWindowDay || got[0].MaxTokens != 5000 {
		t.Fatalf("扁平写法应等价于单维度 limits: %+v", got)
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

// ---------- B 项：多维度 enforce（判据 1–6） ----------

// TestQuotaMultiDimEnforce 判据 1：limits=[minute, day] 两维度独立生效，拒绝按维度归因。
func TestQuotaMultiDimEnforce(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-m"] = quotaSpec{Limits: []quotaLimit{
		{Window: quotaWindowMinute, MaxTokens: 100},
		{Window: quotaWindowDay, MaxTokens: 150},
	}}
	if ok, _ := s.reserveQuota("t-m", 90); !ok {
		t.Fatal("首请求 90 应放行（两维度均在额内）")
	}
	// 分钟维度超限（90+20 > 100），日维度仍有余额 → 归因 minute
	if ok, denied := s.reserveQuota("t-m", 20); ok {
		t.Fatal("分钟维度超限应拒绝")
	} else if denied != quotaWindowMinute {
		t.Fatalf("应归因 minute，实际 %q", denied)
	}
	// 分钟窗口翻转（伪造旧标识）→ 分钟额度重置；此刻只超日维度（90+70 > 150）→ 归因 day
	s.quotaWindowKey["t-m|"+quotaWindowMinute] = "stale-key"
	if ok, denied := s.reserveQuota("t-m", 70); ok {
		t.Fatal("日维度超限应拒绝")
	} else if denied != quotaWindowDay {
		t.Fatalf("应归因 day，实际 %q", denied)
	}
}

// TestQuotaMultiDimWindowIsolation 判据 3：minute 窗口翻转只重置 minute 维度，day 维度计数不受影响。
func TestQuotaMultiDimWindowIsolation(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-i"] = quotaSpec{Limits: []quotaLimit{
		{Window: quotaWindowMinute, MaxTokens: 100},
		{Window: quotaWindowDay, MaxTokens: 200},
	}}
	if ok, _ := s.reserveQuota("t-i", 80); !ok {
		t.Fatal("首请求应放行")
	}
	// 分钟翻转
	s.quotaWindowKey["t-i|"+quotaWindowMinute] = "stale-key"
	if ok, _ := s.reserveQuota("t-i", 80); !ok {
		t.Fatal("分钟窗口重置后应放行")
	}
	s.mu.Lock()
	minuteUsed, dayUsed := s.quotaWindowUsage["t-i|"+quotaWindowMinute], s.quotaWindowUsage["t-i|"+quotaWindowDay]
	s.mu.Unlock()
	if minuteUsed != 80 {
		t.Fatalf("分钟维度翻转后应为 80，实际 %d", minuteUsed)
	}
	if dayUsed != 160 {
		t.Fatalf("日维度不应被分钟翻转重置（80+80=160），实际 %d", dayUsed)
	}
}

// TestQuotaMultiDimRollback 判据 6：失败回滚时**各维度**同步退回（不白占任一窗口额度）。
func TestQuotaMultiDimRollback(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-r"] = quotaSpec{Limits: []quotaLimit{
		{Window: quotaWindowMinute, MaxTokens: 100},
		{Window: quotaWindowDay, MaxTokens: 1000},
	}}
	if ok, _ := s.reserveQuota("t-r", 60); !ok {
		t.Fatal("应放行")
	}
	s.rollbackQuota("t-r", 60)
	s.mu.Lock()
	minuteUsed, dayUsed, tokensIn := s.quotaWindowUsage["t-r|"+quotaWindowMinute], s.quotaWindowUsage["t-r|"+quotaWindowDay], s.usage["t-r"].TokensIn
	s.mu.Unlock()
	if minuteUsed != 0 || dayUsed != 0 {
		t.Fatalf("回滚后两个维度都应归零，实际 minute=%d day=%d", minuteUsed, dayUsed)
	}
	if tokensIn != 0 {
		t.Fatalf("回滚后累计计量应归零，实际 %d", tokensIn)
	}
}

// TestQuotaMultiDimConcurrentNoOversell 判据 2：多维度下并发不超卖（4 并发各占 2 → 8 用满；再要 1 拒绝）。
func TestQuotaMultiDimConcurrentNoOversell(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-cc"] = quotaSpec{Limits: []quotaLimit{{Window: quotaWindowMinute, MaxTokens: 8}}}
	results := make(chan bool, 4)
	for i := 0; i < 4; i++ {
		go func() {
			ok, _ := s.reserveQuota("t-cc", 2)
			results <- ok
		}()
	}
	passed := 0
	for i := 0; i < 4; i++ {
		if <-results {
			passed++
		}
	}
	if passed != 4 {
		t.Fatalf("4 并发各 2 token 应全部放行，实际 %d", passed)
	}
	if ok, _ := s.reserveQuota("t-cc", 1); ok {
		t.Fatal("额度用满后应拒绝（并发不超卖）")
	}
}

// TestHandleQuota_multiDim HTTP 契约（判据 5）：limits 生效与视图回显；冲突/重复 window 400；
// limits:[] 清除 enforce 但保留 shadow。
func TestHandleQuota_multiDim(t *testing.T) {
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

	code, out := post(`{"tenant":"t-x","limits":[{"window":"minute","max_tokens":200},{"window":"day","max_tokens":5000}]}`)
	if code != http.StatusOK {
		t.Fatalf("多维下发应 200，实际 %d", code)
	}
	limits, _ := out["quota_limits"].([]any)
	if len(limits) != 2 {
		t.Fatalf("quota_limits 应回显 2 个维度，实际 %+v", out["quota_limits"])
	}
	if out["window"] != "minute" || out["quota"] != float64(200) {
		t.Fatalf("兼容字段应取主维度（首维度 minute/200），实际 %+v", out)
	}
	if s.quotaWindowOf("t-x") != quotaWindowMinute {
		t.Fatalf("多维配置未写入运行态: %q", s.quotaWindowOf("t-x"))
	}
	// 冲突：limits 与扁平同现 → 400
	if code, _ := post(`{"tenant":"t-x","max_tokens":10,"limits":[{"max_tokens":20}]}`); code != http.StatusBadRequest {
		t.Fatalf("limits 与扁平同现应 400，实际 %d", code)
	}
	// 重复 window → 400
	if code, _ := post(`{"tenant":"t-x","limits":[{"window":"day","max_tokens":1},{"window":"day","max_tokens":2}]}`); code != http.StatusBadRequest {
		t.Fatalf("重复 window 应 400，实际 %d", code)
	}
	// 非法 window → 400
	if code, _ := post(`{"tenant":"t-x","limits":[{"window":"hour","max_tokens":1}]}`); code != http.StatusBadRequest {
		t.Fatalf("非法 window 应 400，实际 %d", code)
	}
	// limits:[] → 清除 enforce；shadow 保留（完整状态语义）
	if code, out := post(`{"tenant":"t-x","limits":[],"shadow":{"rpm":5}}`); code != http.StatusOK {
		t.Fatalf("limits:[] 应 200，实际 %d", code)
	} else if n, _ := out["quota_limits"].([]any); len(n) != 0 {
		t.Fatalf("limits:[] 后不应残留 enforce，实际 %+v", out["quota_limits"])
	}
	s.mu.Lock()
	_, stillThere := s.quota["t-x"]
	shadowKept := stillThere && s.quota["t-x"].Shadow.RPM == 5
	s.mu.Unlock()
	if !shadowKept {
		t.Fatal("limits:[] 应清除 enforce 并保留 shadow（完整状态语义）")
	}
}

// TestQuotaDeniesMetric 判据 1 的指标侧断言：拒绝按维度归因，累计维度归一为 total。
func TestQuotaDeniesMetric(t *testing.T) {
	m := newMetrics()
	m.incQuotaDeny("t-m", quotaWindowMinute)
	m.incQuotaDeny("t-m", quotaWindowNone)
	var buf bytes.Buffer
	m.render(&buf, 0)
	out := buf.String()
	if !strings.Contains(out, `otpmask_quota_denies_total{tenant="t-m",window="minute"} 1`) {
		t.Fatalf("缺 minute 维度归因: %s", out)
	}
	if !strings.Contains(out, `otpmask_quota_denies_total{tenant="t-m",window="total"} 1`) {
		t.Fatalf("累计维度应归一为 total: %s", out)
	}
}
