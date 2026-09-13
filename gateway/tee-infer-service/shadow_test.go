// shadow_test.go — S5（判据 4）影子模式测试：只计数不拒绝 + would_reject 落审计 + 窗口翻转 + 契约校验。
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// setShadowQuota 下发带影子的配额（maxTokens<=0 表示不设 enforce 配额，仅影子）。
func setShadowQuota(t *testing.T, ts *httptest.Server, tenant string, maxTokens int64, shadow map[string]int64) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"tenant": tenant, "max_tokens": maxTokens, "shadow": shadow})
	req, _ := http.NewRequest("POST", ts.URL+"/usage/quota", bytes.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("下发影子失败: %d", resp.StatusCode)
	}
}

// TestShadowWouldRejectAudited 影子命中：请求正常放行（不拒绝）+ 审计落 would_reject + 指标计数。
func TestShadowWouldRejectAudited(t *testing.T) {
	srv, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)

	// 影子 tpm=1（"hello" 估算 in=2 → 首个请求即命中）；不设 enforce 配额
	setShadowQuota(t, ts, "default", 0, map[string]int64{"tpm": 1})

	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 1); code != http.StatusOK {
		t.Fatalf("影子模式不得拒绝请求，got %d", code)
	}
	shadowEvents := filterAudit(srv, "shadow", "would_reject")
	if len(shadowEvents) != 1 {
		t.Fatalf("应落 1 条 shadow/would_reject 审计: %+v", srv.audit.query(""))
	}
	if shadowEvents[0].ShadowRule != "tpm" || shadowEvents[0].TenantID != "default" || shadowEvents[0].TokensIn == 0 {
		t.Fatalf("影子事件内容不符: %+v", shadowEvents[0])
	}
	if got := srv.metrics.shadowWouldReject["default|tpm"]; got != 1 {
		t.Fatalf("指标应记 tpm 命中 1 次，实际 %d", got)
	}

	// 全量计数：窗口内再发一次仍命中（不采样、不抑制）
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 2); code != http.StatusOK {
		t.Fatalf("第二次也应放行，got %d", code)
	}
	if got := srv.metrics.shadowWouldReject["default|tpm"]; got != 2 {
		t.Fatalf("影子应全量计数（2 次），实际 %d", got)
	}

	// 用量视图暴露影子配置与窗口内计数（控制台可见）
	resp, err := http.Get(ts.URL + "/usage?tenant=default")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]struct {
		Shadow *shadowView `json:"shadow"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	sv := out["default"].Shadow
	if sv == nil || sv.TPM != 1 || sv.TPMUsed == 0 {
		t.Fatalf("usage 视图应含影子配置与计数: %+v", sv)
	}
}

// TestShadowClearedWhenDisabled 清空影子（shadow 缺省 + max_tokens<=0）→ 不再命中、不再落审计。
func TestShadowClearedWhenDisabled(t *testing.T) {
	srv, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)
	setShadowQuota(t, ts, "default", 0, map[string]int64{"tpm": 1})
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 1); code != http.StatusOK {
		t.Fatalf("放行失败: %d", code)
	}
	// 清除：max_tokens<=0 且不含 shadow → 该租户配额与影子一并移除
	body, _ := json.Marshal(map[string]any{"tenant": "default", "max_tokens": 0})
	req, _ := http.NewRequest("POST", ts.URL+"/usage/quota", bytes.NewReader(body))
	presp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = presp.Body.Close()
	if _, ok := srv.quota["default"]; ok {
		t.Fatalf("清除后不应保留配额/影子: %+v", srv.quota["default"])
	}
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 2); code != http.StatusOK {
		t.Fatalf("放行失败: %d", code)
	}
	if got := len(filterAudit(srv, "shadow", "would_reject")); got != 1 {
		t.Fatalf("清除后不应新增影子事件（应仍为 1），实际 %d", got)
	}
}

// TestShadowWindowRotation 窗口翻转即重置该维度计数（不跨窗口累计）。
func TestShadowWindowRotation(t *testing.T) {
	s := newQuotaTestServer()
	s.quota["t-a"] = quotaSpec{Shadow: shadowSpec{RPM: 2}}
	// 伪造"上个窗口"的计数与窗口标识
	s.shadowWindowUsage["t-a|rpm"] = 5
	s.shadowWindowKey["t-a|rpm"] = "previous-window"

	// 翻转后重新计数：1 <= 2 → 不命中
	if hits := s.shadowObserve("t-a", "req-1", 1, "", "mock", "sha"); hits != nil {
		t.Fatalf("窗口翻转后不应命中: %v", hits)
	}
	if got := s.shadowWindowUsage["t-a|rpm"]; got != 1 {
		t.Fatalf("窗口翻转应重置计数为 1，实际 %d", got)
	}
	// 再两次 → 第 3 次超 2 命中
	_ = s.shadowObserve("t-a", "req-2", 1, "", "mock", "sha")
	if hits := s.shadowObserve("t-a", "req-3", 1, "", "mock", "sha"); len(hits) != 1 || hits[0] != "rpm" {
		t.Fatalf("第 3 次应命中 rpm: %v", hits)
	}
}

// TestQuotaShadowContract 影子契约：负值 400；未配置影子不落事件；日预算维度可独立配置。
func TestQuotaShadowContract(t *testing.T) {
	srv, ts := newM9Server(t)
	sessionID, ksig, kenc := setupTestSession(t, ts)

	// 负值 → 400
	body, _ := json.Marshal(map[string]any{"tenant": "acme", "max_tokens": 0, "shadow": map[string]int64{"rpm": -1}})
	resp, err := http.Post(ts.URL+"/usage/quota", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("负值影子应 400，实际 %d", resp.StatusCode)
	}

	// 未配置影子 → 无事件
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 1); code != http.StatusOK {
		t.Fatalf("放行失败: %d", code)
	}
	if got := len(filterAudit(srv, "shadow", "would_reject")); got != 0 {
		t.Fatalf("未配置影子不应落事件，实际 %d", got)
	}

	// 日预算维度：阈值 1 → 首请求 in=2 命中 daily_budget
	setShadowQuota(t, ts, "default", 0, map[string]int64{"daily_budget_tokens": 1})
	if code := quotaInfer(t, ts, sessionID, ksig, kenc, "hello", 2); code != http.StatusOK {
		t.Fatalf("放行失败: %d", code)
	}
	evs := filterAudit(srv, "shadow", "would_reject")
	if len(evs) != 1 || evs[0].ShadowRule != "daily_budget" {
		t.Fatalf("应命中 daily_budget 维度: %+v", evs)
	}
}

// filterAudit 过滤指定 action/result 的审计事件。
func filterAudit(s *teeServer, action, result string) []AuditEvent {
	var out []AuditEvent
	for _, e := range s.audit.query("") {
		if e.Action == action && e.Result == result {
			out = append(out, e)
		}
	}
	return out
}
