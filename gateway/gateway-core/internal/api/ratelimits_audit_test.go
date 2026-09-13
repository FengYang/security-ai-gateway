// ratelimits_audit_test.go — 策略变更审计与回滚端点测试（Phase 1 门禁 #7 / 判据 7）
// 与 gateway-core 指标测试（判据 9 控制面部分）。
package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
)

// doJSON 发起带鉴权（可选 X-Actor/X-Request-ID）的请求。
func doJSON(s *Server, method, path, body, token, actor, reqID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if actor != "" {
		req.Header.Set("X-Actor", actor)
	}
	if reqID != "" {
		req.Header.Set("X-Request-ID", reqID)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// historyResp /ratelimits/history 响应。
type historyResp struct {
	EffectiveVersion int                 `json:"effective_version"`
	ChainOK          bool                `json:"chain_ok"`
	EventsTotal      int                 `json:"events_total"`
	Events           []policyaudit.Event `json:"events"`
}

// TestRateLimitChangeAudited PUT 变更落链：谁/何时/哪条/旧→新 + 生效版本与链校验可查。
func TestRateLimitChangeAudited(t *testing.T) {
	s := testServer()
	rec := doJSON(s, http.MethodPut, "/ratelimits", validTableJSON, "tok", "ops-admin", "req-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT 期望 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}

	// 首条规则为 added（种子表无规则）
	h := doJSON(s, http.MethodGet, "/ratelimits/history", "", "tok", "", "")
	if h.Code != http.StatusOK {
		t.Fatalf("history 期望 200，实际 %d", h.Code)
	}
	var hr historyResp
	if err := json.Unmarshal(h.Body.Bytes(), &hr); err != nil {
		t.Fatalf("history 解析失败: %v body=%s", err, h.Body.String())
	}
	if !hr.ChainOK || hr.EffectiveVersion != 2 || hr.EventsTotal != 1 {
		t.Fatalf("history 契约不符: %+v", hr)
	}
	ev := hr.Events[0]
	if ev.Actor != "ops-admin" || ev.Action != policyaudit.ActionApply ||
		ev.RuleID != "t-a-rate" || ev.Change != "added" ||
		ev.VersionFrom != 1 || ev.VersionTo != 2 || ev.RequestID != "req-1" || ev.Timestamp == 0 {
		t.Fatalf("变更事件内容不符: %+v", ev)
	}

	// 第二次变更（rpm 600 → 1200）：落 updated 事件，含旧值→新值
	next := `{"version":3,"issued_at":"2026-09-13T11:00:00Z","rules":[
{"id":"t-a-rate","kind":"rate","scope":"tenant","target":"t-a","rpm":1200,"action":"reject","enabled":true}]}`
	if rec := doJSON(s, http.MethodPut, "/ratelimits", next, "tok", "ops-admin", "req-2"); rec.Code != http.StatusOK {
		t.Fatalf("第二次 PUT 期望 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	h = doJSON(s, http.MethodGet, "/ratelimits/history?limit=1", "", "tok", "", "")
	if err := json.Unmarshal(h.Body.Bytes(), &hr); err != nil {
		t.Fatal(err)
	}
	if len(hr.Events) != 1 || hr.EventsTotal != 2 {
		t.Fatalf("limit=1 应只返回最后一条且总数 2: %+v", hr)
	}
	last := hr.Events[0]
	if last.Change != "updated" || last.Field != "rpm" || last.OldValue != "600" || last.NewValue != "1200" ||
		last.VersionTo != 3 {
		t.Fatalf("updated 事件内容不符: %+v", last)
	}
}

// TestRateLimitRollback 按 version 回滚：以历史规则生成新版本 + 落链（action=rollback）。
func TestRateLimitRollback(t *testing.T) {
	s := testServer()
	if rec := doJSON(s, http.MethodPut, "/ratelimits", validTableJSON, "tok", "ops-admin", "req-1"); rec.Code != http.StatusOK {
		t.Fatalf("前置 PUT 失败: %d", rec.Code)
	}
	next := `{"version":3,"issued_at":"2026-09-13T11:00:00Z","rules":[
{"id":"t-a-rate","kind":"rate","scope":"tenant","target":"t-a","rpm":1200,"action":"reject","enabled":true}]}`
	if rec := doJSON(s, http.MethodPut, "/ratelimits", next, "tok", "ops-admin", "req-2"); rec.Code != http.StatusOK {
		t.Fatalf("前置第二次 PUT 失败: %d", rec.Code)
	}

	// 回滚到 v2（rpm=600）→ 新版本 v4，规则内容等于 v2
	rec := doJSON(s, http.MethodPost, "/ratelimits/rollback", `{"version":2}`, "tok", "ops-admin", "req-3")
	if rec.Code != http.StatusOK {
		t.Fatalf("rollback 期望 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Version int    `json:"version"`
		Action  string `json:"action"`
		Changes []struct {
			RuleID string `json:"rule_id"`
			Change string `json:"change"`
			Field  string `json:"field"`
			Old    string `json:"old"`
			New    string `json:"new"`
		} `json:"changes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if resp.Version != 4 || resp.Action != policyaudit.ActionRollback {
		t.Fatalf("回滚应生成新版本 v4 且 action=rollback: %+v", resp)
	}
	if len(resp.Changes) != 1 || resp.Changes[0].Field != "rpm" || resp.Changes[0].Old != "1200" || resp.Changes[0].New != "600" {
		t.Fatalf("回滚差异应记录 1200→600: %+v", resp.Changes)
	}
	// 生效表内容已回到 v2 的规则
	got := doJSON(s, http.MethodGet, "/ratelimits", "", "tok", "", "")
	var tbl struct {
		Version int `json:"version"`
		Rules   []struct {
			ID  string `json:"id"`
			RPM int64  `json:"rpm"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(got.Body.Bytes(), &tbl); err != nil {
		t.Fatal(err)
	}
	if tbl.Version != 4 || len(tbl.Rules) != 1 || tbl.Rules[0].RPM != 600 {
		t.Fatalf("回滚后生效表不符: %+v", tbl)
	}
	// 回滚事件已落链
	h := doJSON(s, http.MethodGet, "/ratelimits/history?limit=1", "", "tok", "", "")
	var hr historyResp
	if err := json.Unmarshal(h.Body.Bytes(), &hr); err != nil {
		t.Fatal(err)
	}
	if len(hr.Events) != 1 || hr.Events[0].Action != policyaudit.ActionRollback || hr.Events[0].VersionFrom != 3 || hr.Events[0].VersionTo != 4 {
		t.Fatalf("回滚事件落链不符: %+v", hr.Events)
	}
	if hr.EffectiveVersion != 4 || !hr.ChainOK {
		t.Fatalf("生效版本/链状态不符: %+v", hr)
	}

	// 历史中不存在的版本 → 400
	if rec := doJSON(s, http.MethodPost, "/ratelimits/rollback", `{"version":99}`, "tok", "a", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("未知版本应 400，实际 %d", rec.Code)
	}
	// 非法请求体 → 400
	if rec := doJSON(s, http.MethodPost, "/ratelimits/rollback", `{}`, "tok", "a", ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 version 应 400，实际 %d", rec.Code)
	}
}

// TestRateLimitMetrics 控制面指标（门禁 #9）：版本/规则维度/变更结果/审计链长度。
func TestRateLimitMetrics(t *testing.T) {
	s := testServer()
	// 未鉴权 → 401
	if rec := doJSON(s, http.MethodGet, "/metrics", "", "", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("metrics 未鉴权应 401，实际 %d", rec.Code)
	}
	if rec := doJSON(s, http.MethodPut, "/ratelimits", validTableJSON, "tok", "ops-admin", "req-1"); rec.Code != http.StatusOK {
		t.Fatalf("前置 PUT 失败: %d", rec.Code)
	}
	// 同版本重复下发 → 409（计入 rejected）
	if rec := doJSON(s, http.MethodPut, "/ratelimits", validTableJSON, "tok", "ops-admin", "req-1"); rec.Code != http.StatusConflict {
		t.Fatalf("同版本应 409，实际 %d", rec.Code)
	}

	rec := doJSON(s, http.MethodGet, "/metrics", "", "tok", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("metrics 期望 200，实际 %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"gateway_core_ratelimit_table_version 2",
		`gateway_core_ratelimit_rules_total{kind="rate",scope="tenant",action="reject"} 1`,
		`gateway_core_ratelimit_change_total{result="applied"} 1`,
		`gateway_core_ratelimit_change_total{result="rejected"} 1`,
		"gateway_core_policy_audit_events 1",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("指标缺少 %q\nbody=\n%s", want, body)
		}
	}
}
