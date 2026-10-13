package main

// audit_t3b_test.go — P1-7 T3b（§7.3）：出口落链辅助与 MCP request_id 派生的单元测试。
//
// 覆盖：
//   - mcpRequestIDOf / validMCPRequestID：A4-05 唯一派生口径（信封优先 → 会话 ID → 空）；
//   - auditDenyExit（A 类）：显式状态码 + action=deny 落链；
//   - auditAdminExit（B 类）：action 与成功路径同名 + result=rejected_* + tenant="-"；
//   - recordExemptExit（C 类）：豁免计数入 otpmask_audit_exempt_exit_total。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMCPRequestIDOf_Derivation(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		sessID  string
		want    string
	}{
		{"顶层 request_id 优先", `{"jsonrpc":"2.0","request_id":"req-abc.1","method":"tools/call"}`, "sess-1", "req-abc.1"},
		{"params._meta.request_id 次选", `{"method":"tools/call","params":{"_meta":{"request_id":"m-9"}}}`, "sess-1", "m-9"},
		{"顶层优先于 _meta", `{"request_id":"top","params":{"_meta":{"request_id":"meta"}}}`, "sess-1", "top"},
		{"信封无则回退会话 ID", `{"method":"tools/call"}`, "sess-1", "sess-1"},
		{"非法 request_id 回退会话 ID", `{"request_id":"bad id!"}`, "sess-1", "sess-1"},
		{"空 payload 回退会话 ID", ``, "sess-1", "sess-1"},
		{"二者皆无为空串", ``, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := mcpRequestIDOf([]byte(c.payload), c.sessID); got != c.want {
				t.Fatalf("mcpRequestIDOf()=%q, want %q", got, c.want)
			}
		})
	}
}

func TestValidMCPRequestID(t *testing.T) {
	valid := []string{"a", "abc-1_2.3:4", strings.Repeat("x", 128)}
	for _, s := range valid {
		if !validMCPRequestID(s) {
			t.Fatalf("validMCPRequestID(%q) 应为 true", s)
		}
	}
	invalid := []string{"", "has space", "has/slash", "中文", strings.Repeat("x", 129)}
	for _, s := range invalid {
		if validMCPRequestID(s) {
			t.Fatalf("validMCPRequestID(%q) 应为 false", s)
		}
	}
}

func TestAuditDenyExit_WritesDenyEvent(t *testing.T) {
	s := &teeServer{audit: newAuditChain(), metrics: newMetrics()}
	r := httptest.NewRequest(http.MethodPost, "/v1/attest", nil)
	s.auditDenyExitReq(r, "t-1", "req-9", "attest_bad_json", "", http.StatusBadRequest)

	if len(s.audit.events) != 1 {
		t.Fatalf("期望落链 1 条，实际 %d", len(s.audit.events))
	}
	ev := s.audit.events[0]
	if ev.Action != "deny" || ev.Result != "attest_bad_json" {
		t.Fatalf("deny 事件字段不符: action=%q result=%q", ev.Action, ev.Result)
	}
	if ev.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("显式状态码未生效: http_status=%d", ev.HTTPStatus)
	}
	if ev.TenantID != "t-1" || ev.RequestID != "req-9" {
		t.Fatalf("租户/请求 ID 不符: %q/%q", ev.TenantID, ev.RequestID)
	}
}

func TestAuditAdminExit_WritesRejectedEvent(t *testing.T) {
	s := &teeServer{audit: newAuditChain()}
	r := httptest.NewRequest(http.MethodPost, "/config/outputguard", nil)
	r.Header.Set("X-Admin-Actor", "alice")
	r.Header.Set("X-Request-ID", "rid-1")
	s.auditAdminExit(r, "output_guard_mode_change", "rejected_bad_request", http.StatusBadRequest)

	if len(s.audit.events) != 1 {
		t.Fatalf("期望落链 1 条，实际 %d", len(s.audit.events))
	}
	ev := s.audit.events[0]
	if ev.Action != "output_guard_mode_change" || ev.Result != "rejected_bad_request" {
		t.Fatalf("admin 事件字段不符: action=%q result=%q", ev.Action, ev.Result)
	}
	if ev.TenantID != "-" {
		t.Fatalf("管理面 tenant 应为 \"-\"，实际 %q", ev.TenantID)
	}
	if ev.UserID != "alice" || ev.RequestID != "rid-1" {
		t.Fatalf("actor/request_id 未取请求头: %q/%q", ev.UserID, ev.RequestID)
	}
	if ev.HTTPStatus != http.StatusBadRequest {
		t.Fatalf("状态码不符: %d", ev.HTTPStatus)
	}
}

// auditAdminExit 在 nil 请求（如 handleUsageIncremental 无 *http.Request 形参）下安全落链。
func TestAuditAdminExit_NilRequest(t *testing.T) {
	s := &teeServer{audit: newAuditChain()}
	s.auditAdminExit(nil, "usage_read", "rejected_bad_request", http.StatusBadRequest)
	if len(s.audit.events) != 1 {
		t.Fatalf("nil 请求应仍落链 1 条，实际 %d", len(s.audit.events))
	}
}

func TestRecordExemptExit_CountsMetric(t *testing.T) {
	m := newMetrics()
	prev := auditMetrics
	auditMetrics = m
	defer func() { auditMetrics = prev }()

	recordExemptExit("handleAttest", "method_not_allowed")
	recordExemptExit("handleAttest", "method_not_allowed")
	recordExemptExit("handleHealthz", "health")

	if got := m.auditExemptExit["handleAttest|method_not_allowed"]; got != 2 {
		t.Fatalf("handleAttest|method_not_allowed 计数=%d, want 2", got)
	}
	if got := m.auditExemptExit["handleHealthz|health"]; got != 1 {
		t.Fatalf("handleHealthz|health 计数=%d, want 1", got)
	}
}

// 未装配指标时 recordExemptExit 为 no-op（不 panic）——保证既有测试不受影响。
func TestRecordExemptExit_NoMetrics(t *testing.T) {
	prev := auditMetrics
	auditMetrics = nil
	defer func() { auditMetrics = prev }()
	recordExemptExit("handleAttest", "method_not_allowed")
}

// countByActionResult 统计链上 (action, result) 组合的事件数（测试辅助；T3b 后
// 失败出口与成功路径共用同一 action，断言需按 result 区分）。
func countByActionResult(c *auditChain, action, result string) int {
	n := 0
	for _, ev := range c.events {
		if ev.Action == action && ev.Result == result {
			n++
		}
	}
	return n
}
