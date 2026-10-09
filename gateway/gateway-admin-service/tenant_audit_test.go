package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockTeeAudit 返回固定审计事件数组的假 tee-infer（记录收到的 tenant 参数）。
func mockTeeAudit(t *testing.T, gotTenant *string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/audit" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if gotTenant != nil {
			*gotTenant = r.URL.Query().Get("tenant")
		}
		w.Header().Set("Content-Type", "application/json")
		// 含 payload_hash（敏感）与他租户事件（应被剔除）
		_, _ = w.Write([]byte(`[
		  {"timestamp":1791500200000000000,"tenant_id":"t_1","request_id":"req-1","action":"infer","result":"ok",
		   "model":"gpt-4o-mini","tokens_in":312,"tokens_out":180,"cache_hit":false,"is_retry":false,
		   "payload_hash":"SECRET_HASH_SHOULD_NOT_LEAK"},
		  {"timestamp":1791500200000000000,"tenant_id":"t_other","request_id":"req-2","action":"infer","result":"ok"}
		]`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newAuditHandler(t *testing.T, gotTenant *string) *tenantHandler {
	t.Helper()
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	srv := mockTeeAudit(t, gotTenant)
	h.usage = &usageHandler{settings: &usageSettings{url: srv.URL, token: "tok"}, client: srv.Client()}
	return h
}

func TestTenantAudit_ForcesTenantAndWhitelists(t *testing.T) {
	var gotTenant string
	h := newAuditHandler(t, &gotTenant)

	w := httptest.NewRecorder()
	h.handleTenantAudit(w, tenantRequest("GET", tenantAuditPath+"?from=2026-10-01&to=2026-10-09", "", "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	if gotTenant != "t_1" {
		t.Errorf("应强制本租户 tenant=t_1（即使客户端未传）, got=%q", gotTenant)
	}
	body := w.Body.String()
	if strings.Contains(body, "payload_hash") || strings.Contains(body, "SECRET_HASH") {
		t.Error("响应不得包含 payload_hash/原文关联字段（C-3）")
	}

	var resp tenantAuditResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 1 || len(resp.Items) != 1 {
		t.Fatalf("应仅返回本租户 1 条, got total=%d items=%d", resp.Total, len(resp.Items))
	}
	it := resp.Items[0]
	if it.Result != "success" || it.Action != "infer" || it.TokensIn != 312 || it.RequestID != "req-1" {
		t.Errorf("摘要映射不对: %+v", it)
	}
	if !strings.Contains(body, `"timestamp":1791500200`) {
		t.Errorf("timestamp 应为秒: %s", body)
	}
}

func TestTenantAudit_ActionFilter(t *testing.T) {
	h := newAuditHandler(t, nil)
	// action=deny 不匹配 infer 事件 → 空
	w := httptest.NewRecorder()
	h.handleTenantAudit(w, tenantRequest("GET", tenantAuditPath+"?from=2026-10-01&to=2026-10-09&action=deny", "", "t_1", "u1"))
	var resp tenantAuditResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Total != 0 {
		t.Errorf("action=deny 应无匹配, got=%d", resp.Total)
	}
	// action=infer → 1 条
	w2 := httptest.NewRecorder()
	h.handleTenantAudit(w2, tenantRequest("GET", tenantAuditPath+"?from=2026-10-01&to=2026-10-09&action=infer", "", "t_1", "u1"))
	var resp2 tenantAuditResponse
	json.NewDecoder(w2.Body).Decode(&resp2)
	if resp2.Total != 1 {
		t.Errorf("action=infer 应有 1 条, got=%d", resp2.Total)
	}
}

func TestTenantAudit_BadAction_400(t *testing.T) {
	h := newAuditHandler(t, nil)
	w := httptest.NewRecorder()
	h.handleTenantAudit(w, tenantRequest("GET", tenantAuditPath+"?action=not_a_real_action", "", "t_1", "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("未知 action 应 400, got=%d", w.Code)
	}
}

func TestTenantAudit_BadResult_400(t *testing.T) {
	h := newAuditHandler(t, nil)
	w := httptest.NewRecorder()
	h.handleTenantAudit(w, tenantRequest("GET", tenantAuditPath+"?result=bogus", "", "t_1", "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法 result 应 400, got=%d", w.Code)
	}
}

func TestTenantAudit_WindowExceed_400(t *testing.T) {
	h := newAuditHandler(t, nil)
	w := httptest.NewRecorder()
	h.handleTenantAudit(w, tenantRequest("GET", tenantAuditPath+"?from=2026-01-01&to=2026-06-01", "", "t_1", "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("超 92 天窗口应 400, got=%d", w.Code)
	}
}

func TestTenantAudit_DataSourceUnavailable_503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.usage = &usageHandler{settings: &usageSettings{url: ""}, client: http.DefaultClient}
	w := httptest.NewRecorder()
	h.handleTenantAudit(w, tenantRequest("GET", tenantAuditPath, "", "t_1", "u1"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("数据源未配置应 503, got=%d", w.Code)
	}
}

func TestTenantAudit_NoTenantScope_403(t *testing.T) {
	h := newAuditHandler(t, nil)
	w := httptest.NewRecorder()
	h.handleTenantAudit(w, httptest.NewRequest("GET", tenantAuditPath, nil)) // 无租户上下文
	if w.Code != http.StatusForbidden {
		t.Errorf("无租户上下文应 403, got=%d", w.Code)
	}
}

func TestTenantAudit_Pagination(t *testing.T) {
	h := newAuditHandler(t, nil)
	// limit=0 → 夹到最小 1；offset 超范围 → 空
	w := httptest.NewRecorder()
	h.handleTenantAudit(w, tenantRequest("GET", tenantAuditPath+"?from=2026-10-01&to=2026-10-09&offset=99", "", "t_1", "u1"))
	var resp tenantAuditResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Offset != 1 || len(resp.Items) != 0 {
		t.Errorf("offset 超范围应为空: %+v", resp)
	}
}

func TestParseAuditWindow(t *testing.T) {
	// 缺省 → 近 30 天
	from, to, ok := parseAuditWindow("", "")
	if !ok || to-from > int64(tenantAuditDefaultDays+1)*86400 {
		t.Errorf("缺省窗口应约 30 天: from=%d to=%d ok=%v", from, to, ok)
	}
	if _, _, ok := parseAuditWindow("2026-10-01", "2026-10-09"); !ok {
		t.Error("合规窗口应通过")
	}
	if _, _, ok := parseAuditWindow("2026-10-09", "2026-10-01"); ok {
		t.Error("倒序应拒绝")
	}
	if _, _, ok := parseAuditWindow("bad", "2026-10-09"); ok {
		t.Error("非法格式应拒绝")
	}
	if _, _, ok := parseAuditWindow("2026-01-01", "2026-06-01"); ok {
		t.Error("超 92 天应拒绝")
	}
}

func TestMapAuditResult(t *testing.T) {
	cases := map[string]string{
		"ok": "success", "success": "success",
		"deny": "denied", "denied": "denied",
		"": "error", "boom": "error",
	}
	for in, want := range cases {
		if got := mapAuditResult(in); got != want {
			t.Errorf("mapAuditResult(%q)=%q want=%q", in, got, want)
		}
	}
}
