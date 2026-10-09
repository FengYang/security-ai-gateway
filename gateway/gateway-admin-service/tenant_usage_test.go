package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
)

// newTenantBillingTestHandler 构造仅含 store 的 billingHandler（供账单查询/导出复用）。
func newTenantBillingTestHandler(t *testing.T) (*billingHandler, billing.Store) {
	t.Helper()
	st, err := billing.OpenSQLiteStore(":memory:", false)
	if err != nil {
		t.Fatalf("打开 billing store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &billingHandler{store: st}, st
}

// ---------- 用量 ----------

func TestTenantUsage_ForcesTenant(t *testing.T) {
	var gotTenant string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/usage" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		gotTenant = r.URL.Query().Get("tenant")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"series":[]}`))
	}))
	defer srv.Close()

	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.usage = &usageHandler{settings: &usageSettings{url: srv.URL, token: "tok"}, client: srv.Client()}

	// 客户端传入他租户 tenant → 必须被丢弃，改用令牌 tenant
	req := tenantRequest("GET", tenantUsagePath+"?tenant=t_evil&from=2026-10-01&to=2026-10-05", "", "t_1", "u1")
	w := httptest.NewRecorder()
	h.handleTenantUsage(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	if gotTenant != "t_1" {
		t.Errorf("应强制本租户 tenant=t_1, got=%q", gotTenant)
	}
}

func TestTenantUsage_WindowExceed_Returns400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.usage = &usageHandler{settings: &usageSettings{url: "http://unused"}, client: http.DefaultClient}
	req := tenantRequest("GET", tenantUsagePath+"?from=2026-01-01&to=2026-06-01", "", "t_1", "u1")
	w := httptest.NewRecorder()
	h.handleTenantUsage(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("超窗口应 400, got=%d", w.Code)
	}
}

func TestTenantUsage_DataSourceUnavailable_Returns503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.usage = &usageHandler{settings: &usageSettings{url: ""}, client: http.DefaultClient}
	w := httptest.NewRecorder()
	h.handleTenantUsage(w, tenantRequest("GET", tenantUsagePath, "", "t_1", "u1"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("数据源未配置应 503, got=%d", w.Code)
	}
}

func TestTenantUsage_NoTenantScope_Returns403(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.usage = &usageHandler{settings: &usageSettings{url: "http://unused"}, client: http.DefaultClient}
	req := httptest.NewRequest("GET", tenantUsagePath, nil) // 无租户上下文
	w := httptest.NewRecorder()
	h.handleTenantUsage(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("无租户上下文应 403, got=%d", w.Code)
	}
}

// ---------- 账单 ----------

func TestTenantBills_BillingDisabled_Returns503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil) // h.billing == nil
	w := httptest.NewRecorder()
	h.handleTenantBills(w, tenantRequest("GET", tenantBillsPath, "", "t_1", "u1"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("billing 未启用应 503, got=%d", w.Code)
	}
}

func TestTenantBills_ListOnlyOwnTenant(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, st := newTenantBillingTestHandler(t)
	h.billing = bh
	if err := st.Bills().Put(&billing.Bill{ID: "b-1", TenantID: "t_1", Kind: "daily", Period: "2026-10-01"}); err != nil {
		t.Fatal(err)
	}
	if err := st.Bills().Put(&billing.Bill{ID: "b-2", TenantID: "t_2", Kind: "daily", Period: "2026-10-01"}); err != nil {
		t.Fatal(err)
	}

	// 即使客户端传入 tenant=t_2，也只返回本租户
	w := httptest.NewRecorder()
	h.handleTenantBills(w, tenantRequest("GET", tenantBillsPath+"?tenant=t_2", "", "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var resp struct {
		Bills []billing.Bill `json:"bills"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Bills) != 1 || resp.Bills[0].ID != "b-1" {
		t.Errorf("应仅返回本租户账单: %+v", resp.Bills)
	}
}

func TestTenantBillItem_CrossTenant_Returns404(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, st := newTenantBillingTestHandler(t)
	h.billing = bh
	if err := st.Bills().Put(&billing.Bill{ID: "b-9", TenantID: "t_other"}); err != nil {
		t.Fatal(err)
	}
	req := tenantRequest("GET", tenantBillsPath+"/b-9", "", "t_1", "u1")
	req.SetPathValue("id", "b-9")
	w := httptest.NewRecorder()
	h.handleTenantBillItem(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("跨租户应 404（不泄露存在性）, got=%d", w.Code)
	}
}

func TestTenantBillItem_NotFound_Returns404(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, _ := newTenantBillingTestHandler(t)
	h.billing = bh
	req := tenantRequest("GET", tenantBillsPath+"/nope", "", "t_1", "u1")
	req.SetPathValue("id", "nope")
	w := httptest.NewRecorder()
	h.handleTenantBillItem(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("不存在应 404, got=%d", w.Code)
	}
}

func TestTenantBillExport_CSVHeaders(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, st := newTenantBillingTestHandler(t)
	h.billing = bh
	if err := st.Bills().Put(&billing.Bill{ID: "b-x", TenantID: "t_1", Kind: "daily", Period: "2026-10-01"}); err != nil {
		t.Fatal(err)
	}
	req := tenantRequest("GET", tenantBillsPath+"/b-x/export", "", "t_1", "u1")
	req.SetPathValue("id", "b-x")
	w := httptest.NewRecorder()
	h.handleTenantBillExport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Header().Get("Content-Type"), "text/csv") {
		t.Errorf("Content-Type 应 text/csv, got=%q", w.Header().Get("Content-Type"))
	}
	if !strings.Contains(w.Header().Get("Content-Disposition"), "bill-b-x.csv") {
		t.Errorf("Content-Disposition 不对: %q", w.Header().Get("Content-Disposition"))
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("应设 X-Content-Type-Options: nosniff")
	}
}

// ---------- 工具 ----------

func TestParseUsageWindow(t *testing.T) {
	cases := []struct {
		from, to string
		ok       bool
	}{
		{"", "", true},
		{"2026-10-01", "", true},
		{"2026-10-01", "2026-10-05", true},
		{"2026-10-05", "2026-10-01", false}, // 倒序
		{"bad", "2026-10-01", false},        // 非法格式
		{"2026-01-01", "2026-06-01", false}, // 超 92 天
	}
	for _, tc := range cases {
		if _, _, ok := parseUsageWindow(tc.from, tc.to); ok != tc.ok {
			t.Errorf("parseUsageWindow(%q,%q)=%v want=%v", tc.from, tc.to, ok, tc.ok)
		}
	}
}

func TestClampTenantLimit(t *testing.T) {
	cases := map[string]int{"": 100, "10": 10, "9999": tenantQueryMaxLimit, "-1": 100, "abc": 100}
	for in, want := range cases {
		if got := clampTenantLimit(in, 100); got != want {
			t.Errorf("clampTenantLimit(%q)=%d want=%d", in, got, want)
		}
	}
}
