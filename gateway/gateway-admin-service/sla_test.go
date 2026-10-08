// P1-2：SLA/SLO 端点单测（§7.8/§7.9）——Prometheus 聚合、503、租户隔离、SLO 读写与审计。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// newFakeProm 构造假 Prometheus：记录 query 参数，统一返回固定标量。
func newFakeProm(t *testing.T, val string) (*httptest.Server, *[]string) {
	t.Helper()
	var queries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries = append(queries, r.URL.Query().Get("query"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"` + val + `"]}]}}`))
	}))
	return srv, &queries
}

// TestSLA_503WhenPromUnset 验证 Prometheus 未配置 → 503。
func TestSLA_503WhenPromUnset(t *testing.T) {
	h := newSLAHandler("")
	req := httptest.NewRequest(http.MethodGet, slaSummaryPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLASummary(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("Prometheus 未配置应 503，实际 %d", rr.Code)
	}
}

// TestSLA_SummaryAndTenantSelector 验证聚合结果与租户选择器注入。
func TestSLA_SummaryAndTenantSelector(t *testing.T) {
	prom, queries := newFakeProm(t, "0.999")
	defer prom.Close()
	h := newSLAHandler(prom.URL)

	req := httptest.NewRequest(http.MethodGet, slaSummaryPath+"?window=5m", nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor, Tenant: "t-001"}))
	rr := httptest.NewRecorder()
	h.handleSLASummary(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d：%s", rr.Code, rr.Body.String())
	}
	var v slaSummaryView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if v.Tenant != "t-001" || v.Window != "5m" {
		t.Fatalf("作用域字段异常：%+v", v)
	}
	if v.Availability != 0.999 {
		t.Errorf("availability 应为 0.999，实际 %v", v.Availability)
	}
	if len(*queries) == 0 {
		t.Fatal("应产生 Prometheus 查询")
	}
	for _, q := range *queries {
		if !strings.Contains(q, `tenant="t-001"`) {
			t.Errorf("查询应含租户选择器，实际：%s", q)
		}
	}
}

// TestSLA_TenantIsolation 验证非 admin 跨租户 → 403。
func TestSLA_TenantIsolation(t *testing.T) {
	h := newSLAHandler("http://prom.invalid")
	req := httptest.NewRequest(http.MethodGet, slaSummaryPath+"?tenant=other", nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor, Tenant: "t-001"}))
	rr := httptest.NewRecorder()
	h.handleSLASummary(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("跨租户应 403，实际 %d", rr.Code)
	}
}

// TestSLO_PostRequiresChain 验证审计链未启用时 POST → 503（fail-closed）。
func TestSLO_PostRequiresChain(t *testing.T) {
	h := newSLOHandler("", "", nil)
	req := httptest.NewRequest(http.MethodPost, sloPath, strings.NewReader(`{"name":"infer-availability","sli":{"type":"availability","metric":"otpmask_inference_requests_total"},"target":0.999,"window":"30d","alerting":{"fast_burn_rate":14.4,"slow_burn_rate":6,"enabled":true},"enabled":true}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("无审计链应 503，实际 %d", rr.Code)
	}
}

// TestSLO_PostAndGet 验证 SLO 读写往返（§7.9 冻结 schema + 落文件 + 审计链）。
func TestSLO_PostAndGet(t *testing.T) {
	dir := t.TempDir()
	chain, err := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	if err != nil {
		t.Fatalf("构造审计链失败：%v", err)
	}
	defer chain.Close()
	h := newSLOHandler(filepath.Join(dir, "slo.json"), "", chain)

	body := `{"name":"infer-availability","description":"推理服务可用性","sli":{"type":"availability","metric":"otpmask_inference_requests_total","filter":"route=\"/v1/infer\""},"target":0.999,"window":"30d","alerting":{"fast_burn_rate":14.4,"slow_burn_rate":6,"enabled":true},"tenant_id":"t-001","enabled":true}`
	req := httptest.NewRequest(http.MethodPost, sloPath, strings.NewReader(body))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("POST 期望 200，实际 %d：%s", rr.Code, rr.Body.String())
	}
	if chain.len() != 1 {
		t.Fatalf("应落 1 条审计，实际 %d", chain.len())
	}

	req2 := httptest.NewRequest(http.MethodGet, sloPath, nil)
	req2 = req2.WithContext(withClaims(req2.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr2 := httptest.NewRecorder()
	h.handleSLO(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("GET 期望 200，实际 %d", rr2.Code)
	}
	var out struct {
		SLOS []sloDef `json:"slos"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if len(out.SLOS) != 1 || out.SLOS[0].Name != "infer-availability" ||
		out.SLOS[0].Target != 0.999 || out.SLOS[0].SLI.Type != "availability" {
		t.Fatalf("读回异常：%+v", out.SLOS)
	}
}

// TestSLO_LatencyP99Accepted 验证 latency_p99 类型可配置（§7.9）。
func TestSLO_LatencyP99Accepted(t *testing.T) {
	dir := t.TempDir()
	chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	defer chain.Close()
	h := newSLOHandler("", "", chain)
	body := `{"name":"infer-latency","sli":{"type":"latency_p99","metric":"otpmask_ttft_seconds"},"target":0.99,"window":"7d","alerting":{"fast_burn_rate":14.4,"slow_burn_rate":6,"enabled":true},"enabled":true}`
	req := httptest.NewRequest(http.MethodPost, sloPath, strings.NewReader(body))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("latency_p99 应接受，实际 %d：%s", rr.Code, rr.Body.String())
	}
}

// TestSLO_PostInvalid 验证非法定义 → 400（§7.9 schema）。
func TestSLO_PostInvalid(t *testing.T) {
	dir := t.TempDir()
	chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	defer chain.Close()
	h := newSLOHandler("", "", chain)
	for _, body := range []string{
		`{"name":"","sli":{"type":"availability"},"target":0.99,"window":"30d"}`, // name 空
		`{"name":"n","sli":{"type":"bogus"},"target":0.99,"window":"30d"}`,       // sli.type 非法
		`{"name":"n","sli":{},"target":0.99,"window":"30d"}`,                     // sli.type 缺省
		`{"name":"n","sli":{"type":"availability"},"target":1.5,"window":"30d"}`, // target 越界
		`{"name":"n","sli":{"type":"availability"},"target":0.99,"window":""}`,   // window 空
	} {
		req := httptest.NewRequest(http.MethodPost, sloPath, strings.NewReader(body))
		req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
		rr := httptest.NewRecorder()
		h.handleSLO(rr, req)
		if rr.Code != http.StatusBadRequest {
			t.Errorf("非法定义 %s 应 400，实际 %d", body, rr.Code)
		}
	}
}

// TestTracingTenant_Toggle 验证 tracing 灰度开关增删。
func TestTracingTenant_Toggle(t *testing.T) {
	dir := t.TempDir()
	chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	defer chain.Close()
	h := newSLOHandler(filepath.Join(dir, "slo.json"), "", chain)

	post := func(body string) int {
		req := httptest.NewRequest(http.MethodPost, tracingTenantPath, strings.NewReader(body))
		req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
		rr := httptest.NewRecorder()
		h.handleTracingTenant(rr, req)
		return rr.Code
	}
	if code := post(`{"tenant":"t-001","enabled":true}`); code != http.StatusOK {
		t.Fatalf("启用应 200，实际 %d", code)
	}
	h.mu.Lock()
	list := append([]string(nil), h.state.TracingTenants...)
	h.mu.Unlock()
	if len(list) != 1 || list[0] != "t-001" {
		t.Fatalf("启用后 allow-list 异常：%+v", list)
	}
	if code := post(`{"tenant":"t-001","enabled":false}`); code != http.StatusOK {
		t.Fatalf("停用应 200，实际 %d", code)
	}
	h.mu.Lock()
	list = append([]string(nil), h.state.TracingTenants...)
	h.mu.Unlock()
	if len(list) != 0 {
		t.Fatalf("停用后 allow-list 应为空：%+v", list)
	}
	if code := post(`{"tenant":"","enabled":true}`); code != http.StatusBadRequest {
		t.Fatalf("空 tenant 应 400，实际 %d", code)
	}
}
