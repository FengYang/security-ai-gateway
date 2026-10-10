// P1-2：SLA/SLO 端点单测（§7.8/§7.9）——Prometheus 聚合、503、租户隔离、SLO 读写与审计。
package main

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"os"
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

// TestTracingTenant_NotWired 验证未接线（非 in-cluster）时 POST → 503。
// 方案 B3：事实源为 Collector ConfigMap，未接线即无法应用 → fail-closed，绝不"假装成功"。
func TestTracingTenant_NotWired(t *testing.T) {
	dir := t.TempDir()
	chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	defer chain.Close()
	h := newSLOHandler(filepath.Join(dir, "slo.json"), "", chain)
	if h.applier != nil {
		t.Skip("测试环境意外具备 in-cluster 配置，跳过")
	}
	req := httptest.NewRequest(http.MethodPost, tracingTenantPath, strings.NewReader(`{"tenant":"t-001","enabled":true}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTracingTenant(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("未接线应 503，实际 %d", rr.Code)
	}
}

// ---- SLA 端点补充覆盖（§7.8 方法/权限/默认窗口/Prometheus 错误分位）----

// newFakePromFailOn 对含 marker 的查询返回 500，其余返回成功标量（驱动分位数错误分支）。
func newFakePromFailOn(t *testing.T, marker string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Query().Get("query"), marker) {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"0.999"]}]}}`))
	}))
}

// newPromRaw 返回固定状态码与响应体（驱动 promQueryScalar 各错误分支）。
func newPromRaw(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// TestSLA_MethodNotAllowed 验证非 GET → 405。
func TestSLA_MethodNotAllowed(t *testing.T) {
	h := newSLAHandler("http://prom.invalid")
	req := httptest.NewRequest(http.MethodPost, slaSummaryPath, nil)
	rr := httptest.NewRecorder()
	h.handleSLASummary(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET 应 405，实际 %d", rr.Code)
	}
}

// TestSLA_ForbiddenRole 验证角色越权 → 403（epTraceFamilyRead 白名单外）。
func TestSLA_ForbiddenRole(t *testing.T) {
	h := newSLAHandler("http://prom.invalid")
	req := httptest.NewRequest(http.MethodGet, slaSummaryPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "x", Role: roleBillingReader}))
	rr := httptest.NewRecorder()
	h.handleSLASummary(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("越权应 403，实际 %d", rr.Code)
	}
}

// TestSLA_DefaultWindowAdminSelector 验证缺省窗口为 5m、admin（无租户）选择器为空。
func TestSLA_DefaultWindowAdminSelector(t *testing.T) {
	prom, queries := newFakeProm(t, "0.999")
	defer prom.Close()
	h := newSLAHandler(prom.URL)

	req := httptest.NewRequest(http.MethodGet, slaSummaryPath, nil) // 无 window 参数
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLASummary(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rr.Code)
	}
	var v slaSummaryView
	if err := json.Unmarshal(rr.Body.Bytes(), &v); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if v.Window != slaDefaultWindow {
		t.Errorf("缺省窗口应为 %q，实际 %q", slaDefaultWindow, v.Window)
	}
	if v.Tenant != "" {
		t.Errorf("admin 无租户时 tenant 应为空，实际 %q", v.Tenant)
	}
	for _, q := range *queries {
		if strings.Contains(q, "tenant=") {
			t.Errorf("全租户查询不应含租户选择器：%s", q)
		}
	}
	// 直接验证空租户选择器
	if got := promTenantSelector(""); got != "" {
		t.Errorf("空租户选择器应为空串，实际 %q", got)
	}
}

// TestSLA_AvailabilityQueryError 验证可用性查询失败 → 503（不静默返回空）。
func TestSLA_AvailabilityQueryError(t *testing.T) {
	prom := newFakePromFailOn(t, "otpmask_inference_requests_total")
	defer prom.Close()
	h := newSLAHandler(prom.URL)
	req := httptest.NewRequest(http.MethodGet, slaSummaryPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLASummary(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("可用性查询失败应 503，实际 %d", rr.Code)
	}
}

// TestSLA_QuantileQueryError 验证 P50/P95/P99 任一分位查询失败 → 503。
func TestSLA_QuantileQueryError(t *testing.T) {
	for _, marker := range []string{"histogram_quantile(0.50", "histogram_quantile(0.95", "histogram_quantile(0.99"} {
		t.Run(marker, func(t *testing.T) {
			prom := newFakePromFailOn(t, marker)
			defer prom.Close()
			h := newSLAHandler(prom.URL)
			req := httptest.NewRequest(http.MethodGet, slaSummaryPath, nil)
			req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
			rr := httptest.NewRecorder()
			h.handleSLASummary(rr, req)
			if rr.Code != http.StatusServiceUnavailable {
				t.Fatalf("分位查询 %q 失败应 503，实际 %d", marker, rr.Code)
			}
		})
	}
}

// errReadCloser 读取即返回错误，用于覆盖 io.ReadAll 失败分支。
type errReadCloser struct{}

func (errReadCloser) Read([]byte) (int, error) { return 0, errors.New("read boom") }
func (errReadCloser) Close() error             { return nil }

// errBodyTransport 返回携带坏 body 的响应（覆盖读取失败分支）。
type errBodyTransport struct{ status int }

func (t errBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: t.status, Header: http.Header{}, Body: errReadCloser{}}, nil
}

// TestPromQueryScalar_ErrorBranches 直接驱动 promQueryScalar 的各错误/无数据分支。
func TestPromQueryScalar_ErrorBranches(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	t.Run("bad-url", func(t *testing.T) {
		if _, err := promQueryScalar(req, http.DefaultClient, "://bad", "up"); err == nil {
			t.Fatal("非法 URL 应报错")
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		if _, err := promQueryScalar(req, http.DefaultClient, "http://127.0.0.1:1", "up"); err == nil {
			t.Fatal("不可达应报错")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		srv := newPromRaw(t, http.StatusInternalServerError, "")
		defer srv.Close()
		if _, err := promQueryScalar(req, http.DefaultClient, srv.URL, "up"); err == nil {
			t.Fatal("非 200 应报错")
		}
	})
	t.Run("read-error", func(t *testing.T) {
		client := &http.Client{Transport: errBodyTransport{status: http.StatusOK}}
		if _, err := promQueryScalar(req, client, "http://prom.local", "up"); err == nil {
			t.Fatal("body 读取失败应报错")
		}
	})
	t.Run("unmarshal-error", func(t *testing.T) {
		srv := newPromRaw(t, http.StatusOK, "not-json")
		defer srv.Close()
		if _, err := promQueryScalar(req, http.DefaultClient, srv.URL, "up"); err == nil {
			t.Fatal("非法 JSON 应报错")
		}
	})
	t.Run("no-data-zero", func(t *testing.T) {
		srv := newPromRaw(t, http.StatusOK, `{"status":"success","data":{"result":[]}}`)
		defer srv.Close()
		v, err := promQueryScalar(req, http.DefaultClient, srv.URL, "up")
		if err != nil || v != 0 {
			t.Fatalf("无数据应返回 0，实际 v=%v err=%v", v, err)
		}
	})
	t.Run("bad-float-zero", func(t *testing.T) {
		srv, _ := newFakeProm(t, "abc")
		defer srv.Close()
		v, err := promQueryScalar(req, http.DefaultClient, srv.URL, "up")
		if err != nil || v != 0 {
			t.Fatalf("非数值应返回 0，实际 v=%v err=%v", v, err)
		}
	})
}

// ---- SLO / tracing 灰度端点补充覆盖（§7.9）----

// TestNewSLOHandler_CorruptFile 验证状态文件损坏时按空状态处理、不拒绝启动。
func TestNewSLOHandler_CorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "slo.json")
	if err := os.WriteFile(path, []byte("not-a-json"), 0o600); err != nil {
		t.Fatalf("写文件失败：%v", err)
	}
	h := newSLOHandler(path, "", nil)
	if len(h.state.SLOS) != 0 {
		t.Fatalf("损坏文件应按空状态处理，实际 %d 条", len(h.state.SLOS))
	}
}

// TestHandleSLO_MethodNotAllowed 验证非 GET/POST → 405。
func TestHandleSLO_MethodNotAllowed(t *testing.T) {
	h := newSLOHandler("", "", nil)
	req := httptest.NewRequest(http.MethodPut, sloPath, nil)
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET/POST 应 405，实际 %d", rr.Code)
	}
}

// TestGetSLO_ForbiddenRole 验证读端点越权 → 403。
func TestGetSLO_ForbiddenRole(t *testing.T) {
	h := newSLOHandler("", "", nil)
	req := httptest.NewRequest(http.MethodGet, sloPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "x", Role: roleBillingReader}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("越权应 403，实际 %d", rr.Code)
	}
}

// TestGetSLO_BudgetRemaining 验证错误预算余量计算与 [0,1] clamp（非 admin 按 claims 租户作用域）。
func TestGetSLO_BudgetRemaining(t *testing.T) {
	cases := []struct {
		name    string
		promVal string
		want    float64
	}{
		{"in-range", "0.9995", 0.5},
		{"clamp-zero", "0.5", 0},
		{"clamp-one", "1.5", 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prom, _ := newFakeProm(t, tc.promVal)
			defer prom.Close()
			dir := t.TempDir()
			chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
			defer chain.Close()
			h := newSLOHandler(filepath.Join(dir, "slo.json"), prom.URL, chain)
			h.state.SLOS = []sloDef{{Name: "infer-availability", Target: 0.999}}

			req := httptest.NewRequest(http.MethodGet, sloPath, nil)
			req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor, Tenant: "t-001"}))
			rr := httptest.NewRecorder()
			h.handleSLO(rr, req)
			if rr.Code != http.StatusOK {
				t.Fatalf("期望 200，实际 %d：%s", rr.Code, rr.Body.String())
			}
			var out struct {
				Budget map[string]any `json:"budget"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
				t.Fatalf("解析失败：%v", err)
			}
			if out.Budget == nil {
				t.Fatal("应返回 budget 段")
			}
			if b, _ := out.Budget["tenant"].(string); b != "t-001" {
				t.Errorf("budget.tenant 应为 t-001，实际 %q", b)
			}
			got, _ := out.Budget["remaining_fraction"].(float64)
			if math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("remaining_fraction 应为 %v，实际 %v", tc.want, got)
			}
		})
	}
}

// TestGetSLO_BudgetQueryError 验证错误预算查询失败 → 503。
func TestGetSLO_BudgetQueryError(t *testing.T) {
	prom := newFakePromFailOn(t, "") // marker 为空 → 全部查询失败
	defer prom.Close()
	dir := t.TempDir()
	chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	defer chain.Close()
	h := newSLOHandler(filepath.Join(dir, "slo.json"), prom.URL, chain)
	h.state.SLOS = []sloDef{{Name: "infer-availability", Target: 0.999}}

	req := httptest.NewRequest(http.MethodGet, sloPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("错误预算查询失败应 503，实际 %d", rr.Code)
	}
}

// TestGetSLO_TracingReadFailedFallback 验证已接线但读事实源失败时回退本地缓存并如实标注。
func TestGetSLO_TracingReadFailedFallback(t *testing.T) {
	srv := newFailingK8sServer(t)
	defer srv.Close()
	dir := t.TempDir()
	chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	defer chain.Close()
	h := newSLOHandler(filepath.Join(dir, "slo.json"), "", chain)
	h.applier = newTestApplier(srv, "otpmask")

	req := httptest.NewRequest(http.MethodGet, sloPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rr.Code)
	}
	var out struct {
		Source string `json:"tracing_source"`
		Wired  bool   `json:"tracing_wired"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if !out.Wired || out.Source != "local-cache(read-failed)" {
		t.Fatalf("应回退本地缓存并标注，实际 %+v", out)
	}
}

// TestPostSLO_ForbiddenRole 验证写端点越权 → 403。
func TestPostSLO_ForbiddenRole(t *testing.T) {
	h := newSLOHandler("", "", nil)
	req := httptest.NewRequest(http.MethodPost, sloPath, strings.NewReader(`{}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("越权应 403，实际 %d", rr.Code)
	}
}

// TestPostSLO_DecodeError 验证请求体非法 JSON → 400。
func TestPostSLO_DecodeError(t *testing.T) {
	dir := t.TempDir()
	chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	defer chain.Close()
	h := newSLOHandler("", "", chain)
	req := httptest.NewRequest(http.MethodPost, sloPath, strings.NewReader(`{bad json`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("非法请求体应 400，实际 %d", rr.Code)
	}
}

// TestPostSLO_UpdateExisting 验证同名 SLO 为更新（替换）而非追加。
func TestPostSLO_UpdateExisting(t *testing.T) {
	dir := t.TempDir()
	chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	defer chain.Close()
	h := newSLOHandler(filepath.Join(dir, "slo.json"), "", chain)

	post := func(body string) {
		req := httptest.NewRequest(http.MethodPost, sloPath, strings.NewReader(body))
		req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
		rr := httptest.NewRecorder()
		h.handleSLO(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("POST 期望 200，实际 %d：%s", rr.Code, rr.Body.String())
		}
	}
	post(`{"name":"infer-availability","sli":{"type":"availability"},"target":0.99,"window":"30d"}`)
	post(`{"name":"infer-availability","sli":{"type":"availability"},"target":0.95,"window":"30d"}`)

	h.mu.Lock()
	n := len(h.state.SLOS)
	target := 0.0
	if n > 0 {
		target = h.state.SLOS[0].Target
	}
	h.mu.Unlock()
	if n != 1 || target != 0.95 {
		t.Fatalf("同名应替换：n=%d target=%v", n, target)
	}
}

// TestPostSLO_PersistError 验证持久化失败 → 500（fail-closed）。
func TestPostSLO_PersistError(t *testing.T) {
	dir := t.TempDir()
	chain, _ := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	defer chain.Close()
	// 目标目录不存在 → WriteFile 失败
	h := newSLOHandler(filepath.Join(dir, "nodir", "slo.json"), "", chain)
	req := httptest.NewRequest(http.MethodPost, sloPath, strings.NewReader(`{"name":"n","sli":{"type":"availability"},"target":0.99,"window":"30d"}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("持久化失败应 500，实际 %d", rr.Code)
	}
}

// TestHandleTracingTenant_MethodNotAllowed 验证非 POST → 405。
func TestHandleTracingTenant_MethodNotAllowed(t *testing.T) {
	h := newSLOHandler("", "", nil)
	req := httptest.NewRequest(http.MethodGet, tracingTenantPath, nil)
	rr := httptest.NewRecorder()
	h.handleTracingTenant(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 POST 应 405，实际 %d", rr.Code)
	}
}

// TestHandleTracingTenant_ForbiddenRole 验证写端点越权 → 403。
func TestHandleTracingTenant_ForbiddenRole(t *testing.T) {
	h := newSLOHandler("", "", nil)
	req := httptest.NewRequest(http.MethodPost, tracingTenantPath, strings.NewReader(`{"tenant":"t-001"}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor}))
	rr := httptest.NewRecorder()
	h.handleTracingTenant(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("越权应 403，实际 %d", rr.Code)
	}
}

// TestHandleTracingTenant_ChainNil 验证审计链未启用 → 503（fail-closed）。
func TestHandleTracingTenant_ChainNil(t *testing.T) {
	h := newSLOHandler("", "", nil)
	req := httptest.NewRequest(http.MethodPost, tracingTenantPath, strings.NewReader(`{"tenant":"t-001","enabled":true}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTracingTenant(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("无审计链应 503，实际 %d", rr.Code)
	}
}

// TestHandleTracingTenant_WiredDecodeError 验证已接线时请求体非法 → 400。
func TestHandleTracingTenant_WiredDecodeError(t *testing.T) {
	srv := newFailingK8sServer(t)
	defer srv.Close()
	h := newWiredSLOHandler(t, newTestApplier(srv, "otpmask"))
	req := httptest.NewRequest(http.MethodPost, tracingTenantPath, strings.NewReader(`{bad`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTracingTenant(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("非法请求体应 400，实际 %d", rr.Code)
	}
}

// TestHandleTracingTenant_WiredEmptyTenant 验证已接线时 tenant 为空 → 400。
func TestHandleTracingTenant_WiredEmptyTenant(t *testing.T) {
	srv := newFailingK8sServer(t)
	defer srv.Close()
	h := newWiredSLOHandler(t, newTestApplier(srv, "otpmask"))
	req := httptest.NewRequest(http.MethodPost, tracingTenantPath, strings.NewReader(`{"tenant":"  ","enabled":true}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTracingTenant(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("空 tenant 应 400，实际 %d", rr.Code)
	}
}

// TestHandleTracingTenant_WiredPersistErrorStillOK 验证事实源应用成功但本地缓存落盘失败时仍返回 200
// （不掩盖已生效结果，仅告警）。
func TestHandleTracingTenant_WiredPersistErrorStillOK(t *testing.T) {
	_, srv := newFakeK8sServer(t, "otpmask", "otel-collector-config", "otel-collector.yaml", "otel-collector", sampleCollectorCfg)
	defer srv.Close()
	h := newWiredSLOHandler(t, newTestApplier(srv, "otpmask"))
	// 本地缓存落盘失败（目标目录不存在），但 ConfigMap 应用成功
	h.path = filepath.Join(t.TempDir(), "nodir", "slo.json")

	req := httptest.NewRequest(http.MethodPost, tracingTenantPath, strings.NewReader(`{"tenant":"t-001","enabled":true}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTracingTenant(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("应用成功但缓存落盘失败应仍 200，实际 %d：%s", rr.Code, rr.Body.String())
	}
}

// TestSetAllowList_AddRemoveKeep 验证增/删/保留语义与稳定顺序。
func TestSetAllowList_AddRemoveKeep(t *testing.T) {
	// 删除：列表含目标且 enabled=false → 移除
	if got := setAllowList([]string{"a", "b", "c"}, "b", false); len(got) != 2 || got[0] != "a" || got[1] != "c" {
		t.Fatalf("删除语义异常：%v", got)
	}
	// 保留：目标已存在且 enabled=true → 不变
	if got := setAllowList([]string{"a", "b"}, "a", true); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("保留语义异常：%v", got)
	}
	// 新增：目标不存在且 enabled=true → 追加
	if got := setAllowList([]string{"a"}, "z", true); len(got) != 2 || got[1] != "z" {
		t.Fatalf("新增语义异常：%v", got)
	}
	// 空列表新增
	if got := setAllowList(nil, "z", true); len(got) != 1 || got[0] != "z" {
		t.Fatalf("空列表新增异常：%v", got)
	}
}
