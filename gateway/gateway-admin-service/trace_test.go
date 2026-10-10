// P1-2：排障查询 API 单测（§7.7）——CSV 注入防护、聚合、租户隔离、503 与枚举校验。
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestCsvEscape 验证 CSV 公式注入防护（§6.3）。
func TestCsvEscape(t *testing.T) {
	cases := map[string]string{
		"":                  "",
		"normal":            "normal",
		"=cmd|' /C calc'!A": "'=cmd|' /C calc'!A",
		"+1+1":              "'+1+1",
		"-2":                "'-2",
		"@SUM(A1)":          "'@SUM(A1)",
		"\tx":               "'\tx",
		"\rx":               "'\rx",
	}
	for in, want := range cases {
		if got := csvEscape(in); got != want {
			t.Errorf("csvEscape(%q)=%q，期望 %q", in, got, want)
		}
	}
}

// newFakeTempo 构造假 Tempo：/api/search 返回 traceID，/api/traces 返回 span 批次。
func newFakeTempo(t *testing.T, traceID string, traceJSON string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/search", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"traces":[{"traceID":"` + traceID + `"}]}`))
	})
	mux.HandleFunc("/api/traces/"+traceID, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(traceJSON))
	})
	return httptest.NewServer(mux)
}

// traceJSONSample 三段 span（ingress / tee.infer / upstream），含租户与白名单属性。
const traceJSONSample = `{
  "batches": [
    {"scopeSpans": [{"spans": [
      {"name":"envoy.ingress","startTimeUnixNano":"1000000000","endTimeUnixNano":"1002100000","attributes":[{"key":"http.status_code","value":{"intValue":"200"}}]},
      {"name":"tee.infer","startTimeUnixNano":"1002500000","endTimeUnixNano":"1382500000","attributes":[
        {"key":"tenant.id","value":{"stringValue":"t-001"}},
        {"key":"model.id","value":{"stringValue":"qwen-max"}},
        {"key":"cache.hit","value":{"boolValue":false}},
        {"key":"prompt","value":{"stringValue":"SHOULD_BE_DROPPED"}}
      ]},
      {"name":"upstream.model.call","startTimeUnixNano":"1005000000","endTimeUnixNano":"1365000000","attributes":[
        {"key":"ttft.ms","value":{"doubleValue":210.0}},
        {"key":"tokens.out","value":{"intValue":"128"}}
      ]}
    ]}]}
  ]
}`

// newTestTraceHandler 组装 handler（假 Tempo + 假 tee 审计）。
func newTestTraceHandler(t *testing.T, tempoURL, teeURL string) *traceHandler {
	t.Helper()
	return newTraceHandler(tempoURL, &usageSettings{url: teeURL, token: "tee-tok"})
}

// TestTraceAggregate_HappyPath 验证单请求聚合（span 树 + 白名单裁剪 + 审计 + 耗时分解）。
func TestTraceAggregate_HappyPath(t *testing.T) {
	tempo := newFakeTempo(t, "abc123", traceJSONSample)
	defer tempo.Close()
	tee := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/audit" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"request_id":"req-1","action":"infer","result":"ok","cache_hit":false,"is_retry":false},
			{"request_id":"other","action":"infer","result":"ok"}
		]`))
	}))
	defer tee.Close()

	h := newTestTraceHandler(t, tempo.URL, tee.URL)
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor, Tenant: "t-001"}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d：%s", rr.Code, rr.Body.String())
	}
	var agg traceAggregateView
	if err := json.Unmarshal(rr.Body.Bytes(), &agg); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if agg.TraceID != "abc123" || agg.Tenant != "t-001" || agg.RequestID != "req-1" {
		t.Fatalf("聚合头字段异常：%+v", agg)
	}
	if len(agg.Spans) != 3 {
		t.Fatalf("期望 3 条 span，实际 %d", len(agg.Spans))
	}
	// 白名单裁剪：prompt 不得出现
	for _, s := range agg.Spans {
		if _, bad := s.Attrs["prompt"]; bad {
			t.Errorf("span %s 含禁止属性 prompt", s.Name)
		}
	}
	// 耗时分解：ingress=2.1ms，upstream=360ms，tee 开销 = 380-360 = 20ms
	if agg.Breakdown.IngressMs < 2.0 || agg.Breakdown.IngressMs > 2.2 {
		t.Errorf("ingress_ms 异常：%v", agg.Breakdown.IngressMs)
	}
	if agg.Breakdown.UpstreamMs < 359 || agg.Breakdown.UpstreamMs > 361 {
		t.Errorf("upstream_ms 异常：%v", agg.Breakdown.UpstreamMs)
	}
	if agg.Breakdown.TEEOverheadMs < 19 || agg.Breakdown.TEEOverheadMs > 21 {
		t.Errorf("tee_overhead_ms 异常：%v", agg.Breakdown.TEEOverheadMs)
	}
	// 审计：仅 request_id=req-1 的事件被纳入
	if !agg.Audit.Available || agg.Audit.Action != "infer" || agg.Audit.Result != "ok" {
		t.Errorf("审计段异常：%+v", agg.Audit)
	}
}

// TestTraceAggregate_TenantIsolation 验证非 admin 跨租户 → 403（fail-closed）。
func TestTraceAggregate_TenantIsolation(t *testing.T) {
	tempo := newFakeTempo(t, "abc123", traceJSONSample)
	defer tempo.Close()
	h := newTestTraceHandler(t, tempo.URL, "")

	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	// 调用方租户 t-999，trace 归属 t-001 → 403
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor, Tenant: "t-999"}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("跨租户应 403，实际 %d", rr.Code)
	}
}

// TestTraceAggregate_TenantMissingDeniedForNonAdmin 验证非 admin 缺省租户 → 403。
func TestTraceAggregate_TenantMissingDeniedForNonAdmin(t *testing.T) {
	tempo := newFakeTempo(t, "abc123", traceJSONSample)
	defer tempo.Close()
	h := newTestTraceHandler(t, tempo.URL, "")

	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("缺省租户的非 admin 应 403，实际 %d", rr.Code)
	}
}

// TestTraceReport_CSV 验证报告导出（CSV 头 + 附件名）。
func TestTraceReport_CSV(t *testing.T) {
	tempo := newFakeTempo(t, "abc123", traceJSONSample)
	defer tempo.Close()
	h := newTestTraceHandler(t, tempo.URL, "")

	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1/report?format=csv", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceReport(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", rr.Code)
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Errorf("Content-Type 应为 text/csv，实际 %q", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "trace-req-1.csv") {
		t.Errorf("Content-Disposition 应含文件名，实际 %q", cd)
	}
	if !strings.Contains(rr.Body.String(), "section,name") {
		t.Errorf("CSV 应含表头，实际：%s", rr.Body.String())
	}
}

// TestTraceSearch_StatusEnumRejected 验证 status 枚举外值 → 400（§6.3）。
func TestTraceSearch_StatusEnumRejected(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/search?status=bogus", nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceSearch(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("非法 status 应 400，实际 %d", rr.Code)
	}
}

// TestTrace_503WhenTempoUnset 验证 Tempo 未配置 → 503（不静默返回空）。
func TestTrace_503WhenTempoUnset(t *testing.T) {
	h := newTestTraceHandler(t, "", "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("Tempo 未配置应 503，实际 %d", rr.Code)
	}
}

// TestTraceSearch_TenantConvergedForNonAdmin 验证非 admin 传入不一致 tenant → 403。
func TestTraceSearch_TenantConvergedForNonAdmin(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/search?tenant=other", nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor, Tenant: "t-001"}))
	rr := httptest.NewRecorder()
	h.handleTraceSearch(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("跨租户检索应 403，实际 %d", rr.Code)
	}
}

// ---- 补充覆盖：检索/报告/聚合的错误与成功分支 ----

// ctrlTempo 可编程假 Tempo：分别控制 /api/search 与 /api/traces 的状态码、响应体，并记录检索查询串。
type ctrlTempo struct {
	searchStatus int
	searchBody   string
	detailStatus int
	detailBody   string
	lastRawQuery string
}

func (f *ctrlTempo) server() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/search", func(w http.ResponseWriter, r *http.Request) {
		f.lastRawQuery = r.URL.RawQuery
		w.WriteHeader(f.searchStatus)
		_, _ = w.Write([]byte(f.searchBody))
	})
	mux.HandleFunc("/api/traces/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(f.detailStatus)
		_, _ = w.Write([]byte(f.detailBody))
	})
	return httptest.NewServer(mux)
}

// TestHandleTraceSearch_HappyPathAndParams 验证检索成功（body 透传）与 tags/status/时间窗/offset 组装。
func TestHandleTraceSearch_HappyPathAndParams(t *testing.T) {
	ft := &ctrlTempo{searchStatus: http.StatusOK, searchBody: `{"traces":[]}`}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")

	q := "tenant=t-001&model=qwen-max&category=pii&status=ok&from=100&to=200&limit=10&offset=5"
	req := httptest.NewRequest(http.MethodGet, traceSearchPath+"?"+q, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceSearch(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d：%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type 应为 application/json，实际 %q", ct)
	}
	if rr.Body.String() != `{"traces":[]}` {
		t.Errorf("响应体应透传 Tempo 结果，实际 %q", rr.Body.String())
	}
	for _, want := range []string{
		"tenant.id%3Dt-001", "model.id%3Dqwen-max", "og.category%3Dpii",
		"status=ok", "start=100", "end=200", "limit=15", // offset>0 → limit+offset
	} {
		if !strings.Contains(ft.lastRawQuery, want) {
			t.Errorf("检索查询串缺少 %q：%s", want, ft.lastRawQuery)
		}
	}
}

// TestHandleTraceSearch_NonAdminConverged 验证非 admin 未显式传 tenant 时收敛为自身租户标签。
func TestHandleTraceSearch_NonAdminConverged(t *testing.T) {
	ft := &ctrlTempo{searchStatus: http.StatusOK, searchBody: `{"traces":[]}`}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, traceSearchPath+"?model=qwen-max", nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "bob", Role: roleAuditor, Tenant: "t-001"}))
	rr := httptest.NewRecorder()
	h.handleTraceSearch(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d：%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(ft.lastRawQuery, "tenant.id%3Dt-001") {
		t.Errorf("非 admin 应收敛为自身租户标签：%s", ft.lastRawQuery)
	}
}

// TestHandleTraceSearch_MethodNotAllowed 验证非 GET → 405。
func TestHandleTraceSearch_MethodNotAllowed(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodPost, traceSearchPath, nil)
	rr := httptest.NewRecorder()
	h.handleTraceSearch(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET 应 405，实际 %d", rr.Code)
	}
}

// TestHandleTraceSearch_ForbiddenRole 验证越权 → 403。
func TestHandleTraceSearch_ForbiddenRole(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodGet, traceSearchPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "x", Role: roleBillingReader}))
	rr := httptest.NewRecorder()
	h.handleTraceSearch(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("越权应 403，实际 %d", rr.Code)
	}
}

// TestHandleTraceSearch_TempoUnset503 验证 Tempo 未配置 → 503（不静默返回空）。
func TestHandleTraceSearch_TempoUnset503(t *testing.T) {
	h := newTestTraceHandler(t, "", "")
	req := httptest.NewRequest(http.MethodGet, traceSearchPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceSearch(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("Tempo 未配置应 503，实际 %d", rr.Code)
	}
}

// TestHandleTraceSearch_TempoUnreachable503 验证 Tempo 不可达 → 503。
func TestHandleTraceSearch_TempoUnreachable503(t *testing.T) {
	h := newTestTraceHandler(t, "http://127.0.0.1:1", "")
	req := httptest.NewRequest(http.MethodGet, traceSearchPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceSearch(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("不可达应 503，实际 %d", rr.Code)
	}
}

// TestHandleTraceSearch_TempoNon200_503 验证 Tempo 返回非 200 → 503。
func TestHandleTraceSearch_TempoNon200_503(t *testing.T) {
	ft := &ctrlTempo{searchStatus: http.StatusInternalServerError, searchBody: ""}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, traceSearchPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceSearch(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("非 200 应 503，实际 %d", rr.Code)
	}
}

// TestHandleTraceByID_MethodNotAllowed 验证非 GET → 405。
func TestHandleTraceByID_MethodNotAllowed(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodPost, "/v1/adminext/trace/req-1", nil)
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET 应 405，实际 %d", rr.Code)
	}
}

// TestHandleTraceByID_EmptyRequestID 验证缺 request_id → 400。
func TestHandleTraceByID_EmptyRequestID(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/", nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("缺 request_id 应 400，实际 %d", rr.Code)
	}
}

// TestHandleTraceByID_ForbiddenRole 验证越权 → 403。
func TestHandleTraceByID_ForbiddenRole(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "x", Role: roleBillingReader}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("越权应 403，实际 %d", rr.Code)
	}
}

// TestHandleTraceReport_FormatDefaultJSON 验证缺省 format=json 分支（含附件名）。
func TestHandleTraceReport_FormatDefaultJSON(t *testing.T) {
	ft := &ctrlTempo{
		searchStatus: http.StatusOK,
		searchBody:   `{"traces":[{"traceID":"abc123"}]}`,
		detailStatus: http.StatusOK,
		detailBody:   traceJSONSample,
	}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")

	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1/report", nil) // 无 format → json
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceReport(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d：%s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type 应为 application/json，实际 %q", ct)
	}
	if cd := rr.Header().Get("Content-Disposition"); !strings.Contains(cd, "trace-req-1.json") {
		t.Errorf("Content-Disposition 应含 json 文件名，实际 %q", cd)
	}
}

// TestHandleTraceReport_MethodNotAllowed 验证非 GET → 405。
func TestHandleTraceReport_MethodNotAllowed(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodPost, "/v1/adminext/trace/req-1/report", nil)
	rr := httptest.NewRecorder()
	h.handleTraceReport(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET 应 405，实际 %d", rr.Code)
	}
}

// TestHandleTraceReport_EmptyRequestID 验证缺 request_id → 400。
func TestHandleTraceReport_EmptyRequestID(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace//report", nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceReport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("缺 request_id 应 400，实际 %d", rr.Code)
	}
}

// TestHandleTraceReport_ForbiddenRole 验证越权 → 403。
func TestHandleTraceReport_ForbiddenRole(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.invalid", "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1/report", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "x", Role: roleBillingReader}))
	rr := httptest.NewRecorder()
	h.handleTraceReport(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("越权应 403，实际 %d", rr.Code)
	}
}

// TestHandleTraceReport_InvalidFormat 验证 format 非 json/csv → 400（需聚合成功后才进入 format 分支）。
func TestHandleTraceReport_InvalidFormat(t *testing.T) {
	ft := &ctrlTempo{
		searchStatus: http.StatusOK,
		searchBody:   `{"traces":[{"traceID":"abc123"}]}`,
		detailStatus: http.StatusOK,
		detailBody:   traceJSONSample,
	}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1/report?format=xml", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceReport(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("非法 format 应 400，实际 %d", rr.Code)
	}
}

// TestHandleTraceReport_AggregateError 验证聚合失败时按错误码返回（如 404）。
func TestHandleTraceReport_AggregateError(t *testing.T) {
	ft := &ctrlTempo{searchStatus: http.StatusNotFound, searchBody: ""}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1/report", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceReport(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("聚合失败应 503（Tempo 404），实际 %d", rr.Code)
	}
}

// TestTraceAggregate_SearchUnreachable 验证检索 Tempo 不可达 → 503。
func TestTraceAggregate_SearchUnreachable(t *testing.T) {
	h := newTestTraceHandler(t, "http://127.0.0.1:1", "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("检索不可达应 503，实际 %d", rr.Code)
	}
}

// TestTraceAggregate_SearchNon200 验证检索非 200 → 503。
func TestTraceAggregate_SearchNon200(t *testing.T) {
	ft := &ctrlTempo{searchStatus: http.StatusInternalServerError, searchBody: ""}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("检索非 200 应 503，实际 %d", rr.Code)
	}
}

// TestTraceAggregate_SearchInvalidJSON 验证检索响应非法 JSON → 视为未找到（404）。
func TestTraceAggregate_SearchInvalidJSON(t *testing.T) {
	ft := &ctrlTempo{searchStatus: http.StatusOK, searchBody: "not-json"}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("非法检索响应应 404，实际 %d", rr.Code)
	}
}

// TestTraceAggregate_SearchNoTraces 验证检索无命中 → 404。
func TestTraceAggregate_SearchNoTraces(t *testing.T) {
	ft := &ctrlTempo{searchStatus: http.StatusOK, searchBody: `{"traces":[]}`}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("无命中应 404，实际 %d", rr.Code)
	}
}

// TestTraceAggregate_DetailNon200 验证拉取 trace 明细非 200 → 503。
func TestTraceAggregate_DetailNon200(t *testing.T) {
	ft := &ctrlTempo{
		searchStatus: http.StatusOK,
		searchBody:   `{"traces":[{"traceID":"abc123"}]}`,
		detailStatus: http.StatusInternalServerError,
	}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("明细非 200 应 503，实际 %d", rr.Code)
	}
}

// TestTraceAggregate_DetailParseFail 验证明细解析失败 → 502。
func TestTraceAggregate_DetailParseFail(t *testing.T) {
	ft := &ctrlTempo{
		searchStatus: http.StatusOK,
		searchBody:   `{"traces":[{"traceID":"abc123"}]}`,
		detailStatus: http.StatusOK,
		detailBody:   "not-json",
	}
	srv := ft.server()
	defer srv.Close()
	h := newTestTraceHandler(t, srv.URL, "")
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusBadGateway {
		t.Fatalf("明细解析失败应 502，实际 %d", rr.Code)
	}
}

// routeErrTransport：/api/search 成功返回固定体，其余路径返回网络错误（驱动明细 get 失败分支）。
type routeErrTransport struct{ searchBody string }

func (t routeErrTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, "/api/search") {
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     http.Header{},
			Body:       io.NopCloser(strings.NewReader(t.searchBody)),
		}, nil
	}
	return nil, errors.New("detail boom")
}

// TestTraceAggregate_DetailUnreachable 验证明细拉取网络失败 → 503。
func TestTraceAggregate_DetailUnreachable(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.local", "")
	h.client = &http.Client{Transport: routeErrTransport{searchBody: `{"traces":[{"traceID":"abc123"}]}`}}
	req := httptest.NewRequest(http.MethodGet, "/v1/adminext/trace/req-1", nil)
	req.SetPathValue("request_id", "req-1")
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTraceByID(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("明细不可达应 503，实际 %d", rr.Code)
	}
}

// TestTraceGet_ErrorPaths 直接驱动 get 的构造/网络/读取错误分支。
func TestTraceGet_ErrorPaths(t *testing.T) {
	h := newTestTraceHandler(t, "http://tempo.local", "")
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	if _, _, err := h.get(req, "http://[::1"); err == nil {
		t.Error("非法 target 应报错")
	}
	if _, _, err := h.get(req, "http://127.0.0.1:1"); err == nil {
		t.Error("不可达应报错")
	}
	h.client = &http.Client{Transport: errBodyTransport{status: http.StatusOK}}
	if _, _, err := h.get(req, "http://tempo.local/api/search"); err == nil {
		t.Error("body 读取失败应报错")
	}
}

// TestTraceFetchAudit_ErrorPaths 直接驱动 fetchAudit 的错误降级与拒绝事件分支。
func TestTraceFetchAudit_ErrorPaths(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)

	t.Run("bad-url", func(t *testing.T) {
		h := newTestTraceHandler(t, "", "")
		h.settings = &usageSettings{url: "://bad", token: "t"}
		v := h.fetchAudit(req, "t-001", "req-1")
		if v.Available {
			t.Error("构造失败应 Available=false")
		}
	})
	t.Run("unreachable", func(t *testing.T) {
		h := newTestTraceHandler(t, "", "http://127.0.0.1:1")
		v := h.fetchAudit(req, "t-001", "req-1")
		if v.Available {
			t.Error("不可达应 Available=false")
		}
	})
	t.Run("non-200", func(t *testing.T) {
		tee := newAuditServer(t, http.StatusInternalServerError, "")
		defer tee.Close()
		h := newTestTraceHandler(t, "", tee.URL)
		v := h.fetchAudit(req, "t-001", "req-1")
		if v.Available {
			t.Error("非 200 应 Available=false")
		}
	})
	t.Run("invalid-json", func(t *testing.T) {
		tee := newAuditServer(t, http.StatusOK, "not-json")
		defer tee.Close()
		h := newTestTraceHandler(t, "", tee.URL)
		v := h.fetchAudit(req, "t-001", "req-1")
		if v.Available {
			t.Error("非法 JSON 应 Available=false")
		}
	})
	t.Run("read-error", func(t *testing.T) {
		h := newTestTraceHandler(t, "", "http://tee.local")
		h.client = &http.Client{Transport: errBodyTransport{status: http.StatusOK}}
		v := h.fetchAudit(req, "t-001", "req-1")
		if v.Available {
			t.Error("body 读取失败应 Available=false")
		}
	})
	t.Run("deny-and-infer", func(t *testing.T) {
		body := `[
			{"request_id":"req-1","action":"infer","result":"ok","cache_hit":true,"is_retry":false},
			{"request_id":"req-1","action":"output_blocked","result":"blocked_pii"},
			{"request_id":"other","action":"deny","result":"blocked_x"}
		]`
		tee := newAuditServer(t, http.StatusOK, body)
		defer tee.Close()
		h := newTestTraceHandler(t, "", tee.URL)
		v := h.fetchAudit(req, "t-001", "req-1")
		if !v.Available {
			t.Fatal("可达时 Available 应为 true")
		}
		if v.Action != "infer" || !v.CacheHit {
			t.Errorf("infer 事件应写入视图：%+v", v)
		}
		if len(v.Denies) != 1 || v.Denies[0].Result != "output_blocked" || v.Denies[0].Reason != "blocked_pii" {
			t.Errorf("拒绝事件应写入 Denies：%+v", v.Denies)
		}
	})
}

// newAuditServer 返回固定状态码与响应体的假 tee-infer /audit 服务。
func newAuditServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// TestWriteTraceCSV_NoAttrsAndDenies 验证无属性 span 行与 Denies 行（含公式注入防护）。
func TestWriteTraceCSV_NoAttrsAndDenies(t *testing.T) {
	agg := &traceAggregateView{
		Spans: []traceSpanView{{Name: "envoy.ingress", StartMs: 1.5, DurMs: 2.5}}, // 无属性
		Audit: traceAuditView{
			Action: "deny",
			Result: "blocked_pii",
			Denies: []traceDenyView{{Reason: "=cmd", Result: "deny"}},
		},
		Breakdown: traceBreakdownView{IngressMs: 1, TEEOverheadMs: 2, UpstreamMs: 3},
	}
	var buf bytes.Buffer
	if err := writeTraceCSV(&buf, agg); err != nil {
		t.Fatalf("CSV 写出失败：%v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "span,envoy.ingress") {
		t.Errorf("应含无属性 span 行：%s", out)
	}
	if !strings.Contains(out, "'=cmd") {
		t.Errorf("Denies 的 Reason 应做公式注入防护：%s", out)
	}
	if !strings.Contains(out, "breakdown,upstream_ms") {
		t.Errorf("应含耗时分解行：%s", out)
	}
}
