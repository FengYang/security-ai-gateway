// P1-2：排障查询 API 单测（§7.7）——CSV 注入防护、聚合、租户隔离、503 与枚举校验。
package main

import (
	"encoding/json"
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
