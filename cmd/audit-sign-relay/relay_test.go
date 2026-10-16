package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testToken = "t2c-sign-relay-token"

func testRelay(endpoint string) *relay {
	return newRelay(config{
		Endpoint: endpoint,
		Token:    testToken,
		MaxRetry: 2,
		Backoff:  time.Millisecond,
		Timeout:  2 * time.Second,
	})
}

// transformRelay 带映射表与 TRANSFORM 的联调形态（接 Fluent Bit 原始访问日志）。
func transformRelay(t *testing.T, endpoint string) *relay {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "consumer-tenant.json")
	if err := os.WriteFile(p, []byte(`{"otpmask-customer-a":"tenant-a","otpmask-customer-c":"tenant-a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newRelay(config{
		Endpoint:  endpoint,
		Token:     testToken,
		MaxRetry:  2,
		Backoff:   time.Millisecond,
		Timeout:   2 * time.Second,
		Transform: true,
		MapPath:   p,
	})
	return r
}

// ---- parseRecords：输入形态 ----

func TestParseRecordsArray(t *testing.T) {
	in := []byte(`[{"request_id":"r1"},{"request_id":"r2"}]`)
	items, err := parseRecords(in)
	if err != nil || len(items) != 2 {
		t.Fatalf("err=%v n=%d", err, len(items))
	}
	out, _ := marshalReports(items)
	var got struct {
		Reports []map[string]string `json:"reports"`
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got.Reports) != 2 {
		t.Fatalf("输出结构错误: %v / %s", err, out)
	}
}

func TestParseRecordsObjectWithReports(t *testing.T) {
	in := []byte(`{"reports":[{"request_id":"r1"}]}`)
	items, err := parseRecords(in)
	if err != nil || len(items) != 1 {
		t.Fatalf("err=%v n=%d", err, len(items))
	}
}

// TestParseRecordsSingleObject Fluent Bit 单条批次发的是「单个 JSON 对象」
// （2026-10-14 联调实测）⇒ 须视为 1 条记录。
func TestParseRecordsSingleObject(t *testing.T) {
	in := []byte(`{"request_id":"r1","result":"auth_failed"}`)
	items, err := parseRecords(in)
	if err != nil || len(items) != 1 {
		t.Fatalf("err=%v n=%d", err, len(items))
	}
}

func TestParseRecordsNDJSON(t *testing.T) {
	in := []byte("{\"request_id\":\"a\"}\n{\"request_id\":\"b\"}\n\n")
	items, err := parseRecords(in)
	if err != nil || len(items) != 2 {
		t.Fatalf("err=%v n=%d", err, len(items))
	}
}

func TestParseRecordsRejectsInvalid(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "   ",
		"bad_array": `[{"a":`,
		"bad_ndjs":  "{\"a\":1}\nnot-json",
	} {
		if _, err := parseRecords([]byte(in)); err == nil {
			t.Fatalf("%s 应被拒绝", name)
		}
	}
}

// ---- TRANSFORM：访问日志 → 契约记录 ----

func TestTransformResultMapping(t *testing.T) {
	r := transformRelay(t, "http://127.0.0.1:1/audit/report")
	cases := []struct {
		name, code, details, want string
	}{
		{"401", "401", "key-auth::..._Invalid_API_key", "auth_failed"},
		{"429", "429", "cluster-key-rate-limit.rejected", "rate_limited"},
		{"403-ip", "403", "ip-restriction::key-auth.ip_not_allowed", "ip_blocked"},
		{"403-authz", "403", "key-auth::..._Unauthorized_consumer", "consumer_unauthorized"},
	}
	for _, c := range cases {
		got := r.transform(map[string]any{
			"response_code": c.code, "response_code_details": c.details,
			"request_id": "req-" + c.name, "path": "/infer", "start_time": "2026-10-14T05:50:43.331Z",
		})
		if got == nil {
			t.Fatalf("%s：应被保留", c.name)
		}
		if got["result"] != c.want {
			t.Fatalf("%s：result 期望 %q，实际 %q", c.name, c.want, got["result"])
		}
		if got["http_status"].(int) == 0 {
			t.Fatalf("%s：http_status 未解析", c.name)
		}
	}
}

func TestTransformSkipsNonReject(t *testing.T) {
	r := transformRelay(t, "http://127.0.0.1:1/audit/report")
	if got := r.transform(map[string]any{"response_code": "200"}); got != nil {
		t.Fatalf("200 应被跳过，实际 %+v", got)
	}
}

// TestTransformTenantResolution 实测结论：仅 403 授权拒绝子类带 consumer；
// 401/429/403-IP 为 "-" ⇒ 哨兵租户。
func TestTransformTenantResolution(t *testing.T) {
	r := transformRelay(t, "http://127.0.0.1:1/audit/report")
	real := r.transform(map[string]any{
		"response_code": "403", "response_code_details": "key-auth::..._Unauthorized_consumer",
		"x_mse_consumer": "otpmask-customer-c", "request_id": "req-authz",
		"start_time": "2026-10-14T05:50:43.331Z",
	})
	if real["tenant_id"] != "tenant-a" || real["tenant_id_resolution"] != "consumer_map" {
		t.Fatalf("403 授权拒绝应归真实租户，实际 %+v", real)
	}
	sentinel := r.transform(map[string]any{
		"response_code": "429", "response_code_details": "cluster-key-rate-limit.rejected",
		"x_mse_consumer": "-", "request_id": "req-429",
		"start_time": "2026-10-14T05:50:43.331Z",
	})
	if sentinel["tenant_id"] != sentinelTenant || sentinel["tenant_id_resolution"] != "unauthenticated" {
		t.Fatalf("429 应落哨兵租户，实际 %+v", sentinel)
	}
}

// TestTransformDropsSensitiveFields 只取白名单字段，不把 ai_log 等带入上报。
func TestTransformDropsSensitiveFields(t *testing.T) {
	r := transformRelay(t, "http://127.0.0.1:1/audit/report")
	got := r.transform(map[string]any{
		"response_code": "401", "request_id": "req-x",
		"ai_log": "明文请求内容-不得外传", "authority": "example.com",
		"start_time": "2026-10-14T05:50:43.331Z",
	})
	b, _ := json.Marshal(got)
	for _, leak := range []string{"明文请求内容", "ai_log", "authority"} {
		if strings.Contains(string(b), leak) {
			t.Fatalf("输出泄漏字段 %q：%s", leak, b)
		}
	}
}

func TestHandleBatchTransformEndToEnd(t *testing.T) {
	var gotBody []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotBody, _ = io.ReadAll(req.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	r := transformRelay(t, up.URL)
	// 混合批次：2 条拒绝 + 1 条正常（应被跳过）
	body := `[{"request_id":"a","response_code":"401","response_code_details":"key-auth::..._Invalid_API_key","path":"/infer","start_time":"2026-10-14T05:50:43.331Z"},` +
		`{"request_id":"b","response_code":"200","path":"/infer"},` +
		`{"request_id":"c","response_code":"403","response_code_details":"key-auth::..._Unauthorized_consumer","x_mse_consumer":"otpmask-customer-c","path":"/infer","start_time":"2026-10-14T05:50:44.331Z"}]`
	req := httptest.NewRequest(http.MethodPost, "/audit/batch", strings.NewReader(body))
	w := httptest.NewRecorder()
	r.handleBatch(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d: %s", w.Code, w.Body.String())
	}
	var got struct {
		Reports []map[string]any `json:"reports"`
	}
	if err := json.Unmarshal(gotBody, &got); err != nil || len(got.Reports) != 2 {
		t.Fatalf("期望 2 条（正常请求被跳过），实际 %v / %s", err, gotBody)
	}
	if r.skipped.Load() != 1 {
		t.Fatalf("skipped 计数应为 1，实际 %d", r.skipped.Load())
	}
	// 第二条应为 403 授权拒绝且归真实租户
	if got.Reports[1]["result"] != "consumer_unauthorized" || got.Reports[1]["tenant_id"] != "tenant-a" {
		t.Fatalf("403 子类映射错误: %+v", got.Reports[1])
	}
}

// ---- 签名：与 tee-infer 侧算法逐字节一致 ----

func TestSignMatchesServerAlgorithm(t *testing.T) {
	r := testRelay("http://127.0.0.1:1/audit/report")
	body := []byte(`{"reports":[{"request_id":"r1","result":"consumer_unauthorized"}]}`)
	got := r.sign(body)

	mac := hmac.New(sha256.New, []byte(testToken))
	mac.Write(body)
	want := hex.EncodeToString(mac.Sum(nil))
	if got != want {
		t.Fatalf("签名不一致：got=%s want=%s", got, want)
	}
}

// ---- 上游投递：4xx 不重试 / 5xx 重试 ----

func TestForwardNoRetryOn4xx(t *testing.T) {
	var calls atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer up.Close()

	r := testRelay(up.URL)
	status, err := r.forward([]byte(`{"reports":[]}`))
	if status != http.StatusBadRequest || err != nil {
		t.Fatalf("期望 400 且无错误，实际 status=%d err=%v", status, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("4xx 不得重试，实际调用 %d 次", calls.Load())
	}
}

func TestForwardRetryOn5xxThenOK(t *testing.T) {
	var calls atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) <= 2 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	r := testRelay(up.URL)
	status, err := r.forward([]byte(`{"reports":[]}`))
	if err != nil || status != http.StatusOK {
		t.Fatalf("重试后应成功，实际 status=%d err=%v", status, err)
	}
	if calls.Load() != 3 {
		t.Fatalf("期望 3 次调用（首投+2 次重试），实际 %d", calls.Load())
	}
}

// ---- 端点行为 ----

func TestHandleBatchEndToEnd(t *testing.T) {
	var gotBody []byte
	var gotSig, gotToken string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotBody, _ = io.ReadAll(req.Body)
		gotSig = req.Header.Get("X-Audit-Report-Sig")
		gotToken = req.Header.Get("X-Admin-Token")
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	r := testRelay(up.URL)
	req := httptest.NewRequest(http.MethodPost, "/audit/batch",
		strings.NewReader(`[{"request_id":"a","result":"auth_failed"},{"request_id":"b","result":"consumer_unauthorized"}]`))
	w := httptest.NewRecorder()
	r.handleBatch(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d: %s", w.Code, w.Body.String())
	}
	if gotToken != testToken || gotSig == "" {
		t.Fatalf("上报头缺失：token=%q sig=%q", gotToken, gotSig)
	}
	mac := hmac.New(sha256.New, []byte(testToken))
	mac.Write(gotBody)
	if !hmac.Equal([]byte(gotSig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		t.Fatal("上游收到的签名与 body 不匹配")
	}
	if r.forwarded.Load() != 1 || r.itemsIn.Load() != 2 {
		t.Fatalf("计数错误 forwarded=%d items=%d", r.forwarded.Load(), r.itemsIn.Load())
	}
}

func TestHandleBatchOversizeDropped(t *testing.T) {
	r := testRelay("http://127.0.0.1:1/audit/report")
	req := httptest.NewRequest(http.MethodPost, "/audit/batch", strings.NewReader(strings.Repeat("a", maxBatchBytes+10)))
	w := httptest.NewRecorder()
	r.handleBatch(w, req)
	if w.Code != http.StatusRequestEntityTooLarge || r.dropped.Load() != 1 {
		t.Fatalf("期望 413+dropped=1，实际 code=%d dropped=%d", w.Code, r.dropped.Load())
	}
}

func TestHandleBatchUpstream4xxCountedAsDropped(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer up.Close()
	r := testRelay(up.URL)
	req := httptest.NewRequest(http.MethodPost, "/audit/batch",
		strings.NewReader(`[{"request_id":"a","result":"evil_result"}]`))
	w := httptest.NewRecorder()
	r.handleBatch(w, req)
	if w.Code != http.StatusBadGateway || r.dropped.Load() != 1 || r.forwarded.Load() != 0 {
		t.Fatalf("期望 502+dropped=1，实际 code=%d dropped=%d forwarded=%d", w.Code, r.dropped.Load(), r.forwarded.Load())
	}
}

func TestHandleBatchUpstreamUnreachableCountsFailed(t *testing.T) {
	r := testRelay("http://127.0.0.1:1/audit/report")
	req := httptest.NewRequest(http.MethodPost, "/audit/batch",
		strings.NewReader(`[{"request_id":"a","result":"rate_limited"}]`))
	w := httptest.NewRecorder()
	r.handleBatch(w, req)
	if w.Code != http.StatusBadGateway || r.failed.Load() != 1 {
		t.Fatalf("期望 502+failed=1，实际 code=%d failed=%d", w.Code, r.failed.Load())
	}
}

func TestHandleBatchMethodNotAllowed(t *testing.T) {
	r := testRelay("http://127.0.0.1:1/audit/report")
	w := httptest.NewRecorder()
	r.handleBatch(w, httptest.NewRequest(http.MethodGet, "/audit/batch", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("期望 405，实际 %d", w.Code)
	}
}

func TestHandleBatchInvalidPayloadDropped(t *testing.T) {
	r := testRelay("http://127.0.0.1:1/audit/report")
	w := httptest.NewRecorder()
	r.handleBatch(w, httptest.NewRequest(http.MethodPost, "/audit/batch", strings.NewReader("not-json-at-all")))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际 %d", w.Code)
	}
	if strings.Contains(w.Body.String(), "not-json-at-all") {
		t.Fatal("响应回显了原始载荷，存在泄漏风险")
	}
}

func TestHandleHealthz(t *testing.T) {
	r := testRelay("http://127.0.0.1:1/audit/report")
	w := httptest.NewRecorder()
	r.handleHealthz(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("健康检查异常 code=%d body=%s", w.Code, w.Body.String())
	}
}

func TestMetricsExposesCounters(t *testing.T) {
	r := testRelay("http://127.0.0.1:1/audit/report")
	r.dropped.Add(2)
	w := httptest.NewRecorder()
	r.handleMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{"audit_sign_relay_dropped_total 2", "audit_sign_relay_failed_total", "audit_sign_relay_skipped_total"} {
		if !strings.Contains(body, want) {
			t.Fatalf("指标缺 %q：\n%s", want, body)
		}
	}
}

func TestEnvHelpers(t *testing.T) {
	t.Setenv("T2C_STR", "")
	if got := envOr("T2C_STR", "fallback"); got != "fallback" {
		t.Fatalf("envOr 缺省分支错误: %q", got)
	}
	t.Setenv("T2C_STR", "value")
	if got := envOr("T2C_STR", "fallback"); got != "value" {
		t.Fatalf("envOr 取值错误: %q", got)
	}
	if got := envIntOr("T2C_INT_MISSING", 7); got != 7 {
		t.Fatalf("envIntOr 缺省分支错误: %d", got)
	}
	t.Setenv("T2C_INT", "42")
	if got := envIntOr("T2C_INT", 7); got != 42 {
		t.Fatalf("envIntOr 取值错误: %d", got)
	}
	t.Setenv("T2C_INT", "not-a-number")
	if got := envIntOr("T2C_INT", 7); got != 7 {
		t.Fatalf("envIntOr 非法值应回落缺省，实际 %d", got)
	}
	if got := envBoolOr("T2C_BOOL_MISSING", true); !got {
		t.Fatal("envBoolOr 缺省分支错误")
	}
	t.Setenv("T2C_BOOL", "on")
	if got := envBoolOr("T2C_BOOL", false); !got {
		t.Fatal("envBoolOr on 解析错误")
	}
	t.Setenv("T2C_BOOL", "off")
	if got := envBoolOr("T2C_BOOL", true); got {
		t.Fatal("envBoolOr off 解析错误")
	}
}

func TestLoadConfigDefaults(t *testing.T) {
	t.Setenv("AUDIT_REPORT_TOKEN", "tok-x")
	t.Setenv("LISTEN_ADDR", "")
	t.Setenv("AUDIT_REPORT_URL", "")
	t.Setenv("MAX_RETRY", "5")
	t.Setenv("BACKOFF_MS", "50")
	t.Setenv("UPSTREAM_TIMEOUT_MS", "1500")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9090" {
		t.Fatalf("监听地址缺省应为仅本地，实际 %q", cfg.ListenAddr)
	}
	if cfg.MaxRetry != 5 || cfg.Backoff != 50*time.Millisecond || cfg.Timeout != 1500*time.Millisecond {
		t.Fatalf("配置解析错误: %+v", cfg)
	}
	if cfg.Transform {
		t.Fatal("TRANSFORM 缺省应为 off（保持极薄定位）")
	}
}

func TestLoadConfigTransformDefaults(t *testing.T) {
	t.Setenv("AUDIT_REPORT_TOKEN", "tok-x")
	t.Setenv("TRANSFORM", "on")
	t.Setenv("MAP_PATH", "/custom/map.json")
	cfg, err := loadConfig()
	if err != nil {
		t.Fatalf("loadConfig 失败: %v", err)
	}
	if !cfg.Transform || cfg.MapPath != "/custom/map.json" {
		t.Fatalf("TRANSFORM 配置解析错误: %+v", cfg)
	}
}

// TestTransformMapMissingFallsBackToSentinel 映射表缺失/未命中 ⇒ 哨兵租户（不伪报）。
func TestTransformMapMissingFallsBackToSentinel(t *testing.T) {
	r := newRelay(config{Transform: true, MapPath: "/nonexistent/map.json", Token: testToken})
	got := r.transform(map[string]any{
		"response_code": "403", "response_code_details": "key-auth::..._Unauthorized_consumer",
		"x_mse_consumer": "otpmask-customer-z", "request_id": "req-z",
	})
	if got == nil || got["tenant_id"] != sentinelTenant || got["tenant_id_resolution"] != "unauthenticated" {
		t.Fatalf("映射缺失应落哨兵租户，实际 %+v", got)
	}
}

func TestLoadConfigRequiresToken(t *testing.T) {
	t.Setenv("AUDIT_REPORT_TOKEN", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("令牌缺失应报错（不得回落管理令牌，A3-11）")
	}
}
