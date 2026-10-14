package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

// ---- normalize：三种输入形态 ----

func TestNormalizeArrayWrapped(t *testing.T) {
	in := []byte(`[{"request_id":"r1"},{"request_id":"r2"}]`)
	out, n, err := normalize(in)
	if err != nil || n != 2 {
		t.Fatalf("err=%v n=%d", err, n)
	}
	var got struct {
		Reports []map[string]string `json:"reports"`
	}
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("输出非法: %v", err)
	}
	if len(got.Reports) != 2 || got.Reports[0]["request_id"] != "r1" {
		t.Fatalf("整形结果错误: %s", out)
	}
}

func TestNormalizeObjectIdempotent(t *testing.T) {
	in := []byte(`{"reports":[{"request_id":"r1"}]}`)
	out, n, err := normalize(in)
	if err != nil || n != 1 {
		t.Fatalf("err=%v n=%d", err, n)
	}
	if !strings.Contains(string(out), `"reports"`) {
		t.Fatalf("输出缺 reports: %s", out)
	}
}

func TestNormalizeNDJSON(t *testing.T) {
	in := []byte("{\"request_id\":\"a\"}\n{\"request_id\":\"b\"}\n\n")
	out, n, err := normalize(in)
	if err != nil || n != 2 {
		t.Fatalf("err=%v n=%d", err, n)
	}
	var got struct {
		Reports []map[string]string `json:"reports"`
	}
	if err := json.Unmarshal(out, &got); err != nil || len(got.Reports) != 2 {
		t.Fatalf("NDJSON 聚合失败: %v / %s", err, out)
	}
}

func TestNormalizeRejectsInvalid(t *testing.T) {
	for name, in := range map[string]string{
		"empty":     "   ",
		"bad_array": `[{"a":`,
		"no_report": `{"foo":1}`,
		"bad_ndjs":  "{\"a\":1}\nnot-json",
	} {
		if _, _, err := normalize([]byte(in)); err == nil {
			t.Fatalf("%s 应被拒绝", name)
		}
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
	r.cfg.Backoff = time.Millisecond
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

// ---- 端到端：签名、头、body 结构、计数 ----

func TestHandleBatchEndToEnd(t *testing.T) {
	var gotBody []byte
	var gotSig, gotToken string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		gotBody, _ = io.ReadAll(req.Body)
		gotSig = req.Header.Get("X-Audit-Report-Sig")
		gotToken = req.Header.Get("X-Admin-Token")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"accepted":2}`))
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
	// 服务端算法复算校验
	mac := hmac.New(sha256.New, []byte(testToken))
	mac.Write(gotBody)
	if !hmac.Equal([]byte(gotSig), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		t.Fatal("上游收到的签名与 body 不匹配（签名器对最终字节签名的前提被破坏）")
	}
	var got struct {
		Reports []map[string]string `json:"reports"`
	}
	if err := json.Unmarshal(gotBody, &got); err != nil || len(got.Reports) != 2 {
		t.Fatalf("上游收到的结构不符契约: %v / %s", err, gotBody)
	}
	if r.forwarded.Load() != 1 || r.itemsIn.Load() != 2 {
		t.Fatalf("计数错误 forwarded=%d items=%d", r.forwarded.Load(), r.itemsIn.Load())
	}
}

func TestHandleBatchOversizeDropped(t *testing.T) {
	r := testRelay("http://127.0.0.1:1/audit/report")
	big := strings.Repeat("a", maxBatchBytes+10)
	req := httptest.NewRequest(http.MethodPost, "/audit/batch", strings.NewReader(big))
	w := httptest.NewRecorder()
	r.handleBatch(w, req)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("期望 413，实际 %d", w.Code)
	}
	if r.dropped.Load() != 1 {
		t.Fatalf("超限须计入 dropped，实际 %d", r.dropped.Load())
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
		t.Fatalf("期望 502+dropped=1，实际 code=%d dropped=%d forwarded=%d",
			w.Code, r.dropped.Load(), r.forwarded.Load())
	}
}

func TestMetricsExposesCounters(t *testing.T) {
	r := testRelay("http://127.0.0.1:1/audit/report")
	r.dropped.Add(2)
	w := httptest.NewRecorder()
	r.handleMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{"audit_sign_relay_dropped_total 2", "audit_sign_relay_failed_total", "audit_sign_relay_upstream_last_status"} {
		if !strings.Contains(body, want) {
			t.Fatalf("指标缺 %q：\n%s", want, body)
		}
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
	if w.Code != http.StatusBadRequest || r.dropped.Load() != 1 {
		t.Fatalf("期望 400+dropped=1，实际 code=%d dropped=%d", w.Code, r.dropped.Load())
	}
	// 响应不得回显原始载荷（防敏感内容回传）
	if strings.Contains(w.Body.String(), "not-json-at-all") {
		t.Fatal("响应回显了原始载荷，存在泄漏风险")
	}
}

func TestHandleBatchUpstreamUnreachableCountsFailed(t *testing.T) {
	// 上游端口不可达 → 重试耗尽 → failed+1（如实计数，不补链）
	r := testRelay("http://127.0.0.1:1/audit/report")
	req := httptest.NewRequest(http.MethodPost, "/audit/batch",
		strings.NewReader(`[{"request_id":"a","result":"rate_limited"}]`))
	w := httptest.NewRecorder()
	r.handleBatch(w, req)
	if w.Code != http.StatusBadGateway || r.failed.Load() != 1 {
		t.Fatalf("期望 502+failed=1，实际 code=%d failed=%d", w.Code, r.failed.Load())
	}
	if r.forwarded.Load() != 0 {
		t.Fatal("不可达时不得计入 forwarded")
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
	t.Setenv("T2C_INT", "-3")
	if got := envIntOr("T2C_INT", 7); got != 7 {
		t.Fatalf("envIntOr 负数应回落缺省，实际 %d", got)
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
	if cfg.Token != "tok-x" {
		t.Fatalf("令牌解析错误: %q", cfg.Token)
	}
}

func TestLoadConfigRequiresToken(t *testing.T) {
	t.Setenv("AUDIT_REPORT_TOKEN", "")
	if _, err := loadConfig(); err == nil {
		t.Fatal("令牌缺失应报错（不得回落管理令牌，A3-11）")
	}
}
