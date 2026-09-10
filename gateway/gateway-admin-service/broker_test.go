// broker_test.go — 内部凭据 broker 单测（apiTokens Secret 化 M1 试点）。
//
// 覆盖（评审处置记录 R-2 扩充清单）：
//  1. Key 覆盖注入：上游收到 Bearer <Key>，入站 Authorization 不透传
//  2. 路径白名单拒绝：白名单外 404 且上游零调用（含 path.Clean 规范化）
//  3. request_id 透传/生成（响应头 + 上游头一致）
//  4. 日志输出不含 Key（含未知 provider/白名单拒绝/正常中转三类路径）
//  5. 未知 provider 404
//  6. 流式就绪静态断言：FlushInterval=-1、statusRecorder 透传 Flusher
//     +  config：缺省白名单/归一化、fail-closed（未启用、缺 Key、坏 JSON）
package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

const testKey = "test-key-DO-NOT-LOG-abc123"

// newTestUpstream 起一个记录请求头的上游 stub。
func newTestUpstream(t *testing.T, handler http.HandlerFunc) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// newTestBroker 构造含 phala provider 的 broker handler。
func newTestBroker(t *testing.T, upstreamURL string) http.Handler {
	t.Helper()
	u, err := url.Parse(upstreamURL)
	if err != nil {
		t.Fatalf("upstream url: %v", err)
	}
	cfg := &brokerConfig{providers: map[string]*brokerProvider{
		"phala": {upstream: u, key: []byte(testKey), allowPathPrefixes: defaultBrokerPathPrefixes},
	}}
	return newBrokerHandler(cfg)
}

// doBroker 直接调用 handler（不经 mux 子树路由，路径为全路径）。
func doBroker(h http.Handler, method, target string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// 1. Key 覆盖注入：入站凭证不透传，上游收到注入 Key。
func TestBrokerInjectsKeyOverInboundAuthorization(t *testing.T) {
	var gotAuth string
	up := newTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	})
	h := newTestBroker(t, up.URL)

	rec := doBroker(h, "POST", "/llm-broker/phala/v1/chat/completions",
		map[string]string{"Authorization": "Bearer inbound-client-junk"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if gotAuth != "Bearer "+testKey {
		t.Fatalf("upstream Authorization = %q, want injected key (inbound credential must be overwritten)", gotAuth)
	}
}

// 2. 白名单拒绝：404 + 上游零调用；白名单内正常放行（对照）。
func TestBrokerRejectsPathOutsideAllowlist(t *testing.T) {
	called := false
	up := newTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := newTestBroker(t, up.URL)

	rec := doBroker(h, "GET", "/llm-broker/phala/v1/files", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 path_denied", rec.Code)
	}
	if called {
		t.Fatal("upstream must not be called for denied path")
	}

	// 路径规范化：.. 穿越折叠后命中白名单前缀的形态不放行白名单外端点
	rec = doBroker(h, "GET", "/llm-broker/phala/v1/chat/completions/../../files", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("cleaned traversal status = %d, want 404", rec.Code)
	}
	if called {
		t.Fatal("upstream must not be called for cleaned traversal path")
	}

	// 指标断言：path_denied 系列已落（全局 metrics，含断言前缀即可）
	var buf bytes.Buffer
	metrics.render(&buf)
	if !strings.Contains(buf.String(), `reason="path_denied"`) {
		t.Fatalf("metrics missing path_denied series:\n%s", buf.String())
	}
}

// 3. request_id：透传入站值（响应头与上游头一致）；缺省时生成非空值。
func TestBrokerRequestIDPassthroughAndGeneration(t *testing.T) {
	var gotRID1, gotRID2 string
	up := newTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if gotRID1 == "" {
			gotRID1 = r.Header.Get("X-Request-ID")
		} else {
			gotRID2 = r.Header.Get("X-Request-ID")
		}
		w.WriteHeader(http.StatusOK)
	})
	h := newTestBroker(t, up.URL)

	rec := doBroker(h, "POST", "/llm-broker/phala/v1/chat/completions",
		map[string]string{"X-Request-ID": "rid-fixed-1234"})
	if gotRID1 != "rid-fixed-1234" {
		t.Fatalf("upstream rid = %q, want passthrough", gotRID1)
	}
	if rec.Header().Get("X-Request-ID") != "rid-fixed-1234" {
		t.Fatalf("response rid = %q, want passthrough", rec.Header().Get("X-Request-ID"))
	}

	rec2 := doBroker(h, "POST", "/llm-broker/phala/v1/chat/completions", nil)
	gen := rec2.Header().Get("X-Request-ID")
	if gen == "" || gotRID2 == "" || gen != gotRID2 {
		t.Fatalf("generated rid mismatch: resp=%q upstream=%q", gen, gotRID2)
	}
}

// 4. 日志绝不含 Key（未知 provider / 白名单拒绝 / 正常中转三类路径）。
func TestBrokerLogNeverContainsKey(t *testing.T) {
	var buf bytes.Buffer
	old := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(old)

	up := newTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	h := newTestBroker(t, up.URL)

	_ = doBroker(h, "POST", "/llm-broker/phala/v1/chat/completions", nil)
	_ = doBroker(h, "GET", "/llm-broker/phala/v1/files", nil)
	_ = doBroker(h, "GET", "/llm-broker/unknown/v1/models", nil)

	if strings.Contains(buf.String(), testKey) {
		t.Fatalf("log leaked key:\n%s", buf.String())
	}
}

// 5. 未知 provider：404 且不触上游。
func TestBrokerUnknownProvider404(t *testing.T) {
	called := false
	up := newTestUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h := newTestBroker(t, up.URL)

	rec := doBroker(h, "GET", "/llm-broker/nope/v1/models", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 provider_unknown", rec.Code)
	}
	if called {
		t.Fatal("upstream must not be called for unknown provider")
	}
}

// 6. 流式就绪静态断言：FlushInterval=-1（检查表②）与 Flusher 透传。
func TestBrokerStreamingReady(t *testing.T) {
	h := newTestBroker(t, "http://upstream.invalid")
	bh, ok := h.(*brokerHandler)
	if !ok {
		t.Fatalf("handler type = %T", h)
	}
	for name, route := range bh.currentRoutes() {
		if route.proxy.FlushInterval != -1 {
			t.Fatalf("provider %s FlushInterval = %v, want -1", name, route.proxy.FlushInterval)
		}
	}
	// statusRecorder 必须满足 http.Flusher，否则 ReverseProxy 的逐帧 flush 退化缓冲
	var _ http.Flusher = &statusRecorder{ResponseWriter: httptest.NewRecorder()}
}

// ---------- config ----------

// 特性默认关闭：未设置 ADMIN_BROKER_PROVIDERS_JSON 返回 nil，零影响既有行为。
func TestLoadBrokerConfigDisabledByDefault(t *testing.T) {
	t.Setenv("ADMIN_BROKER_PROVIDERS_JSON", "")
	cfg, err := loadBrokerConfig()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if cfg != nil {
		t.Fatal("want nil config when env unset")
	}
}

// fail-closed：provider 已声明但 Key 缺失 → 拒绝启动。
func TestLoadBrokerConfigFailClosedOnMissingKey(t *testing.T) {
	t.Setenv("ADMIN_BROKER_PROVIDERS_JSON", `{"phala":{"upstream":"https://inference.phala.com"}}`)
	t.Setenv("ADMIN_BROKER_KEY_PHALA", "")
	if _, err := loadBrokerConfig(); err == nil {
		t.Fatal("want fail-closed error when provider key missing")
	}
}

// fail-closed：坏 JSON → 拒绝启动。
func TestLoadBrokerConfigFailClosedOnBadJSON(t *testing.T) {
	t.Setenv("ADMIN_BROKER_PROVIDERS_JSON", `{"phala":`)
	if _, err := loadBrokerConfig(); err == nil {
		t.Fatal("want fail-closed error on malformed JSON")
	}
}

// 缺省白名单注入 + 显式前缀归一化（去尾 /）。
// 注：M2 A-1 起 upstream 默认仅允许 https（http 需显式 ADMIN_BROKER_ALLOW_HTTP），故此处用 https。
func TestLoadBrokerConfigDefaultsAndNormalization(t *testing.T) {
	t.Setenv("ADMIN_BROKER_PROVIDERS_JSON",
		`{"phala":{"upstream":"https://inference.phala.com"},"two":{"upstream":"https://10.0.0.1:9000","allowPathPrefixes":["/v1/files/"]}}`)
	t.Setenv("ADMIN_BROKER_KEY_PHALA", testKey)
	t.Setenv("ADMIN_BROKER_KEY_TWO", testKey)

	cfg, err := loadBrokerConfig()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	p := cfg.providers["phala"]
	if p == nil || len(p.allowPathPrefixes) != len(defaultBrokerPathPrefixes) {
		t.Fatalf("phala prefixes = %v, want defaults", p)
	}
	q := cfg.providers["two"]
	if q == nil || len(q.allowPathPrefixes) != 1 || q.allowPathPrefixes[0] != "/v1/files" {
		t.Fatalf("two prefixes = %v, want [/v1/files]", q)
	}
}
