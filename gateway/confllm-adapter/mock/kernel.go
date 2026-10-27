// Package mock 通用 OpenAI 兼容 mock 内核（httptest）+ 离线保护 Transport + proxy 桩。
//
// 设计依据：§1.4 / §7.4 / §7.9。Mock 仅走 loopback，不触外网（离线可跑，QA-4/QA-5）。
//
// mock 内核同时接受多套路径（/v1、/api/v3、/openai/v1 及 NEAR 的 /v1/model/list），
// 以免「路径写错仍全绿」；真实路径由 contract_test 的 golden request 锁定（§7.4）。
package mock

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"
)

// Fixture 单个 mock 场景（§7.4）。
type Fixture struct {
	Scenario   string
	StatusCode int
	Body       []byte
	Delay      time.Duration // 模拟延迟/超时（配合短 context → upstream_timeout）
	Stream     bool          // true=以 SSE 帧返回 Body
	RetryAfter string        // 429 时设置的 Retry-After
}

// chatPaths / modelsPaths mock 内核接受的上游路径（覆盖各厂差异，§7.4）。
var (
	chatPaths = []string{
		"/v1/chat/completions",
		"/api/v3/chat/completions",
		"/openai/v1/chat/completions",
	}
	modelsPaths = []string{
		"/v1/models",
		"/v1/model/list", // NEAR 真实模型列表路径（反例锁定，§7.4 QA2-13/14）
		"/api/v3/models",
		"/openai/v1/models",
	}
)

// Kernel 通用 OpenAI 兼容 mock 内核。
type Kernel struct {
	srv      *httptest.Server
	mu       sync.RWMutex
	fixtures map[string]Fixture
}

// NewKernel 构造 mock 内核（注入差异 fixture；缺省场景自动补齐）。
func NewKernel(fixtures []Fixture) *Kernel {
	k := &Kernel{fixtures: make(map[string]Fixture)}
	for _, f := range fixtures {
		k.fixtures[f.Scenario] = f
	}
	ensure := func(f Fixture) {
		if _, ok := k.fixtures[f.Scenario]; !ok {
			k.fixtures[f.Scenario] = f
		}
	}
	ensure(Fixture{Scenario: "chat_ok", StatusCode: 200, Body: []byte(defaultChatOK)})
	ensure(Fixture{Scenario: "chat_stream", StatusCode: 200, Stream: true, Body: []byte(defaultStream)})
	ensure(Fixture{Scenario: "list", StatusCode: 200, Body: []byte(defaultList)})
	ensure(Fixture{Scenario: "auth_401", StatusCode: 401, Body: []byte(default401)})
	ensure(Fixture{Scenario: "rate_429", StatusCode: 429, RetryAfter: "1", Body: []byte(default429)})
	ensure(Fixture{Scenario: "timeout", StatusCode: 200, Delay: 2 * time.Second, Body: []byte(defaultChatOK)})

	mux := http.NewServeMux()
	for _, p := range chatPaths {
		mux.HandleFunc(p, k.handleChat)
	}
	for _, p := range modelsPaths {
		mux.HandleFunc(p, k.handleModels)
	}
	k.srv = httptest.NewServer(mux)
	return k
}

// URL 返回内核 loopback 地址（注入 ProviderConfig.Endpoint）。
func (k *Kernel) URL() string { return k.srv.URL }

// Close 释放内核。
func (k *Kernel) Close() { k.srv.Close() }

func (k *Kernel) fixtureFor(r *http.Request) Fixture {
	scenario := r.Header.Get("X-Mock-Scenario")
	if scenario == "" {
		scenario = "chat_ok"
	}
	k.mu.RLock()
	defer k.mu.RUnlock()
	if f, ok := k.fixtures[scenario]; ok {
		return f
	}
	return k.fixtures["chat_ok"]
}

func (k *Kernel) handleChat(w http.ResponseWriter, r *http.Request) {
	f := k.fixtureFor(r)
	if f.Delay > 0 {
		time.Sleep(f.Delay)
	}
	if f.StatusCode != 200 {
		if f.RetryAfter != "" {
			w.Header().Set("Retry-After", f.RetryAfter)
		}
		w.WriteHeader(f.StatusCode)
		_, _ = w.Write(f.Body)
		return
	}
	if f.Stream {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, string(f.Body))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(f.Body)
}

func (k *Kernel) handleModels(w http.ResponseWriter, r *http.Request) {
	k.mu.RLock()
	f := k.fixtures["list"]
	k.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(f.StatusCode)
	_, _ = w.Write(f.Body)
}

// ---------- 离线保护 Transport（§7.9 可判定版）----------

// egressAttempts 被拦截的非 loopback 出网尝试累计次数（供 TestMain 断言 ==0）。
var egressAttempts int64

// OfflineTransport 强制离线的 http.RoundTripper 实现。
//
//   - Proxy 显式 nil（防 HTTP_PROXY/HTTPS_PROXY 绕过，§7.9-1）；
//   - DialContext 白名单仅 127.0.0.0/8 与 ::1（0.0.0.0 不在白名单，§7.9-2）；
//   - 非 loopback 一律拒绝（计入 EgressAttempts），错误含 "offline guard"（§7.9-5）。
type OfflineTransport struct {
	scenario string // 非空时注入 X-Mock-Scenario 头（驱动 mock 内核选 fixture，仍为离线 transport）
	rt       *http.Transport
}

// NewOfflineTransport 构造离线 Transport。
//
// 命名说明：Go 不允许 type 与 func 同名，故构造函数用 New* 前缀；语义等同设计 §7.9 的
// 「mock.OfflineTransport()」，返回类型即 *OfflineTransport（供 contract_test 类型断言）。
func NewOfflineTransport() *OfflineTransport {
	return &OfflineTransport{
		rt: &http.Transport{
			Proxy: nil, // §7.9-1：显式禁用代理
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				host, _, err := net.SplitHostPort(addr)
				if err != nil {
					host = addr
				}
				if isLoopback(host) {
					return (&net.Dialer{}).DialContext(ctx, network, addr)
				}
				atomic.AddInt64(&egressAttempts, 1)
				return nil, fmt.Errorf("offline guard: 拒绝连接非 loopback 地址 %s（强制离线）", addr)
			},
		},
	}
}

// NewOfflineScenarioTransport 构造「离线 + 注入场景头」的 Transport（仍为 *OfflineTransport）。
// scenario 非空时对每个出站请求注入 X-Mock-Scenario，驱动 mock 内核选差异 fixture。
func NewOfflineScenarioTransport(scenario string) *OfflineTransport {
	t := NewOfflineTransport()
	t.scenario = scenario
	return t
}

// RoundTrip 实现 http.RoundTripper（注入场景头后委托底层离线 transport）。
func (t *OfflineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.scenario != "" {
		req.Header.Set("X-Mock-Scenario", t.scenario)
	}
	return t.rt.RoundTrip(req)
}

// EgressAttempts 返回被离线保护拦截的非 loopback 出网尝试次数（§7.9-3）。
func EgressAttempts() int64 { return atomic.LoadInt64(&egressAttempts) }

// ResetEgressAttempts 清零计数（负向用例断言后调用，避免污染 TestMain 的 ==0 断言）。
func ResetEgressAttempts() { atomic.StoreInt64(&egressAttempts, 0) }

// isLoopback 仅 127.0.0.0/8 与 ::1（0.0.0.0 不在白名单，§7.9-2）。
func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}
