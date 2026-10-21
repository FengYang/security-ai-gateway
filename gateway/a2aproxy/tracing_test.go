package a2aproxy

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// httpRecGet 发起一次 GET 到给定 handler。
func httpRecGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// TestRealOTLPCollectorExport 真实 OTLP Collector 端到端导出（VA-603 L-B 取证）。
//
// 默认跳过（CI 无 Collector）；显式设置以下环境变量后运行：
//
//	A2A_OTLP_TEST_ENDPOINT=127.0.0.1:14317  Collector OTLP/gRPC 端点
//	A2A_OTLP_TEST_OUT=<file>                Collector file exporter 输出文件
//
// 判据：经数据面一次 SendMessage 后，Collector 落盘的 span 中出现 a2a.invoke。
func TestRealOTLPCollectorExport(t *testing.T) {
	endpoint := os.Getenv("A2A_OTLP_TEST_ENDPOINT")
	outFile := os.Getenv("A2A_OTLP_TEST_OUT")
	if endpoint == "" || outFile == "" {
		t.Skip("未设置 A2A_OTLP_TEST_ENDPOINT/A2A_OTLP_TEST_OUT，跳过真实 Collector 用例")
	}
	t.Setenv("TRACING_ENABLED", "true")
	t.Setenv("TRACING_OTLP_ENDPOINT", endpoint)
	t.Setenv("TRACING_TLS_INSECURE", "true")
	if err := InitTracing(); err != nil {
		t.Fatalf("InitTracing: %v", err)
	}
	h := newHarness(t)
	_, _ = h.invoke(t, "SendMessage", `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-otlp","role":"ROLE_USER","parts":[{"text":"hello otlp"}]}}}`, nil)
	ShutdownTracing() // flush

	deadline := time.Now().Add(15 * time.Second)
	for {
		raw, err := os.ReadFile(outFile)
		if err == nil && strings.Contains(string(raw), "a2a.invoke") {
			t.Logf("VA-603 真实 Collector 证据：span a2a.invoke 已导出到 %s（数据面响应 %s）", outFile, raw)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("Collector 未在截止时间内导出 a2a.invoke（out=%s）", outFile)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// T-5②：tracing 默认关闭时的行为等价性（零开销、零行为变化，C-4/C-8）。

func TestTracingDisabledNoSpanNoHeader(t *testing.T) {
	if a2aTracingEnabled() {
		t.Skip("TRACING_ENABLED=true 环境下不适用本用例")
	}

	// 1) withTracingSpan 关闭时返回原 handler（不引入任何包装）。
	h := newHarness(t)
	var called bool
	wrapped := h.proxy.withTracingSpan(spanInvoke, func(_ http.ResponseWriter, _ *http.Request) { called = true })
	wrapped(nil, nil) // 直接调用不应 panic 且应触达原逻辑
	if !called {
		t.Error("关闭态下 withTracingSpan 应原样透传到目标 handler")
	}

	// 2) injectTraceContext 关闭时不写入任何传播头。
	hdr := http.Header{}
	injectTraceContext(nil, hdr) //nolint:staticcheck // 关闭态不看 ctx
	if len(hdr) != 0 {
		t.Errorf("关闭态不应注入传播头, got %v", hdr)
	}
}

// TestTracingInitDisabledIsNoop TRACING_ENABLED != true 时 InitTracing 应为幂等空操作
// 且 tracer 保持 NoOp（不创建 exporter/provider）。
func TestTracingInitDisabledIsNoop(t *testing.T) {
	t.Setenv("TRACING_ENABLED", "false")
	if err := InitTracing(); err != nil {
		t.Fatalf("关闭态 InitTracing 不应报错: %v", err)
	}
	if a2aTracingEnabled() {
		t.Error("关闭态 enabled 应为 false")
	}
	a2aTracing.mu.RLock()
	providerNil := a2aTracing.provider == nil
	a2aTracing.mu.RUnlock()
	if !providerNil {
		t.Error("关闭态不应创建 TracerProvider")
	}
	ShutdownTracing()
}

// TestTracingProxyRoutesWork 关闭态下数据面路由与指标端点仍正常（回归兜底）。
func TestTracingProxyRoutesWork(t *testing.T) {
	h := newHarness(t)
	rec := httpRecGet(t, h.proxy.Handler(), "/healthz")
	if rec.Code != http.StatusOK {
		t.Errorf("healthz status = %d, want 200", rec.Code)
	}
}
