package a2aproxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// httpRecGet 发起一次 GET 到给定 handler。
func httpRecGet(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
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
