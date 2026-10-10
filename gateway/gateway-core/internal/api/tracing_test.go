// P1-2：控制面 tracing 单测（core.route.change span 创建、属性、关闭时零 span）。
package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

// setCoreTracer 覆写全局 tracing 运行态（测试用），返回恢复函数。
func setCoreTracer(tp *sdktrace.TracerProvider, enabled bool) func() {
	coreTracing.mu.Lock()
	origTracer, origEnabled, origProvider := coreTracing.tracer, coreTracing.enabled, coreTracing.provider
	if tp != nil {
		coreTracing.tracer = tp.Tracer(coreTracingServiceName)
	}
	coreTracing.enabled = enabled
	coreTracing.mu.Unlock()
	return func() {
		coreTracing.mu.Lock()
		coreTracing.tracer, coreTracing.enabled, coreTracing.provider = origTracer, origEnabled, origProvider
		coreTracing.mu.Unlock()
	}
}

// TestWithRouteChangeSpan_EmitsSpan 验证启用时创建 core.route.change span 及属性。
func TestWithRouteChangeSpan_EmitsSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()
	restore := setCoreTracer(tp, true)
	defer restore()

	s := &Server{}
	h := s.withRouteChangeSpan("upsert", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodPut, "/routes/tenant-a/qwen-plus", nil)
	req.SetPathValue("tenant", "tenant-a")
	req.SetPathValue("model", "qwen-plus")
	rr := httptest.NewRecorder()
	h(rr, req)
	_ = tp.ForceFlush(context.Background())

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("期望 1 条 span，实际 %d", len(spans))
	}
	if spans[0].Name != spanNameRouteChange {
		t.Errorf("span 名应为 %q，实际 %q", spanNameRouteChange, spans[0].Name)
	}
	got := map[string]string{}
	for _, a := range spans[0].Attributes {
		got[string(a.Key)] = a.Value.Emit()
	}
	if got["change.type"] != "upsert" {
		t.Errorf("change.type 应为 upsert，实际 %q", got["change.type"])
	}
	if got["route.name"] != "tenant-a/qwen-plus" {
		t.Errorf("route.name 应为 tenant-a/qwen-plus，实际 %q", got["route.name"])
	}
	if got["tenant.id"] != "tenant-a" {
		t.Errorf("tenant.id 应为 tenant-a，实际 %q", got["tenant.id"])
	}
	if got["result"] != "ok" {
		t.Errorf("result 应为 ok，实际 %q", got["result"])
	}
	if got["http.status_code"] != "200" {
		t.Errorf("http.status_code 应为 200，实际 %q", got["http.status_code"])
	}
}

// TestWithRouteChangeSpan_ErrorStatus 验证 4xx/5xx 时 result=error。
func TestWithRouteChangeSpan_ErrorStatus(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()
	restore := setCoreTracer(tp, true)
	defer restore()

	s := &Server{}
	h := s.withRouteChangeSpan("delete", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusConflict)
	})
	req := httptest.NewRequest(http.MethodDelete, "/routes/t/m", nil)
	h(httptest.NewRecorder(), req)
	_ = tp.ForceFlush(context.Background())

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("期望 1 条 span，实际 %d", len(spans))
	}
	got := map[string]string{}
	for _, a := range spans[0].Attributes {
		got[string(a.Key)] = a.Value.Emit()
	}
	if got["result"] != "error" {
		t.Errorf("4xx 应记 result=error，实际 %q", got["result"])
	}
}

// TestWithRouteChangeSpan_DisabledNoSpan 验证 tracing 关闭时不创建 span（零开销）。
func TestWithRouteChangeSpan_DisabledNoSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()
	// tracer 存在但 enabled=false → 应直接透传，不创建 span
	coreTracing.mu.Lock()
	origTracer, origEnabled := coreTracing.tracer, coreTracing.enabled
	coreTracing.tracer, coreTracing.enabled = tp.Tracer(coreTracingServiceName), false
	coreTracing.mu.Unlock()
	defer func() {
		coreTracing.mu.Lock()
		coreTracing.tracer, coreTracing.enabled = origTracer, origEnabled
		coreTracing.mu.Unlock()
	}()

	s := &Server{}
	called := false
	h := s.withRouteChangeSpan("upsert", func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	h(httptest.NewRecorder(), httptest.NewRequest(http.MethodPut, "/routes/t/m", nil))
	_ = tp.ForceFlush(context.Background())

	if !called {
		t.Fatal("关闭时内层 handler 应被调用")
	}
	if n := len(exp.GetSpans()); n != 0 {
		t.Fatalf("关闭时不应创建 span，实际 %d", n)
	}
	// 恢复默认 NoOp（避免影响后续用例）
	coreTracing.mu.Lock()
	coreTracing.tracer = noop.Tracer{}
	coreTracing.mu.Unlock()
}

// saveCoreTracing 保存并恢复 core 包 tracing 全局态，供切换 TRACING_ENABLED 的用例使用（C-4）。
func saveCoreTracing(t *testing.T) {
	t.Helper()
	coreTracing.mu.Lock()
	origEnabled := coreTracing.enabled
	origProvider := coreTracing.provider
	origTracer := coreTracing.tracer
	coreTracing.mu.Unlock()
	t.Cleanup(func() {
		coreTracing.mu.Lock()
		coreTracing.enabled = origEnabled
		coreTracing.provider = origProvider
		coreTracing.tracer = origTracer
		coreTracing.mu.Unlock()
	})
}

// TestInitTracing_DisabledNoop 验证 TRACING_ENABLED != "true" 时装配 NoOp（零开销，C-4）。
func TestInitTracing_DisabledNoop(t *testing.T) {
	saveCoreTracing(t)
	t.Setenv("TRACING_ENABLED", "false")

	if err := InitTracing(); err != nil {
		t.Fatalf("关闭态初始化不应报错：%v", err)
	}
	if coreTracingEnabled() {
		t.Error("关闭态 coreTracingEnabled 应为 false")
	}
	if _, ok := coreTracer().(noop.Tracer); !ok {
		t.Error("关闭态 tracer 应为 NoOp")
	}
	if coreTracing.provider != nil {
		t.Error("关闭态 provider 应为 nil")
	}
}

// TestInitTracing_EnabledLazyProvider 验证启用态装配真实 provider；OTLP 出口惰性连接，
// 不可达端点不阻塞初始化（D-3 / §7.4）。
func TestInitTracing_EnabledLazyProvider(t *testing.T) {
	saveCoreTracing(t)
	t.Setenv("TRACING_ENABLED", "true")
	t.Setenv("TRACING_OTLP_ENDPOINT", "") // 空 → 走默认 endpoint（不可达，验证惰性初始化不阻塞）
	t.Setenv("TRACING_TLS_INSECURE", "true")

	if err := InitTracing(); err != nil {
		t.Fatalf("启用态装配不应失败（惰性连接）：%v", err)
	}
	if !coreTracingEnabled() {
		t.Error("启用态 coreTracingEnabled 应为 true")
	}
	if coreTracing.provider == nil {
		t.Error("启用态 provider 不应为 nil")
	}
	if _, ok := coreTracer().(noop.Tracer); ok {
		t.Error("启用态 tracer 不应为 NoOp")
	}
	ShutdownTracing() // 覆盖非 nil provider 分支
}

// TestShutdownTracing_ResetsToNoop 验证 Shutdown 复位为关闭态且可幂等重复调用。
func TestShutdownTracing_ResetsToNoop(t *testing.T) {
	saveCoreTracing(t)

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
	coreTracing.mu.Lock()
	coreTracing.provider = tp
	coreTracing.tracer = tp.Tracer(coreTracingServiceName)
	coreTracing.enabled = true
	coreTracing.mu.Unlock()

	ShutdownTracing()
	if coreTracingEnabled() || coreTracing.provider != nil {
		t.Fatal("Shutdown 后应复位为关闭态")
	}
	if _, ok := coreTracer().(noop.Tracer); !ok {
		t.Fatal("Shutdown 后 tracer 应为 NoOp")
	}
	ShutdownTracing() // 幂等：provider 为 nil 时不应 panic
}

// TestStatusRecorder_Write 验证未显式 WriteHeader 时 Write 记 200，已设码时保持原码。
func TestStatusRecorder_Write(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &statusRecorder{ResponseWriter: rec}
	n, err := sr.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write 异常：n=%d err=%v", n, err)
	}
	if sr.code != http.StatusOK {
		t.Errorf("未显式 WriteHeader 时 code 应为 200，实际 %d", sr.code)
	}
	if rec.Body.String() != "hello" {
		t.Errorf("响应体应透传，实际 %q", rec.Body.String())
	}

	rec2 := httptest.NewRecorder()
	sr2 := &statusRecorder{ResponseWriter: rec2, code: http.StatusCreated}
	if _, err := sr2.Write([]byte("x")); err != nil {
		t.Fatalf("Write 异常：%v", err)
	}
	if sr2.code != http.StatusCreated {
		t.Errorf("已设码时不应被覆盖，实际 %d", sr2.code)
	}
}
