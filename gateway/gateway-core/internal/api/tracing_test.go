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
