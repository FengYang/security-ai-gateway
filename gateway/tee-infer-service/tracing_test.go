// P1-2：tracing 单元测试（脱敏白名单、上下文透传、上游头剥离、审计关联）。
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// TestSanitizingSpanProcessor_StrictPanics 验证 strict 模式下非白名单属性触发 panic。
func TestSanitizingSpanProcessor_StrictPanics(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(&SanitizingSpanProcessor{Strict: true}),
		sdktrace.WithBatcher(exporter),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tr := tp.Tracer("test")

	defer func() {
		if r := recover(); r == nil {
			t.Error("strict 模式下非白名单属性应触发 panic")
		}
	}()
	_, span := tr.Start(context.Background(), "test-sensitive",
		trace.WithAttributes(
			attribute.String("tenant.id", "t-001"), // 白名单
			attribute.String("prompt", "敏感内容"),     // 非白名单 → panic
		),
	)
	span.End()
	_ = tp.ForceFlush(context.Background())
}

// TestSanitizingSpanProcessor_NonStrictNoPanic 验证非 strict 模式不 panic（Collector 兜底）。
func TestSanitizingSpanProcessor_NonStrictNoPanic(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(&SanitizingSpanProcessor{Strict: false}),
		sdktrace.WithBatcher(exporter),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tr := tp.Tracer("test")
	// 不应 panic
	_, span := tr.Start(context.Background(), "test-nonstrict",
		trace.WithAttributes(
			attribute.String("tenant.id", "t-001"),
			attribute.String("prompt", "敏感内容"), // 非白名单，不 panic（Collector 兜底）
		),
	)
	span.End()
	_ = tp.ForceFlush(context.Background())

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("期望 1 条 span，实际 %d", len(spans))
	}
}

// TestSanitizingSpanProcessor_StrictPassesAllowed 验证 strict 模式下全白名单属性正常通过。
func TestSanitizingSpanProcessor_StrictPassesAllowed(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(&SanitizingSpanProcessor{Strict: true}),
		sdktrace.WithBatcher(exporter),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	tr := tp.Tracer("test")
	_, span := tr.Start(context.Background(), "test-allowed",
		trace.WithAttributes(
			attribute.String("tenant.id", "t-001"),
			attribute.String("request.id", "req-123"),
			attribute.String("model.id", "qwen-max"),
			attribute.String("engine.type", "tee_gpu"),
			attribute.Bool("cache.hit", true),
			attribute.String("cache.mode", "semantic"),
			attribute.Int("tokens.in", 512),
			attribute.Int("tokens.out", 256),
			attribute.String("result", "ok"),
			attribute.String("og.category", "pii"),
			attribute.String("og.mode", "enforcing"),
			attribute.Bool("is.retry", false),
			attribute.Int("http.status_code", 200),
			attribute.Float64("ttft.ms", 210.5),
			attribute.String("input.digest", "abc123"),
			attribute.String("output.digest", "def456"),
		),
	)
	span.End()
	_ = tp.ForceFlush(context.Background())

	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("期望 1 条 span，实际 %d", len(spans))
	}
	// 所有属性都是白名单的，不应 panic，且属性数量应匹配（16 个）
	if len(spans[0].Attributes) < 16 {
		t.Errorf("白名单属性数量不足：期望至少 16，实际 %d", len(spans[0].Attributes))
	}
}

// TestHelperSpans_AllAttributesAllowed 验证所有辅助函数设置的属性均在白名单内。
// 模拟业务调用链，最终用 strict processor 校验（若有非白名单属性会 panic 失败）。
func TestHelperSpans_AllAttributesAllowed(t *testing.T) {
	// 用 strict processor 验证：辅助函数产生的所有属性都是白名单属性
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithSpanProcessor(&SanitizingSpanProcessor{Strict: true}),
		sdktrace.WithBatcher(exporter),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	// 先把全局 tracer 替换为测试用的，避免 NoOp
	globalTracing.mu.Lock()
	origTracer := globalTracing.tracer
	origEnabled := globalTracing.enabled
	globalTracing.tracer = tp.Tracer(tracingServiceName)
	globalTracing.enabled = true
	globalTracing.mu.Unlock()
	defer func() {
		globalTracing.mu.Lock()
		globalTracing.tracer = origTracer
		globalTracing.enabled = origEnabled
		globalTracing.mu.Unlock()
	}()

	// 模拟请求（httptest 仅用于构造 request，不实际发请求）
	req := httptest.NewRequest(http.MethodPost, "/infer", nil)
	req.Header.Set("X-Request-Id", "test-req-001")

	// 主 span（模拟业务调用链）
	ctx, mainSpan := startInferSpan(req, "t-001", "req-001", "qwen-max", "tee_cpu")

	// 缓存子 span
	cctx, cspan := startCacheSpan(ctx)
	setCacheHit(cspan, false, "semantic")
	cspan.End()

	// guardrail 子 span
	gctx, gspan := startGuardrailSpan(cctx, "pii", "enforcing")
	setGuardrailDenied(gspan, "credit_card")
	gspan.End()

	// 上游子 span
	uctx, uspan := startUpstreamSpan(gctx, 512, false, "deadbeef12345678")
	setUpstreamResult(uspan, 200, 256, 120.5, "cafebabe87654321")
	observeTTFT(uspan, 120*1000*1000) // 120ms = 120,000,000 ns
	uspan.End()

	endSpanOK(mainSpan)

	_ = tp.ForceFlush(context.Background())

	spans := exporter.GetSpans()
	if len(spans) < 4 {
		t.Fatalf("期望至少 4 条 span（主+缓存+guardrail+上游），实际 %d", len(spans))
	}

	// 逐 span 校验：所有属性都在白名单内
	for i, s := range spans {
		for _, a := range s.Attributes {
			if !isAllowedAttribute(string(a.Key)) {
				t.Errorf("span[%d] %q 含非白名单属性: %s", i, s.Name, a.Key)
			}
		}
	}

	// 校验 trace_id 可提取
	tid := traceIDFromContext(ctx)
	if tid == "" {
		t.Error("startInferSpan 返回的 context 应含有效 trace_id")
	}

	// 确保 context 变量被使用（避免 unused 警告）
	_ = uctx
}

// TestStripTraceHeadersTransport 验证上游出站追踪头被剥离（§6.4 安全约束）。
func TestStripTraceHeadersTransport(t *testing.T) {
	var captured http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	transport := &stripTraceHeadersTransport{base: http.DefaultTransport}
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	req.Header.Set("tracestate", "vendor1=value1")
	req.Header.Set("X-Request-Id", "abc123")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	if captured.Get("traceparent") != "" {
		t.Error("traceparent 应被剥离")
	}
	if captured.Get("tracestate") != "" {
		t.Error("tracestate 应被剥离")
	}
	if captured.Get("X-Request-Id") != "" {
		t.Error("X-Request-Id 应被剥离")
	}
	// 非追踪头应保留
	if captured.Get("Content-Type") != "application/json" {
		t.Error("Content-Type 不应被剥离")
	}
	if captured.Get("Authorization") != "Bearer test" {
		t.Error("Authorization 不应被剥离")
	}
}

// TestStripTraceHeadersTransport_NilHeader 验证 nil header 场景不 panic。
func TestStripTraceHeadersTransport_NilHeader(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	transport := &stripTraceHeadersTransport{base: http.DefaultTransport}
	client := &http.Client{Transport: transport}

	req, _ := http.NewRequest(http.MethodGet, ts.URL, nil)
	req.Header = nil // 模拟空 header

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("期望 200，实际 %d", resp.StatusCode)
	}
}

// TestTraceIDFromContext_Noop 验证 NoOp context 返回空 trace_id。
func TestTraceIDFromContext_Noop(t *testing.T) {
	id := traceIDFromContext(context.Background())
	if id != "" {
		t.Errorf("NoOp context 应返回空 trace_id，实际 %s", id)
	}
}

// TestTraceIDFromContext_Valid 验证有效 span context 提取 trace_id。
func TestTraceIDFromContext_Valid(t *testing.T) {
	exporter := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exporter),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	ctx, span := tp.Tracer("test").Start(context.Background(), "test")
	id := traceIDFromContext(ctx)
	span.End()

	if id == "" {
		t.Error("有效 span context 应返回非空 trace_id")
	}
	if len(id) != 32 {
		t.Errorf("trace_id 应为 32 hex 字符，实际长度 %d", len(id))
	}
	// 验证为 hex
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			t.Errorf("trace_id 含非 hex 字符: %c", c)
			break
		}
	}
}

// TestInputOutputDigest 验证摘要计算：定长 16 hex、不同输入不同摘要。
func TestInputOutputDigest(t *testing.T) {
	// input.digest：与审计 PayloadSHA 同源，取前 16 hex。
	full := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	d1 := inputDigest(full)
	if d1 != full[:16] {
		t.Errorf("input.digest 应为 PayloadSHA 前 16 hex：got %s", d1)
	}
	if len(d1) != 16 {
		t.Errorf("摘要长度应为 16 hex，实际 %d", len(d1))
	}
	// 短摘要不越界
	if got := inputDigest("abc"); got != "abc" {
		t.Errorf("短摘要应原样返回：got %s", got)
	}

	// outputDigest 空串返回空
	if outputDigest("") != "" {
		t.Error("空串输出摘要应为空")
	}

	od1 := outputDigest("test output")
	od2 := outputDigest("test output")
	od3 := outputDigest("different output")
	if od1 != od2 {
		t.Error("相同输出应产生相同摘要")
	}
	if od1 == od3 {
		t.Error("不同输出应产生不同摘要")
	}
	if len(od1) != 16 {
		t.Errorf("输出摘要长度应为 16 hex，实际 %d", len(od1))
	}
}

// TestTracingDisabled_Noop 验证默认 tracing 未启用时 tracer 为 NoOp。
func TestTracingDisabled_Noop(t *testing.T) {
	// 确保全局状态为 disabled（默认）
	globalTracing.mu.RLock()
	enabled := globalTracing.enabled
	tr := globalTracing.tracer
	globalTracing.mu.RUnlock()

	if enabled {
		t.Skip("tracing 已启用，跳过默认 NoOp 测试")
	}
	if _, ok := tr.(noop.Tracer); !ok {
		t.Error("默认禁用时 tracer 应为 NoOp")
	}
}

// TestIsAllowedAttribute 验证白名单判断。
func TestIsAllowedAttribute(t *testing.T) {
	cases := map[string]bool{
		"tenant.id":        true,
		"request.id":       true,
		"model.id":         true,
		"engine.type":      true,
		"cache.hit":        true,
		"cache.mode":       true,
		"tokens.in":        true,
		"tokens.out":       true,
		"result":           true,
		"deny.reason":      true,
		"og.category":      true,
		"og.mode":          true,
		"is.retry":         true,
		"http.status_code": true,
		"ttft.ms":          true,
		"input.digest":     true,
		"output.digest":    true,
		// 非白名单
		"prompt":       false,
		"response":     false,
		"user.email":   false,
		"custom.field": false,
		"":             false,
	}
	for k, expected := range cases {
		got := isAllowedAttribute(k)
		if got != expected {
			t.Errorf("isAllowedAttribute(%q) = %v，期望 %v", k, got, expected)
		}
	}
}
