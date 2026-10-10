// P1-2：tracing 单元测试（脱敏白名单、上下文透传、上游头剥离、审计关联）。
package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"go.opentelemetry.io/otel"
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

// saveTeeTracing 保存并恢复 tee 包 tracing 全局态（含 otel 全局 provider/propagator）。
// 供切换 TRACING_ENABLED 的用例在结束后恢复，避免污染同包其它用例（C-4/C-8）。
func saveTeeTracing(t *testing.T) {
	t.Helper()
	globalTracing.mu.Lock()
	origEnabled := globalTracing.enabled
	origProvider := globalTracing.provider
	origTracer := globalTracing.tracer
	origTransport := globalTracing.stripTransport
	globalTracing.mu.Unlock()
	origTP := otel.GetTracerProvider()
	origProp := otel.GetTextMapPropagator()
	t.Cleanup(func() {
		globalTracing.mu.Lock()
		globalTracing.enabled = origEnabled
		globalTracing.provider = origProvider
		globalTracing.tracer = origTracer
		globalTracing.stripTransport = origTransport
		globalTracing.mu.Unlock()
		otel.SetTracerProvider(origTP)
		otel.SetTextMapPropagator(origProp)
	})
}

// TestInitTracing_Disabled 验证 TRACING_ENABLED != "true" 时装配 NoOp（零开销，C-4/C-8）。
func TestInitTracing_Disabled(t *testing.T) {
	saveTeeTracing(t)
	t.Setenv("TRACING_ENABLED", "false")

	if err := initTracing(); err != nil {
		t.Fatalf("关闭态初始化不应报错：%v", err)
	}
	if tracingEnabled() {
		t.Error("关闭态 tracingEnabled 应为 false")
	}
	if _, ok := tracer().(noop.Tracer); !ok {
		t.Error("关闭态 tracer 应为 NoOp")
	}
	if globalTracing.provider != nil {
		t.Error("关闭态 provider 应为 nil")
	}
	if upstreamTransport() != http.DefaultTransport {
		t.Error("关闭态上游传输应为默认传输（不剥离）")
	}
}

// TestInitTracing_EnabledLazyProvider 验证启用态装配真实 provider + 剥离传输；
// OTLP 出口惰性连接，不可达端点不阻塞；并覆盖 insecure 分支（§6.2 / D-3）。
func TestInitTracing_EnabledLazyProvider(t *testing.T) {
	saveTeeTracing(t)
	t.Setenv("TRACING_ENABLED", "true")
	t.Setenv("TRACING_OTLP_ENDPOINT", "") // 空 → 走默认 endpoint 分支
	t.Setenv("TRACING_TLS_INSECURE", "true")

	if err := initTracing(); err != nil {
		t.Fatalf("启用态装配不应失败（惰性连接）：%v", err)
	}
	if !tracingEnabled() {
		t.Error("启用态 tracingEnabled 应为 true")
	}
	if globalTracing.provider == nil {
		t.Error("启用态 provider 不应为 nil")
	}
	if _, ok := tracer().(noop.Tracer); ok {
		t.Error("启用态 tracer 不应为 NoOp")
	}
	if _, ok := upstreamTransport().(*stripTraceHeadersTransport); !ok {
		t.Errorf("启用态上游传输应为剥离传输，实际 %T", upstreamTransport())
	}

	// shutdownTracing：覆盖非 nil provider 分支 + 复位
	shutdownTracing()
	if tracingEnabled() || globalTracing.provider != nil {
		t.Fatal("shutdown 后应复位为关闭态")
	}
	if _, ok := tracer().(noop.Tracer); !ok {
		t.Fatal("shutdown 后 tracer 应为 NoOp")
	}
	shutdownTracing() // 幂等：provider 为 nil 时不应 panic
}

// stubRoundTripper 记录收到的请求并返回固定响应（用于直接驱动 RoundTrip，不依赖真实网络）。
type stubRoundTripper struct{ got *http.Request }

func (s *stubRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	s.got = req
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("ok")),
	}, nil
}

// TestStripTraceHeadersTransport_NilHeaderDirect 验证 Header 为 nil 时直接透传、不 panic（§6.4 边界）。
func TestStripTraceHeadersTransport_NilHeaderDirect(t *testing.T) {
	stub := &stubRoundTripper{}
	tr := &stripTraceHeadersTransport{base: stub}
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "http", Host: "upstream.local"}, Header: nil}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		t.Fatalf("nil header 不应报错：%v", err)
	}
	_ = resp.Body.Close()
	if stub.got != req {
		t.Error("nil header 时应原样透传请求")
	}
}

// TestStripTraceHeadersTransport_NonCanonicalVariants 验证非规范大小写键驱动循环内删除分支（§6.4）。
func TestStripTraceHeadersTransport_NonCanonicalVariants(t *testing.T) {
	stub := &stubRoundTripper{}
	tr := &stripTraceHeadersTransport{base: stub}
	req := &http.Request{Method: http.MethodGet, URL: &url.URL{Scheme: "http", Host: "u.local"}, Header: http.Header{}}
	// 绕过 Header.Set 的规范化，构造非规范大小写键以进入兼容循环
	req.Header["TraceParent"] = []string{"00-abc-def-01"}
	req.Header["X-Request-Id"] = []string{"rid"} // 规范键：初始 Del 即删
	req.Header["Content-Type"] = []string{"application/json"}

	if _, err := tr.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip 失败：%v", err)
	}
	if stub.got.Header.Get("X-Request-Id") != "" {
		t.Error("X-Request-Id 应被剥离")
	}
	if stub.got.Header.Get("Content-Type") != "application/json" {
		t.Error("Content-Type 不应被剥离")
	}
	// 原始请求不被修改（Clone 语义）
	if req.Header.Get("X-Request-Id") != "rid" {
		t.Error("原始请求头不应被修改")
	}
}

// TestStartUpstreamSpan_RetryEvent 验证重试复用 span、以 is.retry + retry.start 事件区分（§7.4）。
func TestStartUpstreamSpan_RetryEvent(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()

	globalTracing.mu.Lock()
	origTracer, origEnabled := globalTracing.tracer, globalTracing.enabled
	globalTracing.tracer, globalTracing.enabled = tp.Tracer(tracingServiceName), true
	globalTracing.mu.Unlock()
	defer func() {
		globalTracing.mu.Lock()
		globalTracing.tracer, globalTracing.enabled = origTracer, origEnabled
		globalTracing.mu.Unlock()
	}()

	_, span := startUpstreamSpan(context.Background(), 123, true, "0123456789abcdef")
	span.End()
	_ = tp.ForceFlush(context.Background())

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("期望 1 条 span，实际 %d", len(spans))
	}
	if spans[0].Name != "upstream.model.call" {
		t.Errorf("span 名异常：%q", spans[0].Name)
	}
	got := map[string]string{}
	for _, a := range spans[0].Attributes {
		got[string(a.Key)] = a.Value.Emit()
	}
	if got["is.retry"] != "true" {
		t.Errorf("is.retry 应为 true，实际 %q", got["is.retry"])
	}
	if got["input.digest"] != "0123456789abcdef" {
		t.Errorf("input.digest 异常：%q", got["input.digest"])
	}
	retryEvent := false
	for _, e := range spans[0].Events {
		if e.Name == "retry.start" {
			retryEvent = true
		}
	}
	if !retryEvent {
		t.Error("重试应记录 retry.start 事件")
	}
}

// TestSanitizingSpanProcessor_OnEndStrictPanics 验证 strict 模式 OnEnd 对非白名单属性 panic（D-4 二次校验）。
func TestSanitizingSpanProcessor_OnEndStrictPanics(t *testing.T) {
	p := &SanitizingSpanProcessor{Strict: true}
	stub := tracetest.SpanStub{
		Name:       "guardrail.check",
		Attributes: []attribute.KeyValue{attribute.String("prompt", "secret")},
	}
	defer func() {
		if r := recover(); r == nil {
			t.Error("OnEnd strict 下非白名单属性应触发 panic")
		}
	}()
	p.OnEnd(stub.Snapshot())
}
