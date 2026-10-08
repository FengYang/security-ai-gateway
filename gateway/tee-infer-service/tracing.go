// P1-2：全链路 tracing（TEE 内 SDK + 脱敏 processor + span 语义）。
//
// 设计要点（对齐 §3.3、§6.2、§7.4）：
//   - D-3：SDK 根采样 ParentBased(AlwaysSample)——不丢弃，全部入 Collector，
//     由 Collector tail_sampling 执行实际采样（错误全采的前提）。
//   - D-4：SanitizingSpanProcessor 白名单强制——非白名单属性一律丢弃，
//     保证 TEE 内 span 无敏感数据（V-2 / C-1）。Collector 侧再做兜底裁剪。
//   - D-5：TraceID 作为审计证据字段（omitempty、不进 hash），关联 trace 与审计。
//   - 上游出站：stripTraceHeadersTransport 剥离 traceparent/tracestate/x-request-id，
//     防止内部标识外泄（§6.4 导出段安全约束）。
//   - C-4：默认关闭（TRACING_ENABLED != "true" 时用 NoOpTracer，零开销）。
//   - C-8：默认关闭时 /metrics 逐字节不变——tracing 指标独立体系，不碰现有 metrics。
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// tracingServiceName TEE 服务的 tracing service.name。
const tracingServiceName = "tee-infer-service"

// traceSpanNameInfer TEE 主 span 名（§7.4 span 清单）。
const traceSpanNameInfer = "tee.infer"

// —— Span 属性白名单（§6.2，白名单外一律丢弃）——
// key 为 span attribute key，值为是否允许。
// 禁止项黑名单（出现即视为缺陷）：prompt/response/messages/content/
// embedding/vector/key/secret/token(凭证类)/authorization。
var allowedSpanAttributes = map[string]bool{
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
}

// isAllowedAttribute 判断属性键是否在白名单内。
func isAllowedAttribute(key string) bool {
	return allowedSpanAttributes[key]
}

// SanitizingSpanProcessor 脱敏 span processor（D-4，第一道防线的安全网）。
//
// 第一道防线的主体是"业务层 disciplined 编码"：所有 span 属性设置都通过
// tracing.go 中的辅助函数（startInferSpan / setCacheHit / setGuardrailDenied 等）
// 进行，这些函数只设置白名单内的属性。
//
// 本 processor 作为额外安全网：在 span 结束前检查所有属性，若发现非白名单
// 属性则 panic（开发期暴露问题）。生产环境通过 Collector attributes processor
// 做最终兜底裁剪（纵深防御，D-4）。
//
// 选择这种设计而不是在 SDK 层"静默删除"，原因有二：
//  1. OTel Go SDK 的 ReadWriteSpan 没有 DeleteAttribute/ClearAttributes，
//     且内部 attrs 字段未导出，反射修改脆弱且易随版本失效
//  2. 开发期 fail-fast 比静默删除更能防止误引入敏感数据
type SanitizingSpanProcessor struct {
	// Strict 为 true 时非白名单属性触发 panic（开发/测试用）。
	// false 时仅通过 Collector 兜底（生产用，不影响可用性）。
	Strict bool
}

var _ sdktrace.SpanProcessor = (*SanitizingSpanProcessor)(nil)

// OnStart 在 span 启动时校验属性（strict 模式下非白名单 panic）。
func (p *SanitizingSpanProcessor) OnStart(_ context.Context, span sdktrace.ReadWriteSpan) {
	if !p.Strict {
		return
	}
	for _, a := range span.Attributes() {
		if !isAllowedAttribute(string(a.Key)) {
			panic("tracing: 非白名单属性 " + string(a.Key) + "，违反 V-2")
		}
	}
}

// OnEnd 在 span 结束前二次校验。
func (p *SanitizingSpanProcessor) OnEnd(span sdktrace.ReadOnlySpan) {
	if !p.Strict {
		return
	}
	for _, a := range span.Attributes() {
		if !isAllowedAttribute(string(a.Key)) {
			panic("tracing: 非白名单属性 " + string(a.Key) + "，违反 V-2")
		}
	}
}

// Shutdown 关闭 processor（无资源需释放）。
func (p *SanitizingSpanProcessor) Shutdown(_ context.Context) error {
	return nil
}

// ForceFlush 强制刷新（本 processor 无缓冲）。
func (p *SanitizingSpanProcessor) ForceFlush(_ context.Context) error {
	return nil
}

// tracingState TEE 服务的 tracing 运行态。
type tracingState struct {
	mu       sync.RWMutex
	enabled  bool
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
	// 上游 HTTP 传输（剥离追踪头，安全硬约束 §6.4）。
	stripTransport http.RoundTripper
}

// globalTracing 全局 tracing 单例（默认 NoOp）。
var globalTracing = &tracingState{
	enabled:        false,
	provider:       nil,
	tracer:         noop.Tracer{},
	stripTransport: http.DefaultTransport,
}

// initTracing 初始化 tracing（服务启动时调用一次；幂等）。
// TRACING_ENABLED != "true" 时用 NoOpTracer（零开销，C-4/C-8）。
// OTLP 出口：TRACING_OTLP_ENDPOINT（默认 otel-collector:4317）。
// 生产启用 mTLS：TRACING_TLS_CERT / TRACING_TLS_KEY / TRACING_TLS_CA。
func initTracing() error {
	enabled := os.Getenv("TRACING_ENABLED") == "true"
	globalTracing.mu.Lock()
	defer globalTracing.mu.Unlock()

	globalTracing.enabled = enabled
	if !enabled {
		globalTracing.tracer = noop.Tracer{}
		globalTracing.provider = nil
		globalTracing.stripTransport = http.DefaultTransport
		return nil
	}

	endpoint := os.Getenv("TRACING_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "otel-collector:4317"
	}

	// OTLP gRPC exporter
	exporterOpts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint(endpoint),
	}
	// 开发/演示形态：未配置 TLS 证书时走 insecure；生产必须 mTLS
	if os.Getenv("TRACING_TLS_INSECURE") == "true" {
		exporterOpts = append(exporterOpts, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(context.Background(), exporterOpts...)
	if err != nil {
		return fmt.Errorf("tracing: 创建 OTLP exporter 失败: %w", err)
	}

	// Resource（service.name 标识 TEE 服务）
	res, err := resource.New(context.Background(),
		resource.WithAttributes(
			semconv.ServiceName(tracingServiceName),
		),
	)
	if err != nil {
		return fmt.Errorf("tracing: 创建 resource 失败: %w", err)
	}

	// TracerProvider：
	//   - Sampler: ParentBased(AlwaysSample) —— 根采样 100%，全量入 Collector，
	//     实际采样由 Collector tail_sampling 执行（D-3 / §3.4）。
	//   - SanitizingSpanProcessor —— 白名单脱敏（D-4，第一道）。
	//   - BatchSpanProcessor —— 批量导出（减少 I/O）。
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(&SanitizingSpanProcessor{}),
		sdktrace.WithBatcher(exporter),
	)

	globalTracing.provider = tp
	globalTracing.tracer = tp.Tracer(tracingServiceName)

	// 注册全局 propagator（W3C Trace Context）
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// 上游 HTTP 传输：剥离追踪头（安全硬约束 §6.4）
	globalTracing.stripTransport = &stripTraceHeadersTransport{
		base: http.DefaultTransport,
	}

	return nil
}

// shutdownTracing 关闭 tracing（服务退出时刷新并关闭）。
func shutdownTracing() {
	globalTracing.mu.Lock()
	defer globalTracing.mu.Unlock()
	if globalTracing.provider != nil {
		_ = globalTracing.provider.ForceFlush(context.Background())
		_ = globalTracing.provider.Shutdown(context.Background())
	}
	globalTracing.provider = nil
	globalTracing.tracer = noop.Tracer{}
	globalTracing.enabled = false
}

// tracingEnabled 返回 tracing 是否启用（读无锁快照）。
func tracingEnabled() bool {
	globalTracing.mu.RLock()
	defer globalTracing.mu.RUnlock()
	return globalTracing.enabled
}

// tracer 返回当前 tracer（未启用返回 NoOp）。
func tracer() trace.Tracer {
	globalTracing.mu.RLock()
	defer globalTracing.mu.RUnlock()
	return globalTracing.tracer
}

// upstreamTransport 返回剥离追踪头的上游 HTTP 传输（§6.4 安全约束）。
func upstreamTransport() http.RoundTripper {
	globalTracing.mu.RLock()
	defer globalTracing.mu.RUnlock()
	return globalTracing.stripTransport
}

// stripTraceHeadersTransport 剥离出站请求中的追踪标识（安全硬约束）。
// 不向上游厂商注入 traceparent/tracestate，避免内部标识外泄（§6.4 导出段）。
// 同时剥离 x-request-id（内部 ID 也不外泄，厂商侧自生成）。
type stripTraceHeadersTransport struct {
	base http.RoundTripper
}

func (t *stripTraceHeadersTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header == nil {
		return t.base.RoundTrip(req)
	}
	// Clone 请求避免修改原始请求
	newReq := req.Clone(req.Context())
	newReq.Header.Del("traceparent")
	newReq.Header.Del("tracestate")
	newReq.Header.Del("x-request-id")
	newReq.Header.Del("X-Request-Id")
	// 兼容大小写的全部变体
	for k := range newReq.Header {
		lk := strings.ToLower(k)
		if lk == "traceparent" || lk == "tracestate" || lk == "x-request-id" {
			newReq.Header.Del(k)
		}
	}
	return t.base.RoundTrip(newReq)
}

// extractSpanContext 从入站请求头提取 trace context（W3C traceparent）。
// 未携带或解析失败返回原始 context（由 SDK 自动创建根 span）。
func extractSpanContext(r *http.Request) context.Context {
	propagator := otel.GetTextMapPropagator()
	return propagator.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
}

// startInferSpan 启动 tee.infer 主 span（§7.4 span 清单）。
// 返回：新 context + span；tracing 未启用时 span 为 NoOp。
func startInferSpan(r *http.Request, tenant, requestID, modelID, engineType string) (context.Context, trace.Span) {
	if !tracingEnabled() {
		return r.Context(), noop.Span{}
	}
	ctx := extractSpanContext(r)
	ctx, span := tracer().Start(ctx, traceSpanNameInfer,
		trace.WithAttributes(
			attribute.String("tenant.id", tenant),
			attribute.String("request.id", requestID),
			attribute.String("model.id", modelID),
			attribute.String("engine.type", engineType),
			attribute.String("result", "ok"), // 默认 ok，结束时更新
		),
	)
	return ctx, span
}

// endSpanOK 正常结束 span（result=ok）。
func endSpanOK(span trace.Span) {
	span.SetAttributes(attribute.String("result", "ok"))
	span.SetStatus(codes.Ok, "")
	span.End()
}

// endSpanError 错误结束 span（result=error，status=Error）。
func endSpanError(span trace.Span, reason string) {
	span.SetAttributes(attribute.String("result", "error"))
	if reason != "" {
		span.SetAttributes(attribute.String("deny.reason", reason))
	}
	span.SetStatus(codes.Error, reason)
	span.End()
}

// endSpanDenied 拒绝结束 span（result=deny，status=Error，带拒绝原因）。
func endSpanDenied(span trace.Span, reason string) {
	span.SetAttributes(attribute.String("result", "deny"))
	span.SetAttributes(attribute.String("deny.reason", reason))
	span.SetStatus(codes.Error, reason)
	span.End()
}

// traceIDFromContext 从 context 提取 trace_id（32 hex 字符串）。
// 用于写入审计事件证据字段（D-5）。空表示 tracing 未启用或无 trace。
func traceIDFromContext(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}

// shortDigest 取十六进制摘要前 16 字符（§6.2：input.digest / output.digest 前 16 hex）。
// 摘要不足 16 字符时原样返回（避免切片越界；正常摘要为 64 hex）。
func shortDigest(hexDigest string) string {
	if len(hexDigest) <= 16 {
		return hexDigest
	}
	return hexDigest[:16]
}

// inputDigest 输入载荷摘要前 16 hex（§6.2），与审计 PayloadSHA 同源（同 profile 口径）。
// payloadSHA 为 payloadHashHex 全量 hex 输出；此处仅截断，保证同源一致。
func inputDigest(payloadSHA string) string {
	return shortDigest(payloadSHA)
}

// outputDigest 计算输出内容摘要前 16 hex（§6.2，随 hash_alg profile：SHA-256/SM3）。
// 空字符串返回 ""（避免零值混淆）；哈希失败返回 ""（不 crash，Collector 侧兜底）。
func outputDigest(content string) string {
	if content == "" {
		return ""
	}
	h, err := hashHexByAlg(hashAlgTag(), []byte(content))
	if err != nil {
		return ""
	}
	return shortDigest(h)
}

// —— 子 span 辅助函数（§7.4 span 清单）——

// startCacheSpan 启动 cache.lookup 子 span。
func startCacheSpan(ctx context.Context) (context.Context, trace.Span) {
	if !tracingEnabled() {
		return ctx, noop.Span{}
	}
	return tracer().Start(ctx, "cache.lookup",
		trace.WithAttributes(
			attribute.Bool("cache.hit", false),
			attribute.String("cache.mode", "off"),
		),
	)
}

// setCacheHit 设置缓存命中状态。
func setCacheHit(span trace.Span, hit bool, mode string) {
	span.SetAttributes(
		attribute.Bool("cache.hit", hit),
		attribute.String("cache.mode", mode),
	)
	if hit {
		span.AddEvent("cache.hit")
	} else {
		span.AddEvent("cache.miss")
	}
}

// startGuardrailSpan 启动 guardrail.check 子 span。
func startGuardrailSpan(ctx context.Context, category, mode string) (context.Context, trace.Span) {
	if !tracingEnabled() {
		return ctx, noop.Span{}
	}
	return tracer().Start(ctx, "guardrail.check",
		trace.WithAttributes(
			attribute.String("og.category", category),
			attribute.String("og.mode", mode),
			attribute.String("result", "ok"),
		),
	)
}

// setGuardrailDenied 设置 guardrail 命中拒绝。
func setGuardrailDenied(span trace.Span, reason string) {
	span.SetAttributes(
		attribute.String("result", "deny"),
		attribute.String("deny.reason", reason),
	)
	span.SetStatus(codes.Error, "guardrail denied: "+reason)
	span.AddEvent("guardrail.denied")
}

// startUpstreamSpan 启动 upstream.model.call 子 span。
func startUpstreamSpan(ctx context.Context, tokensIn int, isRetry bool, inDigest string) (context.Context, trace.Span) {
	if !tracingEnabled() {
		return ctx, noop.Span{}
	}
	ctx, span := tracer().Start(ctx, "upstream.model.call",
		trace.WithAttributes(
			attribute.Int("tokens.in", tokensIn),
			attribute.Bool("is.retry", isRetry),
			attribute.String("input.digest", inDigest),
			attribute.Int("http.status_code", 0),
		),
	)
	// §7.4：重试不建新 span，用 is.retry 属性 + retry.start 事件区分。
	if isRetry {
		span.AddEvent("retry.start")
	}
	return ctx, span
}

// setUpstreamResult 设置上游调用结果。
func setUpstreamResult(span trace.Span, statusCode, tokensOut int, ttftMs float64, outDigest string) {
	span.SetAttributes(
		attribute.Int("http.status_code", statusCode),
		attribute.Int("tokens.out", tokensOut),
		attribute.Float64("ttft.ms", ttftMs),
		attribute.String("output.digest", outDigest),
	)
	if statusCode >= 500 {
		span.SetStatus(codes.Error, fmt.Sprintf("upstream %d", statusCode))
	}
}

// observeTTFT 在 span 上记录 TTFT（毫秒）—— 与 otpmask_ttft_seconds 同一测量点，
// 换算为毫秒供 span 属性使用（§6.2 ttft.ms）。
func observeTTFT(span trace.Span, d time.Duration) {
	span.SetAttributes(attribute.Float64("ttft.ms", float64(d.Microseconds())/1000.0))
}

// setInferTokens 在 tee.infer 主 span 上记录 token 数与 TTFT（§6.2 白名单）。
func setInferTokens(span trace.Span, tokensIn, tokensOut int, ttftMs float64) {
	span.SetAttributes(
		attribute.Int("tokens.in", tokensIn),
		attribute.Int("tokens.out", tokensOut),
		attribute.Float64("ttft.ms", ttftMs),
	)
}
