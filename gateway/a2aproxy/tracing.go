package a2aproxy

// P2-2 T-5：A2A 数据面 tracing（复用 P1-2 栈）。
//
// 与 gateway-core/internal/api/tracing.go 同构：
//   - 默认关闭：`TRACING_ENABLED != "true"` 时用 NoOpTracer（零开销，C-4）；
//   - 根采样 100%（ParentBased(AlwaysSample)），实际采样由 Collector tail_sampling 执行；
//   - 属性仅取元数据（tenant.id / a2a.agent / a2a.skill / a2a.method / result /
//     http.status_code），**不落正文**（R-2）；Collector attributes processor 做白名单兜底；
//   - 从入站请求头提取 traceparent 以继承上游 span，并注入后端请求实现任务上下文贯通。
//
// 约束：不新增采集组件——沿用既有 OTLP Collector 与后端设施。

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"

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

// a2aTracingServiceName 数据面 tracing service.name。
const a2aTracingServiceName = "a2a-proxy"

// A2A 数据面 span 名（G-6「任务上下文贯通」）。
const (
	// spanInvoke 覆盖一次数据面调用（含治理判定与后端转发）。
	spanInvoke = "a2a.invoke"
	// spanDiscovery 覆盖 AgentCard 发现/直出。
	spanDiscovery = "a2a.card.discovery"
)

// a2aTracingState 数据面 tracing 运行态（默认 NoOp）。
type a2aTracingState struct {
	mu       sync.RWMutex
	enabled  bool
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

var a2aTracing = &a2aTracingState{tracer: noop.Tracer{}}

// InitTracing 初始化数据面 tracing（服务启动时调用一次；幂等）。
//
// 环境变量与 P1-2 一致以保证运维口径统一：
// TRACING_ENABLED="true" 才启用；TRACING_OTLP_ENDPOINT 默认 `otel-collector:4317`；
// TRACING_TLS_INSECURE="true" 走非 TLS。
func InitTracing() error {
	enabled := os.Getenv("TRACING_ENABLED") == "true"
	a2aTracing.mu.Lock()
	defer a2aTracing.mu.Unlock()
	a2aTracing.enabled = enabled
	if !enabled {
		a2aTracing.tracer = noop.Tracer{}
		a2aTracing.provider = nil
		return nil
	}

	endpoint := os.Getenv("TRACING_OTLP_ENDPOINT")
	if endpoint == "" {
		endpoint = "otel-collector:4317"
	}
	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(endpoint)}
	if os.Getenv("TRACING_TLS_INSECURE") == "true" {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	exporter, err := otlptracegrpc.New(context.Background(), opts...)
	if err != nil {
		return fmt.Errorf("a2aproxy: 创建 OTLP exporter 失败: %w", err)
	}
	res, err := resource.New(context.Background(),
		resource.WithAttributes(semconv.ServiceName(a2aTracingServiceName)))
	if err != nil {
		return fmt.Errorf("a2aproxy: 创建 resource 失败: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
	)
	a2aTracing.provider = tp
	a2aTracing.tracer = tp.Tracer(a2aTracingServiceName)
	return nil
}

// ShutdownTracing 关闭数据面 tracing（进程退出时刷新并关闭）。
func ShutdownTracing() {
	a2aTracing.mu.Lock()
	defer a2aTracing.mu.Unlock()
	if a2aTracing.provider != nil {
		_ = a2aTracing.provider.ForceFlush(context.Background())
		_ = a2aTracing.provider.Shutdown(context.Background())
	}
	a2aTracing.provider = nil
	a2aTracing.tracer = noop.Tracer{}
	a2aTracing.enabled = false
}

func a2aTracingEnabled() bool {
	a2aTracing.mu.RLock()
	defer a2aTracing.mu.RUnlock()
	return a2aTracing.enabled
}

func a2aTracer() trace.Tracer {
	a2aTracing.mu.RLock()
	defer a2aTracing.mu.RUnlock()
	return a2aTracing.tracer
}

// tracingStatusRecorder 记录响应状态码（供 span 属性与错误采样）。
type tracingStatusRecorder struct {
	http.ResponseWriter
	code int
}

func (sr *tracingStatusRecorder) WriteHeader(code int) {
	sr.code = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *tracingStatusRecorder) Write(b []byte) (int, error) {
	if sr.code == 0 {
		sr.code = http.StatusOK
	}
	return sr.ResponseWriter.Write(b)
}

// withTracingSpan 包装数据面处理器并创建 span（任务上下文贯通：G-6）。
//
// tracing 未启用时直接透传（零开销、零行为变化，C-4/C-8）。
func (p *Proxy) withTracingSpan(name string, next http.HandlerFunc) http.HandlerFunc {
	if !a2aTracingEnabled() {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		attrs := []attribute.KeyValue{attribute.String("result", "ok")}
		if tenant := r.PathValue("tenant"); tenant != "" {
			attrs = append(attrs, attribute.String("tenant.id", tenant))
		}
		if agent := r.PathValue("agent"); agent != "" {
			attrs = append(attrs, attribute.String("a2a.agent", agent))
		}
		ctx, span := a2aTracer().Start(ctx, name, trace.WithAttributes(attrs...))
		sr := &tracingStatusRecorder{ResponseWriter: w}
		next(sr, r.WithContext(ctx))
		if sr.code >= 400 {
			span.SetAttributes(attribute.String("result", "error"))
			span.SetStatus(codes.Error, http.StatusText(sr.code))
		}
		if sr.code != 0 {
			span.SetAttributes(attribute.Int("http.status_code", sr.code))
		}
		span.End()
	}
}

// injectTraceContext 将当前 span 上下文注入后端请求头（任务上下文贯通：G-6）。
//
// tracing 未启用时不注入，行为不变。
func injectTraceContext(ctx context.Context, header http.Header) {
	if !a2aTracingEnabled() {
		return
	}
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(header))
}
