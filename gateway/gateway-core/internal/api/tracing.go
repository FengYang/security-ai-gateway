// P1-2：控制面 tracing（M3，§7.4 span 清单 `core.route.change`）。
//
// 设计要点：
//   - C-4：默认关闭（TRACING_ENABLED != "true" 时用 NoOpTracer，零开销）。
//   - 根采样 100%（ParentBased(AlwaysSample)），实际采样由 Collector tail_sampling 执行（D-3）。
//   - 属性仅设置 §7.4 规定的元数据（route.name / change.type / tenant.id / result /
//     http.status_code），Collector attributes processor 做白名单兜底（纵深防御）。
//   - 从入站请求头提取 traceparent，继承网关入口 span（延续全链路）。
package api

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

// coreTracingServiceName 控制面 tracing service.name。
const coreTracingServiceName = "gateway-core"

// spanNameRouteChange 路由变更 span 名（§7.4）。
const spanNameRouteChange = "core.route.change"

// coreTracingState 控制面 tracing 运行态（默认 NoOp）。
type coreTracingState struct {
	mu       sync.RWMutex
	enabled  bool
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

var coreTracing = &coreTracingState{tracer: noop.Tracer{}}

// InitTracing 初始化控制面 tracing（服务启动时调用一次；幂等）。
// TRACING_ENABLED != "true" 时用 NoOpTracer（零开销，C-4）。
// OTLP 出口：TRACING_OTLP_ENDPOINT（默认 otel-collector:4317）。
func InitTracing() error {
	enabled := os.Getenv("TRACING_ENABLED") == "true"
	coreTracing.mu.Lock()
	defer coreTracing.mu.Unlock()
	coreTracing.enabled = enabled
	if !enabled {
		coreTracing.tracer = noop.Tracer{}
		coreTracing.provider = nil
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
		return fmt.Errorf("tracing: 创建 OTLP exporter 失败: %w", err)
	}
	res, err := resource.New(context.Background(),
		resource.WithAttributes(semconv.ServiceName(coreTracingServiceName)))
	if err != nil {
		return fmt.Errorf("tracing: 创建 resource 失败: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
	)
	coreTracing.provider = tp
	coreTracing.tracer = tp.Tracer(coreTracingServiceName)
	return nil
}

// ShutdownTracing 关闭控制面 tracing（进程退出时刷新并关闭）。
func ShutdownTracing() {
	coreTracing.mu.Lock()
	defer coreTracing.mu.Unlock()
	if coreTracing.provider != nil {
		_ = coreTracing.provider.ForceFlush(context.Background())
		_ = coreTracing.provider.Shutdown(context.Background())
	}
	coreTracing.provider = nil
	coreTracing.tracer = noop.Tracer{}
	coreTracing.enabled = false
}

func coreTracingEnabled() bool {
	coreTracing.mu.RLock()
	defer coreTracing.mu.RUnlock()
	return coreTracing.enabled
}

func coreTracer() trace.Tracer {
	coreTracing.mu.RLock()
	defer coreTracing.mu.RUnlock()
	return coreTracing.tracer
}

// statusRecorder 记录响应状态码（供 span 属性 http.status_code 与错误采样）。
type statusRecorder struct {
	http.ResponseWriter
	code int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.code = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(b []byte) (int, error) {
	if sr.code == 0 {
		sr.code = http.StatusOK
	}
	return sr.ResponseWriter.Write(b)
}

// withRouteChangeSpan 包装路由/策略变更处理器，创建 `core.route.change` span（§7.4）。
// changeType ∈ upsert|delete|rollback（变更类别）；route.name 取租户/模型（存在时）。
// tracing 未启用时不创建 span（零开销，行为不变）。
func (s *Server) withRouteChangeSpan(changeType string, next http.HandlerFunc) http.HandlerFunc {
	if !coreTracingEnabled() {
		return next // 关闭时直接透传（零开销、零行为变化，C-4/C-8）
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		attrs := []attribute.KeyValue{
			attribute.String("change.type", changeType),
			attribute.String("result", "ok"),
		}
		// route.name：租户/模型（路径存在时拼接；否则留空不写）
		if tenant := r.PathValue("tenant"); tenant != "" {
			attrs = append(attrs, attribute.String("tenant.id", tenant))
		}
		if model := r.PathValue("model"); model != "" {
			attrs = append(attrs, attribute.String("route.name", r.PathValue("tenant")+"/"+model))
		}
		ctx, span := coreTracer().Start(ctx, spanNameRouteChange, trace.WithAttributes(attrs...))
		sr := &statusRecorder{ResponseWriter: w}
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
