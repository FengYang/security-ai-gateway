// P1-2：管理面 tracing（M3，§7.4 span 清单 `admin.request`）。
//
// 设计要点：
//   - C-4：默认关闭（TRACING_ENABLED != "true" 时用 NoOpTracer，零开销）。
//   - 根采样 100%（ParentBased(AlwaysSample)），实际采样由 Collector 执行（D-3）。
//   - 属性仅设置 §7.4 规定的元数据（http.method / http.route / tenant.id / user.role /
//     result / http.status_code），Collector attributes processor 白名单兜底。
//   - 关闭时 authMiddleware 走原路径（零行为变化，C-8）。
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
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

// adminTracingServiceName 管理面 tracing service.name。
const adminTracingServiceName = "gateway-admin-service"

// spanNameAdminRequest 管理面操作 span 名（§7.4）。
const spanNameAdminRequest = "admin.request"

// adminTracingState 管理面 tracing 运行态（默认 NoOp）。
type adminTracingState struct {
	mu       sync.RWMutex
	enabled  bool
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

var adminTracing = &adminTracingState{tracer: noop.Tracer{}}

// InitTracing 初始化管理面 tracing（服务启动时调用一次；幂等）。
func InitTracing() error {
	enabled := os.Getenv("TRACING_ENABLED") == "true"
	adminTracing.mu.Lock()
	defer adminTracing.mu.Unlock()
	adminTracing.enabled = enabled
	if !enabled {
		adminTracing.tracer = noop.Tracer{}
		adminTracing.provider = nil
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
		resource.WithAttributes(semconv.ServiceName(adminTracingServiceName)))
	if err != nil {
		return fmt.Errorf("tracing: 创建 resource 失败: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.AlwaysSample())),
		sdktrace.WithResource(res),
		sdktrace.WithBatcher(exporter),
	)
	adminTracing.provider = tp
	adminTracing.tracer = tp.Tracer(adminTracingServiceName)
	return nil
}

// ShutdownTracing 关闭管理面 tracing（进程退出时刷新并关闭）。
func ShutdownTracing() {
	adminTracing.mu.Lock()
	defer adminTracing.mu.Unlock()
	if adminTracing.provider != nil {
		_ = adminTracing.provider.ForceFlush(context.Background())
		_ = adminTracing.provider.Shutdown(context.Background())
	}
	adminTracing.provider = nil
	adminTracing.tracer = noop.Tracer{}
	adminTracing.enabled = false
}

func adminTracingEnabled() bool {
	adminTracing.mu.RLock()
	defer adminTracing.mu.RUnlock()
	return adminTracing.enabled
}

func adminTracer() trace.Tracer {
	adminTracing.mu.RLock()
	defer adminTracing.mu.RUnlock()
	return adminTracing.tracer
}

// adminStatusRecorder 记录响应状态码（供 span 属性与错误采样）。
// 仅在 tracing 启用时用于包裹 ResponseWriter，避免关闭时改变既有行为。
type adminStatusRecorder struct {
	http.ResponseWriter
	code int
}

func (sr *adminStatusRecorder) WriteHeader(code int) {
	sr.code = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *adminStatusRecorder) Write(b []byte) (int, error) {
	if sr.code == 0 {
		sr.code = http.StatusOK
	}
	return sr.ResponseWriter.Write(b)
}

// adminTracingMiddleware 是 authMiddleware 的 tracing 版本：在鉴权通过后把
// 身份（tenant/role）写入 `admin.request` span，并在返回时记录状态码与结果。
// 仅在 adminTracingEnabled() 为真时分派进入（见 auth.go）。
func adminTracingMiddleware(cfg *config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := adminTracer().Start(ctx, spanNameAdminRequest,
			trace.WithAttributes(
				attribute.String("http.method", r.Method),
				attribute.String("http.route", r.URL.Path),
				attribute.String("result", "ok"),
			),
		)
		defer span.End()
		sr := &adminStatusRecorder{ResponseWriter: w}

		h := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(h, prefix) {
			metrics.incAuthRejected()
			http.Error(sr, "unauthorized: 缺少 Bearer 内部令牌", http.StatusUnauthorized)
			span.SetAttributes(attribute.String("result", "error"), attribute.Int("http.status_code", sr.code))
			span.SetStatus(codes.Error, "unauthorized")
			return
		}
		c, err := verifyInternalToken(strings.TrimPrefix(h, prefix), cfg)
		if err != nil {
			metrics.incAuthRejected()
			http.Error(sr, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			span.SetAttributes(attribute.String("result", "error"), attribute.Int("http.status_code", sr.code))
			span.SetStatus(codes.Error, "unauthorized")
			return
		}
		// 身份写入 span（§7.4：tenant.id / user.role）
		span.SetAttributes(attribute.String("tenant.id", c.Tenant), attribute.String("user.role", c.Role))
		ctx = withClaims(ctx, c)
		metrics.request()
		next(sr, r.WithContext(ctx))
		if sr.code >= 400 {
			span.SetAttributes(attribute.String("result", "error"))
			span.SetStatus(codes.Error, http.StatusText(sr.code))
		}
		if sr.code != 0 {
			span.SetAttributes(attribute.Int("http.status_code", sr.code))
		}
	}
}
