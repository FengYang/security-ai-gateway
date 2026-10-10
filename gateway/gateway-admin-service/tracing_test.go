// P1-2：管理面 tracing 单测（admin.request span 创建、身份属性、关闭时零 span）。
package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace/noop"
)

// setAdminTracer 覆写全局 tracing 运行态（测试用），返回恢复函数。
func setAdminTracer(tp *sdktrace.TracerProvider, enabled bool) func() {
	adminTracing.mu.Lock()
	origTracer, origEnabled := adminTracing.tracer, adminTracing.enabled
	if tp != nil {
		adminTracing.tracer = tp.Tracer(adminTracingServiceName)
	}
	adminTracing.enabled = enabled
	adminTracing.mu.Unlock()
	return func() {
		adminTracing.mu.Lock()
		adminTracing.tracer, adminTracing.enabled = origTracer, origEnabled
		adminTracing.mu.Unlock()
	}
}

// TestAdminTracingMiddleware_EmitsSpan 验证启用时创建 admin.request span 及身份属性。
func TestAdminTracingMiddleware_EmitsSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()
	restore := setAdminTracer(tp, true)
	defer restore()

	cfg := testCfg()
	// bob 不在 testCfg 的白名单内 → 角色采信令牌声明（auditor）。
	tok := testSignToken(t, testSecret, claims{
		Sub: "bob", Role: roleAuditor, Tenant: "tenant-x",
		Iss: defaultIssuer, Aud: defaultAudience,
	})
	var gotRole string
	h := adminTracingMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if c := claimsFrom(r.Context()); c != nil {
			gotRole = c.Role
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/billing/usage", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h(rr, req)

	if gotRole != roleAuditor {
		t.Fatalf("claims 应透传到 handler，实际 role=%q", gotRole)
	}
	_ = tp.ForceFlush(context.Background())

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("期望 1 条 span，实际 %d", len(spans))
	}
	if spans[0].Name != spanNameAdminRequest {
		t.Errorf("span 名应为 %q，实际 %q", spanNameAdminRequest, spans[0].Name)
	}
	got := map[string]string{}
	for _, a := range spans[0].Attributes {
		got[string(a.Key)] = a.Value.Emit()
	}
	if got["http.method"] != http.MethodGet {
		t.Errorf("http.method 应为 GET，实际 %q", got["http.method"])
	}
	if got["http.route"] != "/billing/usage" {
		t.Errorf("http.route 应为 /billing/usage，实际 %q", got["http.route"])
	}
	if got["tenant.id"] != "tenant-x" {
		t.Errorf("tenant.id 应为 tenant-x，实际 %q", got["tenant.id"])
	}
	if got["user.role"] != roleAuditor {
		t.Errorf("user.role 应为 auditor，实际 %q", got["user.role"])
	}
	if got["result"] != "ok" {
		t.Errorf("result 应为 ok，实际 %q", got["result"])
	}
	if got["http.status_code"] != "200" {
		t.Errorf("http.status_code 应为 200，实际 %q", got["http.status_code"])
	}
}

// TestAuthMiddleware_DisabledNoSpan 验证 tracing 关闭时 authMiddleware 走原路径、无 span。
func TestAuthMiddleware_DisabledNoSpan(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
	)
	defer func() { _ = tp.Shutdown(context.Background()) }()
	restore := setAdminTracer(tp, false)
	defer restore()

	cfg := testCfg()
	tok := testSignToken(t, testSecret, claims{Sub: testAdminUser, Role: roleAdmin})
	h := authMiddleware(cfg, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h(rr, req)
	_ = tp.ForceFlush(context.Background())

	if rr.Code != http.StatusOK {
		t.Fatalf("鉴权通过应 200，实际 %d", rr.Code)
	}
	if n := len(exp.GetSpans()); n != 0 {
		t.Fatalf("关闭时不应创建 span，实际 %d", n)
	}
	// 恢复默认 NoOp
	adminTracing.mu.Lock()
	adminTracing.tracer = noop.Tracer{}
	adminTracing.mu.Unlock()
}

// saveAdminTracing 保存并恢复 admin 包 tracing 全局态，供切换 TRACING_ENABLED 的用例使用（C-4/C-8）。
func saveAdminTracing(t *testing.T) {
	t.Helper()
	adminTracing.mu.Lock()
	origEnabled := adminTracing.enabled
	origProvider := adminTracing.provider
	origTracer := adminTracing.tracer
	adminTracing.mu.Unlock()
	t.Cleanup(func() {
		adminTracing.mu.Lock()
		adminTracing.enabled = origEnabled
		adminTracing.provider = origProvider
		adminTracing.tracer = origTracer
		adminTracing.mu.Unlock()
	})
}

// TestInitTracing_DisabledNoop 验证 TRACING_ENABLED != "true" 时装配 NoOp（零开销，C-4）。
func TestInitTracing_DisabledNoop(t *testing.T) {
	saveAdminTracing(t)
	t.Setenv("TRACING_ENABLED", "false")

	if err := InitTracing(); err != nil {
		t.Fatalf("关闭态初始化不应报错：%v", err)
	}
	if adminTracingEnabled() {
		t.Error("关闭态 adminTracingEnabled 应为 false")
	}
	if _, ok := adminTracer().(noop.Tracer); !ok {
		t.Error("关闭态 tracer 应为 NoOp")
	}
	if adminTracing.provider != nil {
		t.Error("关闭态 provider 应为 nil")
	}
}

// TestInitTracing_EnabledLazyProvider 验证启用态装配真实 provider；OTLP 出口惰性连接，
// 不可达端点不阻塞初始化（D-3 / §7.4）。
func TestInitTracing_EnabledLazyProvider(t *testing.T) {
	saveAdminTracing(t)
	t.Setenv("TRACING_ENABLED", "true")
	t.Setenv("TRACING_OTLP_ENDPOINT", "") // 空 → 走默认 endpoint（不可达，验证惰性初始化不阻塞）
	t.Setenv("TRACING_TLS_INSECURE", "true")

	if err := InitTracing(); err != nil {
		t.Fatalf("启用态装配不应失败（惰性连接）：%v", err)
	}
	if !adminTracingEnabled() {
		t.Error("启用态 adminTracingEnabled 应为 true")
	}
	if adminTracing.provider == nil {
		t.Error("启用态 provider 不应为 nil")
	}
	if _, ok := adminTracer().(noop.Tracer); ok {
		t.Error("启用态 tracer 不应为 NoOp")
	}
	ShutdownTracing() // 覆盖非 nil provider 分支
}

// TestShutdownTracing_ResetsToNoop 验证 Shutdown 复位为关闭态且可幂等重复调用。
func TestShutdownTracing_ResetsToNoop(t *testing.T) {
	saveAdminTracing(t)

	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp))
	adminTracing.mu.Lock()
	adminTracing.provider = tp
	adminTracing.tracer = tp.Tracer(adminTracingServiceName)
	adminTracing.enabled = true
	adminTracing.mu.Unlock()

	ShutdownTracing()
	if adminTracingEnabled() || adminTracing.provider != nil {
		t.Fatal("Shutdown 后应复位为关闭态")
	}
	if _, ok := adminTracer().(noop.Tracer); !ok {
		t.Fatal("Shutdown 后 tracer 应为 NoOp")
	}
	ShutdownTracing() // 幂等：provider 为 nil 时不应 panic
}

// TestAdminStatusRecorder_Write 验证未显式 WriteHeader 时 Write 记 200，已设码时保持原码。
func TestAdminStatusRecorder_Write(t *testing.T) {
	rec := httptest.NewRecorder()
	sr := &adminStatusRecorder{ResponseWriter: rec}
	if _, err := sr.Write([]byte("hello")); err != nil {
		t.Fatalf("Write 异常：%v", err)
	}
	if sr.code != http.StatusOK {
		t.Errorf("未显式 WriteHeader 时 code 应为 200，实际 %d", sr.code)
	}

	rec2 := httptest.NewRecorder()
	sr2 := &adminStatusRecorder{ResponseWriter: rec2, code: http.StatusNoContent}
	if _, err := sr2.Write([]byte("x")); err != nil {
		t.Fatalf("Write 异常：%v", err)
	}
	if sr2.code != http.StatusNoContent {
		t.Errorf("已设码时不应被覆盖，实际 %d", sr2.code)
	}
}

// TestAdminTracingMiddleware_MissingBearer 验证缺 Bearer 时 401 且 span 记 result=error。
func TestAdminTracingMiddleware_MissingBearer(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithBatcher(exp))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	restore := setAdminTracer(tp, true)
	defer restore()

	called := false
	h := adminTracingMiddleware(testCfg(), func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("缺 Bearer 应 401，实际 %d", rr.Code)
	}
	if called {
		t.Fatal("未鉴权不应进入内层 handler")
	}
	_ = tp.ForceFlush(context.Background())
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("期望 1 条 span，实际 %d", len(spans))
	}
	got := map[string]string{}
	for _, a := range spans[0].Attributes {
		got[string(a.Key)] = a.Value.Emit()
	}
	if got["result"] != "error" || got["http.status_code"] != "401" {
		t.Errorf("span 应记 result=error/401，实际 %+v", got)
	}
}

// TestAdminTracingMiddleware_InvalidToken 验证令牌校验失败时 401 且 span 记 result=error。
func TestAdminTracingMiddleware_InvalidToken(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithBatcher(exp))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	restore := setAdminTracer(tp, true)
	defer restore()

	// 用错误密钥签发 → 校验失败
	badTok := testSignToken(t, []byte("wrong-secret-0123456789abcdef"), claims{Sub: "bob", Role: roleAuditor})
	h := adminTracingMiddleware(testCfg(), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+badTok)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("非法令牌应 401，实际 %d", rr.Code)
	}
	_ = tp.ForceFlush(context.Background())
	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("期望 1 条 span，实际 %d", len(spans))
	}
	got := map[string]string{}
	for _, a := range spans[0].Attributes {
		got[string(a.Key)] = a.Value.Emit()
	}
	if got["result"] != "error" || got["http.status_code"] != "401" {
		t.Errorf("span 应记 result=error/401，实际 %+v", got)
	}
}

// TestAdminTracingMiddleware_HandlerError 验证内层 5xx 时 span 记 result=error 与状态码。
func TestAdminTracingMiddleware_HandlerError(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSampler(sdktrace.AlwaysSample()), sdktrace.WithBatcher(exp))
	defer func() { _ = tp.Shutdown(context.Background()) }()
	restore := setAdminTracer(tp, true)
	defer restore()

	tok := testSignToken(t, testSecret, claims{Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience})
	h := adminTracingMiddleware(testCfg(), func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h(rr, req)
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("期望 500，实际 %d", rr.Code)
	}
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
		t.Errorf("5xx 应记 result=error，实际 %q", got["result"])
	}
	if got["http.status_code"] != "500" {
		t.Errorf("http.status_code 应为 500，实际 %q", got["http.status_code"])
	}
}
