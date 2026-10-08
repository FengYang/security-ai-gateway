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
