// P2-4 T-4.2：core 审计链导出端点单测（默认关闭 / 授权 / 来源白名单 / 只读性）。
package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/auditexport"
	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
)

// auditExportPath 导出端点路径（与 core 装配口径一致）。
const auditExportPath = "/v1/internal/audit/chain/export"

// seedAuditEvents 向 server 的审计链追加 n 条事件。
func seedAuditEvents(t *testing.T, s *Server, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if _, err := s.audit.Append(policyaudit.Event{
			EventID: "evt-x", Actor: "tester", Action: policyaudit.ActionApply,
			VersionFrom: i, VersionTo: i + 1, RuleID: "r1",
			Change: policyaudit.ChangeUpdated, Field: "rpm",
			OldValue: "1", NewValue: "2", RequestID: "req", Result: policyaudit.ResultOK,
		}); err != nil {
			t.Fatalf("追加审计事件失败: %v", err)
		}
	}
}

// auditExportWhitelist 构造仅允许 httptest 默认来源（192.0.2.1）的白名单。
func auditExportWhitelist(t *testing.T, cidrs ...string) *auditexport.SourceWhitelist {
	t.Helper()
	wl, err := auditexport.NewSourceWhitelist(cidrs)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	return wl
}

// doExport 发起导出请求（RemoteAddr 由 httptest 固定为 192.0.2.1:1234）。
func doExport(s *Server, query string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, auditExportPath+query, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// TestAuditExportDefaultDisabled 默认关闭：未启用 → 404（零新增攻击面）。
func TestAuditExportDefaultDisabled(t *testing.T) {
	s := testServer()
	seedAuditEvents(t, s, 2)
	if rec := doExport(s, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("默认关闭应 404: got %d", rec.Code)
	}
	// 显式传入 Enabled=false 同样不注册。
	s2 := testServer()
	s2.SetAuditExport(auditexport.Config{Enabled: false, Whitelist: auditExportWhitelist(t, "192.0.2.1/32")})
	if rec := doExport(s2, ""); rec.Code != http.StatusNotFound {
		t.Fatalf("Enabled=false 应 404: got %d", rec.Code)
	}
}

// TestAuditExportEnabledAndRecompute 启用 + 授权 + 白名单内 → 200，
// 且导出内容可独立重算（与链 Verify 结论一致）。
func TestAuditExportEnabledAndRecompute(t *testing.T) {
	s := testServer()
	seedAuditEvents(t, s, 3)
	s.SetAuditExport(auditexport.Config{
		Enabled:    true,
		Authorizer: auditexport.TokenAuthorizer{Token: "export-tok"},
		Whitelist:  auditExportWhitelist(t, "192.0.2.1/32"),
		MaxLimit:   1000,
	})

	req := httptest.NewRequest(http.MethodGet, auditExportPath, nil)
	req.Header.Set("Authorization", "Bearer export-tok")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("授权+白名单内应 200: got %d body=%s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/x-ndjson" {
		t.Fatalf("Content-Type 应为 NDJSON: %s", ct)
	}
	if got := rec.Header().Get(auditexport.HeaderPrefix + "Schema"); got != "core" {
		t.Fatalf("schema 头应为 core: %q", got)
	}
	if got := rec.Header().Get(auditexport.HeaderPrefix + "Events"); got != "3" {
		t.Fatalf("events 头应为 3: %q", got)
	}
	tail := rec.Header().Get(auditexport.HeaderPrefix + "Tail-Hash")
	if tail == "" {
		t.Fatalf("应带链尾哈希头")
	}
	// 导出内容可重算，且与链 Verify 一致。
	ok, n, err := policyaudit.VerifyExport(rec.Body.Bytes())
	if err != nil || !ok || n != 3 {
		t.Fatalf("导出内容重算应自洽: ok=%v n=%d err=%v", ok, n, err)
	}
	cok, cn := s.audit.Verify()
	if cok != ok || cn != n {
		t.Fatalf("重算与链 Verify 结论不一致")
	}
}

// TestAuditExportDenyAllAuthorizer 默认授权（deny-all）→ 403。
func TestAuditExportDenyAllAuthorizer(t *testing.T) {
	s := testServer()
	seedAuditEvents(t, s, 1)
	// Authorizer 留空 → DenyAllAuthorizer。
	s.SetAuditExport(auditexport.Config{Enabled: true, Whitelist: auditExportWhitelist(t, "192.0.2.1/32")})
	if rec := doExport(s, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("deny-all 应 403: got %d", rec.Code)
	}
	// 显式 deny-all 实现。
	s2 := testServer()
	s2.SetAuditExport(auditexport.Config{
		Enabled: true, Authorizer: auditexport.DenyAllAuthorizer{},
		Whitelist: auditExportWhitelist(t, "192.0.2.1/32"),
	})
	if rec := doExport(s2, ""); rec.Code != http.StatusForbidden {
		t.Fatalf("DenyAllAuthorizer 应 403: got %d", rec.Code)
	}
	// 令牌不匹配（TokenAuthorizer）→ 403。
	s3 := testServer()
	s3.SetAuditExport(auditexport.Config{
		Enabled: true, Authorizer: auditexport.TokenAuthorizer{Token: "export-tok"},
		Whitelist: auditExportWhitelist(t, "192.0.2.1/32"),
	})
	req := httptest.NewRequest(http.MethodGet, auditExportPath, nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec := httptest.NewRecorder()
	s3.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("令牌不匹配应 403: got %d", rec.Code)
	}
}

// TestAuditExportSourceWhitelist 来源白名单：白名单外 → 403；空白名单 → 403（fail-closed）。
func TestAuditExportSourceWhitelist(t *testing.T) {
	s := testServer()
	seedAuditEvents(t, s, 1)
	s.SetAuditExport(auditexport.Config{
		Enabled:    true,
		Authorizer: auditexport.TokenAuthorizer{Token: "t"},
		Whitelist:  auditExportWhitelist(t, "10.0.0.0/8"), // 不含 192.0.2.1
	})
	req := httptest.NewRequest(http.MethodGet, auditExportPath, nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("白名单外来源应 403: got %d", rec.Code)
	}

	// 空白名单 = 拒绝所有来源（fail-closed）。
	s2 := testServer()
	s2.SetAuditExport(auditexport.Config{
		Enabled: true, Authorizer: auditexport.TokenAuthorizer{Token: "t"},
		Whitelist: auditExportWhitelist(t),
	})
	req2 := httptest.NewRequest(http.MethodGet, auditExportPath, nil)
	req2.Header.Set("Authorization", "Bearer t")
	rec2 := httptest.NewRecorder()
	s2.Handler().ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusForbidden {
		t.Fatalf("空白名单应拒绝所有来源: got %d", rec2.Code)
	}
}

// TestAuditExportLimitAndSchema 参数校验：limit 边界、非法 limit、schema 口径。
func TestAuditExportLimitAndSchema(t *testing.T) {
	newSrv := func() *Server {
		s := testServer()
		seedAuditEvents(t, s, 5)
		s.SetAuditExport(auditexport.Config{
			Enabled: true, Authorizer: auditexport.TokenAuthorizer{Token: "t"},
			Whitelist: auditExportWhitelist(t, "192.0.2.1/32"), MaxLimit: 3,
		})
		return s
	}
	do := func(s *Server, q string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, auditExportPath+q, nil)
		req.Header.Set("Authorization", "Bearer t")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}
	// limit=2 → 2 行。
	rec := do(newSrv(), "?limit=2")
	if rec.Code != http.StatusOK {
		t.Fatalf("limit=2 应 200: got %d", rec.Code)
	}
	if got := rec.Header().Get(auditexport.HeaderPrefix + "Events"); got != "2" {
		t.Fatalf("limit=2 应导出 2 条: got %q", got)
	}
	if got := rec.Header().Get(auditexport.HeaderPrefix + "Total"); got != "5" {
		t.Fatalf("Total 应为链总长 5: got %q", got)
	}
	// limit 超上限 → 归一到 MaxLimit=3 并标记截断。
	rec = do(newSrv(), "?limit=100")
	if got := rec.Header().Get(auditexport.HeaderPrefix + "Events"); got != "3" {
		t.Fatalf("limit 超上限应归一到 3: got %q", got)
	}
	if got := rec.Header().Get(auditexport.HeaderPrefix + "Truncated"); got != "true" {
		t.Fatalf("应标记截断: got %q", got)
	}
	// 截断导出按 Prev-Hash 重算 → 自洽。
	prev := rec.Header().Get(auditexport.HeaderPrefix + "Prev-Hash")
	ok, n, err := policyaudit.VerifyExportFrom(rec.Body.Bytes(), prev)
	if err != nil || !ok || n != 3 {
		t.Fatalf("截断导出重算应自洽: ok=%v n=%d err=%v", ok, n, err)
	}
	// 非法 limit → 400。
	if r := do(newSrv(), "?limit=-1"); r.Code != http.StatusBadRequest {
		t.Fatalf("负 limit 应 400: got %d", r.Code)
	}
	if r := do(newSrv(), "?limit=abc"); r.Code != http.StatusBadRequest {
		t.Fatalf("非数字 limit 应 400: got %d", r.Code)
	}
	// schema 口径：core 放行；tee/admin → 400。
	if r := do(newSrv(), "?schema=core"); r.Code != http.StatusOK {
		t.Fatalf("schema=core 应 200: got %d", r.Code)
	}
	if r := do(newSrv(), "?schema=tee"); r.Code != http.StatusBadRequest {
		t.Fatalf("schema=tee 应 400: got %d", r.Code)
	}
	// 非 GET → 405（mux 已限方法，显式再确认）。
	req := httptest.NewRequest(http.MethodPost, auditExportPath, strings.NewReader(""))
	req.Header.Set("Authorization", "Bearer t")
	rec = httptest.NewRecorder()
	newSrv().Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed && rec.Code != http.StatusNotFound {
		t.Fatalf("非 GET 应 405（或 mux 404）: got %d", rec.Code)
	}
}

// TestAuditExportReadOnly 导出不改变链状态（Len/Verify/审计文件不变）。
func TestAuditExportReadOnly(t *testing.T) {
	s := testServer()
	seedAuditEvents(t, s, 4)
	s.SetAuditExport(auditexport.Config{
		Enabled: true, Authorizer: auditexport.TokenAuthorizer{Token: "t"},
		Whitelist: auditExportWhitelist(t, "192.0.2.1/32"), MaxLimit: 10,
	})
	beforeLen := s.audit.Len()
	beforeOK, beforeN := s.audit.Verify()
	do := func(q string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, auditExportPath+q, nil)
		req.Header.Set("Authorization", "Bearer t")
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < 3; i++ {
		if rec := do(""); rec.Code != http.StatusOK {
			t.Fatalf("导出应 200: got %d", rec.Code)
		}
	}
	if s.audit.Len() != beforeLen {
		t.Fatalf("导出改变了链长度: %d → %d", beforeLen, s.audit.Len())
	}
	if ok, n := s.audit.Verify(); ok != beforeOK || n != beforeN {
		t.Fatalf("导出改变了链校验结论")
	}
}

// TestAuditExportEmptyChain 空链导出：200 + 0 行（非空错误）。
func TestAuditExportEmptyChain(t *testing.T) {
	s := testServer() // 无审计事件
	s.SetAuditExport(auditexport.Config{
		Enabled: true, Authorizer: auditexport.TokenAuthorizer{Token: "t"},
		Whitelist: auditExportWhitelist(t, "192.0.2.1/32"),
	})
	req := httptest.NewRequest(http.MethodGet, auditExportPath, nil)
	req.Header.Set("Authorization", "Bearer t")
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("空链导出应 200: got %d", rec.Code)
	}
	if got := rec.Header().Get(auditexport.HeaderPrefix + "Events"); got != "0" {
		t.Fatalf("空链 events 应为 0: got %q", got)
	}
	if body := strings.TrimSpace(rec.Body.String()); body != "" {
		t.Fatalf("空链 body 应为空: %q", body)
	}
}
