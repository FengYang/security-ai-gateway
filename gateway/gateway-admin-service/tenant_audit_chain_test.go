package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newAuditTestHandler 构造带审计链的租户 handler（用于验证落链行为）。
func newAuditTestHandler(t *testing.T) (*tenantHandler, *sqliteTenantStore, string) {
	t.Helper()
	return newAuditTestHandlerFor(t, testTenantCfg())
}

// readAudit 读审计文件内容（无文件 → 空串）。
func readAudit(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return ""
		}
		t.Fatalf("读审计文件失败: %v", err)
	}
	return string(data)
}

// A-1：tenant_login 成功/失败均落链，且不落明文邮箱（附录 D）。
func TestLoginAudit_SuccessAndFailure(t *testing.T) {
	h, store, auditFile := newAuditTestHandler(t)
	seedTenantUser(t, store, "audit@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	// 失败（凭据错误）
	w := httptest.NewRecorder()
	h.handleLogin(w, postJSON("/api/login", `{"email":"audit@example.com","password":"WrongPass123!"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("凭据错误应 401, got=%d", w.Code)
	}
	// 成功
	w2 := httptest.NewRecorder()
	h.handleLogin(w2, postJSON("/api/login", `{"email":"audit@example.com","password":"Password123!"}`))
	if w2.Code != http.StatusOK {
		t.Fatalf("登录应 200, got=%d body=%s", w2.Code, w2.Body.String())
	}

	body := readAudit(t, auditFile)
	if n := strings.Count(body, "tenant_login"); n < 2 {
		t.Errorf("应至少 2 条 tenant_login（成功+失败），got=%d\n%s", n, body)
	}
	if !strings.Contains(body, "bad_credentials") {
		t.Errorf("失败原因应落链（bad_credentials）:\n%s", body)
	}
	if strings.Contains(body, "audit@example.com") {
		t.Errorf("审计不得落明文邮箱（附录 D）:\n%s", body)
	}
	if strings.Contains(body, "Password123!") || strings.Contains(body, "WrongPass123!") {
		t.Errorf("审计不得落密码:\n%s", body)
	}
}

// A-1：锁定态登录落链（result=locked）。
func TestLoginAudit_LockedState(t *testing.T) {
	cfg := testTenantCfg()
	cfg.loginMaxFail = 2
	h, store, auditFile := newAuditTestHandlerFor(t, cfg)
	seedTenantUser(t, store, "lock2@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	for i := 0; i < 2; i++ {
		h.handleLogin(httptest.NewRecorder(),
			postJSON("/api/login", `{"email":"lock2@example.com","password":"WrongPass123!"}`))
	}
	// 第 3 次（锁定中）
	w := httptest.NewRecorder()
	h.handleLogin(w, postJSON("/api/login", `{"email":"lock2@example.com","password":"Password123!"}`))
	if w.Code != http.StatusLocked {
		t.Fatalf("锁定应 423, got=%d", w.Code)
	}
	if body := readAudit(t, auditFile); !strings.Contains(body, "locked") {
		t.Errorf("锁定态应落链（locked）:\n%s", body)
	}
}

// A-2：tenant_register 落在 verify 通过时，Target=tenant_id，且不落明文邮箱。
func TestVerifyAudit_TenantRegister(t *testing.T) {
	h, store, auditFile := newAuditTestHandler(t)
	tenantID, _, rawToken := seedPendingVerify(t, store)
	h.binder = &fakeBinder{res: bindResult{Status: tenantStatusActive}}

	w := httptest.NewRecorder()
	h.handleVerify(w, postJSON("/api/verify", `{"email":"v@example.com","token":"`+rawToken+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("验证应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	body := readAudit(t, auditFile)
	if !strings.Contains(body, "tenant_register") {
		t.Fatalf("应落 tenant_register:\n%s", body)
	}
	if !strings.Contains(body, tenantID) {
		t.Errorf("Target 应为 tenant_id(%s):\n%s", tenantID, body)
	}
	if strings.Contains(body, "v@example.com") {
		t.Errorf("审计不得落明文邮箱:\n%s", body)
	}
}

// newAuditTestHandlerFor 构造带审计链的租户 handler（可指定 config）。
// 注：审计链持有文件句柄（运行期语义），故用 os.MkdirTemp + 忽略删除错误（Windows 文件锁）；
// 不用 t.TempDir()——其内部 RemoveAll 失败会 fail 测试。
func newAuditTestHandlerFor(t *testing.T, cfg *config) (*tenantHandler, *sqliteTenantStore, string) {
	t.Helper()
	ts := newTestStore(t)
	dir, err := os.MkdirTemp("", "tenant-audit")
	if err != nil {
		t.Fatalf("创建临时目录失败: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	auditFile := filepath.Join(dir, "admin-audit.log")
	chain, err := newAdminAuditChain(auditFile, "")
	if err != nil {
		t.Fatalf("初始化审计链失败: %v", err)
	}
	if chain == nil {
		t.Fatal("审计链不应为 nil")
	}
	h := newTenantHandler(ts, cfg, nil, nil, nil, nil, chain)
	h.mailer = &fakeMailer{}
	return h, ts, auditFile
}
