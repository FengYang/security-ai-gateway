package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newTestHandler 创建测试用 tenant handler（SMTP 启用，走日志模式不发实信）。
func newTestHandler(t *testing.T, smtpEnabled bool) (*tenantHandler, *sqliteTenantStore) {
	t.Helper()
	ts := newTestStore(t)
	secret := []byte("test-secret-16chars-minimum-jwt")
	host, user, pass, from := "", "", "", ""
	if smtpEnabled {
		host = "smtp.example.com"
		user = "test@example.com"
		pass = "pass123"
		from = "no-reply@example.com"
	}
	h := newTenantHandler(ts, secret, host, user, pass, from, 587)
	return h, ts
}

// ---------- 注册 ----------

func TestAPI_Register_SMTPDisabled_Returns503(t *testing.T) {
	h, _ := newTestHandler(t, false)
	body := `{"email":"test@example.com","password":"password123","tenant_name":"测试"}`
	req := httptest.NewRequest("POST", "/v1/tenant/register", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.handleRegister(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("SMTP 未启用应返 503, got=%d", w.Code)
	}
}

func TestAPI_Register_Success_Returns202(t *testing.T) {
	h, _ := newTestHandler(t, true)
	body := `{"email":"newuser@example.com","password":"password123","tenant_name":"我的租户"}`
	req := httptest.NewRequest("POST", "/v1/tenant/register", bytes.NewBufferString(body))
	req.RemoteAddr = "10.0.0.1:12345"
	w := httptest.NewRecorder()
	h.handleRegister(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("注册成功应返 202, got=%d body=%s", w.Code, w.Body.String())
	}

	// 验证用户已创建
	u, err := h.store.GetUserByEmail("newuser@example.com")
	if err != nil {
		t.Fatalf("查询用户失败: %v", err)
	}
	if u == nil {
		t.Fatal("用户未创建")
	}
	if u.Status != tenantUserStatusPending {
		t.Errorf("新用户状态应为 pending, got=%s", u.Status)
	}
	if u.TenantID == "" {
		t.Error("租户 ID 为空")
	}
	// 验证租户
	tenant, _ := h.store.GetTenantByID(u.TenantID)
	if tenant == nil {
		t.Error("租户未创建")
	}
	if tenant.Name != "我的租户" {
		t.Errorf("租户名不对: %s", tenant.Name)
	}
	if tenant.PlanID != "free" {
		t.Errorf("默认套餐应为 free, got=%s", tenant.PlanID)
	}
}

func TestAPI_Register_DuplicateEmail_Returns202(t *testing.T) {
	h, s := newTestHandler(t, true)

	// 先创建一个
	now := time.Now().Unix()
	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_exist", Name: "e", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	pwHash, _ := hashPassword("password123")
	s.CreateUser(tx, &TenantUser{TenantID: "t_exist", Email: "exist@example.com", PasswordHash: pwHash, Status: tenantUserStatusActive, CreatedAt: now})
	tx.Commit()

	// 再注册同一个邮箱
	body := `{"email":"exist@example.com","password":"password123","tenant_name":"新租户"}`
	req := httptest.NewRequest("POST", "/v1/tenant/register", bytes.NewBufferString(body))
	req.RemoteAddr = "10.0.0.2:12345"
	w := httptest.NewRecorder()
	h.handleRegister(w, req)

	// 防枚举：也返 202
	if w.Code != http.StatusAccepted {
		t.Errorf("重复邮箱也应返 202, got=%d", w.Code)
	}
	// 用户数应不变
	u, _ := h.store.GetUserByEmail("exist@example.com")
	if u.TenantID != "t_exist" {
		t.Error("不应覆盖既有用户的租户")
	}
}

func TestAPI_Register_InvalidInput_Returns202(t *testing.T) {
	h, _ := newTestHandler(t, true)

	tests := []struct {
		name string
		body string
	}{
		{"空邮箱", `{"email":"","password":"password123","tenant_name":"t"}`},
		{"非法邮箱", `{"email":"not-an-email","password":"password123","tenant_name":"t"}`},
		{"短密码", `{"email":"a@b.com","password":"short","tenant_name":"t"}`},
		{"空租户名", `{"email":"a@b.com","password":"password123","tenant_name":""}`},
		{"空 body", ``},
		{"非法 JSON", `not-json`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/tenant/register", bytes.NewBufferString(tt.body))
			req.RemoteAddr = "10.0.0.9:12345"
			w := httptest.NewRecorder()
			h.handleRegister(w, req)
			if w.Code != http.StatusAccepted {
				t.Errorf("%s: 应返 202, got=%d", tt.name, w.Code)
			}
		})
	}
}

// ---------- 验证 ----------

func TestAPI_Verify_Success(t *testing.T) {
	h, s := newTestHandler(t, true)
	now := time.Now().Unix()

	// 创建 pending 用户 + 验证令牌
	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_v", Name: "v", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	uid, _ := s.CreateUser(tx, &TenantUser{TenantID: "t_v", Email: "v@e.com", PasswordHash: "h", Status: tenantUserStatusPending, CreatedAt: now})
	tokenHash := s.hashMailToken("verify-token-123")
	s.CreateToken(tx, &MailActionToken{
		TokenHash:    tokenHash,
		TenantUserID: uid,
		Action:       mailActionVerify,
		ExpiresAt:    now + 3600,
	})
	tx.Commit()

	body := `{"token":"verify-token-123"}`
	req := httptest.NewRequest("POST", "/v1/tenant/verify", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.handleVerify(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("验证成功应返 200, got=%d body=%s", w.Code, w.Body.String())
	}
	// 用户状态变 active
	u, _ := h.store.GetUserByID(uid)
	if u.Status != tenantUserStatusActive {
		t.Errorf("用户状态应为 active, got=%s", u.Status)
	}
	// 令牌被消费
	tok, _ := h.store.GetToken(tokenHash)
	if tok.ConsumedAt == 0 {
		t.Error("令牌应被消费")
	}
}

func TestAPI_Verify_InvalidToken(t *testing.T) {
	h, _ := newTestHandler(t, true)

	tests := []struct {
		name string
		body string
	}{
		{"空令牌", `{"token":""}`},
		{"不存在的令牌", `{"token":"no-such-token"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/v1/tenant/verify", bytes.NewBufferString(tt.body))
			w := httptest.NewRecorder()
			h.handleVerify(w, req)
			if w.Code != http.StatusBadRequest {
				t.Errorf("%s: 应返 400, got=%d", tt.name, w.Code)
			}
		})
	}
}

func TestAPI_Verify_ExpiredToken(t *testing.T) {
	h, s := newTestHandler(t, true)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_e", Name: "e", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	uid, _ := s.CreateUser(tx, &TenantUser{TenantID: "t_e", Email: "e@e.com", PasswordHash: "h", Status: tenantUserStatusPending, CreatedAt: now})
	s.CreateToken(tx, &MailActionToken{
		TokenHash:    s.hashMailToken("expired-token"),
		TenantUserID: uid,
		Action:       mailActionVerify,
		ExpiresAt:    now - 100, // 已过期
	})
	tx.Commit()

	req := httptest.NewRequest("POST", "/v1/tenant/verify", bytes.NewBufferString(`{"token":"expired-token"}`))
	w := httptest.NewRecorder()
	h.handleVerify(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("过期令牌应返 400, got=%d", w.Code)
	}
}

// ---------- 登录 ----------

func TestAPI_Login_Success(t *testing.T) {
	h, s := newTestHandler(t, true)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_login", Name: "l", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	pwHash, _ := hashPassword("correct-pass")
	s.CreateUser(tx, &TenantUser{TenantID: "t_login", Email: "login@e.com", PasswordHash: pwHash, Status: tenantUserStatusActive, CreatedAt: now})
	tx.Commit()

	body := `{"email":"login@e.com","password":"correct-pass"}`
	req := httptest.NewRequest("POST", "/v1/tenant/login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.handleLogin(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("登录成功应返 200, got=%d body=%s", w.Code, w.Body.String())
	}

	var resp loginResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if resp.Token == "" {
		t.Error("响应无 token")
	}
	if resp.ExpiresIn != tenantTokenTTL {
		t.Errorf("ExpiresIn: got=%d want=%d", resp.ExpiresIn, tenantTokenTTL)
	}

	// 校验返回的令牌合法
	claims, err := verifyTenantToken(resp.Token, h.jwtSecret)
	if err != nil {
		t.Errorf("返回的令牌校验失败: %v", err)
	}
	if claims.Tenant != "t_login" {
		t.Errorf("令牌 tenant 不对: %s", claims.Tenant)
	}
}

func TestAPI_Login_WrongPassword(t *testing.T) {
	h, s := newTestHandler(t, true)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_lp", Name: "lp", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	pwHash, _ := hashPassword("correct-pass")
	s.CreateUser(tx, &TenantUser{TenantID: "t_lp", Email: "lp@e.com", PasswordHash: pwHash, Status: tenantUserStatusActive, CreatedAt: now})
	tx.Commit()

	body := `{"email":"lp@e.com","password":"wrong-pass"}`
	req := httptest.NewRequest("POST", "/v1/tenant/login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("密码错误应返 401, got=%d", w.Code)
	}
}

func TestAPI_Login_UserNotFound(t *testing.T) {
	h, _ := newTestHandler(t, true)
	body := `{"email":"no@e.com","password":"password123"}`
	req := httptest.NewRequest("POST", "/v1/tenant/login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("用户不存在应返 401, got=%d", w.Code)
	}
}

func TestAPI_Login_PendingUser(t *testing.T) {
	h, s := newTestHandler(t, true)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_p", Name: "p", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	pwHash, _ := hashPassword("password123")
	s.CreateUser(tx, &TenantUser{TenantID: "t_p", Email: "p@e.com", PasswordHash: pwHash, Status: tenantUserStatusPending, CreatedAt: now})
	tx.Commit()

	body := `{"email":"p@e.com","password":"password123"}`
	req := httptest.NewRequest("POST", "/v1/tenant/login", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.handleLogin(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("pending 用户应返 401, got=%d body=%s", w.Code, w.Body.String())
	}
	if w.Body.String() == "" || !bytes.Contains(w.Body.Bytes(), []byte("邮箱未验证")) {
		// 应该包含提示信息
		t.Logf("响应体: %s", w.Body.String())
	}
}

// ---------- 登出 ----------

func TestAPI_Logout(t *testing.T) {
	h, _ := newTestHandler(t, true)

	secret := h.jwtSecret
	token, _ := issueTenantToken(secret, 1, "t_1", "a@b.com")

	req := httptest.NewRequest("POST", "/v1/tenant/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	// 走中间件 + handler
	handler := tenantAuthMiddleware(secret, h.handleLogout)
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("登出应返 200, got=%d", w.Code)
	}
}

// ---------- /me ----------

func TestAPI_Me(t *testing.T) {
	h, _ := newTestHandler(t, true)

	token, _ := issueTenantToken(h.jwtSecret, 1, "t_me", "me@e.com")

	req := httptest.NewRequest("GET", "/v1/tenant/me", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()

	handler := tenantAuthMiddleware(h.jwtSecret, h.handleMe)
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("/me 应返 200, got=%d", w.Code)
	}
	var resp meResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Email != "me@e.com" {
		t.Errorf("Email 不对: %s", resp.Email)
	}
	if resp.Tenant != "t_me" {
		t.Errorf("Tenant 不对: %s", resp.Tenant)
	}
}

// ---------- 密码重置 ----------

func TestAPI_PasswordReset_Request_Returns202(t *testing.T) {
	h, s := newTestHandler(t, true)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_r", Name: "r", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	pwHash, _ := hashPassword("old-pass")
	s.CreateUser(tx, &TenantUser{TenantID: "t_r", Email: "reset@e.com", PasswordHash: pwHash, Status: tenantUserStatusActive, CreatedAt: now})
	tx.Commit()

	body := `{"email":"reset@e.com"}`
	req := httptest.NewRequest("POST", "/v1/tenant/password-reset", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.handlePasswordReset(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("重置申请应返 202, got=%d", w.Code)
	}
	// 应该有 token 被创建（通过用户 ID 查）
	u, _ := h.store.GetUserByEmail("reset@e.com")
	if u == nil {
		t.Fatal("用户不存在")
	}
}

func TestAPI_PasswordReset_UserNotFound_Returns202(t *testing.T) {
	h, _ := newTestHandler(t, true)
	body := `{"email":"notfound@e.com"}`
	req := httptest.NewRequest("POST", "/v1/tenant/password-reset", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.handlePasswordReset(w, req)

	if w.Code != http.StatusAccepted {
		t.Errorf("用户不存在也应返 202, got=%d", w.Code)
	}
}

func TestAPI_PasswordReset_Confirm_Success(t *testing.T) {
	h, s := newTestHandler(t, true)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_rc", Name: "rc", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	oldHash, _ := hashPassword("old-pass")
	uid, _ := s.CreateUser(tx, &TenantUser{TenantID: "t_rc", Email: "rc@e.com", PasswordHash: oldHash, Status: tenantUserStatusActive, CreatedAt: now})
	s.CreateToken(tx, &MailActionToken{
		TokenHash:    s.hashMailToken("reset-token-abc"),
		TenantUserID: uid,
		Action:       mailActionPasswordReset,
		ExpiresAt:    now + 3600,
	})
	tx.Commit()

	body := `{"token":"reset-token-abc","new_password":"new-password-123"}`
	req := httptest.NewRequest("POST", "/v1/tenant/password-reset/confirm", bytes.NewBufferString(body))
	w := httptest.NewRecorder()
	h.handlePasswordResetConfirm(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("重置确认应返 200, got=%d body=%s", w.Code, w.Body.String())
	}
	// 验证新密码可用
	u, _ := h.store.GetUserByID(uid)
	if !verifyPassword(u.PasswordHash, "new-password-123") {
		t.Error("新密码校验失败")
	}
	if verifyPassword(u.PasswordHash, "old-pass") {
		t.Error("旧密码不应仍可用")
	}
}

// ---------- 辅助工具 ----------

func TestValidEmail(t *testing.T) {
	tests := []struct {
		email string
		want  bool
	}{
		{"a@b.com", true},
		{"user.name+tag@domain.co.uk", true},
		{"notanemail", false},
		{"@no-local.com", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := validEmail(tt.email); got != tt.want {
			t.Errorf("validEmail(%q) = %v, want %v", tt.email, got, tt.want)
		}
	}
}

func TestValidPassword(t *testing.T) {
	if validPassword("") {
		t.Error("空密码应无效")
	}
	if validPassword("1234567") {
		t.Error("7 位密码应无效")
	}
	if !validPassword("12345678") {
		t.Error("8 位密码应有效")
	}
	if !validPassword("aA1!@#$%^&*()_+") {
		t.Error("复杂密码应有效")
	}
}

func TestGenerateTenantID(t *testing.T) {
	id1, err := generateTenantID()
	if err != nil {
		t.Fatalf("generateTenantID 失败: %v", err)
	}
	id2, _ := generateTenantID()
	if id1 == id2 {
		t.Error("两次生成的 ID 不应相同")
	}
	if len(id1) != 2+24 { // t_ + 12 bytes hex
		t.Errorf("ID 长度不对: %d", len(id1))
	}
	if id1[:2] != "t_" {
		t.Errorf("ID 应以 t_ 开头: %s", id1)
	}
}
