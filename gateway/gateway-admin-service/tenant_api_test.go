package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------- 测试辅助 ----------

// testTenantCfg 构造测试用配置（captcha 默认关闭，专项用例单独开启）。
func testTenantCfg() *config {
	return &config{
		jwtSecret:                   []byte("shared-secret-16chars-minimum"),
		tenantPepper:                []byte("test-pepper-32bytes-minimum-padding!!"),
		emailVerifyTTLHours:         24,
		passwordResetTTLHours:       1,
		passwordResetIntervalMin:    15,
		mailTokenFailLimit:          10,
		loginMaxFail:                5,
		loginLockMin:                15,
		registerIPDailyLimit:        5,
		tenantCompensateIntervalMin: 30,
		captchaEnabled:              false,
		captchaTTLMin:               5,
		captchaIPRatePerHour:        30,
		smtpHost:                    "smtp.example.com",
		smtpPort:                    587,
		smtpFrom:                    "no-reply@example.com",
		smtpTLS:                     true,
		portalBaseURL:               "https://portal.example.com",
		apiKeyDefaultTTLDays:        90,
		apiKeyMaxTTLDays:            365,
	}
}

// fakeMailer 记录邮件调用，不真正发信。
type fakeMailer struct {
	verifyCalls     int
	resetCalls      int
	alreadyCalls    int
	lastVerifyToken string
	lastResetToken  string
}

func (m *fakeMailer) SendVerifyEmail(_, _, token string) error {
	m.verifyCalls++
	m.lastVerifyToken = token
	return nil
}
func (m *fakeMailer) SendResetEmail(_, token string) error {
	m.resetCalls++
	m.lastResetToken = token
	return nil
}
func (m *fakeMailer) SendAlreadyRegisteredEmail(string) error {
	m.alreadyCalls++
	return nil
}

// fakeBinder 记录绑定调用。
type fakeBinder struct {
	res    bindResult
	err    error
	calls  int
	tenant string
}

func (b *fakeBinder) BindFree(_ context.Context, tenantID, _ string) (bindResult, error) {
	b.calls++
	b.tenant = tenantID
	return b.res, b.err
}

// newAPITestHandler 构造测试 handler（mailer 替换为 fake）。
func newAPITestHandler(t *testing.T, cfg *config, binder quotaBinder) (*tenantHandler, *sqliteTenantStore, *fakeMailer) {
	t.Helper()
	ts := newTestStore(t)
	h := newTenantHandler(ts, cfg, binder, nil, nil, nil, nil)
	fm := &fakeMailer{}
	h.mailer = fm
	return h, ts, fm
}

// issueTestCaptcha 生成验证码并取回明文（同包访问内部 map）。
func issueTestCaptcha(t *testing.T, h *tenantHandler) (id, code string) {
	t.Helper()
	id, _, err := h.captcha.Issue("10.0.0.1")
	if err != nil {
		t.Fatalf("签发验证码失败: %v", err)
	}
	h.captcha.mu.Lock()
	code = h.captcha.items[id].code
	h.captcha.mu.Unlock()
	return id, code
}

// postJSON 构造 POST 请求。
func postJSON(path, body string) *http.Request {
	req := httptest.NewRequest("POST", path, bytes.NewBufferString(body))
	req.RemoteAddr = "10.0.0.1:12345"
	return req
}

// ---------- 注册 ----------

func TestAPI_Register_MailerDisabled_Returns503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.mailer = nil
	w := httptest.NewRecorder()
	h.handleRegister(w, postJSON("/v1/tenant/register", `{}`))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("SMTP 未配置应 503, got=%d", w.Code)
	}
}

func TestAPI_Register_Success_Returns202(t *testing.T) {
	h, store, fm := newAPITestHandler(t, testTenantCfg(), nil)
	body := `{"email":"new@example.com","password":"Password123!","tenant_name":"我的租户","agree_terms":true}`
	w := httptest.NewRecorder()
	h.handleRegister(w, postJSON("/v1/tenant/register", body))

	if w.Code != http.StatusAccepted {
		t.Fatalf("注册应 202, got=%d body=%s", w.Code, w.Body.String())
	}
	u, _ := store.GetUserByEmail("new@example.com")
	if u == nil || u.Status != tenantUserStatusPending {
		t.Fatal("用户未按 pending 创建")
	}
	tn, _ := store.GetTenantByID(u.TenantID)
	if tn == nil || tn.Status != tenantStatusPending {
		t.Fatalf("租户状态应为 pending, got=%+v", tn)
	}
	if fm.verifyCalls != 1 || fm.lastVerifyToken == "" {
		t.Error("未发送验证邮件")
	}
}

func TestAPI_Register_InvalidParams_Returns400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	cases := map[string]string{
		"非法邮箱":   `{"email":"bad","password":"Password123!","tenant_name":"ab","agree_terms":true}`,
		"弱密码":    `{"email":"a@b.com","password":"short","tenant_name":"ab","agree_terms":true}`,
		"密码类别不足": `{"email":"a@b.com","password":"abcdefghij","tenant_name":"ab","agree_terms":true}`,
		"租户名过短":  `{"email":"a@b.com","password":"Password123!","tenant_name":"a","agree_terms":true}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.handleRegister(w, postJSON("/v1/tenant/register", body))
			if w.Code != http.StatusBadRequest {
				t.Errorf("应 400, got=%d", w.Code)
			}
		})
	}
}

func TestAPI_Register_AgreeTermsFalse_Returns400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	body := `{"email":"a@b.com","password":"Password123!","tenant_name":"ab","agree_terms":false}`
	w := httptest.NewRecorder()
	h.handleRegister(w, postJSON("/v1/tenant/register", body))
	if w.Code != http.StatusBadRequest {
		t.Errorf("未同意条款应 400, got=%d", w.Code)
	}
}

func TestAPI_Register_DuplicateEmail_Returns202WithNotice(t *testing.T) {
	h, store, fm := newAPITestHandler(t, testTenantCfg(), nil)
	seedTenantUser(t, store, "dup@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	body := `{"email":"dup@example.com","password":"Password123!","tenant_name":"新租户","agree_terms":true}`
	w := httptest.NewRecorder()
	h.handleRegister(w, postJSON("/v1/tenant/register", body))
	if w.Code != http.StatusAccepted {
		t.Errorf("重复邮箱应 202, got=%d", w.Code)
	}
	if fm.alreadyCalls != 1 {
		t.Error("未发送已注册提示邮件")
	}
}

func TestAPI_Register_CaptchaRequired(t *testing.T) {
	cfg := testTenantCfg()
	cfg.captchaEnabled = true
	h, _, _ := newAPITestHandler(t, cfg, nil)

	// 缺验证码 → 400
	body := `{"email":"c@example.com","password":"Password123!","tenant_name":"ab","agree_terms":true}`
	w := httptest.NewRecorder()
	h.handleRegister(w, postJSON("/v1/tenant/register", body))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺验证码应 400, got=%d", w.Code)
	}

	// 带正确验证码 → 202
	id, code := issueTestCaptcha(t, h)
	body2 := `{"email":"c@example.com","password":"Password123!","tenant_name":"ab","agree_terms":true,"captcha_id":"` + id + `","captcha_code":"` + code + `"}`
	w2 := httptest.NewRecorder()
	h.handleRegister(w2, postJSON("/v1/tenant/register", body2))
	if w2.Code != http.StatusAccepted {
		t.Errorf("正确验证码应 202, got=%d", w2.Code)
	}
}

// ---------- 邮箱验证 ----------

func TestAPI_Verify_BinderDisabled_Returns503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	w := httptest.NewRecorder()
	h.handleVerify(w, postJSON("/v1/tenant/verify", `{"email":"a@b.com","token":"x"}`))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("billing 未启用应 503, got=%d", w.Code)
	}
}

func TestAPI_Verify_Success_ActiveAndBound(t *testing.T) {
	binder := &fakeBinder{res: bindResult{Status: tenantStatusActive, MonthlyTokens: 1000000, Concurrency: 5}}
	h, store, _ := newAPITestHandler(t, testTenantCfg(), binder)

	tenantID, userID, rawToken := seedPendingVerify(t, store)

	w := httptest.NewRecorder()
	h.handleVerify(w, postJSON("/v1/tenant/verify",
		`{"email":"v@example.com","token":"`+rawToken+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("验证应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var resp verifyResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if resp.Status != tenantStatusActive || resp.PlanID != freePlanID {
		t.Errorf("响应不对: %+v", resp)
	}
	if resp.Quota == nil || !resp.Quota.Applied {
		t.Errorf("quota 应 applied: %+v", resp.Quota)
	}
	if binder.calls != 1 || binder.tenant != tenantID {
		t.Errorf("binder 调用异常: calls=%d tenant=%s", binder.calls, binder.tenant)
	}
	tn, _ := store.GetTenantByID(tenantID)
	if tn.Status != tenantStatusActive {
		t.Errorf("租户应 active, got=%s", tn.Status)
	}
	u, _ := store.GetUserByID(userID)
	if u.Status != tenantUserStatusActive {
		t.Errorf("用户应 active, got=%s", u.Status)
	}
}

func TestAPI_Verify_QuotaPending(t *testing.T) {
	binder := &fakeBinder{res: bindResult{Status: tenantStatusQuotaPending, MonthlyTokens: 1000000, Concurrency: 5}}
	h, store, _ := newAPITestHandler(t, testTenantCfg(), binder)
	tenantID, _, rawToken := seedPendingVerify(t, store)

	w := httptest.NewRecorder()
	h.handleVerify(w, postJSON("/v1/tenant/verify",
		`{"email":"v@example.com","token":"`+rawToken+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var resp verifyResponse
	json.NewDecoder(w.Body).Decode(&resp)
	if resp.Status != tenantStatusQuotaPending || resp.Quota.Applied {
		t.Errorf("应为 quota_pending 且 applied=false: %+v", resp)
	}
	tn, _ := store.GetTenantByID(tenantID)
	if tn.Status != tenantStatusQuotaPending {
		t.Errorf("租户应 quota_pending, got=%s", tn.Status)
	}
}

func TestAPI_Verify_InvalidToken_Returns400(t *testing.T) {
	binder := &fakeBinder{res: bindResult{Status: tenantStatusActive}}
	h, _, _ := newAPITestHandler(t, testTenantCfg(), binder)
	w := httptest.NewRecorder()
	h.handleVerify(w, postJSON("/v1/tenant/verify", `{"email":"v@example.com","token":"bogus"}`))
	if w.Code != http.StatusBadRequest {
		t.Errorf("无效令牌应 400, got=%d", w.Code)
	}
}

// ---------- 登录 ----------

func TestAPI_Login_Success_NoToken(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	seedTenantUser(t, store, "login@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	body := `{"email":"login@example.com","password":"Password123!"}`
	w := httptest.NewRecorder()
	h.handleLogin(w, postJSON("/v1/tenant/login", body))
	if w.Code != http.StatusOK {
		t.Fatalf("登录应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if _, hasToken := resp["token"]; hasToken {
		t.Error("login 不应返回令牌（C-14）")
	}
	if resp["role"] != tenantRole {
		t.Errorf("role 不对: %v", resp["role"])
	}
}

func TestAPI_Login_WrongPassword_Returns401(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	seedTenantUser(t, store, "lp@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	w := httptest.NewRecorder()
	h.handleLogin(w, postJSON("/v1/tenant/login", `{"email":"lp@example.com","password":"WrongPass123!"}`))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("密码错误应 401, got=%d", w.Code)
	}
}

func TestAPI_Login_LockAfterMaxFail(t *testing.T) {
	cfg := testTenantCfg()
	cfg.loginMaxFail = 3
	h, store, _ := newAPITestHandler(t, cfg, nil)
	seedTenantUser(t, store, "lock@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		h.handleLogin(w, postJSON("/v1/tenant/login", `{"email":"lock@example.com","password":"WrongPass123!"}`))
	}
	// 第 4 次（即使密码正确）应因锁定返回 423
	w := httptest.NewRecorder()
	h.handleLogin(w, postJSON("/v1/tenant/login", `{"email":"lock@example.com","password":"Password123!"}`))
	if w.Code != http.StatusLocked {
		t.Errorf("锁定后应 423, got=%d", w.Code)
	}
}

func TestAPI_Login_QuotaPending_Returns403(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	seedTenantUser(t, store, "qp@example.com", "Password123!", tenantUserStatusActive, tenantStatusQuotaPending)
	w := httptest.NewRecorder()
	h.handleLogin(w, postJSON("/v1/tenant/login", `{"email":"qp@example.com","password":"Password123!"}`))
	if w.Code != http.StatusForbidden {
		t.Errorf("quota_pending 应 403, got=%d", w.Code)
	}
}

// ---------- 登出 ----------

func TestAPI_Logout_RequiresCSRF(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	token := newTenantJWT(h.jwtSecret, "1", "t_1", "a@b.com", 3600)
	chain := tenantAuthMiddleware(h.cfg, csrfCheck(h.handleLogout))

	// 缺 CSRF → 403
	req := httptest.NewRequest("POST", "/v1/adminext/tenant/logout", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	chain(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("缺 CSRF 应 403, got=%d", w.Code)
	}

	// 带 CSRF → 200
	req2 := httptest.NewRequest("POST", "/v1/adminext/tenant/logout", nil)
	req2.Header.Set("Authorization", "Bearer "+token)
	req2.Header.Set("X-CSRF-Token", "csrf-token-value")
	req2.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token-value"})
	w2 := httptest.NewRecorder()
	chain(w2, req2)
	if w2.Code != http.StatusOK {
		t.Errorf("带 CSRF 应 200, got=%d", w2.Code)
	}
}

// ---------- 验证码签发 ----------

func TestAPI_Captcha_Issue(t *testing.T) {
	cfg := testTenantCfg()
	cfg.captchaEnabled = true
	h, _, _ := newAPITestHandler(t, cfg, nil)

	req := httptest.NewRequest("GET", "/v1/adminext/captcha", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	w := httptest.NewRecorder()
	h.handleCaptcha(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("签发应 200, got=%d", w.Code)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["captcha_id"] == "" || resp["image"] == "" {
		t.Errorf("响应缺少字段: %+v", resp)
	}
}

func TestAPI_Captcha_Disabled_Returns404(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil) // captchaEnabled=false
	req := httptest.NewRequest("GET", "/v1/adminext/captcha", nil)
	w := httptest.NewRecorder()
	h.handleCaptcha(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("禁用应 404, got=%d", w.Code)
	}
}

// ---------- 密码重置 ----------

func TestAPI_PasswordReset_Flow(t *testing.T) {
	h, store, fm := newAPITestHandler(t, testTenantCfg(), nil)
	seedTenantUser(t, store, "reset@example.com", "OldPass123!", tenantUserStatusActive, tenantStatusActive)

	// 申请
	w := httptest.NewRecorder()
	h.handlePasswordReset(w, postJSON("/v1/tenant/password-reset", `{"email":"reset@example.com"}`))
	if w.Code != http.StatusAccepted {
		t.Fatalf("申请应 202, got=%d", w.Code)
	}
	if fm.resetCalls != 1 || fm.lastResetToken == "" {
		t.Fatal("未发送重置邮件")
	}

	// 确认
	confirmBody := `{"email":"reset@example.com","token":"` + fm.lastResetToken + `","new_password":"NewPass456!"}`
	w2 := httptest.NewRecorder()
	h.handlePasswordResetConfirm(w2, postJSON("/v1/tenant/password-reset/confirm", confirmBody))
	if w2.Code != http.StatusOK {
		t.Fatalf("确认应 200, got=%d body=%s", w2.Code, w2.Body.String())
	}
	u, _ := store.GetUserByEmail("reset@example.com")
	if !verifyPassword(u.PasswordHash, "NewPass456!") {
		t.Error("新密码未生效")
	}
}

func TestAPI_PasswordReset_UnknownEmail_Still202(t *testing.T) {
	h, _, fm := newAPITestHandler(t, testTenantCfg(), nil)
	w := httptest.NewRecorder()
	h.handlePasswordReset(w, postJSON("/v1/tenant/password-reset", `{"email":"nobody@example.com"}`))
	if w.Code != http.StatusAccepted {
		t.Errorf("未知邮箱也应 202, got=%d", w.Code)
	}
	if fm.resetCalls != 0 {
		t.Error("未知邮箱不应发信")
	}
}

// ---------- 工具函数 ----------

func TestValidEmail(t *testing.T) {
	cases := map[string]bool{
		"a@b.com": true, "user.name@domain.co.uk": true,
		"notanemail": false, "@x.com": false, "": false,
	}
	for in, want := range cases {
		if got := validEmail(in); got != want {
			t.Errorf("validEmail(%q)=%v want=%v", in, got, want)
		}
	}
}

func TestValidPassword(t *testing.T) {
	cases := map[string]bool{
		"Password123!": true,  // 四类
		"abcdefghij1":  false, // 仅两类（小写+数字）
		"Abcdefgh12":   true,  // 大写+小写+数字
		"short1A":      false, // 过短
		"abcdefghijk":  false, // 仅一类
	}
	for in, want := range cases {
		if got := validPassword(in); got != want {
			t.Errorf("validPassword(%q)=%v want=%v", in, got, want)
		}
	}
}

func TestSanitizeTenantName(t *testing.T) {
	if _, ok := sanitizeTenantName("a"); ok {
		t.Error("过短应失败")
	}
	if got, ok := sanitizeTenantName("  示例科技  "); !ok || got != "示例科技" {
		t.Errorf("trim 失败: %q ok=%v", got, ok)
	}
}

func TestGenerateTenantID(t *testing.T) {
	id1, err := generateTenantID()
	if err != nil {
		t.Fatal(err)
	}
	id2, _ := generateTenantID()
	if id1 == id2 {
		t.Error("ID 不应重复")
	}
	if len(id1) != 2+24 || id1[:2] != "t_" {
		t.Errorf("ID 格式不对: %s", id1)
	}
}

// ---------- seed 辅助 ----------

// seedTenantUser 直接写入 active/指定状态的租户与用户。
func seedTenantUser(t *testing.T, store *sqliteTenantStore, email, password, userStatus, tenantStatus string) (string, int64) {
	t.Helper()
	now := time.Now().Unix()
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	tid, _ := generateTenantID()
	if err := store.CreateTenant(tx, &Tenant{
		ID: tid, Name: "seed", Status: tenantStatus, PlanID: freePlanID, CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	pwHash, _ := hashPassword(password)
	uid, err := store.CreateUser(tx, &TenantUser{
		TenantID: tid, Email: email, PasswordHash: pwHash, Status: userStatus, CreatedAt: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return tid, uid
}

// seedPendingVerify 写入 pending 租户/用户 + 验证令牌，返回 (tenantID, userID, 明文令牌)。
func seedPendingVerify(t *testing.T, store *sqliteTenantStore) (string, int64, string) {
	t.Helper()
	tid, uid := seedTenantUser(t, store, "v@example.com", "Password123!", tenantUserStatusPending, tenantStatusPending)
	raw, err := randomToken(32)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.CreateToken(tx, &MailActionToken{
		TokenHash: store.hashMailToken(raw), TenantUserID: uid, Action: mailActionVerify,
		ExpiresAt: time.Now().Unix() + 3600,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return tid, uid, raw
}
