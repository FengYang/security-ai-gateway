// Package main — 租户自助门户 API（注册/验证/登录/登出/密码重置/验证码）。
//
// 契约（§6.2，v1.3 定档）：
//   - 公开端点 `/v1/tenant/*`：无需令牌，图形验证码 + 频率限制；
//     register（参数/验证码非法 → 400；频率超限 → 429；成功与邮箱已存在统一 202，防枚举）
//   - 验证码签发 `/v1/adminext/captcha`：Console 内部端点（authMiddleware）
//   - 租户会话端点 `/v1/adminext/tenant/*`：租户令牌 + CSRF（写）
//   - login 只做凭据校验，**不返令牌**（Console 自建 admext1.* 会话，C-14）
//   - verify 绑定 free 并回读确认：通过 → active；未确认 → quota_pending；billing 关闭 → 503
package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	tenantAPIBase     = "/v1/tenant"
	tenantSessionBase = "/v1/adminext/tenant"
	captchaAPIBase    = "/v1/adminext/captcha"
)

// tenantHandler 租户门户 HTTP 处理器。
type tenantHandler struct {
	store      TenantStore
	cfg        *config
	jwtSecret  []byte // 租户会话令牌校验密钥（= cfg.jwtSecret，共享密钥，§6.1）
	mailer     tenantMailer
	captcha    captchaBackend       // 验证码后端（默认进程内 *captchaStore；SECURITY_STORE_PG_DSN 配置后为共享库实现）
	binder     quotaBinder          // nil = billing 域未启用
	issuer     keyIssuer            // nil = Key 签发通道未配置（§6.11）
	usage      *usageHandler        // M4：tee-infer 用量代理（复用）
	billing    *billingHandler      // M4：账单查询/导出（复用；nil = billing 未启用）
	catalog    *modelCatalogHandler // M5：模型目录（复用；nil = 目录未接线）
	audit      *adminAuditChain
	loginGuard *loginGuard
	resetGuard *intervalGuard

	// effects 开通变更联动（N4 重签 / N5 下发），由后续子任务注入；零值 = 空操作。
	effects provisioningEffects
	// dispatch N5 下发调度器（nil = 未接线；管理员手动重放依赖它）。
	dispatch *dispatcher
	// attest N3 证明状态源（nil = 未接线 → 降级 unknown + 强制未闭环，C-19）。
	attest attestStatusSource
}

// newTenantHandler 构造租户 handler（captcha 仅在启用时创建）。
func newTenantHandler(store TenantStore, cfg *config, binder quotaBinder,
	usage *usageHandler, billH *billingHandler, cat *modelCatalogHandler, audit *adminAuditChain) *tenantHandler {
	// 注意：issuer 为接口，须显式判空赋值（避免 *httpKeyIssuer(nil) 造成 typed-nil 非空）
	var issuer keyIssuer
	if cfg.authServiceURL != "" {
		issuer = newHTTPKeyIssuer(cfg.authServiceURL, 10*time.Second)
	}
	h := &tenantHandler{
		store:      store,
		cfg:        cfg,
		jwtSecret:  cfg.jwtSecret,
		mailer:     newTenantMailer(cfg),
		binder:     binder,
		issuer:     issuer,
		usage:      usage,
		billing:    billH,
		catalog:    cat,
		audit:      audit,
		loginGuard: newLoginGuard(cfg.loginMaxFail, cfg.loginLockMin),
		resetGuard: newIntervalGuard(cfg.passwordResetIntervalMin),
	}
	if cfg.captchaEnabled {
		h.captcha = newCaptchaStore(cfg.captchaTTLMin, cfg.captchaIPRatePerHour)
	}
	return h
}

// registerMux 在租户 mux 注册端点（公开 + 租户会话）。
func (h *tenantHandler) registerMux(mux *http.ServeMux) {
	// 公开端点（/v1/tenant/*）：无需令牌
	mux.HandleFunc(tenantAPIBase+"/register", h.handleRegister)
	mux.HandleFunc(tenantAPIBase+"/verify", h.handleVerify)
	mux.HandleFunc(tenantAPIBase+"/login", h.handleLogin)
	mux.HandleFunc(tenantAPIBase+"/password-reset", h.handlePasswordReset)
	mux.HandleFunc(tenantAPIBase+"/password-reset/confirm", h.handlePasswordResetConfirm)

	// 租户会话端点（/v1/adminext/tenant/*）：租户令牌 + CSRF（写）
	mux.HandleFunc(tenantSessionBase+"/logout",
		tenantAuthMiddleware(h.cfg, csrfCheck(h.handleLogout)))

	// API Key 管理（M3）
	h.registerKeyMux(mux)

	// 用量与账单（M4）
	h.registerTenantUsageMux(mux)

	// 策略与模型（M5）
	h.registerTenantPolicyMux(mux)

	// 租户审计视图（M6）
	h.registerTenantAuditMux(mux)

	// 套餐自助（M7）
	h.registerTenantSubscriptionMux(mux)

	// 场景化开通向导（N1）
	h.registerTenantProvisioningMux(mux)

	// 密钥资产视图（N2）
	h.registerTenantSecretsMux(mux)

	// 数据面下发状态/重放（N5）
	h.registerTenantDispatchMux(mux)

	// 承诺边界声明（N4）
	h.registerTenantStatementMux(mux)

	// 远程证明状态看板（N3）
	h.registerTenantAttestMux(mux)
}

// registerCaptcha 在管理面 mux 注册验证码签发端点（Console 内部，authMiddleware）。
func (h *tenantHandler) registerCaptcha(mux *http.ServeMux, cfg *config) {
	mux.HandleFunc(captchaAPIBase, authMiddleware(cfg, h.handleCaptcha))
}

// ---------- 请求/响应结构 ----------

type registerRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	TenantName  string `json:"tenant_name"`
	AgreeTerms  bool   `json:"agree_terms"`
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
}

type verifyRequest struct {
	Email string `json:"email"`
	Token string `json:"token"`
}

type loginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
}

type loginResponse struct {
	TenantID  string `json:"tenant_id"`
	Role      string `json:"role"`
	Status    string `json:"status"`
	ExpiresAt int64  `json:"expires_at"`
}

type passwordResetRequest struct {
	Email       string `json:"email"`
	CaptchaID   string `json:"captcha_id"`
	CaptchaCode string `json:"captcha_code"`
}

type passwordResetConfirmRequest struct {
	Email       string `json:"email"`
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type quotaView struct {
	MonthlyTokens int64 `json:"monthly_tokens"`
	Concurrency   int   `json:"concurrency"`
	Applied       bool  `json:"applied"`
}

type verifyResponse struct {
	TenantID string     `json:"tenant_id"`
	Status   string     `json:"status"`
	PlanID   string     `json:"plan_id"`
	Quota    *quotaView `json:"quota,omitempty"`
}

// ---------- 工具函数 ----------

// tenantWriteJSON 写 JSON 响应。
func tenantWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// tenantWriteError 写 JSON 错误响应。
func tenantWriteError(w http.ResponseWriter, status int, msg string) {
	tenantWriteJSON(w, status, map[string]string{"error": msg})
}

// decodeJSONBody 解码请求体 JSON（限制 1MB）。
func decodeJSONBody(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	return json.NewDecoder(r.Body).Decode(v)
}

// normalizeEmail 归一化邮箱（trim + lowercase，§6.2）。
func normalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// validEmail 邮箱格式校验（net/mail 解析 + 归一化比对）。
func validEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	return addr.Address == email
}

// randomToken 生成加密安全随机令牌（hex 编码，n 为随机字节数）。
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("tenant: random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// generateTenantID 生成租户 ID（t_ + 12 字节 hex）。
func generateTenantID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "t_" + hex.EncodeToString(b), nil
}

// validPassword 密码策略（§6.2）：长度 10-128，且大写/小写/数字/符号四类中至少三类。
func validPassword(p string) bool {
	if len(p) < 10 || len(p) > 128 {
		return false
	}
	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, r := range p {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r), unicode.IsSymbol(r):
			hasSymbol = true
		}
	}
	classes := 0
	for _, ok := range []bool{hasUpper, hasLower, hasDigit, hasSymbol} {
		if ok {
			classes++
		}
	}
	return classes >= 3
}

// sanitizeTenantName 去控制字符并校验 rune 长度 2-64（§6.2）。
func sanitizeTenantName(s string) (string, bool) {
	cleaned := make([]rune, 0, len(s))
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		cleaned = append(cleaned, r)
	}
	out := strings.TrimSpace(string(cleaned))
	n := utf8.RuneCountInString(out)
	if n < 2 || n > 64 {
		return "", false
	}
	return out, true
}

// clientIP 取客户端 IP（M2 取 RemoteAddr；有代理时由边界层归一）。
func clientIP(r *http.Request) string {
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		return addr[:idx]
	}
	return addr
}

// verifyCaptcha 校验验证码（未启用 → 放行；启用但未初始化 → fail-closed 拒绝）。
func (h *tenantHandler) verifyCaptcha(r *http.Request, id, code string) bool {
	if !h.cfg.captchaEnabled {
		return true
	}
	if h.captcha == nil {
		return false
	}
	return h.captcha.Verify(id, code)
}

// auditAppend 落审计链（未启用则跳过）。
func (h *tenantHandler) auditAppend(actor, action string) {
	if h.audit == nil {
		return
	}
	if err := h.audit.append(adminAuditEvent{Actor: actor, Action: action, Result: "ok"}); err != nil {
		log.Printf("[tenant] 审计落链失败 action=%s: %v", action, err)
	}
}

// emailFingerprint 邮箱指纹（SHA-256 前 8 位；审计不落明文邮箱，附录 D）。
func emailFingerprint(email string) string {
	sum := sha256.Sum256([]byte(email))
	return hex.EncodeToString(sum[:])[:8]
}

// auditAppendTenantRegister 落 tenant_register（附录 D：Target=tenant_id；邮箱仅存哈希前缀 8 位）。
func (h *tenantHandler) auditAppendTenantRegister(tenantID, email string) {
	if h.audit == nil {
		return
	}
	fp := emailFingerprint(email)
	if err := h.audit.append(adminAuditEvent{
		Actor: fp, Action: auditActionTenantRegister, Target: tenantID,
		KeyFingerprint: fp, Result: "ok",
	}); err != nil {
		log.Printf("[tenant] 审计落链失败 action=tenant_register: %v", err)
	}
}

// auditAppendLogin 落 tenant_login（附录 D：成功/失败均落链；失败记原因，绝不记密码）。
// Result 取值：ok | bad_credentials | locked | pending | tenant_missing | quota_pending | inactive。
func (h *tenantHandler) auditAppendLogin(email, tenantID, result string) {
	if h.audit == nil {
		return
	}
	if err := h.audit.append(adminAuditEvent{
		Actor: emailFingerprint(email), Action: auditActionTenantLogin,
		Target: tenantID, Result: result,
	}); err != nil {
		log.Printf("[tenant] 审计落链失败 action=tenant_login: %v", err)
	}
}

// ---------- 注册 ----------

// handleRegister 注册端点（§6.2）。
func (h *tenantHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.mailer == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "注册功能暂未启用")
		return
	}

	var req registerRequest
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	req.Email = normalizeEmail(req.Email)
	name, nameOK := sanitizeTenantName(req.TenantName)
	if !validEmail(req.Email) || !validPassword(req.Password) || !nameOK {
		tenantWriteError(w, http.StatusBadRequest, "参数不符合要求")
		return
	}
	if !req.AgreeTerms {
		tenantWriteError(w, http.StatusBadRequest, "须同意服务条款")
		return
	}
	if !h.verifyCaptcha(r, req.CaptchaID, req.CaptchaCode) {
		tenantWriteError(w, http.StatusBadRequest, "验证码错误")
		return
	}

	// 频率限制（同 IP 每日，§10.3 REGISTER_IP_DAILY_LIMIT）
	ip := clientIP(r)
	count, err := h.store.IncRegisterRate(ip, 86400)
	if err != nil {
		log.Printf("[tenant-register] 限流计数失败 ip=%s: %v", ip, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	if count > h.cfg.registerIPDailyLimit {
		tenantWriteError(w, http.StatusTooManyRequests, "注册频率超限")
		return
	}

	// 邮箱已存在 → 发提示邮件、不写新数据（防枚举：与成功同返 202）
	existing, err := h.store.GetUserByEmail(req.Email)
	if err != nil {
		log.Printf("[tenant-register] 查询用户失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	if existing != nil {
		if err := h.mailer.SendAlreadyRegisteredEmail(req.Email); err != nil {
			log.Printf("[tenant-register] 提示邮件发送失败: %v", err)
		}
		tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}

	// 创建租户（pending）+ 用户（pending）+ 验证令牌
	tenantID, err := generateTenantID()
	if err != nil {
		log.Printf("[tenant-register] 生成租户 ID 失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	pwHash, err := hashPassword(req.Password)
	if err != nil {
		log.Printf("[tenant-register] 哈希密码失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	verifyToken, err := randomToken(32)
	if err != nil {
		log.Printf("[tenant-register] 生成验证令牌失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	now := time.Now().Unix()

	tx, err := h.store.Begin()
	if err != nil {
		log.Printf("[tenant-register] 开启事务失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	defer func() { _ = tx.Rollback() }()

	if err := h.store.CreateTenant(tx, &Tenant{
		ID: tenantID, Name: name, Status: tenantStatusPending, PlanID: freePlanID, CreatedAt: now,
	}); err != nil {
		log.Printf("[tenant-register] 创建租户失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	userID, err := h.store.CreateUser(tx, &TenantUser{
		TenantID: tenantID, Email: req.Email, PasswordHash: pwHash,
		Status: tenantUserStatusPending, CreatedAt: now,
	})
	if err != nil {
		log.Printf("[tenant-register] 创建用户失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	tokenHash := h.store.(*sqliteTenantStore).hashMailToken(verifyToken)
	if err := h.store.CreateToken(tx, &MailActionToken{
		TokenHash: tokenHash, TenantUserID: userID, Action: mailActionVerify,
		ExpiresAt: now + int64(h.cfg.emailVerifyTTLHours)*3600,
	}); err != nil {
		log.Printf("[tenant-register] 创建验证令牌失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-register] 提交事务失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "服务暂时不可用")
		return
	}

	// 发验证邮件（失败不回滚：用户可触发重发，且不泄露账户状态）
	if err := h.mailer.SendVerifyEmail(req.Email, name, verifyToken); err != nil {
		log.Printf("[tenant-register] 验证邮件发送失败: %v", err)
	}
	// 注：`tenant_register` 审计按附录 D 落在 **verify 通过时**（见 handleVerify），此处不落链。

	tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

// ---------- 邮箱验证 ----------

// handleVerify 邮箱验证端点（§6.2）：绑定 free + 配额回读确认。
func (h *tenantHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.mailer == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "验证功能暂未启用")
		return
	}
	if h.binder == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "计费域未启用，暂无法开通")
		return
	}

	var req verifyRequest
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	req.Email = normalizeEmail(req.Email)
	if req.Email == "" || req.Token == "" {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}

	tokenHash := h.store.(*sqliteTenantStore).hashMailToken(req.Token)
	tok, err := h.store.GetToken(tokenHash)
	if err != nil {
		log.Printf("[tenant-verify] 查询令牌失败: %v", err)
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	if tok == nil || tok.Action != mailActionVerify {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	if tok.ExpiresAt < time.Now().Unix() || tok.ConsumedAt > 0 {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}

	user, err := h.store.GetUserByID(tok.TenantUserID)
	if err != nil {
		log.Printf("[tenant-verify] 查询用户失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// 邮箱绑定校验：令牌归属用户邮箱须与请求一致
	if user == nil || user.Email != req.Email {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	tenant, err := h.store.GetTenantByID(user.TenantID)
	if err != nil || tenant == nil {
		log.Printf("[tenant-verify] 查询租户失败: %v", err)
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}

	// 幂等：已 active 直接返回
	if tenant.Status == tenantStatusActive {
		tenantWriteJSON(w, http.StatusOK, verifyResponse{
			TenantID: tenant.ID, Status: tenantStatusActive, PlanID: tenant.PlanID,
			Quota: &quotaView{Applied: true},
		})
		return
	}

	// 绑定 free + 配额编译/下发/回读确认
	res, err := h.binder.BindFree(r.Context(), tenant.ID, user.Email)
	if err != nil {
		log.Printf("[tenant-verify] 免费版绑定失败 tenant=%s: %v", tenant.ID, err)
		tenantWriteError(w, http.StatusInternalServerError, "开通失败，请稍后重试")
		return
	}

	// 消费令牌 + 激活用户 + 更新租户状态（同一事务）
	tx, err := h.store.Begin()
	if err != nil {
		log.Printf("[tenant-verify] 开启事务失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer func() { _ = tx.Rollback() }()

	if err := h.store.ConsumeToken(tx, tokenHash); err != nil {
		log.Printf("[tenant-verify] 消费令牌失败: %v", err)
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	if err := h.store.UpdateUserStatus(tx, user.ID, tenantUserStatusActive); err != nil {
		log.Printf("[tenant-verify] 更新用户状态失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := h.store.UpdateTenantStatus(tx, tenant.ID, res.Status); err != nil {
		log.Printf("[tenant-verify] 更新租户状态失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// N5：免费版绑定 = 配额变更，须下发数据面（ai-quota，C-20）。
	if err := h.dispatchBumpInTx(tx, tenant.ID); err != nil {
		log.Printf("[tenant-verify] N5 下发入队失败 tenant=%s: %v", tenant.ID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-verify] 提交事务失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	h.dispatchEnqueue(tenant.ID)

	h.auditAppendTenantRegister(tenant.ID, user.Email)
	log.Printf("[tenant-verify] 验证完成 tenant=%s status=%s", tenant.ID, res.Status)
	tenantWriteJSON(w, http.StatusOK, verifyResponse{
		TenantID: tenant.ID, Status: res.Status, PlanID: freePlanID,
		Quota: &quotaView{
			MonthlyTokens: res.MonthlyTokens,
			Concurrency:   res.Concurrency,
			Applied:       res.Status == tenantStatusActive,
		},
	})
}

// ---------- 登录 ----------

// handleLogin 登录端点（§6.2）：只校验凭据，不返令牌（Console 建会话，C-14）。
func (h *tenantHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req loginRequest
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	req.Email = normalizeEmail(req.Email)
	if !validEmail(req.Email) {
		tenantWriteError(w, http.StatusBadRequest, "参数不符合要求")
		return
	}
	if !h.verifyCaptcha(r, req.CaptchaID, req.CaptchaCode) {
		tenantWriteError(w, http.StatusBadRequest, "验证码错误")
		return
	}
	// 锁定检查（先于凭据校验，防锁定期间爆破）
	if h.loginGuard.isLocked(req.Email) {
		h.auditAppendLogin(req.Email, "", "locked")
		tenantWriteError(w, http.StatusLocked, "账号已锁定，请稍后再试")
		return
	}

	user, err := h.store.GetUserByEmail(req.Email)
	if err != nil {
		log.Printf("[tenant-login] 查询用户失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if user == nil || !verifyPassword(user.PasswordHash, req.Password) {
		h.loginGuard.onFail(req.Email)
		h.auditAppendLogin(req.Email, "", "bad_credentials")
		tenantWriteError(w, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}
	if user.Status == tenantUserStatusLocked {
		h.auditAppendLogin(req.Email, user.TenantID, "locked")
		tenantWriteError(w, http.StatusLocked, "账号已锁定，请联系管理员")
		return
	}
	if user.Status == tenantUserStatusPending {
		h.auditAppendLogin(req.Email, user.TenantID, "pending")
		tenantWriteError(w, http.StatusUnauthorized, "邮箱未验证")
		return
	}

	tenant, err := h.store.GetTenantByID(user.TenantID)
	if err != nil || tenant == nil {
		log.Printf("[tenant-login] 查询租户失败: %v", err)
		h.auditAppendLogin(req.Email, "", "tenant_missing")
		tenantWriteError(w, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}
	if tenant.Status == tenantStatusQuotaPending {
		h.auditAppendLogin(req.Email, tenant.ID, "quota_pending")
		tenantWriteError(w, http.StatusForbidden, "配额尚未就绪，请联系支持")
		return
	}
	if tenant.Status != tenantStatusActive {
		h.auditAppendLogin(req.Email, tenant.ID, "inactive")
		tenantWriteError(w, http.StatusForbidden, "租户未激活")
		return
	}

	h.loginGuard.onSuccess(req.Email)
	h.auditAppendLogin(req.Email, user.TenantID, "ok")
	log.Printf("[tenant-login] 登录成功 user_id=%d tenant=%s", user.ID, user.TenantID)
	tenantWriteJSON(w, http.StatusOK, loginResponse{
		TenantID:  user.TenantID,
		Role:      tenantRole,
		Status:    tenant.Status,
		ExpiresAt: time.Now().Unix() + tenantSessionTTL,
	})
}

// ---------- 登出 ----------

// handleLogout 租户登出（Console 侧清 cookie；Go 落审计 tenant_logout）。
func (h *tenantHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	actor := ""
	if c := tenantFromCtx(r.Context()); c != nil {
		actor = c.Sub
	}
	h.auditAppend(actor, auditActionTenantLogout)
	tenantWriteJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// ---------- 验证码签发 ----------

// handleCaptcha 图形验证码签发（§6.11；Console 内部端点）。
func (h *tenantHandler) handleCaptcha(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !h.cfg.captchaEnabled || h.captcha == nil {
		tenantWriteError(w, http.StatusNotFound, "验证码未启用")
		return
	}
	id, image, err := h.captcha.Issue(clientIP(r))
	if err != nil {
		if errors.Is(err, errCaptchaRateLimited) {
			tenantWriteError(w, http.StatusTooManyRequests, "验证码签发频率超限")
			return
		}
		log.Printf("[tenant-captcha] 生成失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	tenantWriteJSON(w, http.StatusOK, map[string]string{"captcha_id": id, "image": image})
}

// ---------- 密码重置 ----------

// handlePasswordReset 申请密码重置（§6.2：始终 202，不泄露存在性）。
func (h *tenantHandler) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.mailer == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "密码重置功能暂未启用")
		return
	}
	var req passwordResetRequest
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	req.Email = normalizeEmail(req.Email)
	if !validEmail(req.Email) {
		tenantWriteError(w, http.StatusBadRequest, "参数不符合要求")
		return
	}
	if !h.verifyCaptcha(r, req.CaptchaID, req.CaptchaCode) {
		tenantWriteError(w, http.StatusBadRequest, "验证码错误")
		return
	}
	// 同邮箱最小发信间隔（超限仍 202 且不发信）
	if !h.resetGuard.allow(req.Email) {
		tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}

	user, err := h.store.GetUserByEmail(req.Email)
	if err != nil {
		log.Printf("[tenant-reset] 查询用户失败: %v", err)
		tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}
	if user == nil || user.Status == tenantUserStatusLocked {
		tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}

	resetToken, err := randomToken(32)
	if err != nil {
		log.Printf("[tenant-reset] 生成令牌失败: %v", err)
		tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}
	tokenHash := h.store.(*sqliteTenantStore).hashMailToken(resetToken)
	now := time.Now().Unix()

	tx, err := h.store.Begin()
	if err != nil {
		log.Printf("[tenant-reset] 开启事务失败: %v", err)
		tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}
	defer func() { _ = tx.Rollback() }()

	if err := h.store.CreateToken(tx, &MailActionToken{
		TokenHash: tokenHash, TenantUserID: user.ID, Action: mailActionPasswordReset,
		ExpiresAt: now + int64(h.cfg.passwordResetTTLHours)*3600,
	}); err != nil {
		log.Printf("[tenant-reset] 创建令牌失败: %v", err)
		tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-reset] 提交事务失败: %v", err)
		tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
		return
	}

	if err := h.mailer.SendResetEmail(req.Email, resetToken); err != nil {
		log.Printf("[tenant-reset] 重置邮件发送失败: %v", err)
	}
	tenantWriteJSON(w, http.StatusAccepted, map[string]bool{"accepted": true})
}

// handlePasswordResetConfirm 确认密码重置（§6.2）。
func (h *tenantHandler) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if h.mailer == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "密码重置功能暂未启用")
		return
	}
	var req passwordResetConfirmRequest
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	req.Email = normalizeEmail(req.Email)
	if req.Token == "" || !validEmail(req.Email) || !validPassword(req.NewPassword) {
		tenantWriteError(w, http.StatusBadRequest, "参数不符合要求")
		return
	}

	tokenHash := h.store.(*sqliteTenantStore).hashMailToken(req.Token)
	tok, err := h.store.GetToken(tokenHash)
	if err != nil {
		log.Printf("[tenant-reset-confirm] 查询令牌失败: %v", err)
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	if tok == nil || tok.Action != mailActionPasswordReset {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	if tok.ExpiresAt < time.Now().Unix() || tok.ConsumedAt > 0 {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}

	user, err := h.store.GetUserByID(tok.TenantUserID)
	if err != nil || user == nil || user.Email != req.Email {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	newHash, err := hashPassword(req.NewPassword)
	if err != nil {
		log.Printf("[tenant-reset-confirm] 哈希密码失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}

	tx, err := h.store.Begin()
	if err != nil {
		log.Printf("[tenant-reset-confirm] 开启事务失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer func() { _ = tx.Rollback() }()

	if err := h.store.ConsumeToken(tx, tokenHash); err != nil {
		log.Printf("[tenant-reset-confirm] 消费令牌失败: %v", err)
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	if err := h.store.UpdatePassword(tx, user.ID, newHash); err != nil {
		log.Printf("[tenant-reset-confirm] 更新密码失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-reset-confirm] 提交事务失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}

	// 既有会话吊销由 Console 会话层执行（§6.2 会话归属）；此处仅落审计。
	// Actor 用邮箱哈希前缀（与登录/注册同法），审计绝不落明文邮箱（附录 D）。
	h.auditAppend(emailFingerprint(req.Email), auditActionPasswordReset)
	log.Printf("[tenant-reset-confirm] 密码重置成功 user_id=%d", user.ID)
	tenantWriteJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
}

// ---------- 登录失败/锁定（P2-4 T-1.4：默认进程内，可切共享库）----------

// loginAttemptBackend 登录失败计数后端：
//   - *memoryLoginGuard：进程内实现（默认，单副本语义，行为不变）；
//   - *sqlLoginGuardBackend：共享库实现（security_store.go，多副本共享计数）。
type loginAttemptBackend interface {
	isLocked(identity string) bool
	onFail(identity string)
	onSuccess(identity string)
}

// loginGuard 登录失败计数与自动锁定（§10.3 B）。backend 决定进程内或共享库。
type loginGuard struct {
	backend loginAttemptBackend
}

// newLoginGuard 构造登录锁定门禁（默认进程内实现）。
func newLoginGuard(maxFail, lockMin int) *loginGuard {
	return &loginGuard{backend: newMemoryLoginGuard(maxFail, lockMin)}
}

// isLocked 是否处于锁定窗口。
func (g *loginGuard) isLocked(email string) bool { return g.backend.isLocked(email) }

// onFail 记录一次失败；达上限则进入锁定窗口。
func (g *loginGuard) onFail(email string) { g.backend.onFail(email) }

// onSuccess 清零失败计数。
func (g *loginGuard) onSuccess(email string) { g.backend.onSuccess(email) }

// memoryLoginGuard 登录失败计数的进程内实现（原 loginGuard 实现，行为不变）。
type memoryLoginGuard struct {
	mu       sync.Mutex
	attempts map[string]*loginAttempt
	maxFail  int
	lockDur  time.Duration
}

type loginAttempt struct {
	failCount   int
	lockedUntil time.Time
}

func newMemoryLoginGuard(maxFail, lockMin int) *memoryLoginGuard {
	return &memoryLoginGuard{
		attempts: make(map[string]*loginAttempt),
		maxFail:  maxFail,
		lockDur:  time.Duration(lockMin) * time.Minute,
	}
}

// isLocked 是否处于锁定窗口（顺带清理已过期的锁定记录）。
func (g *memoryLoginGuard) isLocked(email string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	a, ok := g.attempts[email]
	if !ok {
		return false
	}
	if a.lockedUntil.After(time.Now()) {
		return true
	}
	if !a.lockedUntil.IsZero() {
		delete(g.attempts, email)
	}
	return false
}

// onFail 记录一次失败；达上限则进入锁定窗口。
func (g *memoryLoginGuard) onFail(email string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := g.attempts[email]
	if a == nil {
		a = &loginAttempt{}
		g.attempts[email] = a
	}
	a.failCount++
	if g.maxFail > 0 && a.failCount >= g.maxFail {
		a.lockedUntil = time.Now().Add(g.lockDur)
	}
}

// onSuccess 清零失败计数。
func (g *memoryLoginGuard) onSuccess(email string) {
	g.mu.Lock()
	delete(g.attempts, email)
	g.mu.Unlock()
}

// intervalGuard 按 key 的最小操作间隔（内存；用于密码重置发信限频）。
type intervalGuard struct {
	mu   sync.Mutex
	last map[string]time.Time
	dur  time.Duration
}

func newIntervalGuard(min int) *intervalGuard {
	return &intervalGuard{last: make(map[string]time.Time), dur: time.Duration(min) * time.Minute}
}

// allow 距上次操作超过间隔则记录并返回 true，否则 false。
func (g *intervalGuard) allow(key string) bool {
	now := time.Now()
	g.mu.Lock()
	defer g.mu.Unlock()
	if last, ok := g.last[key]; ok && now.Sub(last) < g.dur {
		return false
	}
	g.last[key] = now
	return true
}
