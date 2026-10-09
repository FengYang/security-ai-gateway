// Package main — 租户自助门户 API（注册/验证/登录/登出/密码重置）。
//
// M1 最小集：先实现端点基础 API，直接走独立 mux（/v1/tenant/*），
// billing 绑定、CSRF、图形验证码在 M2 及之后补齐。
//
// 端点（公开端点（无需鉴权）：
//   POST /v1/tenant/register                  注册（统一 202，防枚举）
//   POST /v1/tenant/verify               邮箱验证
//   POST /v1/tenant/login                登录（返 JWT）
//   POST /v1/tenant/password-reset      申请密码重置（统一 202）
//   POST /v1/tenant/password-reset/confirm  确认密码重置
//
// 需鉴权端点：
//   POST /v1/tenant/logout               登出（客户端丢令牌）
//   GET  /v1/tenant/me                 当前用户信息
//
// SMTP 未配置 → 注册/验证/密码重置 503（C-12 fail-closed）。
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/mail"
	"strings"
	"time"
)

// tenantAPIBase 租户 API 基础路径。
const tenantAPIBase = "/v1/tenant"

// registerRateLimit 每 IP 每小时最大注册次数（C-11）。
const registerRateLimit = 10
const registerRateWindowSec = 3600 // 1 小时

// tenantHandler 租户门户 HTTP 处理器。
type tenantHandler struct {
	store        TenantStore
	jwtSecret    []byte
	smtpEnabled  bool   // SMTP 是否配置
	// SMTP 配置（M1 仅判断启用/未启用，真实发送在 M2 实现）
	smtpHost     string
	smtpPort     int
	smtpUser     string
	smtpPass     string
	smtpFrom     string
}

// newTenantHandler 构造租户 handler。
// SMTP 配置不全（host/user/from 任一为空）视为未启用 → 相关端点 503。
func newTenantHandler(store TenantStore, jwtSecret []byte,
	smtpHost, smtpUser, smtpPass, smtpFrom string, smtpPort int) *tenantHandler {
	enabled := smtpHost != "" && smtpUser != "" && smtpFrom != ""
	return &tenantHandler{
		store:       store,
		jwtSecret:   jwtSecret,
		smtpEnabled: enabled,
		smtpHost:    smtpHost,
		smtpPort:    smtpPort,
		smtpUser:    smtpUser,
		smtpPass:    smtpPass,
		smtpFrom:    smtpFrom,
	}
}

// registerMux 在 mux 注册租户端点（公开 + 鉴权）。
func (h *tenantHandler) registerMux(mux *http.ServeMux) {
	// 公开端点
	mux.HandleFunc(tenantAPIBase+"/register", h.handleRegister)
	mux.HandleFunc(tenantAPIBase+"/verify", h.handleVerify)
	mux.HandleFunc(tenantAPIBase+"/login", h.handleLogin)
	mux.HandleFunc(tenantAPIBase+"/password-reset", h.handlePasswordReset)
	mux.HandleFunc(tenantAPIBase+"/password-reset/confirm", h.handlePasswordResetConfirm)
	// 需鉴权端点
	mux.HandleFunc(tenantAPIBase+"/logout", tenantAuthMiddleware(h.jwtSecret, h.handleLogout))
	mux.HandleFunc(tenantAPIBase+"/me", tenantAuthMiddleware(h.jwtSecret, h.handleMe))
}

// ---------- 请求/响应结构 ----------

type registerRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	TenantName string `json:"tenant_name"`
}

type verifyRequest struct {
	Token string `json:"token"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token    string `json:"token"`
	ExpiresIn int   `json:"expires_in"` // 秒
}

type passwordResetRequest struct {
	Email string `json:"email"`
}

type passwordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type meResponse struct {
	Email  string `json:"email"`
	Tenant string `json:"tenant"`
	Status string `json:"status"`
}

// ---------- 工具函数 ----------

// tenantWriteJSON 写 JSON 响应（M1 独立命名，避免与其他模块重名）。
func tenantWriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// tenantWriteError 写 JSON 错误响应。
func tenantWriteError(w http.ResponseWriter, status int, msg string) {
	tenantWriteJSON(w, status, map[string]string{"error": msg})
}

// decodeJSON 解码请求体 JSON（限制 1MB）。
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("empty body")
	}
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20) // 1MB
	dec := json.NewDecoder(r.Body)
	return dec.Decode(v)
}

// validEmail 简单邮箱格式校验（net/mail 解析，不做基本语法）。
func validEmail(email string) bool {
	if len(email) > 254 {
		return false
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return false
	}
	return addr.Address == strings.ToLower(strings.TrimSpace(email)) || addr.Address == strings.TrimSpace(email)
}

// validPassword 密码强度：最小 8 位（M1 最简；M2 可加强复杂度）。
func validPassword(p string) bool {
	return len(p) >= 8 && len(p) <= 128
}

// randomToken 生成加密安全随机令牌（hex 编码）。
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("tenant: random token: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// clientIP 取客户端 IP（简单取 RemoteAddr；生产环境有代理时由 X-Forwarded-For 头判断，
// M1 先取 RemoteAddr 简化版）。
func clientIP(r *http.Request) string {
	// 简易：去掉端口前导 :port -> ip:port 格式
	addr := r.RemoteAddr
	if idx := strings.LastIndex(addr, ":"); idx > 0 {
		return addr[:idx]
	}
	return addr
}

// ---------- 注册 ----------

// handleRegister 注册端点。
// 无论成功/失败（邮箱已存在/格式错等）统一返回 202 Accepted，
// 防止邮箱枚举（§6.3 防用户枚举）。
func (h *tenantHandler) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !h.smtpEnabled {
		tenantWriteError(w, http.StatusServiceUnavailable, "注册功能暂未启用")
		return
	}

	var req registerRequest
	if err := decodeJSON(r, &req); err != nil {
		// 防枚举：格式错也返 202
		w.WriteHeader(http.StatusAccepted)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(req.Email) || !validPassword(req.Password) || req.TenantName == "" || len(req.TenantName) > 100 {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// 注册频率限制（C-11）
	ip := clientIP(r)
	count, err := h.store.IncRegisterRate(ip, registerRateWindowSec)
	if err != nil {
		log.Printf("[tenant-register] 限流计数失败 ip=%s: %v", ip, err)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if count > registerRateLimit {
		log.Printf("[tenant-register] 超限流 ip=%s count=%d", ip, count)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// 检查邮箱是否已存在（存在也返 202，不创建）
	existing, err := h.store.GetUserByEmail(req.Email)
	if err != nil {
		log.Printf("[tenant-register] 查询用户失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if existing != nil {
		// 已存在：不创建，但发"邮箱被占也返 202
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// 创建租户 + 用户（事务内）
	tx, err := h.store.Begin()
	if err != nil {
		log.Printf("[tenant-register] 开启事务失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	defer tx.Rollback()

	// 生成租户 ID（M1 用邮箱做前缀 + 随机 生成
	tenantID, err := generateTenantID()
	if err != nil {
		log.Printf("[tenant-register] 生成租户 ID 失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	now := time.Now().Unix()

	tenant := &Tenant{
		ID:        tenantID,
		Name:      req.TenantName,
		Status:    tenantStatusActive,
		PlanID:    "free", // M1 默认 free；M2 后接入 billing 自动绑定
		CreatedAt: now,
	}
	if err := h.store.CreateTenant(tx, tenant); err != nil {
		log.Printf("[tenant-register] 创建租户失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	pwHash, err := hashPassword(req.Password)
	if err != nil {
		log.Printf("[tenant-register] 哈希密码失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	user := &TenantUser{
		TenantID:     tenantID,
		Email:        req.Email,
		PasswordHash: pwHash,
		Status:       tenantUserStatusPending,
		CreatedAt:    now,
	}
	userID, err := h.store.CreateUser(tx, user)
	if err != nil {
		log.Printf("[tenant-register] 创建用户失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// 生成验证令牌
	verifyToken, err := randomToken(32)
	if err != nil {
		log.Printf("[tenant-register] 生成验证令牌失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	tokenHash := h.store.(*sqliteTenantStore).hashMailToken(verifyToken)
	tok := &MailActionToken{
		TokenHash:    tokenHash,
		TenantUserID: userID,
		Action:       mailActionVerify,
		ExpiresAt:    now + int64(tokenTTLVerify.Seconds()),
		ConsumedAt:   0,
	}
	if err := h.store.CreateToken(tx, tok); err != nil {
		log.Printf("[tenant-register] 创建验证令牌失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-register] 提交事务失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// 发送验证邮件（M1：仅记录日志，M2 做实发 SMTP）
	log.Printf("[tenant-register] 注册成功，验证令牌=%s tenant=%s （SMTP未实发，令牌: %s）",
		req.Email, tenantID, verifyToken)

	w.WriteHeader(http.StatusAccepted)
}

// generateTenantID 生成租户 ID（t_ + 16 位随机 hex，共 18 字符）。
func generateTenantID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "t_" + hex.EncodeToString(b), nil
}

// ---------- 邮箱验证 ----------

// handleVerify 邮箱验证端点。
// 验证成功 → 用户状态 active；验证失败 → 400（不暴露原因细节。
func (h *tenantHandler) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !h.smtpEnabled {
		tenantWriteError(w, http.StatusServiceUnavailable, "验证功能暂未启用")
		return
	}

	var req verifyRequest
	if err := decodeJSON(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Token == "" {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}

	// 查令牌
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
	// 过期？
	now := time.Now().Unix()
	if tok.ExpiresAt < now {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	if tok.ConsumedAt > 0 {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}

	// 消费令牌 + 激活用户（事务内）
	tx, err := h.store.Begin()
	if err != nil {
		log.Printf("[tenant-verify] 开启事务失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	if err := h.store.ConsumeToken(tx, tokenHash); err != nil {
		log.Printf("[tenant-verify] 消费令牌失败: %v", err)
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}
	if err := h.store.UpdateUserStatus(tx, tok.TenantUserID, tenantUserStatusActive); err != nil {
		log.Printf("[tenant-verify] 更新用户状态失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-verify] 提交事务失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}

	log.Printf("[tenant-verify] 验证成功 user_id=%d", tok.TenantUserID)
	tenantWriteJSON(w, http.StatusOK, map[string]string{"status": "verified"})
}

// ---------- 登录 ----------

// handleLogin 登录端点。
// 成功返 JWT；失败不泄露具体原因（防枚举）。
func (h *tenantHandler) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		tenantWriteError(w, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))

	user, err := h.store.GetUserByEmail(req.Email)
	if err != nil {
		log.Printf("[tenant-login] 查询用户失败: %v", err)
		tenantWriteError(w, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}
	if user == nil {
		tenantWriteError(w, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}
	if user.Status == tenantUserStatusLocked {
		tenantWriteError(w, http.StatusUnauthorized, "账号已锁定")
		return
	}
	if user.Status == tenantUserStatusPending {
		tenantWriteError(w, http.StatusUnauthorized, "邮箱未验证")
		return
	}
	if !verifyPassword(user.PasswordHash, req.Password) {
		tenantWriteError(w, http.StatusUnauthorized, "邮箱或密码错误")
		return
	}

	// 签发令牌
	token, err := issueTenantToken(h.jwtSecret, user.ID, user.TenantID, user.Email)
	if err != nil {
		log.Printf("[tenant-login] 签发令牌失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}

	log.Printf("[tenant-login] 登录成功 user_id=%d tenant=%s", user.ID, user.TenantID)
	tenantWriteJSON(w, http.StatusOK, loginResponse{
		Token:     token,
		ExpiresIn: tenantTokenTTL,
	})
}

// ---------- 登出 ----------

// handleLogout 登出端点。
// M1：客户端丢令牌即登出（服务端无状态吊销，M3 补 jti 吊销）。
func (h *tenantHandler) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// 无状态：直接返 ok（M3 接吊销后补吊销逻辑）
	tenantWriteJSON(w, http.StatusOK, map[string]string{"status": "logged_out"})
}

// ---------- 当前用户 ----------

// handleMe 当前用户信息。
func (h *tenantHandler) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	c := tenantFromCtx(r.Context())
	if c == nil {
		tenantWriteError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	tenantWriteJSON(w, http.StatusOK, meResponse{
		Email:  c.Email,
		Tenant: c.Tenant,
		Status: "active",
	})
}

// ---------- 密码重置 ----------

// handlePasswordReset 申请密码重置。
// 统一返 202，防邮箱枚举。
func (h *tenantHandler) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !h.smtpEnabled {
		tenantWriteError(w, http.StatusServiceUnavailable, "密码重置功能暂未启用")
		return
	}

	var req passwordResetRequest
	if err := decodeJSON(r, &req); err != nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	if !validEmail(req.Email) {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	user, err := h.store.GetUserByEmail(req.Email)
	if err != nil {
		log.Printf("[tenant-reset] 查询用户失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if user == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if user.Status == tenantUserStatusLocked {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// 生成重置令牌
	resetToken, err := randomToken(32)
	if err != nil {
		log.Printf("[tenant-reset] 生成令牌失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	now := time.Now().Unix()
	tokenHash := h.store.(*sqliteTenantStore).hashMailToken(resetToken)
	tok := &MailActionToken{
		TokenHash:    tokenHash,
		TenantUserID: user.ID,
		Action:       mailActionPasswordReset,
		ExpiresAt:    now + int64(tokenTTLReset.Seconds()),
		ConsumedAt:   0,
	}

	tx, err := h.store.Begin()
	if err != nil {
		log.Printf("[tenant-reset] 开启事务失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	defer tx.Rollback()

	if err := h.store.CreateToken(tx, tok); err != nil {
		log.Printf("[tenant-reset] 创建令牌失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-reset] 提交事务失败: %v", err)
		w.WriteHeader(http.StatusAccepted)
		return
	}

	// M1：日志记录（M2 实发）
	log.Printf("[tenant-reset] 密码重置申请，邮箱=%s 令牌=%s（M2 实发）", req.Email, resetToken)

	w.WriteHeader(http.StatusAccepted)
}

// handlePasswordResetConfirm 确认密码重置。
func (h *tenantHandler) handlePasswordResetConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !h.smtpEnabled {
		tenantWriteError(w, http.StatusServiceUnavailable, "密码重置功能暂未启用")
		return
	}

	var req passwordResetConfirmRequest
	if err := decodeJSON(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "invalid request")
		return
	}
	if req.Token == "" || !validPassword(req.NewPassword) {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或密码不符合要求")
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
	now := time.Now().Unix()
	if tok.ExpiresAt < now || tok.ConsumedAt > 0 {
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}

	// 消费令牌 + 更新密码（事务内）
	tx, err := h.store.Begin()
	if err != nil {
		log.Printf("[tenant-reset-confirm] 开启事务失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback()

	if err := h.store.ConsumeToken(tx, tokenHash); err != nil {
		log.Printf("[tenant-reset-confirm] 消费令牌失败: %v", err)
		tenantWriteError(w, http.StatusBadRequest, "令牌无效或已过期")
		return
	}

	newHash, err := hashPassword(req.NewPassword)
	if err != nil {
		log.Printf("[tenant-reset-confirm] 哈希密码失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := h.store.UpdatePassword(tx, tok.TenantUserID, newHash); err != nil {
		log.Printf("[tenant-reset-confirm] 更新密码失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-reset-confirm] 提交事务失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}

	log.Printf("[tenant-reset-confirm] 密码重置成功 user_id=%d", tok.TenantUserID)
	tenantWriteJSON(w, http.StatusOK, map[string]string{"status": "password_reset"})
}
