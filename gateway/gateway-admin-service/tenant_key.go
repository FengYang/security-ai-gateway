// Package main — 租户 API Key 管理（§6.3，M3）。
//
// 端点（租户会话前缀：TenantAuthMiddleware + CSRF）：
//
//	POST   /v1/adminext/tenant/keys              创建（明文仅一次）
//	GET    /v1/adminext/tenant/keys              列表（无明文）
//	POST   /v1/adminext/tenant/keys/{id}/rotate  轮换（旧 Key 吊销 + 新 Key 明文一次）
//	DELETE /v1/adminext/tenant/keys/{id}         吊销（幂等）
//
// 内部端点：
//
//	GET    /v1/adminext/key-revocations?since=   数据面吊销增量拉取（authMiddleware，§6.11）
//
// Key 形态（D-5）：以租户身份签发的长效 HS256 JWT（claims{sub, tenant, role:"api", jti, iat, exp}），
// 由 auth-service 经 CPS KeyRef `otpmask/jwt/v1` 签发（§8 依赖 5）；本服务仅存 jti/指纹，绝不留明文。
// 签发失败（连接拒绝/非 200/空 token）→ 503 且事务回滚（§9.1 判据 6）。
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	apiKeysPath        = tenantSessionBase + "/keys"
	keyRevocationsPath = "/v1/adminext/key-revocations"
	keyRoleAPI         = "api"
)

// keyIssuer Key 签发通道（auth-service /v1/issue，§6.11）。
type keyIssuer interface {
	IssueKey(ctx context.Context, tenant, sub, jti string, ttlSeconds int64) (string, error)
}

// httpKeyIssuer 经 HTTP 调用 auth-service /v1/issue。
type httpKeyIssuer struct {
	baseURL string
	client  *http.Client
}

// newHTTPKeyIssuer 构造签发客户端（baseURL 空 → nil，表示通道未配置）。
func newHTTPKeyIssuer(baseURL string, timeout time.Duration) *httpKeyIssuer {
	baseURL = strings.TrimRight(baseURL, "/")
	if baseURL == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &httpKeyIssuer{baseURL: baseURL, client: &http.Client{Timeout: timeout}}
}

// IssueKey 调 auth-service 签发租户 API Key 的 JWT。
func (h *httpKeyIssuer) IssueKey(ctx context.Context, tenant, sub, jti string, ttlSeconds int64) (string, error) {
	body, err := json.Marshal(map[string]any{
		"tenant": tenant, "sub": sub, "role": keyRoleAPI, "jti": jti, "ttl_seconds": ttlSeconds,
	})
	if err != nil {
		return "", fmt.Errorf("tenant: marshal issue req: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.baseURL+"/v1/issue", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := h.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("tenant: issue http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tenant: issue status %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("tenant: issue decode: %w", err)
	}
	if out.Token == "" {
		return "", fmt.Errorf("tenant: issue 返回空 token")
	}
	return out.Token, nil
}

// ---------- 路由 ----------

// registerKeyMux 注册租户 Key 端点（租户令牌 + CSRF）。
func (h *tenantHandler) registerKeyMux(mux *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.HandlerFunc {
		return tenantAuthMiddleware(h.cfg, csrfCheck(fn))
	}
	mux.HandleFunc("GET "+apiKeysPath, wrap(h.handleKeyList))
	mux.HandleFunc("POST "+apiKeysPath, wrap(h.handleKeyCreate))
	mux.HandleFunc("POST "+apiKeysPath+"/{id}/rotate", wrap(h.handleKeyRotate))
	mux.HandleFunc("DELETE "+apiKeysPath+"/{id}", wrap(h.handleKeyRevoke))
}

// registerKeyRevocations 注册数据面吊销拉取端点（Console/数据面内部，authMiddleware）。
func (h *tenantHandler) registerKeyRevocations(mux *http.ServeMux, cfg *config) {
	mux.HandleFunc(keyRevocationsPath, authMiddleware(cfg, h.handleKeyRevocations))
}

// ---------- 工具 ----------

// newKeyID 生成 key_id（k- + 6 位 hex）。
func newKeyID() (string, error) {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "k-" + hex.EncodeToString(b), nil
}

// newJTI 生成 jti（12 字节 = 24 位 hex，§3.5）。
func newJTI() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// sha256Hex 计算 SHA-256 全量 hex（指纹）。
func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// fpPrefix 取指纹前 8 位（列表/审计展示）。
func fpPrefix(fp string) string {
	if len(fp) >= 8 {
		return fp[:8]
	}
	return fp
}

// validKeyName Key 名称：去空白后 rune 长度 1-64（§3.5④）。
func validKeyName(name string) bool {
	n := len([]rune(name))
	return n >= 1 && n <= 64
}

// tenantActor 取当前操作人（租户令牌 sub；admin 接管时取管理员登录名，C-6）。
func tenantActor(r *http.Request) string {
	if sub, isAdmin := tenantTakeoverFromCtx(r); isAdmin && sub != "" {
		return sub
	}
	if c := tenantFromCtx(r.Context()); c != nil {
		return c.Sub
	}
	return ""
}

// auditAppendKey 落 Key 审计（只记 key_id + 指纹前 8）。
func (h *tenantHandler) auditAppendKey(actor, action, keyID, fingerprint string) {
	if h.audit == nil {
		return
	}
	if err := h.audit.append(adminAuditEvent{
		Actor: actor, Action: action, Target: keyID,
		KeyFingerprint: fpPrefix(fingerprint), Result: "ok",
	}); err != nil {
		log.Printf("[tenant-key] 审计落链失败 action=%s key=%s: %v", action, keyID, err)
	}
}

// ---------- 列表 ----------

// handleKeyList GET /v1/adminext/tenant/keys（无明文）。
func (h *tenantHandler) handleKeyList(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	keys, err := h.store.ListAPIKeysByTenant(tenantID)
	if err != nil {
		log.Printf("[tenant-key] 列表失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		item := map[string]any{
			"id":          k.KeyID,
			"name":        k.Name,
			"fingerprint": fpPrefix(k.Fingerprint),
			"status":      k.Status,
			"created_at":  k.CreatedAt,
			"expires_at":  k.ExpiresAt,
		}
		if k.LastUsedAt > 0 {
			item["last_used_at"] = k.LastUsedAt
		}
		out = append(out, item)
	}
	tenantWriteJSON(w, http.StatusOK, map[string]any{"keys": out})
}

// ---------- 创建 ----------

// handleKeyCreate POST /v1/adminext/tenant/keys（明文仅一次）。
func (h *tenantHandler) handleKeyCreate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.issuer == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 签发通道未就绪")
		return
	}
	var req struct {
		Name       string `json:"name"`
		ExpireDays int    `json:"expire_days"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if !validKeyName(req.Name) {
		tenantWriteError(w, http.StatusBadRequest, "name 长度须为 1-64")
		return
	}
	// 同租户 active 名称唯一（§3.5④）
	existing, err := h.store.GetActiveAPIKeyByName(tenantID, req.Name)
	if err != nil {
		log.Printf("[tenant-key] 校验重名失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if existing != nil {
		tenantWriteError(w, http.StatusConflict, "同名 Key 已存在")
		return
	}
	ttlDays := req.ExpireDays
	if ttlDays <= 0 {
		ttlDays = h.cfg.apiKeyDefaultTTLDays
	}
	if ttlDays > h.cfg.apiKeyMaxTTLDays {
		tenantWriteError(w, http.StatusBadRequest, "expire_days 超出上限")
		return
	}
	ttlSeconds := int64(ttlDays) * 86400

	keyID, err := newKeyID()
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	jti, err := newJTI()
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	actor := tenantActor(r)

	token, err := h.issuer.IssueKey(r.Context(), tenantID, actor, jti, ttlSeconds)
	if err != nil {
		log.Printf("[tenant-key] 签发失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 签发失败，请稍后重试")
		return
	}
	fingerprint := sha256Hex(token)
	now := time.Now().Unix()
	key := &APIKey{
		KeyID: keyID, TenantID: tenantID, Name: req.Name, JTI: jti,
		Fingerprint: fingerprint, Status: apiKeyStatusActive, CreatedBy: actor,
		CreatedAt: now, ExpiresAt: now + ttlSeconds,
	}
	tx, err := h.store.Begin()
	if err != nil {
		log.Printf("[tenant-key] 开启事务失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 落库失败")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.store.CreateAPIKey(tx, key); err != nil {
		log.Printf("[tenant-key] 落库失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 落库失败")
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-key] 提交失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 落库失败")
		return
	}

	h.auditAppendKey(actor, auditActionAPIKeyCreate, keyID, fingerprint)
	log.Printf("[tenant-key] 创建成功 tenant=%s key=%s fp=%s", tenantID, keyID, fpPrefix(fingerprint))
	tenantWriteJSON(w, http.StatusOK, map[string]any{
		"id":          keyID,
		"name":        req.Name,
		"fingerprint": fpPrefix(fingerprint),
		"api_key":     token, // 明文仅此一次
		"expires_at":  key.ExpiresAt,
		"note":        "请立即保存；服务端不保存明文",
	})
}

// ---------- 轮换 ----------

// handleKeyRotate POST /v1/adminext/tenant/keys/{id}/rotate（旧吊销 + 新明文一次）。
func (h *tenantHandler) handleKeyRotate(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.issuer == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 签发通道未就绪")
		return
	}
	old, ok := h.loadTenantKey(w, r, tenantID)
	if !ok {
		return
	}
	if old.Status != apiKeyStatusActive {
		tenantWriteError(w, http.StatusConflict, "Key 已吊销，无法轮换")
		return
	}

	keyID, err := newKeyID()
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	jti, err := newJTI()
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	actor := tenantActor(r)

	token, err := h.issuer.IssueKey(r.Context(), tenantID, actor, jti, h.remainingTTLSeconds(old))
	if err != nil {
		log.Printf("[tenant-key] 轮换签发失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 签发失败，请稍后重试")
		return
	}
	fingerprint := sha256Hex(token)
	now := time.Now().Unix()

	// 事务：旧 Key 吊销 + 新 Key 落库
	tx, err := h.store.Begin()
	if err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 轮换失败")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.store.RevokeAPIKey(tx, old.KeyID, now); err != nil {
		log.Printf("[tenant-key] 轮换吊销旧 Key 失败 key=%s: %v", old.KeyID, err)
		tenantWriteError(w, http.StatusConflict, "Key 轮换失败")
		return
	}
	newKey := &APIKey{
		KeyID: keyID, TenantID: tenantID, Name: old.Name, JTI: jti,
		Fingerprint: fingerprint, Status: apiKeyStatusActive, CreatedBy: actor,
		CreatedAt: now, ExpiresAt: old.ExpiresAt,
	}
	if err := h.store.CreateAPIKey(tx, newKey); err != nil {
		log.Printf("[tenant-key] 轮换落库失败: %v", err)
		tenantWriteError(w, http.StatusConflict, "Key 轮换失败")
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("[tenant-key] 轮换提交失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 轮换失败")
		return
	}

	h.auditAppendKey(actor, auditActionAPIKeyRotate, keyID, fingerprint)
	log.Printf("[tenant-key] 轮换成功 tenant=%s old=%s new=%s", tenantID, old.KeyID, keyID)
	tenantWriteJSON(w, http.StatusOK, map[string]any{
		"id":          keyID,
		"name":        old.Name,
		"fingerprint": fpPrefix(fingerprint),
		"api_key":     token, // 明文仅此一次
		"expires_at":  old.ExpiresAt,
		"note":        "请立即保存；服务端不保存明文",
	})
}

// ---------- 吊销 ----------

// handleKeyRevoke DELETE /v1/adminext/tenant/keys/{id}（幂等）。
func (h *tenantHandler) handleKeyRevoke(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	key, ok := h.loadTenantKey(w, r, tenantID)
	if !ok {
		return
	}
	if key.Status == apiKeyStatusRevoked {
		// 幂等
		tenantWriteJSON(w, http.StatusOK, map[string]any{"id": key.KeyID, "status": apiKeyStatusRevoked})
		return
	}
	now := time.Now().Unix()
	tx, err := h.store.Begin()
	if err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 吊销失败")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.store.RevokeAPIKey(tx, key.KeyID, now); err != nil {
		log.Printf("[tenant-key] 吊销失败 key=%s: %v", key.KeyID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 吊销失败")
		return
	}
	if err := tx.Commit(); err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "Key 吊销失败")
		return
	}
	h.auditAppendKey(tenantActor(r), auditActionAPIKeyRevoke, key.KeyID, key.Fingerprint)
	log.Printf("[tenant-key] 吊销成功 tenant=%s key=%s", tenantID, key.KeyID)
	tenantWriteJSON(w, http.StatusOK, map[string]any{"id": key.KeyID, "status": apiKeyStatusRevoked})
}

// loadTenantKey 取路径 {id} 的 Key 并校验归属（跨租户 → 404，不泄露存在性）。
// 失败时已写响应，返回 ok=false。
func (h *tenantHandler) loadTenantKey(w http.ResponseWriter, r *http.Request, tenantID string) (*APIKey, bool) {
	id := r.PathValue("id")
	if id == "" {
		tenantWriteError(w, http.StatusBadRequest, "缺少 Key id")
		return nil, false
	}
	key, err := h.store.GetAPIKeyByID(id)
	if err != nil {
		log.Printf("[tenant-key] 查询失败 key=%s: %v", id, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return nil, false
	}
	if key == nil || key.TenantID != tenantID {
		tenantWriteError(w, http.StatusNotFound, "Key 不存在")
		return nil, false
	}
	return key, true
}

// ---------- 数据面吊销拉取 ----------

// handleKeyRevocations GET /v1/adminext/key-revocations?since=<unix秒>（§6.11）。
// 响应 {revoked:[{jti, revoked_at}], server_time}；数据面据此增量更新本地吊销集（≤60s）。
func (h *tenantHandler) handleKeyRevocations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var since int64
	if s := r.URL.Query().Get("since"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v < 0 {
			tenantWriteError(w, http.StatusBadRequest, "since 非法")
			return
		}
		since = v
	}
	keys, err := h.store.ListRevokedAPIKeysSince(since)
	if err != nil {
		log.Printf("[tenant-key] 吊销拉取失败 since=%d: %v", since, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	revoked := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		revoked = append(revoked, map[string]any{"jti": k.JTI, "revoked_at": k.RevokedAt})
	}
	tenantWriteJSON(w, http.StatusOK, map[string]any{
		"revoked":     revoked,
		"server_time": time.Now().Unix(),
	})
}

// remainingTTLSeconds 轮换时沿用原 Key 的到期时间（余量不足则取下限 60s）。
func (h *tenantHandler) remainingTTLSeconds(k *APIKey) int64 {
	remain := k.ExpiresAt - time.Now().Unix()
	if remain < 60 {
		remain = 60
	}
	return remain
}
