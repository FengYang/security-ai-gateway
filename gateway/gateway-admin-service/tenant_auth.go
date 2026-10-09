// Package main — 租户自助门户认证层（JWT 签发/校验 + 中间件）。
//
// 租户 JWT 与内部管理 JWT 独立密钥，避免跨域混用：
//   - 内部管理令牌：ADMIN_SVC_JWT_SECRET（HS256/SM3 按 cryptop）
//   - 租户会话令牌：TENANT_JWT_SECRET（恒 HS256，C-8；对齐 auth-service 租户 Key 策略）
//
// 双策略鉴权（§6.2）：
//  1. 租户令牌（role=tenant_user + tenant 非空）→ 租户上下文
//  2. admin 令牌 + target_tenant → 管理员接管上下文（落审计留痕）
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// tenantRole 租户用户角色（M1 只有一种）。
const tenantRole = "tenant_user"

// tenantClaims 租户 JWT 载荷。
type tenantClaims struct {
	Sub    string `json:"sub"`              // 用户 ID（字符串化，与 JWT 惯例一致）
	Tenant string `json:"tenant"`           // 租户 ID
	Role   string `json:"role"`             // 恒 "tenant_user"
	Email  string `json:"email,omitempty"`  // 邮箱（便于前端展示，不做授权依据）
	IAT    int64  `json:"iat"`
	EXP    int64  `json:"exp"`
}

// tenantCtxKey 租户上下文键。
type tenantCtxKey struct{}

// withTenantClaims 把租户 claims 写入请求上下文。
func withTenantClaims(ctx context.Context, c *tenantClaims) context.Context {
	return context.WithValue(ctx, tenantCtxKey{}, c)
}

// tenantFromCtx 从上下文取租户 claims（nil = 未鉴权）。
func tenantFromCtx(ctx context.Context) *tenantClaims {
	c, _ := ctx.Value(tenantCtxKey{}).(*tenantClaims)
	return c
}

// tenantB64 与内部 JWT 同一编码（RFC 7515：base64url 无 padding）。
var tenantB64 = base64.RawURLEncoding

// ---------- 签发 ----------

// tenantTokenTTL 租户会话令牌有效期（M1 暂定 8h，与管理面绝对超时对齐；
// Console 接入后按会话策略调整）。
const tenantTokenTTL = 8 * 3600 // 秒

// issueTenantToken 签发租户会话 JWT（恒 HS256，C-8）。
func issueTenantToken(secret []byte, userID int64, tenantID, email string) (string, error) {
	now := time.Now().Unix()
	claims := tenantClaims{
		Sub:    fmt.Sprintf("%d", userID),
		Tenant: tenantID,
		Role:   tenantRole,
		Email:  email,
		IAT:    now,
		EXP:    now + tenantTokenTTL,
	}
	return signTenantJWT(secret, claims)
}

// signTenantJWT 构造并签名租户 JWT（手写 HS256，零依赖，与内部 JWT 同风格）。
func signTenantJWT(secret []byte, claims tenantClaims) (string, error) {
	header := `{"alg":"HS256","typ":"JWT"}`
	headerB64 := tenantB64.EncodeToString([]byte(header))

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("tenant: marshal claims: %w", err)
	}
	payloadB64 := tenantB64.EncodeToString(payload)

	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	sig := mac.Sum(nil)
	sigB64 := tenantB64.EncodeToString(sig)

	return signingInput + "." + sigB64, nil
}

// ---------- 校验 ----------

// verifyTenantToken 校验租户 JWT：签名 → 过期 → role/tenant 非空。
func verifyTenantToken(token string, secret []byte) (*tenantClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("tenant: token 格式错误（须为 3 段 JWT）")
	}

	signingInput := parts[0] + "." + parts[1]
	sig, err := tenantB64.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("tenant: 签名段非 base64url")
	}
	// 常量时间比较
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	expected := mac.Sum(nil)
	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return nil, errors.New("tenant: 签名校验失败")
	}

	payload, err := tenantB64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("tenant: 载荷段非 base64url")
	}
	var c tenantClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errors.New("tenant: 载荷非合法 JSON")
	}

	now := time.Now().Unix()
	if c.EXP > 0 && now > c.EXP {
		return nil, errors.New("tenant: 令牌已过期")
	}
	if c.Role != tenantRole {
		return nil, fmt.Errorf("tenant: 角色非 %q（got=%q）", tenantRole, c.Role)
	}
	if c.Tenant == "" {
		return nil, errors.New("tenant: 令牌缺少 tenant 声明")
	}
	if c.Sub == "" {
		return nil, errors.New("tenant: 令牌缺少 sub 声明")
	}
	return &c, nil
}

// ---------- 中间件 ----------

// tenantAuthMiddleware 租户令牌鉴权中间件。
// 校验 Authorization: Bearer <租户 JWT>，通过后写入上下文。
// 失败返回 401，不 fallback 到 admin 令牌（admin 接管走独立路径）。
func tenantAuthMiddleware(secret []byte, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(h, prefix) {
			http.Error(w, "unauthorized: 缺少 Bearer 令牌", http.StatusUnauthorized)
			return
		}
		tokenStr := strings.TrimPrefix(h, prefix)
		claims, err := verifyTenantToken(tokenStr, secret)
		if err != nil {
			log.Printf("[tenant-auth] 令牌校验失败: %v", err)
			http.Error(w, "unauthorized: 令牌无效或已过期", http.StatusUnauthorized)
			return
		}
		ctx := withTenantClaims(r.Context(), claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// requireTenantScope 确保请求上下文中有合法租户声明（fail-closed）。
// handler 内调用，拿到 tenantID 后再做业务逻辑。
func requireTenantScope(r *http.Request) (string, error) {
	c := tenantFromCtx(r.Context())
	if c == nil || c.Tenant == "" {
		return "", errors.New("tenant: 无租户上下文")
	}
	return c.Tenant, nil
}

// bearerFromHeader 从 Authorization 头提取 Bearer token。
func bearerFromHeader(h string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimPrefix(h, prefix), true
}
