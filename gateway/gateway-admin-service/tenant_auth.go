// Package main — 租户自助门户认证层（租户会话令牌校验 + 中间件）。
//
// 令牌口径（§6.1，v1.3 定档）：
//   - 租户会话令牌 = Console 用**共享密钥**（ADMIN_SVC_JWT_SECRET）签发的 HS256 JWT，
//     payload 含 {role:"tenant_user", tenant:...}；Go 侧只校验、不签发（**无独立租户密钥**）。
//   - 恒 HS256（R-9）：与内部令牌链的 cryptop 分派（intl=HMAC-SHA256 / sm=HMAC-SM3）解耦，
//     故此处固定 crypto/hmac + sha256，不经 cryptoProvider。
//   - 双 mux 隔离（C-16）：本中间件仅用于租户子树；admin mux 的 validRole 不含
//     tenant_user（C-13），租户令牌在管理端点自然 401。
//
// 双策略（§6.1）：
//  1. 租户令牌（role=tenant_user + tenant 非空）→ 租户上下文
//  2. 内部 admin 令牌 + target_tenant → 管理员接管上下文（留待后续模块）
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

// tenantRole 租户用户角色（M1+ 只有一种）。
const tenantRole = "tenant_user"

// tenantSessionTTL 租户会话提示有效期（秒）：login 响应 expires_at 用；
// 实际会话由 Console AdminExtSessionService 生成并管理（§6.2 会话归属）。
const tenantSessionTTL = 8 * 3600

// tenantClaims 租户 JWT 载荷（Console 签发，Go 侧解析；容忍额外字段）。
type tenantClaims struct {
	Sub    string `json:"sub"`             // 用户 ID（字符串化，与 JWT 惯例一致）
	Tenant string `json:"tenant"`          // 租户 ID
	Role   string `json:"role"`            // 恒 "tenant_user"
	Email  string `json:"email,omitempty"` // 邮箱（展示用，非授权依据）
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

// verifyTenantToken 校验租户会话 JWT：签名（恒 HS256）→ 过期 → role/tenant 非空。
// secret = cfg.jwtSecret（共享密钥，§6.1）。
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
	// 恒 HS256（R-9）：固定 hmac-sha256，不经 cryptop 分派（sm profile 下仍为 HS256）。
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

// tenantAuthMiddleware 租户令牌鉴权中间件（租户子树专用）。
// 校验 Authorization: Bearer <租户 JWT>，通过后写入上下文；失败 401（不 fallback admin 令牌）。
func tenantAuthMiddleware(secret []byte, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, ok := bearerFromHeader(r.Header.Get("Authorization"))
		if !ok {
			http.Error(w, "unauthorized: 缺少 Bearer 令牌", http.StatusUnauthorized)
			return
		}
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

// requireTenantScope 确保请求上下文中有合法租户声明（fail-closed）；
// 返回 tenantID 供业务逻辑做强制租户过滤（C-15）。
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
