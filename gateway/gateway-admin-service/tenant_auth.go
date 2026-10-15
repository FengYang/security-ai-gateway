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
// 双策略（§6.1 / C-16）：
//  1. 租户令牌（role=tenant_user + tenant 非空，恒 HS256）→ 租户上下文
//  2. 内部 admin 令牌（verifyInternalToken）+ `target_tenant` 查询参数 → 管理员接管上下文
//     （无 target_tenant → 403，防全量枚举；接管一律留痕 actor/target_tenant，C-6）
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
	"sync"
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

// tenantScope 解析后的操作租户作用域（L1/L2，C-15/C-16）。
// IsAdmin=true 表示内部管理员经 target_tenant 接管（审计留痕 AdminSub）。
type tenantScope struct {
	TenantID string
	IsAdmin  bool
	AdminSub string
}

// tenantScopeKey 作用域上下文键。
type tenantScopeKey struct{}

// withTenantScope 把操作租户作用域写入请求上下文。
func withTenantScope(ctx context.Context, s tenantScope) context.Context {
	return context.WithValue(ctx, tenantScopeKey{}, s)
}

// tenantScopeFromCtx 取操作租户作用域。
func tenantScopeFromCtx(ctx context.Context) (tenantScope, bool) {
	s, ok := ctx.Value(tenantScopeKey{}).(tenantScope)
	return s, ok
}

// tenantAdminRoles 可经 target_tenant 接管租户端点的内部角色（C-16：仅 admin 类，非枚举）。
var tenantAdminRoles = map[string]struct{}{roleAdmin: {}, roleSystemAdmin: {}}

// isTenantAdminRole 内部令牌角色是否允许接管租户端点。
func isTenantAdminRole(role string) bool {
	_, ok := tenantAdminRoles[role]
	return ok
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

// tenantAuthMiddleware 租户端点门禁中间件（租户子树专用，C-16 双策略）。
// 策略① 租户会话令牌（role=tenant_user + tenant 非空，恒 HS256）；
// 策略② 内部 admin 令牌（verifyInternalToken）+ `target_tenant` 查询参数（缺失 → 403）。
// 其余凭证一律 401（不 fallback 到非 admin 内部角色）。
func tenantAuthMiddleware(cfg *config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr, ok := bearerFromHeader(r.Header.Get("Authorization"))
		if !ok {
			http.Error(w, "unauthorized: 缺少 Bearer 令牌", http.StatusUnauthorized)
			return
		}
		// 策略①：租户会话令牌（恒 HS256，无独立租户密钥）。
		if claims, err := verifyTenantToken(tokenStr, cfg.jwtSecret); err == nil {
			binding := resolveTenantBinding(claims.Tenant, declaredTenantFromRequest(r))
			if binding.Overridden {
				log.Printf("[tenant-auth][tenant_id_resolution] 自声明租户 %q 被令牌真值 %q 覆盖",
					binding.DeclaredTenant, binding.TenantID)
			}
			ctx := withTenantClaims(r.Context(), claims)
			ctx = withTenantScope(ctx, tenantScope{TenantID: claims.Tenant})
			ctx = withTenantBinding(ctx, binding)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// 策略②：内部 admin 令牌 + target_tenant 接管（C-6 留痕）。
		if c, err := verifyInternalToken(tokenStr, cfg); err == nil && isTenantAdminRole(c.Role) {
			target := strings.TrimSpace(r.URL.Query().Get("target_tenant"))
			if target == "" {
				noteSentinelFailure(http.StatusForbidden)
				http.Error(w, "forbidden: admin 接管须携带 target_tenant", http.StatusForbidden)
				return
			}
			ctx := withTenantScope(r.Context(), tenantScope{TenantID: target, IsAdmin: true, AdminSub: c.Sub})
			ctx = withTenantBinding(ctx, resolveTenantBinding(target, declaredTenantFromRequest(r)))
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		log.Printf("[tenant-auth] 令牌校验失败（既不满足租户策略，也不满足 admin 接管策略）")
		noteSentinelFailure(http.StatusUnauthorized)
		http.Error(w, "unauthorized: 令牌无效或已过期", http.StatusUnauthorized)
	}
}

// requireTenantScope 确保请求上下文中有合法租户作用域（fail-closed）；
// 返回操作租户 ID 供业务逻辑做强制租户过滤（C-15）。
func requireTenantScope(r *http.Request) (string, error) {
	if s, ok := tenantScopeFromCtx(r.Context()); ok && s.TenantID != "" {
		return s.TenantID, nil
	}
	// 兼容：仅写入 tenantClaims 的调用方（如既有单测）。
	if c := tenantFromCtx(r.Context()); c != nil && c.Tenant != "" {
		return c.Tenant, nil
	}
	return "", errors.New("tenant: 无租户上下文")
}

// tenantTakeoverFromCtx 返回管理员接管信息（isAdmin=true 时 sub 为管理员登录名，C-6）。
func tenantTakeoverFromCtx(r *http.Request) (sub string, isAdmin bool) {
	if s, ok := tenantScopeFromCtx(r.Context()); ok && s.IsAdmin {
		return s.AdminSub, true
	}
	return "", false
}

// ---------- N7 · 多租户隔离增强（§4.3.7，V-S7）----------
//
// 在 L1/L2/L3 三层隔离之上补齐：①consumer→tenant 映射 RBAC（防改写审计归因）；
// ②tenant 解析一致性（自声明头一律以已验证令牌真值覆盖，防伪造 X-Tenant-ID）；
// ③哨兵租户（消费者缺失的 401/429/403 归 `_unauthenticated`，加噪声抑制与告警）。

// sentinelTenant 未认证哨兵租户（§4.3.7 item 4）：`X-Mse-Consumer` 缺失的失败归此。
const sentinelTenant = "_unauthenticated"

// selfDeclaredTenantHeaders 可被客户端/网关透传的自声明租户头；N7 一律以令牌真值覆盖。
var selfDeclaredTenantHeaders = []string{"X-Tenant-ID", "X-Mse-Consumer", "X-Consumer"}

// tenantBinding consumer→tenant 绑定与 tenant 解析一致性裁决结果（N7 item 1/2/3）。
type tenantBinding struct {
	TenantID       string `json:"tenant_id"`
	Consumer       string `json:"consumer"`
	DeclaredTenant string `json:"declared_tenant,omitempty"`
	Overridden     bool   `json:"overridden,omitempty"`
	Sentinel       bool   `json:"sentinel,omitempty"`
}

// tenantBindingKey 绑定上下文键。
type tenantBindingKey struct{}

// withTenantBinding 把 consumer→tenant 绑定写入请求上下文。
func withTenantBinding(ctx context.Context, b tenantBinding) context.Context {
	return context.WithValue(ctx, tenantBindingKey{}, b)
}

// tenantBindingFromCtx 取 consumer→tenant 绑定（零值 = 未解析）。
func tenantBindingFromCtx(ctx context.Context) tenantBinding {
	b, _ := ctx.Value(tenantBindingKey{}).(tenantBinding)
	return b
}

// consumerForTenant consumer 维度值 = 租户（Higress consumer 维度天然隔离）；缺失 → 哨兵租户。
func consumerForTenant(tenantID string) string {
	if strings.TrimSpace(tenantID) == "" {
		return sentinelTenant
	}
	return tenantID
}

// declaredTenantFromRequest 提取请求自声明的租户（头优先，其次 query `tenant`）。
func declaredTenantFromRequest(r *http.Request) string {
	for _, h := range selfDeclaredTenantHeaders {
		if v := strings.TrimSpace(r.Header.Get(h)); v != "" {
			return v
		}
	}
	return strings.TrimSpace(r.URL.Query().Get("tenant"))
}

// resolveTenantBinding 解析并裁决 consumer→tenant 绑定（纯函数，可单测）：
// 权威租户 = 已验证令牌的 tenant；任何自声明头与之不一致 → 覆盖（Overridden=true，
// 供审计 `tenant_id_resolution` 一致性裁决）；权威租户缺失 → 落哨兵租户。
func resolveTenantBinding(authoritative, declared string) tenantBinding {
	authoritative = strings.TrimSpace(authoritative)
	declared = strings.TrimSpace(declared)
	if authoritative == "" {
		return tenantBinding{Consumer: sentinelTenant, DeclaredTenant: declared, Sentinel: true}
	}
	return tenantBinding{
		TenantID:       authoritative,
		Consumer:       consumerForTenant(authoritative),
		DeclaredTenant: declared,
		Overridden:     declared != "" && declared != authoritative,
	}
}

// tenantBindingOfRequest 从请求上下文解析 consumer→tenant 绑定（N7）。
func tenantBindingOfRequest(r *http.Request) tenantBinding {
	authoritative := ""
	if s, ok := tenantScopeFromCtx(r.Context()); ok {
		authoritative = s.TenantID
	}
	if authoritative == "" {
		if c := tenantFromCtx(r.Context()); c != nil {
			authoritative = c.Tenant
		}
	}
	return resolveTenantBinding(authoritative, declaredTenantFromRequest(r))
}

// errTenantMappingTamper consumer→tenant 映射篡改（自声明租户与令牌真值不一致）。
var errTenantMappingTamper = errors.New("tenant: consumer→tenant 映射篡改（自声明租户与令牌不一致）")

// authorizeConsumerBindingWrite 校验 consumer→tenant 映射写权限（N7 item 3）：
//   - 无权威租户（哨兵）→ 拒绝；
//   - 请求携带与权威不一致的自声明租户 → 拒绝（篡改审计归因）；
//   - 其余放行，返回操作租户与是否 admin 接管（admin 写一律留痕，C-6）。
func authorizeConsumerBindingWrite(r *http.Request) (tenantID string, isAdmin bool, err error) {
	b := tenantBindingOfRequest(r)
	if b.Sentinel {
		return "", false, errors.New("tenant: 无租户上下文（哨兵）不可写映射")
	}
	if b.Overridden {
		return "", false, errTenantMappingTamper
	}
	_, admin := tenantTakeoverFromCtx(r)
	return b.TenantID, admin, nil
}

// tenantSentinelWindowSeconds 哨兵租户告警抑制窗口（秒）：同窗口内仅告警一次，防噪声。
const tenantSentinelWindowSeconds = 60

// tenantSentinelNoise 哨兵租户噪声抑制 + 告警计数（§4.3.7 item 4）。
type tenantSentinelNoise struct {
	mu     sync.Mutex
	last   int64
	window int64
	count  int64
}

// observe 记录一次哨兵事件；同窗口内首次返回 true（= 应告警），其余抑制。
func (n *tenantSentinelNoise) observe(nowUnix int64) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.count++
	if n.last != 0 && nowUnix-n.last < n.window {
		return false
	}
	n.last = nowUnix
	return true
}

// total 累计哨兵事件数（观测用）。
func (n *tenantSentinelNoise) total() int64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.count
}

// tenantSentinel 全局哨兵噪声抑制器（未认证 401/403/429 归 `_unauthenticated`）。
var tenantSentinel = &tenantSentinelNoise{window: tenantSentinelWindowSeconds}

// noteSentinelFailure 记录一次"消费者缺失"失败（401/429/403 → 哨兵租户）：
// 同窗口首次触发告警日志，其余抑制（N7 item 4）。
func noteSentinelFailure(status int) {
	if status != http.StatusUnauthorized && status != http.StatusForbidden &&
		status != http.StatusTooManyRequests {
		return
	}
	if tenantSentinel.observe(time.Now().Unix()) {
		log.Printf("[tenant-auth][sentinel] consumer 缺失 → %s（status=%d，窗口内已抑制重复告警）",
			sentinelTenant, status)
	}
}

// bearerFromHeader 从 Authorization 头提取 Bearer token。
func bearerFromHeader(h string) (string, bool) {
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return "", false
	}
	return strings.TrimPrefix(h, prefix), true
}
