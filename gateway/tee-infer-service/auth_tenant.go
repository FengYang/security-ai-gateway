package main

// 租户 JWT 验签（P1-8 T3，GAP-02 飞地端鉴权自研）。
//
// 定位依据（§6 红线）：加密段之后 body 依赖型插件失效，
// 网关侧 jwt-auth 只验证到"请求合法"但无法把租户身份安全传递到飞地。
// 飞地端必须结构性自研租户鉴权，信任根 = 飞地持有的租户密钥（HMAC）。
//
// 契约对齐（与网关侧 jwt-auth 同算法/同格式）：
//   - 算法：HS256（HMAC-SHA256），通过 cryptoProvider.HMAC 计算
//     （intl 档 = 标准 HMAC-SHA256；sm 档 = HMAC-SM3，随 crypto profile 自动切换）
//   - 格式：标准 JWT（base64url(header).base64url(payload).base64url(signature)）
//   - 标准声明：sub（租户ID）、iat（签发时间）、exp（过期时间）、jti（令牌ID）
//   - 自定义声明：tenant（冗余租户声明，可选，与 sub 一致即视为有效）
//
// fail-closed 原则（启动期 + 运行时）：
//   - 密钥为空 → 启动拒（租户 JWT 必须配置）
//   - 令牌缺失 → 401
//   - 签名无效 / 格式非法 / 已过期 → 401
//   - 租户不匹配（JWT sub ≠ URL/Header 指定的租户） → 403
//   - X-Tenant-ID 与 JWT sub 冲突 → 以 JWT 为准，冲突则 403
//
// 零侵入保证：
//   - 既有 auth.go（飞地↔网关 attest 握手）零改动
//   - 租户 JWT 是独立的一层，由业务入口显式调用 requireTenant

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// ---------- 常量 ----------

const (
	// tenantJWTIssuer 预期签发者（与网关侧对齐，空 = 不校验 iss）。
	tenantJWTIssuer = ""
	// tenantJWTClaimTenant 自定义声明名（冗余租户 ID）。
	tenantJWTClaimTenant = "tenant"
	// jwtHS256Alg HS256 算法标识（intl 档）。
	jwtHS256Alg = "HS256"
	// jwtType 令牌类型。
	jwtType = "JWT"
)

// ---------- 类型 ----------

// tenantJWTClaims JWT 声明结构（仅解析需要的字段，其余忽略）。
type tenantJWTClaims struct {
	Sub string `json:"sub"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
	Jti string `json:"jti,omitempty"`
	Iss string `json:"iss,omitempty"`
	// Tenant 冗余租户声明（可选，与 sub 一致则有效）。
	Tenant string `json:"tenant,omitempty"`
}

// valid 校验声明有效性（签名由 verifyTenantJWT 校验）。
// 校验项：sub 非空、exp 未过期、iat 合理（不校验 nbf 以兼容最简签发）。
func (c *tenantJWTClaims) valid(now time.Time, leeway time.Duration) error {
	if c.Sub == "" {
		return errors.New("jwt: sub 为空")
	}
	if c.Exp == 0 {
		return errors.New("jwt: 缺少 exp 声明")
	}
	if now.After(time.Unix(c.Exp, 0).Add(leeway)) {
		return fmt.Errorf("jwt: 已过期（exp=%d）", c.Exp)
	}
	if c.Iat > 0 && now.Before(time.Unix(c.Iat, 0).Add(-leeway)) {
		return fmt.Errorf("jwt: iat 在未来（iat=%d）", c.Iat)
	}
	return nil
}

// tenantID 返回声明中的租户 ID（优先 sub，其次 tenant 自定义声明）。
func (c *tenantJWTClaims) tenantID() string {
	if c.Sub != "" {
		return c.Sub
	}
	return c.Tenant
}

// ---------- 验签核心 ----------

// verifyTenantJWT 验证租户 JWT 并返回解析后的声明。
//
// token = "base64url(header).base64url(payload).base64url(signature)"
// key = 租户 HMAC 密钥（从 keystore 取，由调用方传入，避免本文件直接依赖 keystore）
//
// 校验项：格式 / 算法 / 签名 / 声明有效性（sub/exp/iat）。
// fail-closed：任何不满足 → 返回错误（不静默通过）。
func verifyTenantJWT(token string, key []byte, now time.Time, leeway time.Duration) (*tenantJWTClaims, error) {
	if token == "" {
		return nil, errors.New("jwt: 令牌为空")
	}
	if len(key) == 0 {
		return nil, errors.New("jwt: 密钥为空")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: 格式非法（非 3 段）")
	}

	// 解码 header
	headerRaw, err := base64urlDecode(parts[0])
	if err != nil {
		return nil, fmt.Errorf("jwt: header 解码失败: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, fmt.Errorf("jwt: header 解析失败: %w", err)
	}
	// 算法校验：intl 档 = HS256；sm 档的 "HS256" 语义上为 HMAC-SM3，
	// 由 cryptoProvider.HMAC 的 profile 决定，header 仍标 HS256（与网关侧对齐）。
	if header.Alg != jwtHS256Alg {
		return nil, fmt.Errorf("jwt: 算法不支持: %s", header.Alg)
	}
	if header.Typ != "" && header.Typ != jwtType {
		return nil, fmt.Errorf("jwt: 类型不支持: %s", header.Typ)
	}

	// 解码 payload
	payloadRaw, err := base64urlDecode(parts[1])
	if err != nil {
		return nil, fmt.Errorf("jwt: payload 解码失败: %w", err)
	}
	var claims tenantJWTClaims
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, fmt.Errorf("jwt: payload 解析失败: %w", err)
	}

	// 签名校验（常量时间比对）
	sig, err := base64urlDecode(parts[2])
	if err != nil {
		return nil, fmt.Errorf("jwt: signature 解码失败: %w", err)
	}
	signingInput := parts[0] + "." + parts[1]
	expected := cryptoProvider.HMAC(key, []byte(signingInput))
	if subtle.ConstantTimeCompare(sig, expected) != 1 {
		return nil, errors.New("jwt: 签名无效")
	}

	// 声明有效性校验
	if err := claims.valid(now, leeway); err != nil {
		return nil, err
	}

	// 若同时有 sub 和 tenant 自定义声明，须一致（避免歧义）
	if claims.Tenant != "" && claims.Sub != claims.Tenant {
		return nil, fmt.Errorf("jwt: sub 与 tenant 声明不一致（sub=%s, tenant=%s）", claims.Sub, claims.Tenant)
	}

	return &claims, nil
}

// base64urlDecode base64url 解码（不带 padding，按 RFC 7515 §2）。
func base64urlDecode(s string) ([]byte, error) {
	// 补 padding
	switch len(s) % 4 {
	case 2:
		s += "=="
	case 3:
		s += "="
	}
	return base64.URLEncoding.DecodeString(s)
}

// base64urlEncode base64url 编码（不带 padding，便于测试用例构造）。
func base64urlEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// ---------- HTTP 中间件 ----------

// tenantJWTKeySource 租户密钥来源接口（由调用方注入，避免本文件直接依赖 keystore）。
//
// 生产实现：从 keystore 取对应租户的 HMAC 密钥。
// 测试实现：内存 map。
type tenantJWTKeySource interface {
	// GetKey 返回租户对应的 HMAC 密钥；不存在返回 nil, false。
	GetKey(tenantID string) ([]byte, bool)
	// Required 返回 true 表示租户 JWT 必须配置（fail-closed：缺失则启动拒）。
	Required() bool
}

// requireTenant HTTP 中间件：校验 Authorization: Bearer <jwt> 的租户身份。
//
// 校验通过 → 将 tenantID 注入 request context，调用 next；
// 校验失败 → 直接写 401/403 响应，不调用 next。
//
// expectedTenant 若非空，则额外校验 JWT 中的租户 ID 与之匹配（403 而非 401）。
// 这是为了防止 A 租户拿自己的令牌访问 B 租户的资源。
//
// X-Tenant-ID 头处理（降级为提示）：
//   - 若 JWT 存在 → 以 JWT 的 sub/tenant 为准；
//     若 X-Tenant-ID 与 JWT 冲突 → 403（跨租户访问拒绝）
//   - 若 JWT 不存在 → 401（不回退到 X-Tenant-ID 信任，fail-closed）
//
// 注意：本函数是"守卫"级别的独立中间件，不依赖既有 auth.go 的 attest 握手。
// 两者是分层的：attest 验证网关身份（通道可信），tenant JWT 验证终端租户身份。
func requireTenant(next http.HandlerFunc, keySource tenantJWTKeySource, expectedTenant string, leeway time.Duration) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if keySource == nil || !keySource.Required() {
			// 未配置租户 JWT → 启动期应已 fail-closed；
			// 运行时防御：直接 503（绝不静默放行）。
			http.Error(w, "tenant auth not configured", http.StatusServiceUnavailable)
			return
		}

		// 取 Bearer token
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "missing authorization", http.StatusUnauthorized)
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
			http.Error(w, "invalid authorization format", http.StatusUnauthorized)
			return
		}
		token := parts[1]

		// 预期租户：优先 expectedTenant（URL 路径级），其次 X-Tenant-ID（头级）
		wantTenant := expectedTenant
		if wantTenant == "" {
			wantTenant = r.Header.Get("X-Tenant-ID")
		}

		// 注意：因为密钥是租户级的，我们需要先知道预期租户才能取对应密钥验签。
		// 这是 HMAC 模式的必然选择（非对称 RS256 才可以先解析再选密钥）。
		// 网关侧 jwt-auth 同样是"按路由/租户配置 JWKS"的模式，此处对齐。
		if wantTenant == "" {
			http.Error(w, "missing tenant identifier", http.StatusUnauthorized)
			return
		}

		key, ok := keySource.GetKey(wantTenant)
		if !ok || len(key) == 0 {
			// 租户未配置密钥 → fail-closed（不回退到任何其它密钥）
			http.Error(w, "tenant key not found", http.StatusUnauthorized)
			return
		}

		now := time.Now()
		claims, err := verifyTenantJWT(token, key, now, leeway)
		if err != nil {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		// 双重校验：JWT 声明的租户必须与预期租户一致
		if claims.tenantID() != wantTenant {
			http.Error(w, "tenant mismatch", http.StatusForbidden)
			return
		}

		// 校验通过：注入 context 并继续
		ctx := withTenantID(r.Context(), claims.tenantID())
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// ---------- context 辅助 ----------

type tenantContextKey struct{}

// withTenantID 将租户 ID 注入 context。
func withTenantID(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, tenantContextKey{}, tenantID)
}

// TenantIDFromContext 从 context 取租户 ID（不存在返回空字符串）。
func TenantIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(tenantContextKey{}).(string)
	return v
}

// ---------- 测试辅助密钥源（仅同包测试用，不导出） ----------

// mapTenantKeySource 内存 map 密钥源（测试用）。
type mapTenantKeySource struct {
	keys     map[string][]byte
	required bool
}

func (m *mapTenantKeySource) GetKey(tenantID string) ([]byte, bool) {
	k, ok := m.keys[tenantID]
	return k, ok
}
func (m *mapTenantKeySource) Required() bool { return m.required }
