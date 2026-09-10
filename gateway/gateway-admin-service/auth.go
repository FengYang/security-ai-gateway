// Package main — 内部服务令牌校验与最小角色控制。
//
// Java 控制台（admin-ext controller）→ gateway-admin-service 的内部调用认证：
// 请求携带共享密钥签发的 HS256 JWT（Bearer），本服务校验签名、过期、受众，
// 拒绝非控制台来源（docs/管理门户-细化方案.md §3.1/§6）。
//
// 复用 auth-service/jwt.go 的手写 HS256 风格（RFC 7515，base64url 无 padding，零依赖）；
// 因各服务为独立 main 包，此处按本服务 claims 独立实现。
//
// 最小角色控制（M2 §2.4，S-1 定案）：
//   - 授权依据 = 本服务配置的管理员白名单（ADMIN_SVC_ROLE_ADMINS），**不采信 JWT 内 role 声明**
//     （Java 侧对全部会话恒签发 role=admin，作为授权依据无意义）；
//   - 写端点（凭据下发/删除）要求 role=admin，读端点允许 role=auditor；
//   - 白名单未配置 → 全部按 auditor（无人可写，fail-closed）。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// 管理面角色（D6/D10：admin / auditor 两角色起步）。
const (
	roleAdmin   = "admin"
	roleAuditor = "auditor"
)

// claims 内部服务令牌载荷。
type claims struct {
	Sub  string `json:"sub"`           // 操作人登录名（控制台会话解出后透传）
	Role string `json:"role"`          // admin / auditor（**本服务不采信，见 resolveRole**）
	Iss  string `json:"iss,omitempty"` // 签发方（higress-console）
	Aud  string `json:"aud,omitempty"` // 受众（gateway-admin-service）
	IAT  int64  `json:"iat"`
	EXP  int64  `json:"exp"`
}

var b64 = base64.RawURLEncoding // RFC 7515：base64url 无 padding

// validRole 校验角色是否在管理面白名单内（仅令牌格式校验，非授权依据）。
func validRole(role string) bool {
	return role == roleAdmin || role == roleAuditor
}

// resolveRole 由本服务配置的管理员白名单派生角色（唯一授权依据，M2 §2.4）。
func (cfg *config) resolveRole(sub string) string {
	if _, ok := cfg.roleAdmins[sub]; ok {
		return roleAdmin
	}
	return roleAuditor
}

// verifyInternalToken 校验内部 JWT：签名 → 过期 → 受众/签发方（若带）→ 角色/主体非空。
func verifyInternalToken(token string, cfg *config) (*claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("auth: token 格式错误（须为 3 段 JWT）")
	}

	// 签名校验：signingInput = header.payload，HMAC-SHA256(secret)。
	signingInput := parts[0] + "." + parts[1]
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("auth: 签名段非 base64url")
	}
	mac := hmac.New(sha256.New, cfg.jwtSecret)
	_, _ = mac.Write([]byte(signingInput))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("auth: 签名校验失败（共享密钥不匹配或令牌被篡改）")
	}

	// 载荷解析。
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("auth: 载荷段非 base64url")
	}
	var c claims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errors.New("auth: 载荷非合法 JSON")
	}

	// 过期校验（管理令牌有效期短，不做时钟偏移宽容）。
	if c.EXP > 0 && time.Now().Unix() > c.EXP {
		return nil, errors.New("auth: 令牌已过期")
	}
	// 受众/签发方：字段缺失视为未声明不拦（兼容早期签发），声明则必须匹配。
	if c.Aud != "" && c.Aud != cfg.jwtAudience {
		return nil, fmt.Errorf("auth: 受众不匹配（got=%q want=%q）", c.Aud, cfg.jwtAudience)
	}
	if c.Iss != "" && c.Iss != cfg.jwtIssuer {
		return nil, fmt.Errorf("auth: 签发方不匹配（got=%q want=%q）", c.Iss, cfg.jwtIssuer)
	}
	if !validRole(c.Role) {
		return nil, fmt.Errorf("auth: 未知角色 %q（允许 admin/auditor）", c.Role)
	}
	if c.Sub == "" {
		return nil, errors.New("auth: 主体（sub）为空，无法留痕到人")
	}

	// 最小角色控制：丢弃令牌内角色，改由本服务白名单派生（M2 §2.4）。
	c.Role = cfg.resolveRole(c.Sub)
	return &c, nil
}

// authMiddleware 内部令牌鉴权中间件：校验 Authorization: Bearer <JWT>。
// 通过后把 claims 放入请求上下文，供 handler 取操作人/角色。
func authMiddleware(cfg *config, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := r.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(h, prefix) {
			metrics.incAuthRejected()
			http.Error(w, "unauthorized: 缺少 Bearer 内部令牌", http.StatusUnauthorized)
			return
		}
		c, err := verifyInternalToken(strings.TrimPrefix(h, prefix), cfg)
		if err != nil {
			metrics.incAuthRejected()
			http.Error(w, "unauthorized: "+err.Error(), http.StatusUnauthorized)
			return
		}
		ctx := withClaims(r.Context(), c)
		metrics.request()
		next(w, r.WithContext(ctx))
	}
}

// requireReadAccess 读端点授权：任意**已认证**会话（admin 或 auditor）均可读。
//
// 与 requireRole 的分工：读 = 认证即可；写 = 必须精确匹配 admin。
// 无 claims（未经 authMiddleware）一律拒绝，防端点被误注册为免鉴权而越权读取。
func requireReadAccess(w http.ResponseWriter, r *http.Request) bool {
	if claimsFrom(r.Context()) != nil {
		return true
	}
	metrics.incAuthRejected()
	log.Printf("[adminext] 403 读端点缺少认证上下文：%s %s rid=%s", r.Method, r.URL.Path, r.Header.Get("X-Request-ID"))
	http.Error(w, "forbidden: 需要已认证会话", http.StatusForbidden)
	return false
}

// requireRole 校验当前请求角色；不满足则写 403 并返回 false（M2 §2.4）。
//
// 用于方法级授权：写端点（凭据下发/删除）要求 role 精确等于 admin。
func requireRole(w http.ResponseWriter, r *http.Request, want string) bool {
	c := claimsFrom(r.Context())
	if c != nil && c.Role == want {
		return true
	}
	got, sub := "<nil>", ""
	if c != nil {
		got, sub = c.Role, c.Sub
	}
	metrics.incAuthRejected()
	log.Printf("[adminext] 403 越权拒绝：sub=%s role=%s 需要=%s %s %s rid=%s",
		sub, got, want, r.Method, r.URL.Path, r.Header.Get("X-Request-ID"))
	http.Error(w, "forbidden: 需要 "+want+" 角色", http.StatusForbidden)
	return false
}
