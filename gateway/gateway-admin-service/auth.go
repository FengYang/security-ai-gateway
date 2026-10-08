// Package main — 内部服务令牌校验与最小角色控制。
//
// Java 控制台（admin-ext controller）→ gateway-admin-service 的内部调用认证：
// 请求携带共享密钥签发的 HS256 JWT（Bearer），本服务校验签名、过期、受众，
// 拒绝非控制台来源（docs/管理门户-细化方案.md §3.1/§6）。
//
// 复用 auth-service/jwt.go 的手写 HS256 风格（RFC 7515，base64url 无 padding，零依赖）；
// 因各服务为独立 main 包，此处按本服务 claims 独立实现。
//
// 最小角色控制（M3-A 修订，取代 M2 §2.4 的 S-1 全量派生）：
//   - 授权依据 = JWT 内 role 声明。M2 不采信的理由（Java 恒签发 admin，声明无意义）
//     已被 M3-A 消除：Java 侧 AdminExtSessionService 按账号表派生真实角色签发；
//   - ADMIN_SVC_ROLE_ADMINS 降级为**运维层强制加成**：白名单内 sub 恒 admin
//     （优先于 JWT role）。定位 = K8s/账号表故障时的最后防线（集群运维通道，
//     不依赖账号 Secret 可读），向后兼容 M2 既有部署配置；
//   - 写端点要求 role=admin，读端点允许 role=auditor / billing_reader（P0-3 §4.3.5）；
//   - 白名单未配置 → 全按 JWT role（原"无人可写 fail-closed"改由 Java 会话 + 账号表承担）。
package main

import (
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

// 管理面角色（D6/D10：admin / auditor 起步；P0-3 §4.3.5 增只读角色 billing_reader）。
const (
	roleAdmin         = "admin"
	roleAuditor       = "auditor"
	roleBillingReader = "billing_reader" // 只读账单/套餐/用量（§4.3.5；写端点仍仅 admin）
)

// claims 内部服务令牌载荷。
type claims struct {
	Sub  string `json:"sub"`           // 操作人登录名（控制台会话解出后透传）
	Role string `json:"role"`          // admin / auditor（**本服务不采信，见 resolveRole**）
	Iss  string `json:"iss,omitempty"` // 签发方（higress-console）
	Aud  string `json:"aud,omitempty"` // 受众（gateway-admin-service）
	// Tenant GA-计费 P0-3（§7.4）：租户声明（可空）。
	// 语义：非 admin 会话仅可访问本声明租户的计费数据（跨租户 → 403，fail-closed）；
	// admin 不受限（可跨租户）。缺省（旧令牌无此字段）→ 非 admin 读计费端点一律 403。
	// 兼容性：字段可选，旧令牌解析不受影响（json.Unmarshal 缺字段保持零值）。
	Tenant string `json:"tenant,omitempty"`
	IAT    int64  `json:"iat"`
	EXP    int64  `json:"exp"`
}

var b64 = base64.RawURLEncoding // RFC 7515：base64url 无 padding

// validRole 校验角色是否在管理面白名单内（仅令牌格式校验，非授权依据）。
func validRole(role string) bool {
	return role == roleAdmin || role == roleAuditor || role == roleBillingReader
}

// resolveRole 派生授权角色（M3-A）：JWT role 为授权依据，运维白名单强制加成。
//
// 白名单命中 → 恒 admin（优先于令牌声明；定位 = 运维层最后防线，不依赖账号表）；
// 未命中 → 采信令牌内角色（Java 侧账号表派生，签发受内部签名密钥保护）。
func (cfg *config) resolveRole(sub, tokenRole string) string {
	if _, ok := cfg.roleAdmins[sub]; ok {
		return roleAdmin
	}
	return tokenRole
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
	// 签名校验：signingInput = header.payload，MAC 经 cryptop（intl=HMAC-SHA256；sm=HMAC-SM3）。
	// key 不落插件/日志；比较为常量时间（§5.4.2 二分口径：Go 侧 subtle 可保留）。
	mac := cryptoProvider.HMAC(cfg.jwtSecret, []byte(signingInput))
	if subtle.ConstantTimeCompare(sig, mac) != 1 {
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
		return nil, fmt.Errorf("auth: 未知角色 %q（允许 admin/auditor/billing_reader）", c.Role)
	}
	if c.Sub == "" {
		return nil, errors.New("auth: 主体（sub）为空，无法留痕到人")
	}

	// 角色派生（M3-A）：采信令牌内角色，运维白名单强制加成（覆盖令牌声明）。
	c.Role = cfg.resolveRole(c.Sub, c.Role)
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
