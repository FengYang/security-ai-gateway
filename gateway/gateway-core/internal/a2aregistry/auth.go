package a2aregistry

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

// Authn 是解析后的调用方身份（§5.4）。
type Authn struct {
	Tenant string // 安全租户；JWT 的 tenant claim
	Role   string // a2a_admin | a2a_viewer | platform_admin
	Sub    string
	// Target 是 platform_admin 的目标租户覆盖（X-GA-Tenant）；仅 platform_admin 生效。
	Target string
}

// 角色常量（§5.4）。
const (
	RoleA2AAdmin      = "a2a_admin"
	RoleA2AViewer     = "a2a_viewer"
	RolePlatformAdmin = "platform_admin"
)

var (
	errAuthUnauthorized = errors.New("未授权")
	errAuthForbidden    = errors.New("禁止访问")
	errTenantRequired   = errors.New("需指定目标租户（X-GA-Tenant）")
)

// jwtClaims 是控制面 JWT 载荷（兼容 auth-service HS256 签发）。
type jwtClaims struct {
	Sub    string `json:"sub"`
	Tenant string `json:"tenant"`
	Role   string `json:"role,omitempty"`
	Aud    string `json:"aud,omitempty"`
	JTI    string `json:"jti,omitempty"`
	IAT    int64  `json:"iat"`
	EXP    int64  `json:"exp"`
}

// resolveAuth 解析请求身份：
//   - Authorization: Bearer <JWT>（3 段，且已配置 jwtSecret）→ 验签取 tenant/role
//   - Bearer <静态 token> → 仅 DevMode 允许，降级为 platform_admin
//
// 租户一律来自 JWT/静态 token 的授权结果；body/path 不得覆盖（§5.4）。
func resolveAuth(r *http.Request, staticToken, jwtSecret string, devMode bool) (Authn, error) {
	authz := r.Header.Get("Authorization")
	if !strings.HasPrefix(authz, "Bearer ") {
		return Authn{}, errAuthUnauthorized
	}
	tok := strings.TrimSpace(strings.TrimPrefix(authz, "Bearer "))
	if tok == "" {
		return Authn{}, errAuthUnauthorized
	}
	target := strings.TrimSpace(r.Header.Get("X-GA-Tenant"))
	// JWT 路径
	if jwtSecret != "" && strings.Count(tok, ".") == 2 {
		claims, err := verifyHS256(jwtSecret, tok)
		if err != nil {
			return Authn{}, errAuthUnauthorized
		}
		role := claims.Role
		if role == "" {
			role = RoleA2AViewer // 缺省为只读角色（最小权限）
		}
		if !validRole(role) {
			return Authn{}, errAuthUnauthorized
		}
		authn := Authn{Tenant: claims.Tenant, Role: role, Sub: claims.Sub}
		if role == RolePlatformAdmin {
			authn.Target = target
		}
		return authn, nil
	}
	// 静态 token 降级（仅 DevMode；生产启动须拒绝，见 cmd/main.go 装配）。
	if devMode && staticToken != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(staticToken)) == 1 {
		return Authn{Tenant: target, Role: RolePlatformAdmin, Sub: "static-token", Target: target}, nil
	}
	return Authn{}, errAuthUnauthorized
}

func validRole(role string) bool {
	switch role {
	case RoleA2AAdmin, RoleA2AViewer, RolePlatformAdmin:
		return true
	}
	return false
}

// requireAdmin 校验管理角色并返回错误（否则 nil）。
func (a Authn) requireAdmin() error {
	if a.Role == RolePlatformAdmin || a.Role == RoleA2AAdmin {
		return nil
	}
	return errAuthForbidden
}

// targetTenant 解析操作目标租户：
//   - platform_admin：X-GA-Tenant 覆盖优先，其次自身租户；均无 → 拒绝
//   - 其他角色：绑定自身租户（忽略任何覆盖）
//
// 覆盖仅来自请求头 X-GA-Tenant（解析授权时采集），body/path 一律不得覆盖（§5.4）。
func (a Authn) targetTenant() (string, error) {
	if a.Role == RolePlatformAdmin {
		if a.Target != "" {
			return a.Target, nil
		}
		if a.Tenant != "" {
			return a.Tenant, nil
		}
		return "", errTenantRequired
	}
	if a.Tenant == "" {
		return "", errTenantRequired
	}
	return a.Tenant, nil
}

// verifyHS256 校验 HS256 JWT（RFC 8725：exp 必填、常量时间比较、alg=HS256）。
func verifyHS256(secret, token string) (*jwtClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt: 段数不为 3")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(parts[0] + "." + parts[1]))
	expected := mac.Sum(nil)
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || subtle.ConstantTimeCompare(sig, expected) != 1 {
		return nil, errors.New("jwt: 签名无效")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt: 载荷解码失败")
	}
	// 校验 alg=HS256
	header, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var h struct {
		Alg string `json:"alg"`
	}
	_ = json.Unmarshal(header, &h)
	if h.Alg != "HS256" {
		return nil, errors.New("jwt: 不支持的 alg")
	}
	var c jwtClaims
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, errors.New("jwt: 载荷解析失败")
	}
	if c.EXP == 0 || c.EXP < time.Now().Unix() {
		return nil, errors.New("jwt: token 缺失 exp 或已过期")
	}
	return &c, nil
}
