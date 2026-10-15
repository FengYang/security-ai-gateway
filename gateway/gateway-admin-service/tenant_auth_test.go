package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// signTenantJWT 测试辅助：用共享密钥构造租户令牌（生产由 Console 签发）。
func signTenantJWT(secret []byte, claims tenantClaims) string {
	headerB64 := tenantB64.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	payload, _ := json.Marshal(claims)
	payloadB64 := tenantB64.EncodeToString(payload)
	signingInput := headerB64 + "." + payloadB64
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + tenantB64.EncodeToString(mac.Sum(nil))
}

// newTenantJWT 构造合法租户令牌（ttl 秒）。
func newTenantJWT(secret []byte, sub, tenant, email string, ttl int64) string {
	now := time.Now().Unix()
	return signTenantJWT(secret, tenantClaims{
		Sub: sub, Tenant: tenant, Role: tenantRole, Email: email, IAT: now, EXP: now + ttl,
	})
}

func TestTenantJWT_Verify(t *testing.T) {
	secret := []byte("shared-secret-16chars-minimum")
	token := newTenantJWT(secret, "42", "t_test1", "user@example.com", 3600)

	claims, err := verifyTenantToken(token, secret)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if claims.Sub != "42" || claims.Tenant != "t_test1" || claims.Role != tenantRole {
		t.Errorf("claims 不匹配: %+v", claims)
	}
}

func TestTenantJWT_InvalidSignature(t *testing.T) {
	token := newTenantJWT([]byte("secret-one-16chars-minimum"), "1", "t_1", "a@b.com", 3600)
	if _, err := verifyTenantToken(token, []byte("secret-two-16chars-minimum")); err == nil {
		t.Error("错误密钥不应通过")
	}
}

func TestTenantJWT_Expired(t *testing.T) {
	secret := []byte("shared-secret-16chars-minimum")
	token := signTenantJWT(secret, tenantClaims{
		Sub: "1", Tenant: "t_1", Role: tenantRole,
		IAT: time.Now().Unix() - 10, EXP: time.Now().Unix() - 5,
	})
	if _, err := verifyTenantToken(token, secret); err == nil {
		t.Error("过期令牌不应通过")
	}
}

func TestTenantJWT_InvalidFormat(t *testing.T) {
	if _, err := verifyTenantToken("not-a-jwt", []byte("x")); err == nil {
		t.Error("格式错误应报错")
	}
}

func TestTenantJWT_WrongRole(t *testing.T) {
	secret := []byte("shared-secret-16chars-minimum")
	token := signTenantJWT(secret, tenantClaims{
		Sub: "1", Tenant: "t_1", Role: "admin", IAT: time.Now().Unix(), EXP: time.Now().Unix() + 3600,
	})
	if _, err := verifyTenantToken(token, secret); err == nil {
		t.Error("非 tenant_user 角色应被拒")
	}
}

func TestTenantJWT_EmptyTenant(t *testing.T) {
	secret := []byte("shared-secret-16chars-minimum")
	token := signTenantJWT(secret, tenantClaims{
		Sub: "1", Tenant: "", Role: tenantRole, IAT: time.Now().Unix(), EXP: time.Now().Unix() + 3600,
	})
	if _, err := verifyTenantToken(token, secret); err == nil {
		t.Error("空 tenant 应被拒")
	}
}

// tenantTestCfg 构造仅含共享密钥的最小配置（租户端点门禁测试用）。
func tenantTestCfg(secret []byte) *config {
	return &config{
		jwtSecret:   secret,
		jwtIssuer:   defaultIssuer,
		jwtAudience: defaultAudience,
		roleAdmins:  map[string]struct{}{},
	}
}

func TestTenantAuthMiddleware_ValidToken(t *testing.T) {
	secret := []byte("shared-secret-16chars-minimum")
	token := newTenantJWT(secret, "1", "t_test", "u@e.com", 3600)

	handler := tenantAuthMiddleware(tenantTestCfg(secret), func(w http.ResponseWriter, r *http.Request) {
		c := tenantFromCtx(r.Context())
		if c == nil || c.Tenant != "t_test" {
			t.Errorf("上下文 tenant 不对: %+v", c)
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("状态码: %d", w.Code)
	}
}

func TestTenantAuthMiddleware_NoToken(t *testing.T) {
	handler := tenantAuthMiddleware(tenantTestCfg([]byte("x")), func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler 不应被调用")
	})
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("应为 401, got=%d", w.Code)
	}
}

func TestTenantAuthMiddleware_BadToken(t *testing.T) {
	handler := tenantAuthMiddleware(tenantTestCfg([]byte("shared-secret-16chars-minimum")), func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler 不应被调用")
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer bad.token.here")
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("应为 401, got=%d", w.Code)
	}
}

func TestRequireTenantScope(t *testing.T) {
	secret := []byte("shared-secret-16chars-minimum")
	token := newTenantJWT(secret, "1", "t_abc", "u@e.com", 3600)

	handler := tenantAuthMiddleware(tenantTestCfg(secret), func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := requireTenantScope(r)
		if err != nil || tenantID != "t_abc" {
			t.Errorf("requireTenantScope: id=%s err=%v", tenantID, err)
		}
		w.WriteHeader(http.StatusOK)
	})
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("状态码: %d", w.Code)
	}
}

func TestBearerFromHeader(t *testing.T) {
	if tok, ok := bearerFromHeader("Bearer abc123"); !ok || tok != "abc123" {
		t.Errorf("解析失败: ok=%v tok=%s", ok, tok)
	}
	if _, ok := bearerFromHeader("Basic abc"); ok {
		t.Error("非 Bearer 应 false")
	}
	if _, ok := bearerFromHeader(""); ok {
		t.Error("空串应 false")
	}
}
