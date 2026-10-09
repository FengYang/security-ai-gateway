package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ---------- 签发与校验 ----------

func TestTenantJWT_SignAndVerify(t *testing.T) {
	secret := []byte("test-secret-16chars-minimum")
	token, err := issueTenantToken(secret, 42, "t_test1", "user@example.com")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if token == "" {
		t.Fatal("令牌为空")
	}

	claims, err := verifyTenantToken(token, secret)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if claims.Sub != "42" {
		t.Errorf("Sub 不匹配: got=%s want=42", claims.Sub)
	}
	if claims.Tenant != "t_test1" {
		t.Errorf("Tenant 不匹配: got=%s", claims.Tenant)
	}
	if claims.Role != tenantRole {
		t.Errorf("Role 不匹配: got=%s", claims.Role)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("Email 不匹配: got=%s", claims.Email)
	}
	if claims.EXP <= claims.IAT {
		t.Error("EXP 应大于 IAT")
	}
	if claims.EXP-claims.IAT != tenantTokenTTL {
		t.Errorf("TTL 不匹配: got=%d want=%d", claims.EXP-claims.IAT, tenantTokenTTL)
	}
}

func TestTenantJWT_InvalidSignature(t *testing.T) {
	secret1 := []byte("secret-one-16chars-minimum")
	secret2 := []byte("secret-two-16chars-minimum")
	token, _ := issueTenantToken(secret1, 1, "t_1", "a@b.com")

	_, err := verifyTenantToken(token, secret2)
	if err == nil {
		t.Error("用错误密钥校验不应通过")
	}
}

func TestTenantJWT_Expired(t *testing.T) {
	secret := []byte("test-secret-16chars-minimum")
	// 手工构造一个已过期的令牌
	claims := tenantClaims{
		Sub:    "1",
		Tenant: "t_1",
		Role:   tenantRole,
		IAT:    time.Now().Unix() - 10,
		EXP:    time.Now().Unix() - 5, // 已过期 5 秒
	}
	token, err := signTenantJWT(secret, claims)
	if err != nil {
		t.Fatal(err)
	}
	_, err = verifyTenantToken(token, secret)
	if err == nil {
		t.Error("过期令牌不应通过校验")
	}
}

func TestTenantJWT_InvalidFormat(t *testing.T) {
	secret := []byte("test-secret-16chars-minimum")
	_, err := verifyTenantToken("not-a-jwt", secret)
	if err == nil {
		t.Error("格式错误的令牌应报错")
	}
}

func TestTenantJWT_WrongRole(t *testing.T) {
	secret := []byte("test-secret-16chars-minimum")
	claims := tenantClaims{
		Sub:    "1",
		Tenant: "t_1",
		Role:   "admin", // 错误角色
		IAT:    time.Now().Unix(),
		EXP:    time.Now().Unix() + 3600,
	}
	token, _ := signTenantJWT(secret, claims)
	_, err := verifyTenantToken(token, secret)
	if err == nil {
		t.Error("非 tenant_user 角色应被拒")
	}
}

func TestTenantJWT_EmptyTenant(t *testing.T) {
	secret := []byte("test-secret-16chars-minimum")
	claims := tenantClaims{
		Sub:    "1",
		Tenant: "",
		Role:   tenantRole,
		IAT:    time.Now().Unix(),
		EXP:    time.Now().Unix() + 3600,
	}
	token, _ := signTenantJWT(secret, claims)
	_, err := verifyTenantToken(token, secret)
	if err == nil {
		t.Error("空 tenant 应被拒")
	}
}

// ---------- 中间件 ----------

func TestTenantAuthMiddleware_ValidToken(t *testing.T) {
	secret := []byte("test-secret-16chars-minimum")
	token, _ := issueTenantToken(secret, 1, "t_test", "u@e.com")

	handler := tenantAuthMiddleware(secret, func(w http.ResponseWriter, r *http.Request) {
		c := tenantFromCtx(r.Context())
		if c == nil {
			t.Error("上下文无 tenant claims")
			return
		}
		if c.Tenant != "t_test" {
			t.Errorf("Tenant 不对: %s", c.Tenant)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("状态码不对: got=%d", w.Code)
	}
}

func TestTenantAuthMiddleware_NoToken(t *testing.T) {
	secret := []byte("test-secret-16chars-minimum")
	handler := tenantAuthMiddleware(secret, func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler 不应被调用")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("状态码应为 401, got=%d", w.Code)
	}
}

func TestTenantAuthMiddleware_BadToken(t *testing.T) {
	secret := []byte("test-secret-16chars-minimum")
	handler := tenantAuthMiddleware(secret, func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler 不应被调用")
	})

	req := httptest.NewRequest("GET", "/test", nil)
	req.Header.Set("Authorization", "Bearer invalid-token-jwt")
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("状态码应为 401, got=%d", w.Code)
	}
}

// ---------- requireTenantScope ----------

func TestRequireTenantScope(t *testing.T) {
	secret := []byte("test-secret-16chars-minimum")
	token, _ := issueTenantToken(secret, 1, "t_abc", "u@e.com")

	handler := tenantAuthMiddleware(secret, func(w http.ResponseWriter, r *http.Request) {
		tenantID, err := requireTenantScope(r)
		if err != nil {
			t.Errorf("requireTenantScope 失败: %v", err)
			return
		}
		if tenantID != "t_abc" {
			t.Errorf("tenantID 不对: %s", tenantID)
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

// ---------- bearerFromHeader ----------

func TestBearerFromHeader(t *testing.T) {
	tok, ok := bearerFromHeader("Bearer abc123")
	if !ok || tok != "abc123" {
		t.Errorf("失败: ok=%v tok=%s", ok, tok)
	}
	_, ok = bearerFromHeader("Basic abc")
	if ok {
		t.Error("非 Bearer 应返回 false")
	}
	_, ok = bearerFromHeader("")
	if ok {
		t.Error("空串应返回 false")
	}
	if !strings.HasPrefix("Bearer x", "Bearer ") {
		t.Error("基本前缀检测失败")
	}
}
