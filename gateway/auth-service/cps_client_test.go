package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// mockCPS 构造返回固定 MAC 的假 cryptopsvc。
func mockCPS(t *testing.T, macFn func(data []byte) []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/hmac" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		var req struct {
			KeyRef string `json:"key_ref"`
			Data   string `json:"data"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		data, _ := base64.StdEncoding.DecodeString(req.Data)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"mac": base64.StdEncoding.EncodeToString(macFn(data)),
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestCPSClient_HMAC(t *testing.T) {
	srv := mockCPS(t, func(d []byte) []byte { return append([]byte("mac:"), d...) })
	c := newCPSClient(srv.URL, "otpmask/jwt/v1", time.Second)
	mac, err := c.HMAC([]byte("hello"))
	if err != nil {
		t.Fatalf("HMAC 失败: %v", err)
	}
	if string(mac) != "mac:hello" {
		t.Errorf("mac=%q", mac)
	}
}

func TestCPSClient_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	c := newCPSClient(srv.URL, "k", time.Second)
	if _, err := c.HMAC([]byte("x")); err == nil {
		t.Error("非 200 应报错")
	}
}

func TestCPSClient_Unreachable(t *testing.T) {
	// 不可达地址 → Ping 失败（对应启动 fail-closed）
	c := newCPSClient("http://127.0.0.1:1", "k", 200*time.Millisecond)
	if err := c.Ping(); err == nil {
		t.Error("不可达应返回错误")
	}
}

func TestSignJWTClaims_WithCPS(t *testing.T) {
	var seenData []byte
	srv := mockCPS(t, func(d []byte) []byte {
		seenData = d
		return []byte("sig")
	})
	c := newCPSClient(srv.URL, "otpmask/jwt/v1", time.Second)
	now := time.Now().Unix()
	tok, err := signJWTClaims(cpsSigner{client: c}, Claims{
		Sub: "u1", Tenant: "acme", Role: "api", JTI: "j1", IAT: now, EXP: now + 3600,
	})
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if tok == "" {
		t.Fatal("token 为空")
	}
	if len(seenData) == 0 {
		t.Fatal("应经 CPS 求 MAC（signingInput 已下发）")
	}

	// 用同一签名器验签（重算 MAC = sig）
	claims, err := verifyJWTWith(cpsSigner{client: c}, tok)
	if err != nil {
		t.Fatalf("验签失败: %v", err)
	}
	if claims.Tenant != "acme" || claims.Role != "api" || claims.JTI != "j1" {
		t.Errorf("claims 不对: %+v", claims)
	}
}

func TestSignJWTClaims_MissingExp(t *testing.T) {
	if _, err := signJWTClaims(localSigner{secret: testSecret}, Claims{Tenant: "acme"}); err == nil {
		t.Error("缺失 exp 应报错")
	}
}
