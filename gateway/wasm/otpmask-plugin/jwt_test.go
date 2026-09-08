package main

// C-1 JWT 单元测试：exp 必填（RFC 8725 §3.1），缺失（=0）一律拒绝。

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"strings"
	"testing"
	"time"
)

var testSecret = []byte("0123456789abcdef0123456789abcdef")

// craftJWT 手工构造指定载荷的 HS256 token（测试用，绕过签发端以控制 exp 字段）。
func craftJWT(t *testing.T, secret []byte, payload string) string {
	t.Helper()
	signingInput := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`)) +
		"." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestVerifyAcceptsValidExp(t *testing.T) {
	tok := craftJWT(t, testSecret, `{"sub":"acme","tenant":"acme","exp":`+strconv.FormatInt(time.Now().Unix()+3600, 10)+`}`)
	c, err := verifyJWT(testSecret, tok)
	if err != nil {
		t.Fatalf("有效 exp 应通过校验: %v", err)
	}
	if c.Tenant != "acme" {
		t.Fatalf("声明不符: %+v", c)
	}
}

func TestVerifyMissingExp(t *testing.T) {
	tok := craftJWT(t, testSecret, `{"sub":"acme","tenant":"acme","iat":1600000000}`)
	if _, err := verifyJWT(testSecret, tok); err == nil || !strings.Contains(err.Error(), "exp") {
		t.Fatalf("缺失 exp 的 token 应被拒，got %v", err)
	}
}

func TestVerifyZeroExp(t *testing.T) {
	tok := craftJWT(t, testSecret, `{"sub":"acme","tenant":"acme","exp":0}`)
	if _, err := verifyJWT(testSecret, tok); err == nil || !strings.Contains(err.Error(), "exp") {
		t.Fatalf("exp=0 的 token 应被拒，got %v", err)
	}
}

func TestVerifyExpired(t *testing.T) {
	tok := craftJWT(t, testSecret, `{"sub":"acme","tenant":"acme","exp":`+strconv.FormatInt(time.Now().Unix()-60, 10)+`}`)
	if _, err := verifyJWT(testSecret, tok); err == nil || !strings.Contains(err.Error(), "过期") {
		t.Fatalf("过期 token 应被拒，got %v", err)
	}
}
