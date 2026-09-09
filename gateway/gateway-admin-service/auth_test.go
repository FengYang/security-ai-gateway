// Package main — 内部令牌校验单测。
//
// 本服务只校验不签发（签发方 = Java 控制台），测试内联 testSignToken 构造令牌。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// testSecret 测试共享密钥（≥16 字节）。
var testSecret = []byte("test-admin-shared-secret-0123456789")

// testCfg 测试配置（签发方/受众取默认）。
func testCfg() *config {
	return &config{
		jwtSecret:   testSecret,
		jwtIssuer:   defaultIssuer,
		jwtAudience: defaultAudience,
	}
}

// testSignToken 内联签发 HS256 令牌（仅测试用）：expIn 秒偏移，0=不过期由调用方控制。
func testSignToken(t *testing.T, secret []byte, c claims) string {
	t.Helper()
	now := time.Now().Unix()
	if c.IAT == 0 {
		c.IAT = now
	}
	if c.EXP == 0 {
		c.EXP = now + 300
	}
	header, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	payload, _ := json.Marshal(c)
	signingInput := b64.EncodeToString(header) + "." + b64.EncodeToString(payload)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + b64.EncodeToString(mac.Sum(nil))
}

func TestVerifyInternalToken(t *testing.T) {
	cfg := testCfg()
	base := claims{Sub: "alice", Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience}

	cases := []struct {
		name    string
		mutate  func(*claims)
		rebuild func(t *testing.T, c claims) string // 覆盖默认签发路径（改签名等）
		wantErr bool
	}{
		{"合法令牌（admin）", nil, nil, false},
		{"合法令牌（auditor）", func(c *claims) { c.Role = roleAuditor }, nil, false},
		{"未声明 iss/aud 兼容", func(c *claims) { c.Iss, c.Aud = "", "" }, nil, false},
		{"过期令牌", func(c *claims) { c.EXP = time.Now().Unix() - 60 }, nil, true},
		{"未知角色", func(c *claims) { c.Role = "superuser" }, nil, true},
		{"空 sub 无法留痕", func(c *claims) { c.Sub = "" }, nil, true},
		{"受众不匹配", func(c *claims) { c.Aud = "other-service" }, nil, true},
		{"签发方不匹配", func(c *claims) { c.Iss = "attacker" }, nil, true},
		{"错误密钥签名", nil, func(t *testing.T, c claims) string {
			return testSignToken(t, []byte("wrong-secret-key-0123456789abcdef"), c)
		}, true},
		{"三非法段格式", nil, func(*testing.T, claims) string { return "a.b" }, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := base
			if tc.mutate != nil {
				tc.mutate(&c)
			}
			var token string
			if tc.rebuild != nil {
				token = tc.rebuild(t, c)
			} else {
				token = testSignToken(t, testSecret, c)
			}
			got, err := verifyInternalToken(token, cfg)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("期望校验失败，实际通过：%+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("期望校验通过，实际失败：%v", err)
			}
			if got.Sub != c.Sub || got.Role != c.Role {
				t.Fatalf("claims 回读不一致：got sub=%q role=%q", got.Sub, got.Role)
			}
		})
	}
}

func TestVerifyInternalTokenSignatureTamper(t *testing.T) {
	cfg := testCfg()
	token := testSignToken(t, testSecret, claims{Sub: "alice", Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience})
	// 篡改载荷段后再签名区保持原样 → 签名校验必须失败。
	parts := strings.Split(token, ".")
	payload, _ := b64.DecodeString(parts[1])
	tampered := strings.Replace(string(payload), `"role":"admin"`, `"role":"auditor"`, 1)
	parts[1] = b64.EncodeToString([]byte(tampered))
	if _, err := verifyInternalToken(strings.Join(parts, "."), cfg); err == nil {
		t.Fatal("篡改载荷后签名校验应失败")
	}
}
