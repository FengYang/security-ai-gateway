// Package main — 内部令牌校验与最小角色控制单测。
//
// 本服务只校验不签发（签发方 = Java 控制台），测试内联 testSignToken 构造令牌。
//
// M2 §2.4 起：授权角色由本服务白名单（ADMIN_SVC_ROLE_ADMINS）派生，
// **不采信令牌内 role 声明**，故用例断言"派生角色"而非"令牌角色"。
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// testSecret 测试共享密钥（≥16 字节）。
var testSecret = []byte("test-admin-shared-secret-0123456789")

// testAdminUser 测试用管理员（在 testCfg 白名单内）。
const testAdminUser = "alice"

// testCfg 测试配置（签发方/受众取默认；alice 为管理员）。
func testCfg() *config {
	return &config{
		jwtSecret:   testSecret,
		jwtIssuer:   defaultIssuer,
		jwtAudience: defaultAudience,
		roleAdmins:  map[string]struct{}{testAdminUser: {}},
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
	base := claims{Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience}

	cases := []struct {
		name     string
		mutate   func(*claims)
		rebuild  func(t *testing.T, c claims) string // 覆盖默认签发路径（改签名等）
		wantErr  bool
		wantRole string // 期望**派生**角色（wantErr=false 时校验）
	}{
		{"合法令牌（白名单内 → admin）", nil, nil, false, roleAdmin},
		{"白名单外用户 → auditor", func(c *claims) { c.Sub = "bob" }, nil, false, roleAuditor},
		{"令牌自称 auditor 但白名单内 → 仍派生 admin（不采信 JWT role）", func(c *claims) { c.Role = roleAuditor }, nil, false, roleAdmin},
		{"未声明 iss/aud 兼容", func(c *claims) { c.Iss, c.Aud = "", "" }, nil, false, roleAdmin},
		{"过期令牌", func(c *claims) { c.EXP = time.Now().Unix() - 60 }, nil, true, ""},
		{"未知角色（格式校验）", func(c *claims) { c.Role = "superuser" }, nil, true, ""},
		{"空 sub 无法留痕", func(c *claims) { c.Sub = "" }, nil, true, ""},
		{"受众不匹配", func(c *claims) { c.Aud = "other-service" }, nil, true, ""},
		{"签发方不匹配", func(c *claims) { c.Iss = "attacker" }, nil, true, ""},
		{"错误密钥签名", nil, func(t *testing.T, c claims) string {
			return testSignToken(t, []byte("wrong-secret-key-0123456789abcdef"), c)
		}, true, ""},
		{"三非法段格式", nil, func(*testing.T, claims) string { return "a.b" }, true, ""},
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
			if got.Sub != c.Sub {
				t.Fatalf("sub 回读不一致：got %q want %q", got.Sub, c.Sub)
			}
			if got.Role != tc.wantRole {
				t.Fatalf("派生角色不符：got %q want %q（授权依据 = 本服务白名单）", got.Role, tc.wantRole)
			}
		})
	}
}

func TestVerifyInternalTokenSignatureTamper(t *testing.T) {
	cfg := testCfg()
	token := testSignToken(t, testSecret, claims{Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience})
	// 篡改载荷段后再签名区保持原样 → 签名校验必须失败。
	parts := strings.Split(token, ".")
	payload, _ := b64.DecodeString(parts[1])
	tampered := strings.Replace(string(payload), `"role":"admin"`, `"role":"auditor"`, 1)
	parts[1] = b64.EncodeToString([]byte(tampered))
	if _, err := verifyInternalToken(strings.Join(parts, "."), cfg); err == nil {
		t.Fatal("篡改载荷后签名校验应失败")
	}
}

// TestResolveRoleEmptyAllowlistFailClosed 白名单未配置 → 全员 auditor（无人可写）。
func TestResolveRoleEmptyAllowlistFailClosed(t *testing.T) {
	cfg := &config{roleAdmins: parseRoleAdmins("")}
	if got := cfg.resolveRole("anyone"); got != roleAuditor {
		t.Fatalf("未配置白名单时角色应为 auditor，实际 %q", got)
	}
	cfg2 := &config{roleAdmins: parseRoleAdmins(" alice , bob ,, ")}
	if got := cfg2.resolveRole("bob"); got != roleAdmin {
		t.Fatalf("白名单解析（空白项忽略）后 bob 应为 admin，实际 %q", got)
	}
	if got := cfg2.resolveRole("carol"); got != roleAuditor {
		t.Fatalf("白名单外 carol 应为 auditor，实际 %q", got)
	}
}

// TestRequireRoleRejectsAuditor 写操作授权：auditor → 403；admin → 放行。
// 关键断言：令牌自称 role=admin 但 sub 不在白名单，仍须 403（不采信 JWT role）。
func TestRequireRoleRejectsAuditor(t *testing.T) {
	cfg := testCfg()
	protected := authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if !requireRole(w, r, roleAdmin) {
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	call := func(t *testing.T, sub string) int {
		t.Helper()
		token := testSignToken(t, testSecret, claims{
			Sub: sub, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/adminext/broker-providers/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		protected(rec, req)
		return rec.Code
	}

	if got := call(t, "bob"); got != http.StatusForbidden {
		t.Fatalf("白名单外用户写操作应 403（令牌自称 admin 亦不可信），实际 %d", got)
	}
	if got := call(t, testAdminUser); got != http.StatusOK {
		t.Fatalf("管理员写操作应放行，实际 %d", got)
	}
}

// TestRequireRoleRejectsNilClaims 未经 authMiddleware 时（无 claims）必须拒绝，防越权绕过。
func TestRequireRoleRejectsNilClaims(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	if requireRole(rec, req, roleAdmin) {
		t.Fatal("无 claims 时必须拒绝")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("期望 403，实际 %d", rec.Code)
	}
}
