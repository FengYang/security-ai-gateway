// P2-4 T-4.2：共享安全边界单测（开关 / 授权钩子 / 来源白名单 / limit 归一）。
package auditexport

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestParseLimit limit 归一：空/0 = 上限；超限截断；负数/非数字 = 错误。
func TestParseLimit(t *testing.T) {
	cases := []struct {
		raw       string
		max       int
		wantLimit int
		wantTrunc bool
		wantErr   bool
	}{
		{raw: "", max: 100, wantLimit: 100, wantTrunc: false},
		{raw: "0", max: 100, wantLimit: 100, wantTrunc: true},
		{raw: "10", max: 100, wantLimit: 10, wantTrunc: false},
		{raw: "1000", max: 100, wantLimit: 100, wantTrunc: true},
		{raw: "-1", max: 100, wantErr: true},
		{raw: "abc", max: 100, wantErr: true},
		{raw: "5", max: 0, wantLimit: 5}, // max<=0 → 默认上限
	}
	for _, tc := range cases {
		got, trunc, err := ParseLimit(tc.raw, tc.max)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("ParseLimit(%q) 应报错", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseLimit(%q) 不应报错: %v", tc.raw, err)
		}
		if got != tc.wantLimit || trunc != tc.wantTrunc {
			t.Fatalf("ParseLimit(%q) = (%d,%v) want (%d,%v)", tc.raw, got, trunc, tc.wantLimit, tc.wantTrunc)
		}
	}
}

// TestAuthorizers 授权钩子：默认 deny-all；静态令牌空/不匹配拒绝，匹配放行。
func TestAuthorizers(t *testing.T) {
	if err := (DenyAllAuthorizer{}).Authorize(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatalf("DenyAllAuthorizer 应拒绝")
	}
	// Config 未注入授权器 → 归一为 deny-all。
	var cfg Config
	if err := cfg.authorizer().Authorize(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatalf("未注入授权器应归一为 deny-all")
	}
	empty := TokenAuthorizer{}
	if err := empty.Authorize(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Fatalf("空令牌应拒绝")
	}
	ta := TokenAuthorizer{Token: "dummy"}
	reqOK := httptest.NewRequest(http.MethodGet, "/", nil)
	reqOK.Header.Set("Authorization", "Bearer dummy")
	if err := ta.Authorize(reqOK); err != nil {
		t.Fatalf("正确令牌应放行: %v", err)
	}
	reqBad := httptest.NewRequest(http.MethodGet, "/", nil)
	reqBad.Header.Set("Authorization", "Bearer nope")
	if err := ta.Authorize(reqBad); err == nil {
		t.Fatalf("错误令牌应拒绝")
	}
	reqNoHeader := httptest.NewRequest(http.MethodGet, "/", nil)
	if err := ta.Authorize(reqNoHeader); err == nil {
		t.Fatalf("无 Authorization 头应拒绝")
	}
	// 函数式适配器。
	fa := FuncAuthorizer(func(r *http.Request) error { return nil })
	if err := fa.Authorize(reqNoHeader); err != nil {
		t.Fatalf("FuncAuthorizer 放行失败: %v", err)
	}
}

// TestSourceWhitelist 白名单：空 = 拒绝所有（fail-closed）；非法 CIDR = 错误。
func TestSourceWhitelist(t *testing.T) {
	var nilWL *SourceWhitelist
	if !nilWL.Empty() || nilWL.Allows(net.ParseIP("10.0.0.1")) {
		t.Fatalf("nil 白名单应拒绝所有来源")
	}
	empty, err := NewSourceWhitelist(nil)
	if err != nil {
		t.Fatalf("构造空白名单失败: %v", err)
	}
	if !empty.Empty() || empty.Allows(net.ParseIP("10.0.0.1")) || empty.Allows(nil) {
		t.Fatalf("空白名单应拒绝所有来源（含 nil IP）")
	}
	if _, err := NewSourceWhitelist([]string{"10.0.0.0/8", "bad"}); err == nil {
		t.Fatalf("非法 CIDR 应报错")
	}
	wl, err := NewSourceWhitelist([]string{" 10.0.0.0/8 ", "", "192.168.1.1/32"})
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	if wl.Empty() {
		t.Fatalf("非空白名单不应为空")
	}
	for _, ip := range []string{"10.255.255.255", "192.168.1.1"} {
		if !wl.Allows(net.ParseIP(ip)) {
			t.Fatalf("%s 应在白名单内", ip)
		}
	}
	for _, ip := range []string{"192.0.2.1", "172.16.0.1"} {
		if wl.Allows(net.ParseIP(ip)) {
			t.Fatalf("%s 不应在白名单内", ip)
		}
	}
}

// TestClientIP 来源 IP 只取 RemoteAddr（不信任 X-Forwarded-For）。
func TestClientIP(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:4567"
	req.Header.Set("X-Forwarded-For", "9.9.9.9") // 伪造头不得生效
	ip, err := ClientIP(req)
	if err != nil {
		t.Fatalf("解析来源失败: %v", err)
	}
	if ip.String() != "10.1.2.3" {
		t.Fatalf("应取 RemoteAddr: got %s", ip)
	}
	// 无端口形式。
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.9.9.9"
	if ip2, err := ClientIP(req2); err != nil || ip2.String() != "10.9.9.9" {
		t.Fatalf("无端口形式解析失败: %v %v", ip2, err)
	}
	// 非法地址 → 错误（fail-closed）。
	req3 := httptest.NewRequest(http.MethodGet, "/", nil)
	req3.RemoteAddr = "not-an-ip:80"
	if _, err := ClientIP(req3); err == nil {
		t.Fatalf("非法来源地址应报错")
	}
}

// TestConfigCheck 门控总入口：未启用 → ErrDisabled；授权/来源失败 → 错误。
func TestConfigCheck(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:4567"

	off := Config{Whitelist: mustWL(t, "10.0.0.0/8")}
	if err := off.Check(req); err != ErrDisabled {
		t.Fatalf("未启用应返回 ErrDisabled: %v", err)
	}
	deny := Config{Enabled: true, Whitelist: mustWL(t, "10.0.0.0/8")}
	if err := deny.Check(req); err == nil {
		t.Fatalf("deny-all 应拒绝")
	}
	outside := Config{Enabled: true, Authorizer: FuncAuthorizer(func(*http.Request) error { return nil }),
		Whitelist: mustWL(t, "192.168.0.0/16")}
	if err := outside.Check(req); err == nil || !strings.Contains(err.Error(), "白名单") {
		t.Fatalf("白名单外应拒绝: %v", err)
	}
	allow := Config{Enabled: true, Authorizer: FuncAuthorizer(func(*http.Request) error { return nil }),
		Whitelist: mustWL(t, "10.0.0.0/8")}
	if err := allow.Check(req); err != nil {
		t.Fatalf("白名单内+授权放行应通过: %v", err)
	}
}

// mustWL 构造测试白名单。
func mustWL(t *testing.T, cidrs ...string) *SourceWhitelist {
	t.Helper()
	wl, err := NewSourceWhitelist(cidrs)
	if err != nil {
		t.Fatalf("构造白名单失败: %v", err)
	}
	return wl
}
