// credential_endpoint_test.go — 段① 凭据只读投递端点单测（Phase 1 门禁 #8）。
//
// 覆盖：令牌校验（常量时间比较路径）、方法限制、名称白名单、文件缺失/损坏/权限过宽
// 一律 503 fail-closed、sig_key 十六进制与长度校验、未配置令牌 = 端点不注册。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// testSigKeyHex 合法 K_sig（32 字节 hex）。
const testSigKeyHex = "3031323334353637383961626364656630313233343536373839616263646566"

// writeCredentialFile 写入测试凭据文件（0600）。
func writeCredentialFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "otpmask-keys.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写凭据文件: %v", err)
	}
	return path
}

// 测试用读取令牌（每集合独立；长度满足下限，仅测试值）。
const (
	testCredentialToken  = "test-credential-token-0123456789"
	testCoreChannelToken = "test-core-channel-token-0123456789"
)

// credentialMux 组装与 main 同构的凭据端点路由（单集合：otpmask-keys）。
func credentialMux(path string) (*http.ServeMux, string) {
	mux := http.NewServeMux()
	h := newCredentialHandler(&credentialSettings{sets: []credentialSet{
		{Name: credentialNameOTPMask, File: path, Token: testCredentialToken},
	}})
	mux.HandleFunc(credentialAPIBase+"/", h.handle)
	return mux, testCredentialToken
}

// credentialMuxMulti 双集合路由（otpmask-keys + core-channel），用于多集合/跨集合令牌用例。
func credentialMuxMulti(otpmaskPath, channelPath string) *http.ServeMux {
	mux := http.NewServeMux()
	h := newCredentialHandler(&credentialSettings{sets: []credentialSet{
		{Name: credentialNameOTPMask, File: otpmaskPath, Token: testCredentialToken},
		{Name: credentialNameCoreChannel, File: channelPath, Token: testCoreChannelToken},
	}})
	mux.HandleFunc(credentialAPIBase+"/", h.handle)
	return mux
}

// writeChannelFile 写入通道令牌文件（KEY=VALUE，0600）。
func writeChannelFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "gateway-core-token.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("写通道令牌文件: %v", err)
	}
	return path
}

// doCredential 发起带令牌的请求。
func doCredential(t *testing.T, mux *http.ServeMux, method, target, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	if token != "" {
		req.Header.Set("X-Credential-Token", token)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestCredentialEndpoint_ok(t *testing.T) {
	path := writeCredentialFile(t, "# 测试\nsig_key="+testSigKeyHex+"\nattest_token=test-attest-token\n")
	mux, token := credentialMux(path)

	rec := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/"+credentialNameOTPMask, token)
	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	var got credentialResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("响应解析失败: %v", err)
	}
	if got.Name != credentialNameOTPMask || got.SigKeyHex != testSigKeyHex || got.AttestToken != "test-attest-token" {
		t.Fatalf("响应内容不符: %+v", got)
	}
}

func TestCredentialEndpoint_tokenMismatch_401(t *testing.T) {
	path := writeCredentialFile(t, "sig_key="+testSigKeyHex+"\nattest_token=test-attest-token\n")
	mux, _ := credentialMux(path)

	for _, tk := range []string{"", "wrong-token"} {
		rec := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/"+credentialNameOTPMask, tk)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("令牌 %q 期望 401，实际 %d", tk, rec.Code)
		}
		if rec.Body.String() == "" {
			t.Fatalf("错误响应体为空（应给出可读错误）")
		}
	}
}

func TestCredentialEndpoint_methodNotAllowed_405(t *testing.T) {
	path := writeCredentialFile(t, "sig_key="+testSigKeyHex+"\nattest_token=test-attest-token\n")
	mux, token := credentialMux(path)

	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		rec := doCredential(t, mux, m, credentialAPIBase+"/"+credentialNameOTPMask, token)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s 期望 405，实际 %d", m, rec.Code)
		}
	}
}

func TestCredentialEndpoint_unknownName_404(t *testing.T) {
	path := writeCredentialFile(t, "sig_key="+testSigKeyHex+"\nattest_token=test-attest-token\n")
	mux, token := credentialMux(path)

	rec := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/other-keys", token)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际 %d", rec.Code)
	}
}

func TestCredentialEndpoint_badFile_failClosed503(t *testing.T) {
	cases := map[string]string{
		"sig_key 缺失":      "attest_token=test-attest-token\n",
		"sig_key 非 hex":   "sig_key=zz01323334353637383961626364656630313233343536373839616263646566\nattest_token=t\n",
		"sig_key 长度错误":    "sig_key=3031\nattest_token=test-attest-token\n",
		"attest_token 缺失": "sig_key=" + testSigKeyHex + "\n",
	}
	for name, content := range cases {
		path := writeCredentialFile(t, content)
		mux, token := credentialMux(path)
		rec := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/"+credentialNameOTPMask, token)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s：期望 503 fail-closed，实际 %d", name, rec.Code)
		}
		// 错误响应不得回显凭据值
		if body := rec.Body.String(); strings.Contains(body, testSigKeyHex) {
			t.Fatalf("%s：错误响应疑似回显凭据值: %s", name, body)
		}
	}
}

func TestCredentialEndpoint_missingFile_503(t *testing.T) {
	mux, token := credentialMux(filepath.Join(t.TempDir(), "nope.env"))
	rec := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/"+credentialNameOTPMask, token)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("期望 503，实际 %d", rec.Code)
	}
}

func TestCredentialEndpoint_loosePermission_503(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 无 Unix 权限位语义，跳过权限校验用例")
	}
	path := writeCredentialFile(t, "sig_key="+testSigKeyHex+"\nattest_token=test-attest-token\n")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	mux, token := credentialMux(path)
	rec := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/"+credentialNameOTPMask, token)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("权限过宽期望 503（fail-closed），实际 %d", rec.Code)
	}
}

func TestLoadCredentialSettings_disabledWithoutToken(t *testing.T) {
	t.Setenv("ADMIN_CREDENTIAL_SETS", "")
	t.Setenv("ADMIN_CREDENTIAL_TOKEN", "")
	if s := loadCredentialSettings(); s != nil {
		t.Fatalf("未配置令牌应返回 nil（端点不注册），实际 %+v", s)
	}
	// 未配置 = handler 为 nil（端点不注册；修正此前"未配置却注册"的裸奔风险）
	if h := newCredentialHandler(nil); h != nil {
		t.Fatalf("未配置应返回 nil handler，实际 %+v", h)
	}
	t.Setenv("ADMIN_CREDENTIAL_TOKEN", "tk")
	t.Setenv("ADMIN_CREDENTIAL_FILE", "")
	s := loadCredentialSettings()
	if s == nil || len(s.sets) != 1 || s.sets[0].Name != credentialNameOTPMask ||
		s.sets[0].File != defaultCredentialFile {
		t.Fatalf("单集合兼容写法未生效（缺省文件路径）: %+v", s)
	}
}

// TestLoadCredentialSettings_sets 多集合写法（ADMIN_CREDENTIAL_SETS）解析与非法条目跳过。
func TestLoadCredentialSettings_sets(t *testing.T) {
	t.Setenv("ADMIN_CREDENTIAL_TOKEN", "")
	t.Setenv("ADMIN_CREDENTIAL_SETS",
		"otpmask-keys:deploy/secrets/otpmask-keys.env:tok-otpmask,"+
			"core-channel:deploy/secrets/gateway-core-token.env:tok-core,"+
			"unknown-set:a:b,"+ // 未支持集合 → 跳过
			"bad-entry") // 字段数不足 → 跳过
	s := loadCredentialSettings()
	if s == nil || len(s.sets) != 2 {
		t.Fatalf("应解析出 2 个集合（其余非法条目跳过）: %+v", s)
	}
	if s.find(credentialNameCoreChannel) == nil || s.find(credentialNameOTPMask) == nil {
		t.Fatalf("应含 otpmask-keys 与 core-channel: %+v", s.sets)
	}
	if s.find("unknown-set") != nil {
		t.Fatal("未支持的集合不得注册")
	}
	if got := s.setNames(); got != "otpmask-keys,core-channel" {
		t.Fatalf("集合名列表不符: %s", got)
	}
}

// TestCredentialEndpoint_coreChannel 通道令牌集：仅返回 token（字段白名单，不泄露其他字段）。
func TestCredentialEndpoint_coreChannel(t *testing.T) {
	otpmaskPath := writeCredentialFile(t, "sig_key="+testSigKeyHex+"\nattest_token=test-attest-token\n")
	// 文件内**故意多写** sig_key：白名单只允许 token，多写字段不得被投递
	channelPath := writeChannelFile(t, "sig_key="+testSigKeyHex+"\ntoken=core-channel-token-0123456789abcdef\n")
	mux := credentialMuxMulti(otpmaskPath, channelPath)

	rec := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/"+credentialNameCoreChannel, testCoreChannelToken)
	if rec.Code != http.StatusOK {
		t.Fatalf("通道令牌集期望 200，实际 %d body=%s", rec.Code, rec.Body.String())
	}
	var got map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["name"] != credentialNameCoreChannel || got["token"] != "core-channel-token-0123456789abcdef" {
		t.Fatalf("响应不符: %v", got)
	}
	if _, leaked := got["sig_key"]; leaked {
		t.Fatalf("白名单外字段不得投递: %v", got)
	}
	if _, leaked := got["attest_token"]; leaked {
		t.Fatalf("白名单外字段不得投递: %v", got)
	}
	// otpmask-keys 仍正常，且响应不含 token 字段
	rec2 := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/"+credentialNameOTPMask, testCredentialToken)
	if rec2.Code != http.StatusOK {
		t.Fatalf("otpmask-keys 期望 200，实际 %d", rec2.Code)
	}
	var got2 map[string]string
	_ = json.Unmarshal(rec2.Body.Bytes(), &got2)
	if _, leaked := got2["token"]; leaked {
		t.Fatalf("otpmask-keys 不应含 token 字段: %v", got2)
	}
}

// TestCredentialEndpoint_crossSetTokenRejected 跨集合令牌一律 401（每集合独立令牌＝最小权限）。
func TestCredentialEndpoint_crossSetTokenRejected(t *testing.T) {
	otpmaskPath := writeCredentialFile(t, "sig_key="+testSigKeyHex+"\nattest_token=test-attest-token\n")
	channelPath := writeChannelFile(t, "token=core-channel-token-0123456789abcdef\n")
	mux := credentialMuxMulti(otpmaskPath, channelPath)

	cases := []struct {
		name  string
		path  string
		token string
	}{
		{"core 令牌读 otpmask-keys", credentialNameOTPMask, testCoreChannelToken},
		{"otpmask 令牌读 core-channel", credentialNameCoreChannel, testCredentialToken},
	}
	for _, c := range cases {
		rec := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/"+c.path, c.token)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s 期望 401（最小权限），实际 %d", c.name, rec.Code)
		}
	}
}

// TestCredentialEndpoint_coreChannelShortToken_503 通道令牌过短 → 503（fail-closed，不投递弱令牌）。
func TestCredentialEndpoint_coreChannelShortToken_503(t *testing.T) {
	otpmaskPath := writeCredentialFile(t, "sig_key="+testSigKeyHex+"\nattest_token=test-attest-token\n")
	channelPath := writeChannelFile(t, "token=short\n")
	mux := credentialMuxMulti(otpmaskPath, channelPath)
	rec := doCredential(t, mux, http.MethodGet, credentialAPIBase+"/"+credentialNameCoreChannel, testCoreChannelToken)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("过短令牌期望 503，实际 %d", rec.Code)
	}
}
