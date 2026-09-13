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

// credentialMux 组装与 main 同构的凭据端点路由。
func credentialMux(path string) (*http.ServeMux, string) {
	const token = "test-credential-token-0123456789"
	mux := http.NewServeMux()
	h := newCredentialHandler(&credentialSettings{file: path, token: token})
	mux.HandleFunc(credentialAPIBase+"/", h.handle)
	return mux, token
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
		"sig_key 缺失":     "attest_token=test-attest-token\n",
		"sig_key 非 hex":  "sig_key=zz01323334353637383961626364656630313233343536373839616263646566\nattest_token=t\n",
		"sig_key 长度错误":  "sig_key=3031\nattest_token=test-attest-token\n",
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
	t.Setenv("ADMIN_CREDENTIAL_TOKEN", "")
	if s := loadCredentialSettings(); s != nil {
		t.Fatalf("未配置令牌应返回 nil（端点不注册），实际 %+v", s)
	}
	t.Setenv("ADMIN_CREDENTIAL_TOKEN", "tk")
	t.Setenv("ADMIN_CREDENTIAL_FILE", "")
	s := loadCredentialSettings()
	if s == nil || s.file != defaultCredentialFile {
		t.Fatalf("缺省文件路径未生效: %+v", s)
	}
}
