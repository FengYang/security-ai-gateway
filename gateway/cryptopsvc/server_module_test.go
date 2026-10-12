package cryptopsvc

// server_module_test.go —— sm-module 档 sidecar 装配测试（P1-5 M3）。
//
// 验证 V-1（sm-module 启动成功）：经 mock 后端构造 moduleProvider 后，
// NewServer 装配成功、/v1/capabilities 如实上报 sm-module 档与合规标注（P4）、
// 无密钥运算端点（rand/hash）在模块档下可用、#9 指标 active 序列为 sm-module。
// 有密钥运算（hmac/seal/sign/...）的模块档路径随 M4 密钥托管导入后覆盖。

import (
	"bytes"
	"encoding/base64"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/cryptop"
	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

// newModuleTestServer mock 后端 + sm-module Provider 装配 sidecar（V-1）。
func newModuleTestServer(t *testing.T) (*Server, *httptest.Server, *cryptopmodule.MockBackend) {
	t.Helper()
	b := cryptopmodule.NewMockBackend()
	cfgM := cryptopmodule.DefaultConfig()
	cfgM.Backend = cryptopmodule.BackendMock
	cfgM.MaxSessions = 4
	prov, err := cryptop.NewModuleProviderWithBackend(b, cfgM)
	if err != nil {
		t.Fatalf("NewModuleProviderWithBackend: %v", err)
	}
	s, err := NewServer(prov, Config{
		Profile:     cryptop.ProfileSMModule,
		CallTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("NewServer(sm-module): %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(func() { _ = b.Close() })
	return s, ts, b
}

func TestModuleAssemblyV1(t *testing.T) {
	s, ts, _ := newModuleTestServer(t)

	// ① /v1/capabilities 如实上报 sm-module 档 + mock 合规标注（P4）。
	code, caps := getJSON(t, ts, "/v1/capabilities")
	if code != 200 {
		t.Fatalf("capabilities HTTP %d", code)
	}
	if caps["profile"] != "sm-module" {
		t.Fatalf("profile=%v, want sm-module", caps["profile"])
	}
	if caps["suite"] != float64(2) { // suite=2 = SM4-GCM（§4.3）
		t.Fatalf("suite=%v, want 2", caps["suite"])
	}
	note, _ := caps["compliance_note"].(string)
	if !strings.Contains(note, "mock") || !strings.Contains(note, "不满足密评") {
		t.Fatalf("compliance_note 未如实标注 mock 后端: %q", note)
	}
	sizes, _ := caps["sizes"].(map[string]any)
	if sizes["symmetric_key"] != float64(16) || sizes["hash"] != float64(32) {
		t.Fatalf("sizes 异常: %v", sizes)
	}

	// ② 无密钥运算在模块档可用：/v1/rand、/v1/hash。
	if code, _ := postJSON(t, ts, "/v1/rand", map[string]any{"n": 16}, nil); code != 200 {
		t.Fatalf("/v1/rand 在 sm-module 档应可用（HTTP %d）", code)
	}
	code, resp := postJSON(t, ts, "/v1/hash", map[string]any{"data": b64([]byte("module-assembly"))}, nil)
	if code != 200 {
		t.Fatalf("/v1/hash 在 sm-module 档应可用（HTTP %d）", code)
	}
	if resp["digest"] == nil || resp["digest"] == "" {
		t.Fatalf("/v1/hash 响应异常: %v", resp)
	}

	// ③ #9 指标：sm-module 为 active=true 生效序列（R-28/R-S3-3）。
	raw := renderMetrics(t, s)
	want := `cryptop_profile_info{profile="sm-module",meets_mpy="true",compliance_note="` +
		"国密算法 + 认证密码模块/密码服务；可用于政企合规声明（仍须密码应用方案评估与密评）" +
		`；⚠ 当前为 mock 后端（软件实现，仅适配层功能验证，不满足密评，禁止用于生产合规声明）",active="true"} 1`
	if !strings.Contains(raw, want) {
		t.Fatalf("#9 指标缺 sm-module active 序列:\nwant %q\ngot:\n%s", want, raw)
	}
	if strings.Count(raw, `active="true"`) != 1 {
		t.Fatalf("恰一条 active=true，got:\n%s", raw)
	}
}

// TestModuleAssemblyFailClosed 装配门禁（C-3）：sm-module 无厂商配置 → 启动拒。
func TestModuleAssemblyFailClosed(t *testing.T) {
	// 生产路径（env 驱动）在无 MODULE_LIB_PATH 时 New 失败。
	if _, err := cryptop.New(cryptop.ProfileSMModule); err == nil {
		t.Fatal("无厂商配置的 sm-module 应 fail-closed（C-3）")
	}
	// 显式 mock 在生产路径被拒（P4）。
	t.Setenv("MODULE_BACKEND", "mock")
	if _, err := cryptop.New(cryptop.ProfileSMModule); err == nil {
		t.Fatal("生产路径应拒绝 mock 后端")
	}
}

// TestModuleAssemblyKeyedOps M4 落地后有密钥运算在 sm-module 档可用：
// 静态密钥经 moduleStore 导入模块（B-6.1-5），/v1/hmac 在模块内执行。
func TestModuleAssemblyKeyedOps(t *testing.T) {
	b := cryptopmodule.NewMockBackend()
	cfgM := cryptopmodule.DefaultConfig()
	cfgM.Backend = cryptopmodule.BackendMock
	cfgM.MaxSessions = 4
	prov, err := cryptop.NewModuleProviderWithBackend(b, cfgM)
	if err != nil {
		t.Fatalf("NewModuleProviderWithBackend: %v", err)
	}
	s, err := NewServer(prov, Config{
		Profile:     cryptop.ProfileSMModule,
		CallTimeout: time.Second,
		StaticKeys: map[string][]byte{
			"static/hmac": bytes.Repeat([]byte{0xCD}, 16), // sm-module 对称键长 16
		},
	})
	if err != nil {
		t.Fatalf("NewServer(sm-module+static): %v", err)
	}
	ts := httptest.NewServer(s.Handler())
	t.Cleanup(ts.Close)
	t.Cleanup(func() { _ = b.Close() })

	code, resp := postJSON(t, ts, "/v1/hmac", map[string]any{
		"key_ref": "static/hmac",
		"data":    b64([]byte("module-hmac")),
	}, nil)
	if code != 200 {
		t.Fatalf("sm-module 档 /v1/hmac 应可用（静态密钥已入模块，HTTP %d）", code)
	}
	macB64, _ := resp["mac"].(string)
	if macB64 == "" {
		t.Fatalf("响应缺 mac: %v", resp)
	}
	// 与软件档逐字节一致（跨档 KAT：HMAC-SM3）。
	sw, err := cryptop.New(cryptop.ProfileSMSW)
	if err != nil {
		t.Fatalf("cryptop.New(sm-software): %v", err)
	}
	want := sw.HMAC(bytes.Repeat([]byte{0xCD}, 16), []byte("module-hmac"))
	got, err := base64.StdEncoding.DecodeString(macB64)
	if err != nil {
		t.Fatalf("mac base64 解码: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("模块档 HMAC 与软件档不一致（KAT）")
	}
}
