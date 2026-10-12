package main

// enclave_module_test.go —— sm-module 档 enclave 密封/解封往返测试（P1-5 M4）。
//
// 验证：进程 provider 为 mock 模块档时，NewMockEnclave 的密封密钥走模块 KEK
// 路径（token 语义），Seal/Unseal 经 cryptoProvider 在模块内完成 AEAD（C-4），
// 篡改/错上下文 fail-closed；非模块档路径不受影响（既有测试覆盖）。

import (
	"bytes"
	"testing"

	"security-ai-gateway/gateway/cryptop"
	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

// withModuleProvider 临时把进程 provider 切换为 mock 模块档（测试后恢复）。
func withModuleProvider(t *testing.T) *cryptopmodule.MockBackend {
	t.Helper()
	old := cryptoProvider
	b := cryptopmodule.NewMockBackend()
	cfg := cryptopmodule.DefaultConfig()
	cfg.Backend = cryptopmodule.BackendMock
	mp, err := cryptop.NewModuleProviderWithBackend(b, cfg)
	if err != nil {
		t.Fatalf("NewModuleProviderWithBackend: %v", err)
	}
	cryptoProvider = mp
	t.Cleanup(func() { cryptoProvider = old; _ = b.Close() })
	return b
}

func TestEnclaveModuleSealUnsealRoundtrip(t *testing.T) {
	withModuleProvider(t)

	e, err := NewMockEnclave()
	if err != nil {
		t.Fatalf("NewMockEnclave(sm-module): %v", err)
	}
	// 密封密钥应为模块 token（非 16B 明密）。
	if tok := e.rootKey(); len(tok) == 16 {
		t.Fatal("sm-module 档密封密钥应为模块 token，不应是 16B 明密")
	}
	pt := []byte("模块档密封往返")
	sealed, err := e.Seal(pt, "enclave/test/v1")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed) == 0 || sealed[0] != 2 { // suite=2 = SM4-GCM
		t.Fatalf("sealed 首字节应为 suite=2，got %d", sealed[0])
	}
	got, err := e.Unseal(sealed, "enclave/test/v1")
	if err != nil {
		t.Fatalf("Unseal: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("Seal/Unseal 往返不一致: %q", got)
	}
	// 错上下文 → fail-closed。
	if _, err := e.Unseal(sealed, "enclave/other"); err == nil {
		t.Fatal("错上下文解封应失败")
	}
	// 篡改 → fail-closed。
	bad := append([]byte(nil), sealed...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := e.Unseal(bad, "enclave/test/v1"); err == nil {
		t.Fatal("篡改密文解封应失败")
	}
}

func TestEnclaveModuleKeyImportDeterministic(t *testing.T) {
	withModuleProvider(t)
	// env 导入既有密封密钥（hex 16B）：两次 Load 得到同一模块对象（确定性）。
	t.Setenv(moduleSealKeyEnv, "30313233343536373839616263646566")
	e1, err := NewMockEnclave()
	if err != nil {
		t.Fatalf("NewMockEnclave #1: %v", err)
	}
	sealed, err := e1.Seal([]byte("deterministic"), "ctx")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	e2, err := NewMockEnclave()
	if err != nil {
		t.Fatalf("NewMockEnclave #2: %v", err)
	}
	got, err := e2.Unseal(sealed, "ctx")
	if err != nil {
		t.Fatalf("Unseal（同源导入密钥）: %v", err)
	}
	if string(got) != "deterministic" {
		t.Fatalf("往返不一致: %q", got)
	}
}

// TestEnclaveNonModulePathUnchanged 锁定非模块档路径零改动（intl 档）。
func TestEnclaveNonModulePathUnchanged(t *testing.T) {
	// 进程 provider 保持默认 intl（未切换）。
	e, err := NewMockEnclave()
	if err != nil {
		t.Fatalf("NewMockEnclave(intl): %v", err)
	}
	pt := []byte("intl-档不受影响")
	sealed, err := e.Seal(pt, "ctx")
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed[0] != 1 { // intl = SuiteAESGCM
		t.Fatalf("intl 档 suite 应为 1，got %d", sealed[0])
	}
	got, err := e.Unseal(sealed, "ctx")
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("intl 档往返失败: %v %q", err, got)
	}
}
