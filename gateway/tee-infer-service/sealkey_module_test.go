package main

// sealkey_module_test.go —— moduleSealKeySource 测试（P1-5 M4）。
//
// 契约：Load 返回**模块对象 token**（非明文字节）；env 导入路径 fail-closed；
// 与 P1-8 T4 的 SealKeySource 接口契约兼容（编译期断言）。

import (
	"context"
	"encoding/hex"
	"strings"
	"testing"

	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

func newTestModuleSealKeySource(t *testing.T) (*moduleSealKeySource, *cryptopmodule.MockBackend) {
	t.Helper()
	b := cryptopmodule.NewMockBackend()
	cfg := cryptopmodule.DefaultConfig()
	cfg.Backend = cryptopmodule.BackendMock
	if err := b.Init(cfg); err != nil {
		t.Fatalf("Init: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return NewModuleSealKeySource(b), b
}

func TestModuleSealKeySourceGenerate(t *testing.T) {
	src, _ := newTestModuleSealKeySource(t)
	tok, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	// token 语义：非 16B 明密、含 mock 前缀（不透明引用，B-6.1-4）。
	if len(tok) == 0 {
		t.Fatal("token 不应为空")
	}
	if len(tok) == 16 {
		t.Fatal("Load 不应返回 16B 明密（应为模块 token）")
	}
	if !strings.HasPrefix(string(tok), "mock:") {
		t.Fatalf("mock 后端 token 应有 mock: 前缀，got %q", tok)
	}
}

func TestModuleSealKeySourceEnvImport(t *testing.T) {
	src, _ := newTestModuleSealKeySource(t)
	keyHex := hex.EncodeToString([]byte("0123456789abcdef"))
	t.Setenv(moduleSealKeyEnv, keyHex)
	tok, err := src.Load(context.Background())
	if err != nil {
		t.Fatalf("Load(env): %v", err)
	}
	// env 导入 → 以固定 alias 登记（token 可预期：mock:<alias>）。
	if string(tok) != "mock:"+moduleSealKeyAlias {
		t.Fatalf("env 导入 token 异常: %q", tok)
	}
	// 非法 hex → fail-closed。
	t.Setenv(moduleSealKeyEnv, "zzzz")
	if _, err := src.Load(context.Background()); err == nil {
		t.Fatal("非法 hex 应失败")
	}
	// 长度不符 → 导入失败（fail-closed）。
	t.Setenv(moduleSealKeyEnv, hex.EncodeToString([]byte("too-short")))
	if _, err := src.Load(context.Background()); err == nil {
		t.Fatal("长度不符应失败")
	}
}

func TestModuleSealKeySourceInterfaceCompliance(t *testing.T) {
	// 编译期已断言；此处锁定"第四实现不改变既有接口"的文档化事实。
	var _ SealKeySource = (*moduleSealKeySource)(nil)
}
