package main

// credential_test.go — 段① 凭据运行态拉取的纯逻辑单测（Phase 1 门禁 #8）。
//
// 覆盖：载荷校验（hex/长度/令牌长度）、K_sig 与 attest token 的**运行态优先 → 静态回退**
// 取值顺序、缺失时返回空（不 panic）。不含 hostcall（hostcall 由 metricsHostGuard 与
// 真实链路验证覆盖）。

import (
	"strings"
	"testing"
)

// testSigKeyHex 合法 K_sig（32 字节 hex），与 admin-service 端点用例同值。
const testSigKeyHex = "3031323334353637383961626364656630313233343536373839616263646566"

// resetCredRuntime 复位全局凭据运行态（用例间隔离；不复制含 mutex 的结构体）。
func resetCredRuntime(t *testing.T) {
	t.Helper()
	reset := func() {
		credRuntime.mu.Lock()
		credRuntime.sigKeyHex = ""
		credRuntime.attestToken = ""
		credRuntime.mu.Unlock()
	}
	reset()
	t.Cleanup(reset)
}

func TestValidateCredentialPayload(t *testing.T) {
	valid := credentialResponse{Name: "otpmask-keys", SigKeyHex: testSigKeyHex, AttestToken: "attest-token-1"}
	if err := validateCredentialPayload(valid); err != nil {
		t.Fatalf("合法载荷被拒: %v", err)
	}

	bad := map[string]credentialResponse{
		"sig_key 长度错误":  {SigKeyHex: "3031", AttestToken: "attest-token-1"},
		"sig_key 非 hex":  {SigKeyHex: strings.Repeat("z", 64), AttestToken: "attest-token-1"},
		"sig_key 为空":     {SigKeyHex: "", AttestToken: "attest-token-1"},
		"attest_token 过短": {SigKeyHex: testSigKeyHex, AttestToken: "short"},
	}
	for name, payload := range bad {
		if err := validateCredentialPayload(payload); err == nil {
			t.Fatalf("%s：期望校验失败，实际通过", name)
		}
	}
}

func TestSigKey_runtimePrecedenceThenStatic(t *testing.T) {
	resetCredRuntime(t)

	staticHex := strings.Repeat("ab", 32) // 64 位 hex（合法）
	runtimeHex := strings.Repeat("cd", 32)
	cfg := PluginConfig{SigKeyHex: staticHex}

	// 无运行态值 → 用静态
	if k := cfg.sigKey(); len(k) != 32 {
		t.Fatalf("静态回退失败：len=%d", len(k))
	}
	// 有运行态值 → 覆盖静态
	credRuntime.mu.Lock()
	credRuntime.sigKeyHex = runtimeHex
	credRuntime.mu.Unlock()
	got := cfg.sigKey()
	if len(got) != 32 || got[0] != 0xcd {
		t.Fatalf("运行态未优先生效：len=%d first=%x", len(got), got[0])
	}
	// 运行态非法（非 hex）→ 视为未生效，回退静态
	credRuntime.mu.Lock()
	credRuntime.sigKeyHex = strings.Repeat("z", 64)
	credRuntime.mu.Unlock()
	if k := cfg.sigKey(); len(k) != 32 || k[0] != 0xab {
		t.Fatalf("运行态非法时应回退静态：len=%d", len(k))
	}
	// 两者都无 → nil（由上层 fail-closed 处理）
	credRuntime.mu.Lock()
	credRuntime.sigKeyHex = ""
	credRuntime.mu.Unlock()
	empty := PluginConfig{}
	if k := empty.sigKey(); k != nil {
		t.Fatalf("无密钥时应返回 nil，实际 len=%d", len(k))
	}
}

func TestCurrentAttestToken_runtimePrecedenceThenStatic(t *testing.T) {
	resetCredRuntime(t)

	cfg := PluginConfig{AttestToken: "static-token"}
	if got := currentAttestToken(cfg); got != "static-token" {
		t.Fatalf("静态回退失败: %q", got)
	}
	credRuntime.mu.Lock()
	credRuntime.attestToken = "runtime-token"
	credRuntime.mu.Unlock()
	if got := currentAttestToken(cfg); got != "runtime-token" {
		t.Fatalf("运行态未优先生效: %q", got)
	}
	credRuntime.mu.Lock()
	credRuntime.attestToken = ""
	credRuntime.mu.Unlock()
	if got := currentAttestToken(PluginConfig{}); got != "" {
		t.Fatalf("两者皆空应返回空串: %q", got)
	}
}
