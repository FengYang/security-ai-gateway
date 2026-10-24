//go:build pkcs11

// pkcs11_live_test.go —— PKCS#11 后端真机用例（M4-1）。
//
// 运行前提（.248 联调机）：SoftHSMv2 token（libsofthsm2.so）+ 环境变量：
//
//	P11_LIVE=1                    启用（未设置则 Skip，不以 mock 冒充真机）
//	P11_LIVE_LIB=/usr/lib/softhsm/libsofthsm2.so
//	P11_LIVE_PIN=0000             口令（测试内以 env: 载体传入，验证 R-S3-2 链路）
//
// SoftHSM 实测（2026-10-24）无 SM 机制，故：
//   - 生命周期用例把 RequiredMechanisms 收窄为 ["rand"]（验证探测→校验正路径）；
//   - 缺省六机制必然启动拒（验证 R-S3-11 fail-closed 负路径）。
package cryptopmodule

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func p11LiveConfig(t *testing.T, required []string) *Config {
	t.Helper()
	if os.Getenv("P11_LIVE") != "1" {
		t.Skip("P11_LIVE != 1，跳过真机用例（不以 mock 冒充真机）")
	}
	cfg := DefaultConfig()
	cfg.Backend = BackendPKCS11
	cfg.LibPath = envOr("P11_LIVE_LIB", "/usr/lib/softhsm/libsofthsm2.so")
	cfg.Slot = 0                    // GetSlotList 下标语义（SoftHSM 单 token）
	cfg.PinRef = "env:P11_LIVE_PIN" // 载体引用（R-S3-2），非字面值
	cfg.MaxSessions = 4
	cfg.SessionQueueSize = 2
	cfg.RequiredMechanisms = required
	return cfg
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// profilePath 随源码发布的 profile 文件（go test 工作目录即包目录）。
func profilePath(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join("profiles", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("profile 文件缺失: %s: %v", p, err)
	}
	return p
}

// TestPKCS11LiveLifecycleRand M4-1 主链路：Init→Capabilities→Rand→会话池→
// Health→Close（§7.4 验证项"真机跑通 OpenDevice+GenerateRandom"的 PKCS#11 等价物）。
func TestPKCS11LiveLifecycleRand(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11): %v", err)
	}
	defer func() { _ = backend.Close() }()

	caps := backend.Capabilities()
	if caps.Backend != BackendPKCS11 {
		t.Fatalf("caps.Backend=%q want pkcs11", caps.Backend)
	}
	if !caps.HasMechanism(MechRand) {
		t.Fatalf("caps 应含 rand（C_GenerateRandom 通用），实得 %v", caps.Mechanisms)
	}
	t.Logf("探测到能力: vendor=%q model=%q mechanisms=%v", caps.Vendor, caps.Model, caps.Mechanisms)

	r1, err := backend.Rand(32)
	if err != nil {
		t.Fatalf("Rand(32): %v", err)
	}
	if len(r1) != 32 {
		t.Fatalf("Rand(32) 长度=%d", len(r1))
	}
	r2, err := backend.Rand(32)
	if err != nil {
		t.Fatalf("Rand(32) 第二次: %v", err)
	}
	if string(r1) == string(r2) {
		t.Fatal("两次 Rand(32) 相同——CSPRNG 异常")
	}

	s, err := backend.AcquireSession()
	if err != nil {
		t.Fatalf("AcquireSession: %v", err)
	}
	if err := backend.ReleaseSession(s); err != nil {
		t.Fatalf("ReleaseSession: %v", err)
	}

	if h := backend.Health(); h != HealthOK {
		t.Fatalf("Health=%v want ok", h)
	}

	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if h := backend.Health(); h != HealthDown {
		t.Fatalf("Close 后 Health=%v want down", h)
	}
	if _, err := backend.Rand(16); err == nil {
		t.Fatal("Close 后 Rand 应失败（fail-closed）")
	}
}

// TestPKCS11LiveDefaultMechanismsFailClosed R-S3-11：SoftHSM 无 SM 机制，
// 缺省六机制必须启动拒并列出缺失清单（fail-closed，不冒充合规）。
func TestPKCS11LiveDefaultMechanismsFailClosed(t *testing.T) {
	cfg := p11LiveConfig(t, DefaultRequiredMechanisms())
	backend, err := NewBackend(cfg)
	if err == nil {
		_ = backend.Close()
		t.Fatal("SoftHSM 无 SM 机制，缺省六机制应启动拒（R-S3-11）")
	}
	if !errors.Is(err, ErrMechanismMissing) {
		t.Fatalf("应返回 ErrMechanismMissing，实得: %v", err)
	}
	msg := err.Error()
	for _, m := range []string{MechSM4GCM, MechSM3, MechHMACSM3, MechSM2Sign, MechSM2ECDH} {
		if !strings.Contains(msg, m) {
			t.Fatalf("缺失清单应含 %s，实得: %s", m, msg)
		}
	}
	t.Logf("R-S3-11 fail-closed 如实触发: %v", err)
}

// TestPKCS11LiveLiteralPINRejected R-S3-2：PinRef 字面值（无 file:/env: 载体）
// 必须在 Init 期拒绝。
func TestPKCS11LiveLiteralPINRejected(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	cfg.PinRef = "0000" // 字面值：违规
	backend, err := NewBackend(cfg)
	if err == nil {
		_ = backend.Close()
		t.Fatal("PinRef 字面值应被拒绝（R-S3-2）")
	}
	t.Logf("R-S3-2 如实触发: %v", err)
}

// TestPKCS11LiveMechProfileFunctional M4-3/B-6.1-2：generic profile 登记的
// 标准机制（SoftHSM 实测有）→ Init 成功，Capabilities 只含探测命中项，
// Profile 字段溯源 profile_id。
func TestPKCS11LiveMechProfileFunctional(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand, MechAESGCM, MechAESKeyWrap, MechSHA256})
	cfg.MechanismProfile = profilePath(t, "softhsm-generic.json")
	backend, err := NewBackend(cfg)
	if err != nil {
		t.Fatalf("NewBackend(pkcs11, generic profile): %v", err)
	}
	defer func() { _ = backend.Close() }()

	caps := backend.Capabilities()
	if caps.Profile != "softhsm-generic" {
		t.Fatalf("caps.Profile=%q want softhsm-generic（B-6.1-2 溯源）", caps.Profile)
	}
	for _, m := range []string{MechRand, MechAESGCM, MechAESKeyWrap, MechSHA256} {
		if !caps.HasMechanism(m) {
			t.Fatalf("caps 应含 %s，实得 %v", m, caps.Mechanisms)
		}
	}
	// 功能验证档不得冒充合规档：任何 SM 机制都不得出现。
	for _, m := range []string{MechSM4GCM, MechSM3, MechHMACSM3, MechSM2Sign, MechSM2ECDH} {
		if caps.HasMechanism(m) {
			t.Fatalf("generic profile 不得登记 SM 机制 %q（不得冒充合规），实得 %v", m, caps.Mechanisms)
		}
	}
	t.Logf("generic profile 探测命中: mechanisms=%v", caps.Mechanisms)
}

// TestPKCS11LiveGenericProfileNoSM R-S3-11：即使配置了 generic profile，
// 缺省六 SM 机制仍必须启动拒（证明功能验证档不冒充合规档）。
func TestPKCS11LiveGenericProfileNoSM(t *testing.T) {
	cfg := p11LiveConfig(t, DefaultRequiredMechanisms())
	cfg.MechanismProfile = profilePath(t, "softhsm-generic.json")
	backend, err := NewBackend(cfg)
	if err == nil {
		_ = backend.Close()
		t.Fatal("generic profile 无 SM 机制，缺省六机制应启动拒（R-S3-11）")
	}
	if !errors.Is(err, ErrMechanismMissing) {
		t.Fatalf("应返回 ErrMechanismMissing，实得: %v", err)
	}
	t.Logf("generic profile + SM 缺省六机制 fail-closed 如实触发: %v", err)
}

// TestPKCS11LiveMechProfileTemplateRejected B-6.1-2：厂商模板（CKM 未填）
// 必须在 Init 期 fail-closed，且错误信息指明待填机制。
func TestPKCS11LiveMechProfileTemplateRejected(t *testing.T) {
	cfg := p11LiveConfig(t, []string{MechRand})
	cfg.MechanismProfile = profilePath(t, "template-vendor-sm.json")
	backend, err := NewBackend(cfg)
	if err == nil {
		_ = backend.Close()
		t.Fatal("厂商模板（CKM 未填）应启动拒（fail-closed，禁止臆测标准值）")
	}
	msg := err.Error()
	for _, want := range []string{"sm4-gcm", "CKM"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("错误信息应含 %q，实得: %s", want, msg)
		}
	}
	t.Logf("厂商模板 fail-closed 如实触发: %v", err)
}
