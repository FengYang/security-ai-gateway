package cryptop

// module_test.go —— moduleProvider 测试（P1-5 M2/§6.2）。
//
// 覆盖：20 方法映射语义、KAT 跨档交叉验签（V-4：SM2 交叉验签、SM3 逐字节）、
// UID 配置（GM2-06）、New() 生产门禁（mock 拒绝/厂商缺失 fail-closed）、
// ComplianceNote 如实标注（P4）、Keystream 软件例外路径。

import (
	"bytes"
	"strings"
	"testing"

	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

// newTestModuleProvider mock 后端 + 适配层功能验证 Provider。
func newTestModuleProvider(t *testing.T) (Provider, *cryptopmodule.MockBackend) {
	t.Helper()
	b := cryptopmodule.NewMockBackend()
	cfg := cryptopmodule.DefaultConfig()
	cfg.Backend = cryptopmodule.BackendMock
	cfg.MaxSessions = 4
	cfg.SessionQueueSize = 8
	p, err := NewModuleProviderWithBackend(b, cfg)
	if err != nil {
		t.Fatalf("NewModuleProviderWithBackend: %v", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	return p, b
}

func TestModuleProviderProfileAndSizes(t *testing.T) {
	p, _ := newTestModuleProvider(t)
	if p.Profile() != ProfileSMModule {
		t.Fatalf("Profile=%q, want sm-module", p.Profile())
	}
	if p.SymmetricKeySize() != 16 || p.NonceSize() != 12 || p.HashSize() != 32 {
		t.Fatalf("尺寸方法与 sm 档不一致: %d/%d/%d", p.SymmetricKeySize(), p.NonceSize(), p.HashSize())
	}
	// P4 如实标注：mock 后端必须显式声明不满足密评。
	note := p.ComplianceNote()
	if !strings.Contains(note, "mock") || !strings.Contains(note, "不满足密评") {
		t.Fatalf("mock 后端 ComplianceNote 未如实标注: %q", note)
	}
}

func TestModuleProviderSealOpenRoundtrip(t *testing.T) {
	p, b := newTestModuleProvider(t)
	kek, err := b.GenerateKey("sm4-128", "kek")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	nonce := bytes.Repeat([]byte{0x0A}, 12)
	pt := []byte("模块档信封往返")
	aad := []byte("cryptop/envelope/v2")
	ct, err := p.Seal(kek, nonce, pt, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	got, err := p.Open(kek, nonce, ct, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, pt) {
		t.Fatalf("Seal/Open 往返不一致: %q", got)
	}
	// SealWithNonce：nonce 由模块 Rand 生成。
	n2, ct2, err := p.SealWithNonce(kek, pt, aad)
	if err != nil {
		t.Fatalf("SealWithNonce: %v", err)
	}
	if len(n2) != 12 {
		t.Fatalf("nonce 长度=%d, want 12", len(n2))
	}
	got2, err := p.Open(kek, n2, ct2, aad)
	if err != nil || !bytes.Equal(got2, pt) {
		t.Fatalf("SealWithNonce 往返失败: %v %q", err, got2)
	}
}

// TestModuleProviderKATCross V-4 跨档交叉验签：module 与 sm-software 互验。
func TestModuleProviderKATCross(t *testing.T) {
	mp, _ := newTestModuleProvider(t)
	sw := newSMProvider()

	// SM3 逐字节一致。
	msg := []byte("kat-cross-国密")
	if !bytes.Equal(mp.Hash(msg), sw.Hash(msg)) {
		t.Fatal("Hash 跨档不一致")
	}
	// SM2 交叉验签（默认 uid）：module 签→软件验；软件签→module 验。
	privTok, pub, err := mp.GenerateSignKeyPair()
	if err != nil {
		t.Fatalf("GenerateSignKeyPair: %v", err)
	}
	sig, err := mp.Sign(privTok, msg)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sw.Verify(pub, msg, sig); err != nil {
		t.Fatalf("软件档验 module 签名失败: %v", err)
	}
	swPriv, swPub, err := sw.GenerateSignKeyPair()
	if err != nil {
		t.Fatalf("sw.GenerateSignKeyPair: %v", err)
	}
	swSig, err := sw.Sign(swPriv, msg)
	if err != nil {
		t.Fatalf("sw.Sign: %v", err)
	}
	if err := mp.Verify(swPub, msg, swSig); err != nil {
		t.Fatalf("module 验软件档签名失败: %v", err)
	}
	// ECDH 跨档一致（双方各一把，交叉协商）。
	mPriv, mPub, err := mp.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("GenerateECDHKeyPair: %v", err)
	}
	sPriv, sPub, err := sw.GenerateECDHKeyPair()
	if err != nil {
		t.Fatalf("sw.GenerateECDHKeyPair: %v", err)
	}
	ss1, err := mp.ECDH(mPriv, sPub)
	if err != nil {
		t.Fatalf("mp.ECDH: %v", err)
	}
	ss2, err := sw.ECDH(sPriv, mPub)
	if err != nil {
		t.Fatalf("sw.ECDH: %v", err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("ECDH 跨档共享秘密不一致")
	}
	// Keystream 软件例外路径：与 sm-software 逐字节一致（同 key/domain/counter）。
	key := bytes.Repeat([]byte{0x2B}, 16)
	ks1, err := mp.Keystream(key, []byte("mask"), 0, 64)
	if err != nil {
		t.Fatalf("mp.Keystream: %v", err)
	}
	ks2, err := sw.Keystream(key, []byte("mask"), 0, 64)
	if err != nil {
		t.Fatalf("sw.Keystream: %v", err)
	}
	if !bytes.Equal(ks1, ks2) {
		t.Fatal("Keystream 跨档不一致")
	}
}

// TestModuleProviderUIDConfig GM2-06：module_sm2_uid 配置生效（与软件档默认 UID 互通）。
func TestModuleProviderUIDConfig(t *testing.T) {
	b := cryptopmodule.NewMockBackend()
	cfg := cryptopmodule.DefaultConfig()
	cfg.Backend = cryptopmodule.BackendMock
	cfg.SM2UID = "tenant-a"
	p, err := NewModuleProviderWithBackend(b, cfg)
	if err != nil {
		t.Fatalf("NewModuleProviderWithBackend: %v", err)
	}
	defer b.Close()
	sw := newSMProvider() // 软件档恒用默认 UID

	privTok, pub, err := p.GenerateSignKeyPair()
	if err != nil {
		t.Fatalf("GenerateSignKeyPair: %v", err)
	}
	sig, err := p.Sign(privTok, []byte("uid-test"))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// 配置 uid 签名 → 软件档（默认 uid）验签应失败（uid 隔离）。
	if err := sw.Verify(pub, []byte("uid-test"), sig); err == nil {
		t.Fatal("异 uid 验签应失败（GM2-06）")
	}
	// 同 uid（module 自身 Verify 用同配置）应通过。
	if err := p.Verify(pub, []byte("uid-test"), sig); err != nil {
		t.Fatalf("同 uid 验签应通过: %v", err)
	}
}

// TestModuleProviderFailClosed New(ProfileSMModule) 生产门禁（C-3/P4）。
func TestModuleProviderFailClosed(t *testing.T) {
	// 无厂商配置（默认 sdf，无库路径）→ 错误。
	if _, err := New(ProfileSMModule); err == nil {
		t.Fatal("无厂商配置应 fail-closed")
	}
	// mock 后端在生产路径被拒。
	t.Setenv("MODULE_BACKEND", "mock")
	_, err := New(ProfileSMModule)
	if err == nil {
		t.Fatal("生产路径应拒绝 mock 后端")
	}
	if !strings.Contains(err.Error(), "mock") {
		t.Fatalf("错误信息应说明 mock 被拒: %v", err)
	}
}

// TestModuleProviderBackendErrorPropagation 后端故障经 Provider 传播（不静默）。
func TestModuleProviderBackendErrorPropagation(t *testing.T) {
	p, b := newTestModuleProvider(t)
	kek, _ := b.GenerateKey("sm4-128", "kek")
	b.FailSeal = cryptopmodule.ErrModuleUnavailable
	if _, err := p.Seal(kek, bytes.Repeat([]byte{1}, 12), []byte("x"), nil); err == nil {
		t.Fatal("后端 Seal 故障应传播")
	}
	b.FailSeal = nil
	b.FailRand = cryptopmodule.ErrModuleUnavailable
	if _, err := p.Rand(16); err == nil {
		t.Fatal("后端 Rand 故障应传播")
	}
	b.FailRand = nil
	// 恢复后可用（无粘滞故障）。
	if _, err := p.Seal(kek, bytes.Repeat([]byte{1}, 12), []byte("x"), nil); err != nil {
		t.Fatalf("故障清除后应恢复: %v", err)
	}
}

// TestModuleProviderWrapUnwrap 跨档兼容（V-6 双读语义的 provider 级验证）。
func TestModuleProviderWrapUnwrap(t *testing.T) {
	mp, b := newTestModuleProvider(t)
	sw := newSMProvider()
	kek, _ := b.GenerateKey("sm4-128", "kek")
	dek := bytes.Repeat([]byte{0x5A}, 16)
	wrapped, err := mp.WrapKey(kek, dek)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	// module 封装 → module 解封。
	got, err := mp.UnwrapKey(kek, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("module Wrap/Unwrap 往返失败: %v", err)
	}
	// 篡改必须失败。
	bad := append([]byte(nil), wrapped...)
	bad[len(bad)-1] ^= 0xFF
	if _, err := mp.UnwrapKey(kek, bad); err == nil {
		t.Fatal("篡改密文解封应失败")
	}
	// 软件档同构性：相同 kek 字节下 wrapped 形态一致（nonce||ct）。
	swKek := bytes.Repeat([]byte{0x11}, 16)
	swWrapped, err := sw.WrapKey(swKek, dek)
	if err != nil {
		t.Fatalf("sw.WrapKey: %v", err)
	}
	if len(swWrapped) != len(wrapped) {
		t.Fatalf("wrapped 长度跨档不一致: %d vs %d", len(swWrapped), len(wrapped))
	}
}
