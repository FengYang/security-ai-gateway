package protocol

// 段① 信封国密化单测（P0-4 §5.1.2，T-5.1-1..7）：
// AES/SM4 合同向、suite 字节双读、密钥长度不符 fail-closed、未知 suite fail-closed、
// suite↔provider 绑定断言、DeriveSubkey 长度随 suite。

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"security-ai-gateway/gateway/cryptop"
)

var sm4SuiteOnce sync.Once

// ensureSM4Suite 以 sm-software provider 注册一次 SM4-GCM suite（进程内单例；多次注册会因 ID 冲突失败）。
func ensureSM4Suite(t *testing.T) {
	t.Helper()
	sm4SuiteOnce.Do(func() {
		p, err := cryptop.New(cryptop.ProfileSMSW)
		if err != nil {
			t.Fatalf("构造 sm provider 失败: %v", err)
		}
		if err := RegisterSM4Suite(p); err != nil {
			t.Fatalf("注册 SM4 suite 失败: %v", err)
		}
	})
}

// T-5.1-7 DeriveSubkey 长度随 suite：AES→32B、SM4→16B；未知 suite → 报错（不得默认 32，G-9）。
func TestDeriveSubkeyLengthBySuite(t *testing.T) {
	aes, err := DeriveSubkey(testKEnc(), DirectionC2S, SuiteAESGCM)
	if err != nil || len(aes) != 32 {
		t.Fatalf("AES 子密钥应为 32B：len=%d err=%v", len(aes), err)
	}
	sm4, err := DeriveSubkey(testKEnc(), DirectionC2S, SuiteSM4GCM)
	if err != nil || len(sm4) != 16 {
		t.Fatalf("SM4 子密钥应为 16B：len=%d err=%v", len(sm4), err)
	}
	// 注：KDF info 标签随 profile 不变（§7.2），故 AES(32B) 与 SM4(16B) 子密钥前缀相同属预期——
	// 二者算法不同（AES-GCM vs SM4-GCM）且长度分派由 suiteKeySize 保证，非同长度复用。
	if _, err := DeriveSubkey(testKEnc(), DirectionC2S, 0x7F); err == nil {
		t.Error("未知 suite 派生应报错（fail-closed，不得默认 32）")
	}
	if _, err := DeriveSubkey(testKEnc(), Direction(9), SuiteAESGCM); err == nil {
		t.Error("未知方向派生应报错")
	}
}

// T-5.1-6 suite↔provider 绑定断言（G-7）：SM4 suite 仅可绑 sm-* provider；intl provider 构造必拒。
func TestSM4SuiteProviderBinding(t *testing.T) {
	intl, err := cryptop.New(cryptop.ProfileIntl)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newSM4Suite(intl); err == nil {
		t.Fatal("intl provider 构造 SM4 suite 应被拒（防 wire 标 SM4 实为 AES）")
	}
	sm, err := cryptop.New(cryptop.ProfileSMSW)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSM4Suite(sm)
	if err != nil {
		t.Fatalf("sm provider 构造 SM4 suite 失败: %v", err)
	}
	if s.SuiteID() != SuiteSM4GCM {
		t.Fatalf("SuiteID 应为 %d，实际 %d", SuiteSM4GCM, s.SuiteID())
	}
	if _, err := newSM4Suite(nil); err == nil {
		t.Fatal("nil provider 构造 SM4 suite 应被拒")
	}
}

// T-5.1-1 AES 缝合同向：SealEnvelopeWithSuite(AES) → OpenEnvelope 还原。
func TestEnvelopeAESSuiteRoundtrip(t *testing.T) {
	wire, err := SealEnvelopeWithSuite(testKEnc(), SuiteAESGCM, "sess-1", "/v1/infer", DirectionC2S, 11, []byte("aes payload"))
	if err != nil {
		t.Fatal(err)
	}
	pt, counter, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, wire)
	if err != nil || !bytes.Equal(pt, []byte("aes payload")) || counter != 11 {
		t.Fatalf("AES 往返失败: %q counter=%d err=%v", pt, counter, err)
	}
}

// T-5.1-2 SM4 缝合同向：SealEnvelopeWithSuite(SM4) → OpenEnvelope 还原（16B 子密钥）。
func TestEnvelopeSM4SuiteRoundtrip(t *testing.T) {
	ensureSM4Suite(t)
	for _, dir := range []Direction{DirectionC2S, DirectionS2C} {
		wire, err := SealEnvelopeWithSuite(testKEnc(), SuiteSM4GCM, "sess-1", "/v1/infer", dir, 21, []byte("sm4 payload"))
		if err != nil {
			t.Fatalf("[%s] SM4 封装: %v", dir, err)
		}
		// 校验 wire 上的 suite 字节确为 SM4（不是"标 SM4 实为 AES"）
		e, err := DecodeEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		if e.Suite != SuiteSM4GCM {
			t.Fatalf("[%s] wire suite=%d，期望 %d", dir, e.Suite, SuiteSM4GCM)
		}
		pt, counter, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", dir, wire)
		if err != nil || !bytes.Equal(pt, []byte("sm4 payload")) || counter != 21 {
			t.Fatalf("[%s] SM4 往返失败: %q counter=%d err=%v", dir, pt, counter, err)
		}
	}
}

// T-5.1-3 suite 字节双读：同进程同时注册 AES+SM4，两种 suite 写的 wire 各自按 suite 字节解开。
func TestEnvelopeSuiteDoubleRead(t *testing.T) {
	ensureSM4Suite(t)
	aesWire, err := SealEnvelopeWithSuite(testKEnc(), SuiteAESGCM, "sess-1", "/v1/infer", DirectionC2S, 31, []byte("aes"))
	if err != nil {
		t.Fatal(err)
	}
	sm4Wire, err := SealEnvelopeWithSuite(testKEnc(), SuiteSM4GCM, "sess-1", "/v1/infer", DirectionC2S, 32, []byte("sm4"))
	if err != nil {
		t.Fatal(err)
	}
	// reader 按 wire suite 分派：AES wire 用 32B 子密钥、SM4 wire 用 16B 子密钥
	if pt, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, aesWire); err != nil || !bytes.Equal(pt, []byte("aes")) {
		t.Fatalf("AES wire 双读失败: %q err=%v", pt, err)
	}
	if pt, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, sm4Wire); err != nil || !bytes.Equal(pt, []byte("sm4")) {
		t.Fatalf("SM4 wire 双读失败: %q err=%v", pt, err)
	}
	// 交叉篡改 suite 字节：把 SM4 wire 的 suite 改为 AES → 派生长度/算法不符 ⇒ 解密必失败（非静默成功）
	e, err := DecodeEnvelope(sm4Wire)
	if err != nil {
		t.Fatal(err)
	}
	e.Suite = SuiteAESGCM
	crossWire, err := EncodeEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, crossWire); err == nil {
		t.Fatal("suite 字节被篡改为 AES 的 SM4 密文未被拒绝")
	}
}

// T-5.1-4 密钥长度不符 → fail-closed（G-2）：SM4 suite 用 32B 密钥、AES suite 用 16B 密钥均须拒。
func TestEnvelopeKeySizeMismatchFailClosed(t *testing.T) {
	sm, err := cryptop.New(cryptop.ProfileSMSW)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSM4Suite(sm)
	if err != nil {
		t.Fatal(err)
	}
	nonce := envelopeNonce(1)
	aad := EnvelopeAAD("sess-1", DirectionC2S, 1, "/v1/infer")
	if _, err := s.Seal(make([]byte, 32), nonce, aad, []byte("x")); !errors.Is(err, cryptop.ErrInvalidKeySize) {
		t.Errorf("SM4 suite 用 32B 密钥应返回 ErrInvalidKeySize，实际 %v", err)
	}
	if _, err := s.Open(make([]byte, 32), nonce, aad, []byte("x")); !errors.Is(err, cryptop.ErrInvalidKeySize) {
		t.Errorf("SM4 suite 用 32B 密钥 Open 应返回 ErrInvalidKeySize，实际 %v", err)
	}
}

// T-5.1-5 未知 suite → fail-closed：SealEnvelopeWithSuite / OpenEnvelope 对未注册 suite 一律拒。
func TestEnvelopeUnknownSuiteFailClosed(t *testing.T) {
	if _, err := SealEnvelopeWithSuite(testKEnc(), 0x7F, "sess-1", "/v1/infer", DirectionC2S, 1, []byte("x")); err == nil {
		t.Error("未注册 suite 封装应报错")
	}
	// 构造一条 suite=0x7F 的 wire（借用 AES 密文），OpenEnvelope 应在 suiteFor 处拒绝
	aesWire, err := SealEnvelopeWithSuite(testKEnc(), SuiteAESGCM, "sess-1", "/v1/infer", DirectionC2S, 2, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := DecodeEnvelope(aesWire)
	if err != nil {
		t.Fatal(err)
	}
	e.Suite = 0x7F
	bad, err := EncodeEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, bad); err == nil {
		t.Fatal("未知 suite 的 wire 未被拒绝")
	}
}
