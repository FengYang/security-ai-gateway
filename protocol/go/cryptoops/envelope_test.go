package cryptoops

// 段① 信封**密码求值**单测（P0-4 §5.4.5 拆包：由 `protocol/go` 下沉）。
//
// 覆盖：AES/SM4 往返、篡改拒绝、方向/上下文绑定、版本/套件拒绝、国密接缝注册、
// suite↔provider 绑定断言、DeriveSubkey 长度随 suite、密钥长度不符 fail-closed。
// framing-only 测试（计数器窗口/流序号）留 `protocol/go`。

import (
	"bytes"
	"errors"
	"sync"
	"testing"

	"security-ai-gateway/gateway/cryptop"
	protocol "security-ai-gateway/protocol/go"
)

func testKEnc() []byte { return []byte("test-k-enc-32-bytes-key-materia") } // 32 字节

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

func TestEnvelopeRoundtrip(t *testing.T) {
	for _, dir := range []protocol.Direction{protocol.DirectionC2S, protocol.DirectionS2C} {
		wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", dir, 7, []byte("hello envelope"))
		if err != nil {
			t.Fatalf("[%s] SealEnvelope: %v", dir, err)
		}
		pt, counter, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", dir, wire)
		if err != nil {
			t.Fatalf("[%s] OpenEnvelope: %v", dir, err)
		}
		if !bytes.Equal(pt, []byte("hello envelope")) {
			t.Fatalf("[%s] 明文不一致: %q", dir, pt)
		}
		if counter != 7 {
			t.Fatalf("[%s] 计数器不一致: %d", dir, counter)
		}
	}
	// 空明文合法（如心跳/结束分片）
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, wire); err != nil {
		t.Fatalf("空明文信封解密失败: %v", err)
	}
}

func TestEnvelopeTamperRejected(t *testing.T) {
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, 3, []byte("secret payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 篡改密文尾部（GCM tag）
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, tampered); err == nil {
		t.Fatal("篡改 tag 后解密未被拒绝")
	}
	// 篡改密文中部
	tampered2 := append([]byte(nil), wire...)
	tampered2[len(tampered2)/2] ^= 0x01
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, tampered2); err == nil {
		t.Fatal("篡改密文后解密未被拒绝")
	}
	// 篡改计数器（nonce/AAD 随之失效）；wire 布局 version(1)+suite(1)+direction(1)+counter(8)
	tampered3 := append([]byte(nil), wire...)
	tampered3[3] ^= 0x01 // counter 首字节
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, tampered3); err == nil {
		t.Fatal("篡改计数器后解密未被拒绝")
	}
}

func TestEnvelopeDirectionMismatch(t *testing.T) {
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, 5, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 以 s2c 方向解密 c2s 信封：方向校验直接拒绝
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionS2C, wire); err == nil {
		t.Fatal("方向不匹配未被拒绝")
	}
	// 方向子密钥独立（c2s/s2c 派生结果不同）
	kc2s, _ := DeriveSubkey(testKEnc(), protocol.DirectionC2S, protocol.SuiteAESGCM)
	ks2c, _ := DeriveSubkey(testKEnc(), protocol.DirectionS2C, protocol.SuiteAESGCM)
	if bytes.Equal(kc2s, ks2c) {
		t.Fatal("方向子密钥不应相同")
	}
}

func TestEnvelopeContextBinding(t *testing.T) {
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, 9, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 错误 sessionID（跨会话重放）
	if _, _, err := OpenEnvelope(testKEnc(), "sess-2", "/v1/infer", protocol.DirectionC2S, wire); err == nil {
		t.Fatal("跨会话重放未被拒绝")
	}
	// 错误 endpoint（跨端点重放）
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/key/issue", protocol.DirectionC2S, wire); err == nil {
		t.Fatal("跨端点重放未被拒绝")
	}
	// 错误 K_enc
	if _, _, err := OpenEnvelope([]byte("wrong-k-enc-32-bytes-key-materi"), "sess-1", "/v1/infer", protocol.DirectionC2S, wire); err == nil {
		t.Fatal("错误会话密钥未被拒绝")
	}
}

func TestEnvelopeVersionAndSuiteRejected(t *testing.T) {
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, 2, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 版本不匹配：wire 首字节为 version varint
	tampered := append([]byte(nil), wire...)
	tampered[0] = 0x02
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, tampered); err == nil {
		t.Fatal("版本不匹配未被拒绝")
	}
	// 未知套件 ID（未注册的国密/其他套件显式拒绝）
	e, err := protocol.DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	e.Suite = 0xEE
	bad, err := protocol.EncodeEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, bad); err == nil {
		t.Fatal("未知套件未被拒绝")
	}
	// 尾部冗余字节拒绝
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, append(append([]byte(nil), wire...), 0x00)); err == nil {
		t.Fatal("尾部冗余字节未被拒绝")
	}
}

// xorTestSuite 非密码学安全的测试套件，仅验证 CryptoSuite 国密接缝可插拔。
type xorTestSuite struct{}

func (xorTestSuite) SuiteID() byte { return 0xEE }

func (xorTestSuite) Seal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	return xorBytes(key, nonce, plaintext), nil
}

func (xorTestSuite) Open(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	return xorBytes(key, nonce, ciphertext), nil
}

func xorBytes(key, nonce, data []byte) []byte {
	out := make([]byte, len(data))
	for i := range data {
		out[i] = data[i] ^ key[i%len(key)] ^ nonce[i%len(nonce)]
	}
	return out
}

func TestCryptoSuiteSeam(t *testing.T) {
	if err := RegisterSuite(xorTestSuite{}); err != nil {
		t.Fatalf("套件注册失败: %v", err)
	}
	if err := RegisterSuite(xorTestSuite{}); err == nil {
		t.Fatal("重复注册未被拒绝")
	}
	// 注册表可解析已注册套件
	if _, err := suiteFor(0xEE); err != nil {
		t.Fatalf("suiteFor 未解析已注册套件: %v", err)
	}
	// 接缝套件直接往返（v1.2 起 DeriveSubkey 长度按 suiteKeySize 闭合集分派：
	// AES→32 / SM4→16；故 0xEE 这类测试套件的密钥用 AES 长度派生，验套件自身 Seal/Open 接缝）
	subkey, err := DeriveSubkey(testKEnc(), protocol.DirectionC2S, protocol.SuiteAESGCM)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := xorTestSuite{}.Seal(subkey, protocol.EnvelopeNonce(4), protocol.EnvelopeAAD("sess-1", protocol.DirectionC2S, 4, "/v1/infer"), []byte("sm4-placeholder"))
	if err != nil {
		t.Fatal(err)
	}
	pt, err := xorTestSuite{}.Open(subkey, protocol.EnvelopeNonce(4), protocol.EnvelopeAAD("sess-1", protocol.DirectionC2S, 4, "/v1/infer"), ct)
	if err != nil || !bytes.Equal(pt, []byte("sm4-placeholder")) {
		t.Fatalf("接缝套件往返不一致: %q err=%v", pt, err)
	}
	// 非闭合集 suite（0xEE 已注册但 suiteKeySize 不识）经 OpenEnvelope 派生失败 ⇒ fail-closed
	wire, err := protocol.EncodeEnvelope(&protocol.Envelope{Version: protocol.EnvelopeVersion, Suite: 0xEE, Direction: protocol.DirectionC2S, Counter: 4, Ciphertext: ct})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, wire); err == nil {
		t.Fatal("非闭合集 suite 的信封未被拒绝（应 fail-closed）")
	}
}

// T-5.1-7 DeriveSubkey 长度随 suite：AES→32B、SM4→16B；未知 suite → 报错（不得默认 32，G-9）。
func TestDeriveSubkeyLengthBySuite(t *testing.T) {
	aes, err := DeriveSubkey(testKEnc(), protocol.DirectionC2S, protocol.SuiteAESGCM)
	if err != nil || len(aes) != 32 {
		t.Fatalf("AES 子密钥应为 32B：len=%d err=%v", len(aes), err)
	}
	sm4, err := DeriveSubkey(testKEnc(), protocol.DirectionC2S, protocol.SuiteSM4GCM)
	if err != nil || len(sm4) != 16 {
		t.Fatalf("SM4 子密钥应为 16B：len=%d err=%v", len(sm4), err)
	}
	// 注：KDF info 标签随 profile 不变（§7.2），故 AES(32B) 与 SM4(16B) 子密钥前缀相同属预期——
	// 二者算法不同（AES-GCM vs SM4-GCM）且长度分派由 suiteKeySize 保证，非同长度复用。
	if _, err := DeriveSubkey(testKEnc(), protocol.DirectionC2S, 0x7F); err == nil {
		t.Error("未知 suite 派生应报错（fail-closed，不得默认 32）")
	}
	if _, err := DeriveSubkey(testKEnc(), protocol.Direction(9), protocol.SuiteAESGCM); err == nil {
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
	if s.SuiteID() != protocol.SuiteSM4GCM {
		t.Fatalf("SuiteID 应为 %d，实际 %d", protocol.SuiteSM4GCM, s.SuiteID())
	}
	if _, err := newSM4Suite(nil); err == nil {
		t.Fatal("nil provider 构造 SM4 suite 应被拒")
	}
}

// T-5.1-1 AES 缝合同向：SealEnvelopeWithSuite(AES) → OpenEnvelope 还原。
func TestEnvelopeAESSuiteRoundtrip(t *testing.T) {
	wire, err := SealEnvelopeWithSuite(testKEnc(), protocol.SuiteAESGCM, "sess-1", "/v1/infer", protocol.DirectionC2S, 11, []byte("aes payload"))
	if err != nil {
		t.Fatal(err)
	}
	pt, counter, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, wire)
	if err != nil || !bytes.Equal(pt, []byte("aes payload")) || counter != 11 {
		t.Fatalf("AES 往返失败: %q counter=%d err=%v", pt, counter, err)
	}
}

// T-5.1-2 SM4 缝合同向：SealEnvelopeWithSuite(SM4) → OpenEnvelope 还原（16B 子密钥）。
func TestEnvelopeSM4SuiteRoundtrip(t *testing.T) {
	ensureSM4Suite(t)
	for _, dir := range []protocol.Direction{protocol.DirectionC2S, protocol.DirectionS2C} {
		wire, err := SealEnvelopeWithSuite(testKEnc(), protocol.SuiteSM4GCM, "sess-1", "/v1/infer", dir, 21, []byte("sm4 payload"))
		if err != nil {
			t.Fatalf("[%s] SM4 封装: %v", dir, err)
		}
		// 校验 wire 上的 suite 字节确为 SM4（不是"标 SM4 实为 AES"）
		e, err := protocol.DecodeEnvelope(wire)
		if err != nil {
			t.Fatal(err)
		}
		if e.Suite != protocol.SuiteSM4GCM {
			t.Fatalf("[%s] wire suite=%d，期望 %d", dir, e.Suite, protocol.SuiteSM4GCM)
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
	aesWire, err := SealEnvelopeWithSuite(testKEnc(), protocol.SuiteAESGCM, "sess-1", "/v1/infer", protocol.DirectionC2S, 31, []byte("aes"))
	if err != nil {
		t.Fatal(err)
	}
	sm4Wire, err := SealEnvelopeWithSuite(testKEnc(), protocol.SuiteSM4GCM, "sess-1", "/v1/infer", protocol.DirectionC2S, 32, []byte("sm4"))
	if err != nil {
		t.Fatal(err)
	}
	// reader 按 wire suite 分派：AES wire 用 32B 子密钥、SM4 wire 用 16B 子密钥
	if pt, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, aesWire); err != nil || !bytes.Equal(pt, []byte("aes")) {
		t.Fatalf("AES wire 双读失败: %q err=%v", pt, err)
	}
	if pt, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, sm4Wire); err != nil || !bytes.Equal(pt, []byte("sm4")) {
		t.Fatalf("SM4 wire 双读失败: %q err=%v", pt, err)
	}
	// 交叉篡改 suite 字节：把 SM4 wire 的 suite 改为 AES → 派生长度/算法不符 ⇒ 解密必失败（非静默成功）
	e, err := protocol.DecodeEnvelope(sm4Wire)
	if err != nil {
		t.Fatal(err)
	}
	e.Suite = protocol.SuiteAESGCM
	crossWire, err := protocol.EncodeEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, crossWire); err == nil {
		t.Fatal("suite 字节被篡改为 AES 的 SM4 密文未被拒绝")
	}
}

// T-5.1-4 密钥长度不符 → fail-closed（G-2）：SM4 suite 用 32B 密钥须拒。
func TestEnvelopeKeySizeMismatchFailClosed(t *testing.T) {
	sm, err := cryptop.New(cryptop.ProfileSMSW)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSM4Suite(sm)
	if err != nil {
		t.Fatal(err)
	}
	nonce := protocol.EnvelopeNonce(1)
	aad := protocol.EnvelopeAAD("sess-1", protocol.DirectionC2S, 1, "/v1/infer")
	if _, err := s.Seal(make([]byte, 32), nonce, aad, []byte("x")); !errors.Is(err, cryptop.ErrInvalidKeySize) {
		t.Errorf("SM4 suite 用 32B 密钥应返回 ErrInvalidKeySize，实际 %v", err)
	}
	if _, err := s.Open(make([]byte, 32), nonce, aad, []byte("x")); !errors.Is(err, cryptop.ErrInvalidKeySize) {
		t.Errorf("SM4 suite 用 32B 密钥 Open 应返回 ErrInvalidKeySize，实际 %v", err)
	}
}

// T-5.1-5 未知 suite → fail-closed：SealEnvelopeWithSuite / OpenEnvelope 对未注册 suite 一律拒。
func TestEnvelopeUnknownSuiteFailClosed(t *testing.T) {
	if _, err := SealEnvelopeWithSuite(testKEnc(), 0x7F, "sess-1", "/v1/infer", protocol.DirectionC2S, 1, []byte("x")); err == nil {
		t.Error("未注册 suite 封装应报错")
	}
	// 构造一条 suite=0x7F 的 wire（借用 AES 密文），OpenEnvelope 应在 suiteFor 处拒绝
	aesWire, err := SealEnvelopeWithSuite(testKEnc(), protocol.SuiteAESGCM, "sess-1", "/v1/infer", protocol.DirectionC2S, 2, []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	e, err := protocol.DecodeEnvelope(aesWire)
	if err != nil {
		t.Fatal(err)
	}
	e.Suite = 0x7F
	bad, err := protocol.EncodeEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", protocol.DirectionC2S, bad); err == nil {
		t.Fatal("未知 suite 的 wire 未被拒绝")
	}
}
