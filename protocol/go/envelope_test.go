package protocol

// P1a 信封单测：往返、篡改拒绝、方向/上下文绑定、反重放窗口、
// SSE 严格序号、版本/套件拒绝、国密接缝注册。

import (
	"bytes"
	"testing"
)

func testKEnc() []byte { return []byte("test-k-enc-32-bytes-key-materia") } // 32 字节

func TestEnvelopeRoundtrip(t *testing.T) {
	for _, dir := range []Direction{DirectionC2S, DirectionS2C} {
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
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, wire); err != nil {
		t.Fatalf("空明文信封解密失败: %v", err)
	}
}

func TestEnvelopeTamperRejected(t *testing.T) {
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, 3, []byte("secret payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 篡改密文尾部（GCM tag）
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 0xFF
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, tampered); err == nil {
		t.Fatal("篡改 tag 后解密未被拒绝")
	}
	// 篡改密文中部
	tampered2 := append([]byte(nil), wire...)
	tampered2[len(tampered2)/2] ^= 0x01
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, tampered2); err == nil {
		t.Fatal("篡改密文后解密未被拒绝")
	}
	// 篡改计数器（nonce/AAD 随之失效）；wire 布局 version(1)+suite(1)+direction(1)+counter(8)
	tampered3 := append([]byte(nil), wire...)
	tampered3[3] ^= 0x01 // counter 首字节
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, tampered3); err == nil {
		t.Fatal("篡改计数器后解密未被拒绝")
	}
}

func TestEnvelopeDirectionMismatch(t *testing.T) {
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, 5, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 以 s2c 方向解密 c2s 信封：方向校验直接拒绝
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionS2C, wire); err == nil {
		t.Fatal("方向不匹配未被拒绝")
	}
	// 方向子密钥独立（c2s/s2c 派生结果不同）
	kc2s, _ := DeriveSubkey(testKEnc(), DirectionC2S)
	ks2c, _ := DeriveSubkey(testKEnc(), DirectionS2C)
	if bytes.Equal(kc2s, ks2c) {
		t.Fatal("方向子密钥不应相同")
	}
}

func TestEnvelopeContextBinding(t *testing.T) {
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, 9, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 错误 sessionID（跨会话重放）
	if _, _, err := OpenEnvelope(testKEnc(), "sess-2", "/v1/infer", DirectionC2S, wire); err == nil {
		t.Fatal("跨会话重放未被拒绝")
	}
	// 错误 endpoint（跨端点重放）
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/key/issue", DirectionC2S, wire); err == nil {
		t.Fatal("跨端点重放未被拒绝")
	}
	// 错误 K_enc
	if _, _, err := OpenEnvelope([]byte("wrong-k-enc-32-bytes-key-materi"), "sess-1", "/v1/infer", DirectionC2S, wire); err == nil {
		t.Fatal("错误会话密钥未被拒绝")
	}
}

func TestEnvelopeVersionAndSuiteRejected(t *testing.T) {
	wire, err := SealEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, 2, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	// 版本不匹配：wire 首字节为 version varint
	tampered := append([]byte(nil), wire...)
	tampered[0] = 0x02
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, tampered); err == nil {
		t.Fatal("版本不匹配未被拒绝")
	}
	// 未知套件 ID（未注册的国密/其他套件显式拒绝）
	e, err := DecodeEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	e.Suite = 0xEE
	bad, err := EncodeEnvelope(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, bad); err == nil {
		t.Fatal("未知套件未被拒绝")
	}
	// 尾部冗余字节拒绝
	if _, _, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, append(append([]byte(nil), wire...), 0x00)); err == nil {
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
	subkey, err := DeriveSubkey(testKEnc(), DirectionC2S)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := xorTestSuite{}.Seal(subkey, envelopeNonce(4), EnvelopeAAD("sess-1", DirectionC2S, 4, "/v1/infer"), []byte("sm4-placeholder"))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := EncodeEnvelope(&Envelope{Version: EnvelopeVersion, Suite: 0xEE, Direction: DirectionC2S, Counter: 4, Ciphertext: ct})
	if err != nil {
		t.Fatal(err)
	}
	// OpenEnvelope 按 wire 套件 ID 分派到已注册套件
	pt, counter, err := OpenEnvelope(testKEnc(), "sess-1", "/v1/infer", DirectionC2S, wire)
	if err != nil {
		t.Fatalf("接缝套件解密失败: %v", err)
	}
	if !bytes.Equal(pt, []byte("sm4-placeholder")) || counter != 4 {
		t.Fatalf("接缝套件往返不一致: %q counter=%d", pt, counter)
	}
}

func TestCounterWindow(t *testing.T) {
	// 期望决策序列与 cross_test.py 中 Python CounterWindow 完全一致（跨语言一致性）
	cases := []struct {
		counter uint64
		accept  bool
	}{
		{1, true},   // 窗口启动
		{2, true},
		{3, true},
		{2, false},  // 重放（窗口内重复）
		{5, true},   // 跳号前进
		{4, true},   // 有界乱序容忍
		{4, false},  // 乱序后重放
		{10, true},
		{12, true},
		{11, true},  // 有界乱序
		{6, true},   // 窗口内未见过的旧计数器（合法新值）
		{100, true}, // 大步前进（窗口清空重置）
		{100, false},
		{12, false}, // 落后窗口（highest-100 距离 88 ≥ 64）
	}
	var w CounterWindow
	for i, c := range cases {
		err := w.Check(c.counter)
		if (err == nil) != c.accept {
			t.Fatalf("计数器 %d 期望 accept=%v，实际 err=%v（第 %d 例）", c.counter, c.accept, err, i+1)
		}
	}
}

func TestCheckStreamSequence(t *testing.T) {
	if err := CheckStreamSequence(0, 1); err != nil {
		t.Fatalf("合法首分片被拒绝: %v", err)
	}
	if err := CheckStreamSequence(1, 2); err != nil {
		t.Fatalf("合法递增被拒绝: %v", err)
	}
	if err := CheckStreamSequence(1, 1); err == nil {
		t.Fatal("重复分片序号未被拒绝")
	}
	if err := CheckStreamSequence(1, 3); err == nil {
		t.Fatal("跳号分片未被拒绝")
	}
	if err := CheckStreamSequence(2, 1); err == nil {
		t.Fatal("回退分片序号未被拒绝")
	}
}
