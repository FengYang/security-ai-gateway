package keymgmt

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"security-ai-gateway/cipher/paillier"
)

func testKeys(t *testing.T) (*paillier.PublicKey, *paillier.PrivateKey) {
	t.Helper()
	pub, priv, err := paillier.GenerateKey(rand.Reader, paillier.MinBits)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func TestMarshalPublicKeyRoundTrip(t *testing.T) {
	pub, _ := testKeys(t)
	data, err := MarshalPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalPublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(pub.N) != 0 || got.G.Cmp(pub.G) != 0 {
		t.Fatal("公钥往返不一致")
	}
	if got.NSq.Cmp(pub.NSq) != 0 {
		t.Fatal("n² 推导不一致")
	}
}

func TestMarshalPrivateKeyRoundTrip(t *testing.T) {
	pub, priv := testKeys(t)
	data, err := MarshalPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalPrivateKey(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(priv.N) != 0 || got.Lambda.Cmp(priv.Lambda) != 0 || got.Mu.Cmp(priv.Mu) != 0 {
		t.Fatal("私钥核心字段不一致")
	}
	// CRT 字段保留
	if got.P == nil || got.Q == nil || got.LambdaP == nil || got.MuP == nil || got.LambdaQ == nil || got.MuQ == nil {
		t.Fatal("CRT 预计算字段丢失")
	}
	if got.P.Cmp(priv.P) != 0 || got.MuP.Cmp(priv.MuP) != 0 {
		t.Fatal("CRT 字段不一致")
	}

	// 序列化后的私钥必须可用（含 CRT 路径）
	c, err := paillier.NewCipher(pub, got)
	if err != nil {
		t.Fatal(err)
	}
	m := big.NewInt(123456789)
	ct, _ := c.Encrypt(m)
	dec, err := c.Decrypt(ct)
	if err != nil {
		t.Fatalf("序列化后私钥解密失败: %v", err)
	}
	if dec.Cmp(m) != 0 {
		t.Fatal("序列化后解密结果错误")
	}
}

func TestMarshalInvalidInputs(t *testing.T) {
	if _, err := MarshalPublicKey(nil); err == nil {
		t.Fatal("nil 公钥应报错")
	}
	if _, err := MarshalPrivateKey(nil); err == nil {
		t.Fatal("nil 私钥应报错")
	}
	if _, err := UnmarshalPublicKey([]byte("garbage")); err == nil {
		t.Fatal("无效 PEM 应报错")
	}
	if _, err := UnmarshalPrivateKey([]byte("garbage")); err == nil {
		t.Fatal("无效 PEM 应报错")
	}
}

func TestMemEnvelopeRoundTrip(t *testing.T) {
	env, err := NewMemEnvelope(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("sensitive-key-material")
	sealed, err := env.Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(sealed, secret) {
		t.Fatal("密封数据不应为明文")
	}
	opened, err := env.Decrypt(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(opened, secret) {
		t.Fatal("信封往返不一致")
	}
}

func TestMemEnvelopeTamperDetected(t *testing.T) {
	env, _ := NewMemEnvelope(rand.Reader)
	sealed, _ := env.Encrypt([]byte("secret"))

	// 篡改认证数据（最后一个字节翻转）
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := env.Decrypt(tampered); err == nil {
		t.Fatal("篡改密封数据应被检测")
	}

	// 错误信封密钥
	env2, _ := NewMemEnvelope(rand.Reader)
	if _, err := env2.Decrypt(sealed); err == nil {
		t.Fatal("错误密钥解密应失败")
	}
}

func TestSealOpenPrivateKey(t *testing.T) {
	_, priv := testKeys(t)
	env, _ := NewMemEnvelope(rand.Reader)

	sealed, err := SealPrivateKey(priv, env)
	if err != nil {
		t.Fatal(err)
	}
	// 密封数据不含明文 PEM（可检测的快速检查：不含 "PRIVATE KEY" 字样）
	if bytes.Contains(sealed, []byte("PRIVATE KEY")) {
		t.Fatal("密封数据不应包含明文 PEM")
	}

	opened, err := OpenPrivateKey(sealed, env)
	if err != nil {
		t.Fatal(err)
	}
	if opened.N.Cmp(priv.N) != 0 {
		t.Fatal("密封-解封私钥不一致")
	}

	// 篡改密封数据
	tampered := append([]byte(nil), sealed...)
	tampered[len(tampered)-1] ^= 0x01
	if _, err := OpenPrivateKey(tampered, env); err == nil {
		t.Fatal("篡改密封私钥应报错")
	}
	// 错误信封
	env2, _ := NewMemEnvelope(rand.Reader)
	if _, err := OpenPrivateKey(sealed, env2); err == nil {
		t.Fatal("错误信封应报错")
	}
	// 非法格式
	if _, err := OpenPrivateKey([]byte("Xgarbage"), env); err == nil {
		t.Fatal("非法密封格式应报错")
	}
}
