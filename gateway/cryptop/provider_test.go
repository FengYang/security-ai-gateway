package cryptop

import (
	"bytes"
	"errors"
	"testing"
)

// TestProfileCompliance 合规标注口径（避免"软件实现被当合规实现"）。
func TestProfileCompliance(t *testing.T) {
	if ProfileIntl.MeetsMPY() || ProfileSMSW.MeetsMPY() {
		t.Error("intl 与 sm-software 均不得宣称满足密评")
	}
	if !ProfileSMModule.MeetsMPY() {
		t.Error("sm-module 应可用于政企合规声明")
	}
	for _, p := range []Profile{ProfileIntl, ProfileSMSW, ProfileSMModule, "bogus"} {
		if p.ComplianceNote() == "" {
			t.Errorf("profile %q 必须有合规标注文案", p)
		}
	}
	if !bytes.Contains([]byte(ProfileSMSW.ComplianceNote()), []byte("不满足密评")) {
		t.Error("sm-software 标注必须显式说明不满足密评")
	}
}

// TestNewProfileDispatch 本轮仅 intl 可用；sm 档必须明确"未实现"而非静默回退。
func TestNewProfileDispatch(t *testing.T) {
	p, err := New(ProfileIntl)
	if err != nil || p.Profile() != ProfileIntl {
		t.Fatalf("intl 应可用，实际 err=%v profile=%v", err, p)
	}
	for _, prof := range []Profile{ProfileSMSW, ProfileSMModule} {
		if _, err := New(prof); !errors.Is(err, ErrNotImplemented) {
			t.Errorf("%s 本轮应返回 ErrNotImplemented，实际 %v", prof, err)
		}
	}
	if _, err := New("bogus"); !errors.Is(err, ErrUnknownProfile) {
		t.Errorf("未知 profile 应返回 ErrUnknownProfile，实际 %v", err)
	}
}

func newIntl(t *testing.T) Provider {
	t.Helper()
	p, err := New(ProfileIntl)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSealOpenRoundtrip AEAD 往返 + AAD 绑定 + 篡改检测。
func TestSealOpenRoundtrip(t *testing.T) {
	p := newIntl(t)
	key, _ := p.Rand(p.SymmetricKeySize())
	aad := []byte("otpmask/envelope/v1")
	pt := []byte("明文摘要与向量：hello-tensor")

	nonce, ct, err := p.SealWithNonce(key, pt, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(nonce) != p.NonceSize() {
		t.Errorf("nonce 长度应为 %d，实际 %d", p.NonceSize(), len(nonce))
	}
	got, err := p.Open(key, nonce, ct, aad)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("解密应还原明文：err=%v got=%q", err, got)
	}
	// AAD 不符 → 拒绝
	if _, err := p.Open(key, nonce, ct, []byte("other-aad")); !errors.Is(err, ErrDecrypt) {
		t.Errorf("AAD 不符应返回 ErrDecrypt，实际 %v", err)
	}
	// 密文篡改 → 拒绝
	bad := append([]byte(nil), ct...)
	bad[0] ^= 0x01
	if _, err := p.Open(key, nonce, bad, aad); !errors.Is(err, ErrDecrypt) {
		t.Errorf("密文篡改应返回 ErrDecrypt，实际 %v", err)
	}
	// 密钥错误长度 → 明确报错（业务代码不得硬编码长度）
	if _, err := p.Seal(key[:16], nonce, pt, aad); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("密钥长度非法应返回 ErrInvalidKeySize，实际 %v", err)
	}
}

// TestSealWithNonceUnique 两次加密的 nonce 必须不同（AEAD 复用 nonce 是致命错误）。
func TestSealWithNonceUnique(t *testing.T) {
	p := newIntl(t)
	key, _ := p.Rand(p.SymmetricKeySize())
	n1, _, err := p.SealWithNonce(key, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	n2, _, err := p.SealWithNonce(key, []byte("x"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(n1, n2) {
		t.Fatal("随机 nonce 不应重复")
	}
}

// TestHashAndHMAC 哈希长度、HMAC 确定性与密钥敏感性。
func TestHashAndHMAC(t *testing.T) {
	p := newIntl(t)
	if got := len(p.Hash([]byte("abc"))); got != p.HashSize() {
		t.Errorf("哈希长度应为 %d，实际 %d", p.HashSize(), got)
	}
	if !bytes.Equal(p.Hash([]byte("abc")), p.Hash([]byte("abc"))) {
		t.Error("哈希应为确定性")
	}
	k1, _ := p.Rand(32)
	k2, _ := p.Rand(32)
	m1 := p.HMAC(k1, []byte("msg"))
	if !bytes.Equal(m1, p.HMAC(k1, []byte("msg"))) {
		t.Error("HMAC 应为确定性")
	}
	if bytes.Equal(m1, p.HMAC(k2, []byte("msg"))) {
		t.Error("不同密钥的 HMAC 不应相同")
	}
}

// TestKDF 派生确定性与参数敏感性。
func TestKDF(t *testing.T) {
	p := newIntl(t)
	secret, _ := p.Rand(32)
	salt, _ := p.Rand(16)
	out, err := p.KDF(secret, salt, []byte("otpmask/kdf/enc/v1"), 32)
	if err != nil || len(out) != 32 {
		t.Fatalf("KDF 应输出 32 字节：err=%v len=%d", err, len(out))
	}
	again, _ := p.KDF(secret, salt, []byte("otpmask/kdf/enc/v1"), 32)
	if !bytes.Equal(out, again) {
		t.Error("同参数 KDF 应确定性")
	}
	other, _ := p.KDF(secret, salt, []byte("otpmask/kdf/sig/v1"), 32)
	if bytes.Equal(out, other) {
		t.Error("不同 info 的 KDF 输出不应相同（密钥域分离）")
	}
	if _, err := p.KDF(secret, salt, nil, 0); err == nil {
		t.Error("非法输出长度应报错")
	}
}

// TestECDHSharedSecret 双方协商出相同共享密钥。
func TestECDHSharedSecret(t *testing.T) {
	p := newIntl(t)
	aPriv, aPub, err := p.GenerateECDHKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bPriv, bPub, err := p.GenerateECDHKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	ab, err := p.ECDH(aPriv, bPub)
	if err != nil {
		t.Fatal(err)
	}
	ba, err := p.ECDH(bPriv, aPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(ab, ba) {
		t.Fatal("双方共享密钥应一致")
	}
}

// TestSignVerify 签名往返与篡改检测。
func TestSignVerify(t *testing.T) {
	p := newIntl(t)
	priv, pub, err := p.GenerateSignKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("虚拟 Key payload")
	sig, err := p.Sign(priv, msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Verify(pub, msg, sig); err != nil {
		t.Fatalf("正确签名应通过：%v", err)
	}
	if err := p.Verify(pub, []byte("tampered"), sig); err == nil {
		t.Error("篡改消息应验签失败")
	}
}

// TestWrapUnwrapKey 密钥封装往返与错误 KEK 拒绝。
func TestWrapUnwrapKey(t *testing.T) {
	p := newIntl(t)
	kek, _ := p.Rand(p.SymmetricKeySize())
	dek, _ := p.Rand(32)
	wrapped, err := p.WrapKey(kek, dek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.UnwrapKey(kek, wrapped)
	if err != nil || !bytes.Equal(got, dek) {
		t.Fatalf("解封应还原 DEK：err=%v", err)
	}
	other, _ := p.Rand(p.SymmetricKeySize())
	if _, err := p.UnwrapKey(other, wrapped); !errors.Is(err, ErrDecrypt) {
		t.Errorf("错误 KEK 应返回 ErrDecrypt，实际 %v", err)
	}
	if _, err := p.UnwrapKey(kek, []byte("short")); !errors.Is(err, ErrDecrypt) {
		t.Errorf("截断密文应返回 ErrDecrypt，实际 %v", err)
	}
}
