package cryptop

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// 一致性测试口径：**同一套业务语义**必须在两个算法族下都成立（这是"切换 profile 时代码零改动"的证据）。
// sm-module（认证密码模块）未实现，不参与。
var conformanceProfiles = []Profile{ProfileIntl, ProfileSMSW}

func providerFor(t *testing.T, prof Profile) Provider {
	t.Helper()
	p, err := New(prof)
	if err != nil {
		t.Fatalf("New(%s) 失败：%v", prof, err)
	}
	return p
}

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
	for _, p := range []Profile{ProfileIntl, ProfileSMSW} {
		if !bytes.Contains([]byte(p.ComplianceNote()), []byte("不满足密评")) {
			t.Errorf("%s 标注必须显式说明不满足密评", p)
		}
	}
}

// TestNewProfileDispatch 分派语义：intl 与 sm-software 可用；sm-module 在无厂商
// 配置时明确失败（fail-closed 启动拒，不静默回退——P1-5 M2/C-3）。
func TestNewProfileDispatch(t *testing.T) {
	for _, prof := range conformanceProfiles {
		p, err := New(prof)
		if err != nil || p.Profile() != prof {
			t.Fatalf("%s 应可用，实际 err=%v", prof, err)
		}
	}
	// sm-module 生产路径：未配置厂商库 → 错误（绝不返回可用 Provider）。
	_, err := New(ProfileSMModule)
	if err == nil {
		t.Fatal("sm-module 无厂商配置时应失败（fail-closed）")
	}
	// 显式 mock 后端在生产路径同样被拒（防软件实现冒充合规，P4）。
	t.Setenv("MODULE_BACKEND", "mock")
	if _, err := New(ProfileSMModule); err == nil {
		t.Fatal("sm-module 生产路径应拒绝 mock 后端")
	}
	if _, err := New("bogus"); !errors.Is(err, ErrUnknownProfile) {
		t.Errorf("未知 profile 应返回 ErrUnknownProfile，实际 %v", err)
	}
}

// TestPrimitiveConformance 原语语义一致性（逐算法族执行同一组断言）。
func TestPrimitiveConformance(t *testing.T) {
	for _, prof := range conformanceProfiles {
		t.Run(string(prof), func(t *testing.T) {
			p := providerFor(t, prof)

			// --- AEAD 往返 + AAD 绑定 + 篡改检测 ---
			key, err := p.Rand(p.SymmetricKeySize())
			if err != nil {
				t.Fatal(err)
			}
			if len(key) != p.SymmetricKeySize() {
				t.Fatalf("密钥长度应为 %d，实际 %d", p.SymmetricKeySize(), len(key))
			}
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
			if _, err := p.Open(key, nonce, ct, []byte("other-aad")); !errors.Is(err, ErrDecrypt) {
				t.Errorf("AAD 不符应返回 ErrDecrypt，实际 %v", err)
			}
			bad := append([]byte(nil), ct...)
			bad[0] ^= 0x01
			if _, err := p.Open(key, nonce, bad, aad); !errors.Is(err, ErrDecrypt) {
				t.Errorf("密文篡改应返回 ErrDecrypt，实际 %v", err)
			}
			// 错误密钥长度（少 1 字节）→ 明确报错
			if _, err := p.Seal(key[:p.SymmetricKeySize()-1], nonce, pt, aad); !errors.Is(err, ErrInvalidKeySize) {
				t.Errorf("密钥长度非法应返回 ErrInvalidKeySize，实际 %v", err)
			}
			// nonce 不得复用
			n1, _, _ := p.SealWithNonce(key, pt, nil)
			n2, _, _ := p.SealWithNonce(key, pt, nil)
			if bytes.Equal(n1, n2) {
				t.Error("随机 nonce 不应重复")
			}

			// --- 哈希：长度、确定性 ---
			if got := len(p.Hash([]byte("abc"))); got != p.HashSize() {
				t.Errorf("哈希长度应为 %d，实际 %d", p.HashSize(), got)
			}
			if !bytes.Equal(p.Hash([]byte("abc")), p.Hash([]byte("abc"))) {
				t.Error("哈希应为确定性")
			}

			// --- HMAC：确定性 + 密钥敏感 ---
			k1, _ := p.Rand(32)
			k2, _ := p.Rand(32)
			m1 := p.HMAC(k1, []byte("msg"))
			if !bytes.Equal(m1, p.HMAC(k1, []byte("msg"))) {
				t.Error("HMAC 应为确定性")
			}
			if bytes.Equal(m1, p.HMAC(k2, []byte("msg"))) {
				t.Error("不同密钥的 HMAC 不应相同")
			}

			// --- KDF：确定性 + 域分离（不同 info 输出不同）---
			secret, _ := p.Rand(32)
			salt, _ := p.Rand(16)
			o1, err := p.KDF(secret, salt, []byte("otpmask/kdf/enc/v1"), 32)
			if err != nil || len(o1) != 32 {
				t.Fatalf("KDF 应输出 32 字节：err=%v len=%d", err, len(o1))
			}
			o1b, _ := p.KDF(secret, salt, []byte("otpmask/kdf/enc/v1"), 32)
			if !bytes.Equal(o1, o1b) {
				t.Error("同参数 KDF 应确定性")
			}
			o2, _ := p.KDF(secret, salt, []byte("otpmask/kdf/sig/v1"), 32)
			if bytes.Equal(o1, o2) {
				t.Error("不同 info 的 KDF 输出不应相同（密钥域分离）")
			}
			if _, err := p.KDF(secret, salt, nil, 0); err == nil {
				t.Error("非法输出长度应报错")
			}

			// --- ECDH：双方共享密钥一致 ---
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
				t.Error("双方共享密钥应一致")
			}

			// --- 签名：往返 + 篡改检测 ---
			sPriv, sPub, err := p.GenerateSignKeyPair()
			if err != nil {
				t.Fatal(err)
			}
			msg := []byte("虚拟 Key payload")
			sig, err := p.Sign(sPriv, msg)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Verify(sPub, msg, sig); err != nil {
				t.Errorf("正确签名应通过：%v", err)
			}
			if err := p.Verify(sPub, []byte("tampered"), sig); err == nil {
				t.Error("篡改消息应验签失败")
			}

			// --- 密钥封装往返 + 错误 KEK 拒绝 ---
			kek, _ := p.Rand(p.SymmetricKeySize())
			dek, _ := p.Rand(32)
			wrapped, err := p.WrapKey(kek, dek)
			if err != nil {
				t.Fatal(err)
			}
			unwrapped, err := p.UnwrapKey(kek, wrapped)
			if err != nil || !bytes.Equal(unwrapped, dek) {
				t.Fatalf("解封应还原 DEK：err=%v", err)
			}
			otherKek, _ := p.Rand(p.SymmetricKeySize())
			if _, err := p.UnwrapKey(otherKek, wrapped); !errors.Is(err, ErrDecrypt) {
				t.Errorf("错误 KEK 应返回 ErrDecrypt，实际 %v", err)
			}
			if _, err := p.UnwrapKey(kek, []byte("short")); !errors.Is(err, ErrDecrypt) {
				t.Errorf("截断密文应返回 ErrDecrypt，实际 %v", err)
			}
		})
	}
}

// TestCrossProfileKeySizeMismatch 两档密钥长度不同（intl 32B vs sm 16B）：
// 跨档混用必须被拒——这正是"业务代码不得硬编码长度、必须用 Provider 尺寸方法"的原因。
func TestCrossProfileKeySizeMismatch(t *testing.T) {
	intl := providerFor(t, ProfileIntl)
	sm := providerFor(t, ProfileSMSW)
	if intl.SymmetricKeySize() == sm.SymmetricKeySize() {
		t.Fatal("两档对称密钥长度应不同（否则本用例无意义）")
	}
	intlKey, _ := intl.Rand(intl.SymmetricKeySize())
	smKey, _ := sm.Rand(sm.SymmetricKeySize())
	if _, err := sm.Seal(intlKey, make([]byte, sm.NonceSize()), []byte("x"), nil); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("intl 密钥用于 sm 档应报 ErrInvalidKeySize，实际 %v", err)
	}
	if _, err := intl.Seal(smKey, make([]byte, intl.NonceSize()), []byte("x"), nil); !errors.Is(err, ErrInvalidKeySize) {
		t.Errorf("sm 密钥用于 intl 档应报 ErrInvalidKeySize，实际 %v", err)
	}
	if intl.HashSize() == sm.HashSize() {
		t.Log("提示：两档哈希长度相同（SHA-256 与 SM3 均为 32 字节），属预期")
	}
}

// TestSM3KnownAnswer 已知答案测试（GB/T 32905 / 取自 gmsm 自带测试向量）：
// 用**外部标准向量**验证 SM3 实现，而非实现自证。
func TestSM3KnownAnswer(t *testing.T) {
	p := providerFor(t, ProfileSMSW)
	cases := []struct {
		desc string
		in   []byte
		want string
	}{
		{"abc", []byte("abc"), "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{"abcd×16", bytes.Repeat([]byte("abcd"), 16), "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
	}
	for _, c := range cases {
		got := hex.EncodeToString(p.Hash(c.in))
		if got != c.want {
			t.Errorf("SM3(%s) 与标准向量不符\n got=%s\nwant=%s", c.desc, got, c.want)
		}
	}
}

// TestSHA256KnownAnswer 对照档亦做已知答案（NIST 向量："abc"）。
func TestSHA256KnownAnswer(t *testing.T) {
	p := providerFor(t, ProfileIntl)
	got := hex.EncodeToString(p.Hash([]byte("abc")))
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Errorf("SHA-256(abc) 与标准向量不符\n got=%s\nwant=%s", got, want)
	}
}
