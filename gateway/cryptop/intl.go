package cryptop

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
)

// intl 档实现：AES-256-GCM / SHA-256 / HMAC-SHA256 / HKDF-SHA256 / X25519 / Ed25519。
//
// 说明：本实现即仓库现状所用算法的集中封装（当前调用点尚未接入，见 provider.go 头部说明）。
// 它**不满足密评**（见 Profile.ComplianceNote），仅供非政企客户与内部验证使用。

const (
	intlSymmetricKeySize = 32 // AES-256
	intlNonceSize        = 12 // GCM 标准 nonce
	intlHashSize         = sha256.Size
)

type intlProvider struct{}

func newIntlProvider() *intlProvider { return &intlProvider{} }

func (p *intlProvider) Profile() Profile       { return ProfileIntl }
func (p *intlProvider) ComplianceNote() string { return ProfileIntl.ComplianceNote() }
func (p *intlProvider) SymmetricKeySize() int  { return intlSymmetricKeySize }
func (p *intlProvider) NonceSize() int         { return intlNonceSize }
func (p *intlProvider) HashSize() int          { return intlHashSize }

func (p *intlProvider) Rand(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("cryptop: Rand 长度非法")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// aead 按 profile 规定的密钥长度构造 AEAD。
func (p *intlProvider) aead(key []byte) (cipher.AEAD, error) {
	if len(key) != intlSymmetricKeySize {
		return nil, ErrInvalidKeySize
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(blk)
}

func (p *intlProvider) Seal(key, nonce, plaintext, aad []byte) ([]byte, error) {
	if len(nonce) != intlNonceSize {
		return nil, errors.New("cryptop: nonce 长度非法")
	}
	a, err := p.aead(key)
	if err != nil {
		return nil, err
	}
	return a.Seal(nil, nonce, plaintext, aad), nil
}

func (p *intlProvider) Open(key, nonce, ciphertext, aad []byte) ([]byte, error) {
	if len(nonce) != intlNonceSize {
		return nil, errors.New("cryptop: nonce 长度非法")
	}
	a, err := p.aead(key)
	if err != nil {
		return nil, err
	}
	pt, err := a.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		// 不区分"标签不符/长度非法"，避免作为解密预言机；且绝不返回部分明文。
		return nil, ErrDecrypt
	}
	return pt, nil
}

func (p *intlProvider) SealWithNonce(key, plaintext, aad []byte) ([]byte, []byte, error) {
	nonce, err := p.Rand(intlNonceSize)
	if err != nil {
		return nil, nil, err
	}
	ct, err := p.Seal(key, nonce, plaintext, aad)
	if err != nil {
		return nil, nil, err
	}
	return nonce, ct, nil
}

func (p *intlProvider) Hash(data []byte) []byte {
	sum := sha256.Sum256(data)
	return sum[:]
}

func (p *intlProvider) HMAC(key, data []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(data)
	return m.Sum(nil)
}

func (p *intlProvider) KDF(secret, salt, info []byte, outLen int) ([]byte, error) {
	if outLen <= 0 {
		return nil, errors.New("cryptop: KDF 输出长度非法")
	}
	// 标准库 crypto/hkdf（Go 1.24+）：HKDF-SHA256；info 为 string（stdlib 签名）。
	out, err := hkdf.Key(sha256.New, secret, salt, string(info), outLen)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Keystream intl 档：HMAC-SHA256 PRG，**逐字节等价 cipher/mask 现役实现**
// （`cipher/mask/mask.go` 每个候选元素 = HMAC-SHA256(seed, BE64(counter)‖domain) 前 8 字节）。
//
// 输出 = concat_{k=0..} HMAC-SHA256(key, BE64(counter+k)‖domain)[:8]，截断到 n 字节。
// 仅产流不做认证（掩码"打散"用）。与 cipher/mask 的 hmacPRG 逐字节一致（T-5.3-8）。
// key 长度须 = intlSymmetricKeySize（32B，随 profile）——fail-closed 防误配（如误传 sm 16B 密钥）。
func (p *intlProvider) Keystream(key, domain []byte, counter uint64, n int) ([]byte, error) {
	if n < 0 {
		return nil, errors.New("cryptop: Keystream 长度非法")
	}
	if n == 0 {
		return []byte{}, nil
	}
	if len(key) != intlSymmetricKeySize {
		return nil, ErrInvalidKeySize
	}
	out := make([]byte, 0, n+8)
	var ctr [8]byte
	for len(out) < n {
		binary.BigEndian.PutUint64(ctr[:], counter)
		mac := hmac.New(sha256.New, key)
		_, _ = mac.Write(ctr[:]) // hash.Hash.Write 按规范永不返回错误
		if len(domain) > 0 {
			_, _ = mac.Write(domain)
		}
		sum := mac.Sum(nil)
		out = append(out, sum[:8]...)
		counter++
	}
	return out[:n], nil
}

func (p *intlProvider) GenerateECDHKeyPair() ([]byte, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv.Bytes(), priv.PublicKey().Bytes(), nil
}

func (p *intlProvider) ECDH(priv, peerPub []byte) ([]byte, error) {
	k, err := ecdh.X25519().NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return k.ECDH(pub)
}

func (p *intlProvider) GenerateSignKeyPair() ([]byte, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

func (p *intlProvider) Sign(priv, msg []byte) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, errors.New("cryptop: Ed25519 私钥长度非法")
	}
	return ed25519.Sign(ed25519.PrivateKey(priv), msg), nil
}

func (p *intlProvider) Verify(pub, msg, sig []byte) error {
	if len(pub) != ed25519.PublicKeySize {
		return errors.New("cryptop: Ed25519 公钥长度非法")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), msg, sig) {
		return errors.New("cryptop: 验签失败")
	}
	return nil
}

// WrapKey 用 KEK 封装 DEK：nonce 前缀 + AES-256-GCM 密文，AAD 绑定用途标签。
func (p *intlProvider) WrapKey(kek, dek []byte) ([]byte, error) {
	nonce, ct, err := p.SealWithNonce(kek, dek, []byte("cryptop/keywrap/v1"))
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

func (p *intlProvider) UnwrapKey(kek, wrapped []byte) ([]byte, error) {
	if len(wrapped) <= intlNonceSize {
		return nil, ErrDecrypt
	}
	return p.Open(kek, wrapped[:intlNonceSize], wrapped[intlNonceSize:], []byte("cryptop/keywrap/v1"))
}
