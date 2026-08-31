package secagg

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"security-ai-gateway/cipher/kex"
)

// domainSepAEAD AEAD 密钥派生的域分离常量。
var domainSepAEAD = []byte("otp-mask/secagg/aead/v1")

// deriveAEADKey 由 ECDH 共享密钥派生 AES-256-GCM 密钥。
func deriveAEADKey(shared []byte) []byte {
	h := sha256.New()
	h.Write(domainSepAEAD)
	h.Write(shared)
	return h.Sum(nil)
}

// sealShare 用本方加密密钥与对端加密公钥派生的密钥加密份额包。
// 双方各持一 ECDH 密钥对（c 密钥对），加密密钥 = SHA-256(ECDH(cSK, cPk))，
// 与论文 AE.enc(KA.agree(cSK_u, cPK_v), ·) 语义一致。
// AES-GCM 使用每次新鲜生成的随机 nonce（G407 合规）。
func sealShare(self *kex.KeyPair, peerPub []byte, plaintext []byte) ([]byte, error) {
	shared, err := self.DeriveSeed(peerPub)
	if err != nil {
		return nil, fmt.Errorf("secagg: 派生加密密钥失败: %w", err)
	}
	key := deriveAEADKey(shared)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secagg: 初始化 AES 失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secagg: 初始化 GCM 失败: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("secagg: 生成 nonce 失败: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// openShare 解密份额包（密文头部携带随机 nonce）。
func openShare(self *kex.KeyPair, peerPub []byte, ciphertext []byte) ([]byte, error) {
	shared, err := self.DeriveSeed(peerPub)
	if err != nil {
		return nil, fmt.Errorf("secagg: 派生解密密钥失败: %w", err)
	}
	key := deriveAEADKey(shared)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secagg: 初始化 AES 失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secagg: 初始化 GCM 失败: %w", err)
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("secagg: 份额密文过短")
	}
	nonce, sealed := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("secagg: 份额包解密失败: %w", err)
	}
	return plaintext, nil
}
