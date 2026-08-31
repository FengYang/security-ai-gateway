// Package keymgmt 提供 Paillier 密钥的序列化与安全存储。
//
// 设计对齐工业级改造方案 
// - 序列化：PEM 封装自定义 ASN.1（n, g, λ, μ, p, q + CRT 预计算）
// - 存储：KMS Envelope 模式——私钥在受信环境本地生成，云 KMS
// 仅做信封加密（云 KMS 不支持同态运算，调研确认）
// - 轮换：调用方以版本化方式管理（Seal/Open 与密钥 ID 解耦）
package keymgmt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"

	"security-ai-gateway/cipher/paillier"
)

// pemPublicKeyType / pemPrivateKeyType PEM 块类型标识。
const (
	pemPublicKeyType  = "PAILLIER PUBLIC KEY"
	pemPrivateKeyType = "PAILLIER PRIVATE KEY"
)

// asn1PublicKey 公钥 ASN.1 结构。
type asn1PublicKey struct {
	N *big.Int
	G *big.Int
}

// asn1PrivateKey 私钥 ASN.1 结构（含 CRT 预计算参数）。
type asn1PrivateKey struct {
	Version int
	N       *big.Int
	G       *big.Int
	Lambda  *big.Int
	Mu      *big.Int
	P       *big.Int
	Q       *big.Int
	LambdaP *big.Int
	MuP     *big.Int
	LambdaQ *big.Int
	MuQ     *big.Int
}

// MarshalPublicKey 将公钥序列化为 PEM 字节。
func MarshalPublicKey(pub *paillier.PublicKey) ([]byte, error) {
	if pub == nil || pub.N == nil || pub.G == nil {
		return nil, errors.New("keymgmt: 公钥字段不完整")
	}
	der, err := asn1.Marshal(asn1PublicKey{N: pub.N, G: pub.G})
	if err != nil {
		return nil, fmt.Errorf("keymgmt: 公钥 ASN.1 编码失败: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPublicKeyType, Bytes: der}), nil
}

// UnmarshalPublicKey 从 PEM 字节解析公钥。
func UnmarshalPublicKey(data []byte) (*paillier.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemPublicKeyType {
		return nil, errors.New("keymgmt: 无效的公钥 PEM")
	}
	var a asn1PublicKey
	if _, err := asn1.Unmarshal(block.Bytes, &a); err != nil {
		return nil, fmt.Errorf("keymgmt: 公钥 ASN.1 解码失败: %w", err)
	}
	if a.N == nil || a.G == nil {
		return nil, errors.New("keymgmt: 公钥字段缺失")
	}
	return &paillier.PublicKey{
		N:   a.N,
		G:   a.G,
		NSq: new(big.Int).Mul(a.N, a.N),
	}, nil
}

// MarshalPrivateKey 将私钥序列化为 PEM 字节。
// g 由 g = n+1 推导（本实现固定构造）。
func MarshalPrivateKey(priv *paillier.PrivateKey) ([]byte, error) {
	if priv == nil || priv.Lambda == nil || priv.Mu == nil || priv.N == nil {
		return nil, errors.New("keymgmt: 私钥字段不完整")
	}
	a := asn1PrivateKey{
		Version: 1,
		N:       priv.N,
		G:       new(big.Int).Add(priv.N, big.NewInt(1)),
		Lambda:  priv.Lambda,
		Mu:      priv.Mu,
		P:       priv.P,
		Q:       priv.Q,
		LambdaP: priv.LambdaP,
		MuP:     priv.MuP,
		LambdaQ: priv.LambdaQ,
		MuQ:     priv.MuQ,
	}
	der, err := asn1.Marshal(a)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: 私钥 ASN.1 编码失败: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: pemPrivateKeyType, Bytes: der}), nil
}

// UnmarshalPrivateKey 从 PEM 字节解析私钥。
func UnmarshalPrivateKey(data []byte) (*paillier.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != pemPrivateKeyType {
		return nil, errors.New("keymgmt: 无效的私钥 PEM")
	}
	var a asn1PrivateKey
	if _, err := asn1.Unmarshal(block.Bytes, &a); err != nil {
		return nil, fmt.Errorf("keymgmt: 私钥 ASN.1 解码失败: %w", err)
	}
	if a.N == nil || a.Lambda == nil || a.Mu == nil {
		return nil, errors.New("keymgmt: 私钥字段缺失")
	}
	return &paillier.PrivateKey{
		Lambda:  a.Lambda,
		Mu:      a.Mu,
		N:       a.N,
		P:       a.P,
		Q:       a.Q,
		LambdaP: a.LambdaP,
		MuP:     a.MuP,
		LambdaQ: a.LambdaQ,
		MuQ:     a.MuQ,
	}, nil
}

// Envelope 为密钥加密信封接口（KMS 集成点）。
// 云 KMS 不支持同态运算，HE 私钥须本地生成，经 KMS 信封加密静态存储。
type Envelope interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// MemEnvelope 基于 AES-256-GCM 的内存信封（测试与单机部署）。
// 生产环境应替换为 AWS KMS / Azure Key Vault / GCP KMS 实现。
type MemEnvelope struct {
	key []byte
}

// NewMemEnvelope 以随机 32 字节密钥构造内存信封。
func NewMemEnvelope(randReader io.Reader) (*MemEnvelope, error) {
	if randReader == nil {
		randReader = rand.Reader
	}
	key := make([]byte, 32)
	if _, err := io.ReadFull(randReader, key); err != nil {
		return nil, fmt.Errorf("keymgmt: 生成信封密钥失败: %w", err)
	}
	return &MemEnvelope{key: key}, nil
}

// Encrypt 密封明文（AES-256-GCM，随机 nonce 前置）。
func (e *MemEnvelope) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt 解封密文（校验认证标签，防篡改）。
func (e *MemEnvelope) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("keymgmt: 密封数据过短")
	}
	nonce, sealed := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]
	plaintext, err := aead.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: 信封解密失败（可能被篡改或密钥不符）: %w", err)
	}
	return plaintext, nil
}

// SealPrivateKey 将私钥经信封加密存储。
// 返回信封密文（含版本前缀），私钥明文仅在调用方内存短暂存在。
func SealPrivateKey(priv *paillier.PrivateKey, env Envelope) ([]byte, error) {
	if env == nil {
		return nil, errors.New("keymgmt: 信封为空")
	}
	pemBytes, err := MarshalPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	sealed, err := env.Encrypt(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("keymgmt: 密封私钥失败: %w", err)
	}
	out := make([]byte, 0, len(sealed)+1)
	out = append(out, 'K')
	out = append(out, sealed...)
	return out, nil
}

// OpenPrivateKey 从信封密文恢复私钥（校验封装与解析）。
func OpenPrivateKey(data []byte, env Envelope) (*paillier.PrivateKey, error) {
	if env == nil {
		return nil, errors.New("keymgmt: 信封为空")
	}
	if len(data) < 1 || data[0] != 'K' {
		return nil, errors.New("keymgmt: 无效的密封私钥格式")
	}
	pemBytes, err := env.Decrypt(data[1:])
	if err != nil {
		return nil, err
	}
	return UnmarshalPrivateKey(pemBytes)
}
