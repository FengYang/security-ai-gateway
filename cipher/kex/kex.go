// Package kex 提供用户间密钥协商与掩码种子派生。
//
// 对齐 Bonawitz CCS 2017 ECDH 密钥协商 + SHA-256 哈希派生
// 共享密钥（论文记为 su,v = H((g^xv)^xu)）。此处使用 NIST P-256。
package kex

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

// domainSep 派生域分离常量，防止跨用途密钥复用。
var domainSep = []byte("otp-mask/kex/v1")

// KeyPair 为 ECDH P-256 密钥对。
type KeyPair struct {
	priv *ecdh.PrivateKey
	pub  *ecdh.PublicKey
}

// Generate 生成 ECDH P-256 密钥对。
func Generate(randReader io.Reader) (*KeyPair, error) {
	if randReader == nil {
		randReader = rand.Reader
	}
	curve := ecdh.P256()
	priv, err := curve.GenerateKey(randReader)
	if err != nil {
		return nil, fmt.Errorf("kex: 生成密钥失败: %w", err)
	}
	return &KeyPair{priv: priv, pub: priv.PublicKey()}, nil
}

// PublicBytes 返回可序列化的公钥字节。
func (k *KeyPair) PublicBytes() []byte {
	return k.pub.Bytes()
}

// DeriveSeed 用本方私钥与对端公钥派生 32 字节共享种子。
// 双方调用结果一致（ECDH 对称性）。
func (k *KeyPair) DeriveSeed(peerPubBytes []byte) ([]byte, error) {
	if k == nil || k.priv == nil {
		return nil, errors.New("kex: 密钥对未初始化")
	}
	peerPub, err := k.priv.Curve().NewPublicKey(peerPubBytes)
	if err != nil {
		return nil, fmt.Errorf("kex: 对端公钥无效: %w", err)
	}
	shared, err := k.priv.ECDH(peerPub)
	if err != nil {
		return nil, fmt.Errorf("kex: ECDH 失败: %w", err)
	}
	h := sha256.New()
	h.Write(domainSep)
	h.Write(shared)
	return h.Sum(nil), nil
}
