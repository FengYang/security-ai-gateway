package cacheengine

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"strconv"
)

// KeyProvider 缓存加密密钥提供者（§5.3）。
// 密钥由 TEE 内密钥管理派生，进程内持有、不落盘、不下发；不可用时应返回错误（调用方 fail-closed）。
type KeyProvider interface {
	Key(ctx context.Context) ([]byte, error)
}

// StaticKeyProvider 固定密钥提供者（测试与部署注入；生产应由 TEE 派生后注入）。
type StaticKeyProvider struct{ key []byte }

// NewStaticKeyProvider 构造固定密钥提供者（key 必须为 32 字节）。
func NewStaticKeyProvider(key []byte) (*StaticKeyProvider, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cache: aes-256 key must be 32 bytes, got %d", len(key))
	}
	cp := make([]byte, 32)
	copy(cp, key)
	return &StaticKeyProvider{key: cp}, nil
}

// Key 返回密钥副本。
func (p *StaticKeyProvider) Key(ctx context.Context) ([]byte, error) {
	if len(p.key) != 32 {
		return nil, fmt.Errorf("cache: key unavailable")
	}
	out := make([]byte, 32)
	copy(out, p.key)
	return out, nil
}

// BuildAAD 生成 AAD（§5.3）：keyHash || "|" || expire_at || "|" || policy_ver。
// 密文被搬运到别的键/过期时间/策略版本时 AAD 不匹配 → 解封失败（防投毒，§7.4）。
func BuildAAD(keyHash string, expireAt int64, policyVer string) []byte {
	return []byte(keyHash + "|" + strconv.FormatInt(expireAt, 10) + "|" + policyVer)
}

// AEADSeal 用 AES-256-GCM 封装明文；输出 = nonce || ciphertext。
func AEADSeal(key, aad, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("cache: nonce: %w", err)
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

// AEADOpen 解封（AAD 不匹配或密文损坏 → 失败）。
func AEADOpen(key, aad, blob []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(blob) < ns {
		return nil, fmt.Errorf("cache: ciphertext too short")
	}
	nonce, ct := blob[:ns], blob[ns:]
	plain, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, fmt.Errorf("cache: aead open: %w", err)
	}
	return plain, nil
}

// newGCM 构造 AES-256-GCM。
func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("cache: aes-256 key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
