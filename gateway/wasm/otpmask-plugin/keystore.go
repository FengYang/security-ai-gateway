package main

import (
	"encoding/hex"
	"fmt"
	"sync"
)

// MemKeyStore 内存版请求级密钥存储（M2 测试用，对应技术方案 的 MemKeyStore）。
//
// 协议：为每个请求签发独立 seed + nonce（请求级密钥），密文请求携带 nonce；
// 响应解密时按 nonce 回溯 seed，使用后立即删除（一次性）并清零。
//
// 安全注意：M2 为 MVP 演示实现，seed 驻留网关内存；
// 生产环境将改为 TEE KeyService 签发 + 短 TTL 缓存 + memzero。
// P0-4：seed/nonce 的随机数经 cryptop sidecar `/v1/rand`（§5.4.5 / B-4.6-2），插件零密码。
type MemKeyStore struct {
	mu   sync.Mutex
	keys map[string][]byte // hex(nonce) → seed
}

// NewMemKeyStore 构造空密钥存储。
func NewMemKeyStore() *MemKeyStore {
	return &MemKeyStore{keys: make(map[string][]byte)}
}

// seedLen 种子长度（与 cipher/mask 的 MinSeedLen=32 对齐，256 位）。
const seedLen = 32

// Issue 签发新请求密钥：经 cryptop sidecar `/v1/rand` 生成 256 位随机 seed 与 16 字节 nonce（CPS）。
// 返回 seed（调用方使用后应清零）与 nonce 的 hex 编码（用于密文请求/响应）。
// sidecar 不可用 → 拒绝（fail-closed，无本地回退，C-4/R-11）。
func (k *MemKeyStore) Issue(cb func(seed []byte, nonceHex string, err error)) {
	if !cryptoUsable() {
		cb(nil, "", errCryptoUnavailable)
		return
	}
	CryptoClient.Rand(seedLen, func(seed []byte, serr error) {
		if serr != nil {
			cb(nil, "", fmt.Errorf("otpmask: 生成 seed 失败: %w", serr))
			return
		}
		CryptoClient.Rand(16, func(nonce []byte, nerr error) {
			if nerr != nil {
				cb(nil, "", fmt.Errorf("otpmask: 生成 nonce 失败: %w", nerr))
				return
			}
			nonceHex := hex.EncodeToString(nonce)
			k.Store(nonceHex, seed)
			cb(seed, nonceHex, nil)
		})
	})
}

// Store 注入外部签发的请求密钥（所有密钥均经此入库，签发计数不双计）。
func (k *MemKeyStore) Store(key string, seed []byte) {
	metricKeysIssued.incr() // W-1：密钥签发计数
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys[key] = append([]byte(nil), seed...)
}

// Lookup 按 nonce 回溯请求密钥（响应解密用）。返回 seed 副本。
func (k *MemKeyStore) Lookup(nonceHex string) ([]byte, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	seed, ok := k.keys[nonceHex]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), seed...), true
}

// Delete 删除一次性密钥（响应解密后调用）。
func (k *MemKeyStore) Delete(nonceHex string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if seed, ok := k.keys[nonceHex]; ok {
		for i := range seed {
			seed[i] = 0
		}
		delete(k.keys, nonceHex)
		metricKeysDeleted.incr() // W-1：仅实删计数（onStreamDone 幂等兜底不重复计）
	}
}
