// Package teecore — TEE 可信侧核心库
//
// 提供两个子模块：
// - KeyManager：主密钥生命周期 + 请求密钥派生
// - nonlinear：非线性算子补算
//
// 对应技术方案：
// - 主密钥：TEE 生成 256 位真随机，TTL 轮换，历史密钥销毁（前向保密）
// - 请求密钥：request_key = HMAC(master, requestID || model || timestamp)
// - 非线性算子：ReLU / GELU / Softmax / LayerNorm（浮点域，真实模型推理用）
package teecore

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"security-ai-gateway/internal/memzero"
)

// DefaultMasterTTL 主密钥默认有效期。
const DefaultMasterTTL = 5 * time.Minute

// InFlightWindow 主密钥轮换后在途请求窗口（旧密钥保留期）。
const InFlightWindow = 30 * time.Second

// keyRecord 请求密钥记录。
type keyRecord struct {
	seed      []byte
	masterID  uint64
	issuedAt  time.Time
}

// KeyManager 主密钥 + 请求密钥派生管理器（模拟 TEE 飞地内安全存储）。
//
// 并发安全；所有密钥仅内存驻留，轮换后旧主密钥在在途窗口内保留后销毁。
type KeyManager struct {
	mu        sync.Mutex
	masterKey []byte
	masterID  uint64
	masterGen time.Time
	keys      map[string]keyRecord // nonce(hex) → 请求密钥
	masterTTL time.Duration
	stop      chan struct{}
}

// NewKeyManager 构造 KeyManager 并启动主密钥轮换。
// ttl <= 0 时使用 DefaultMasterTTL。
func NewKeyManager(ttl time.Duration) (*KeyManager, error) {
	if ttl <= 0 {
		ttl = DefaultMasterTTL
	}
	km := &KeyManager{
		masterTTL: ttl,
		keys:      make(map[string]keyRecord),
		stop:      make(chan struct{}),
	}
	if err := km.rotateLocked(); err != nil {
		return nil, err
	}
	go km.rotateLoop()
	return km, nil
}

// NewKeyManagerWithMaster 用飞地 Unseal 恢复的主密钥构造 KeyManager。
// 主密钥由调用方从 Enclave.Unseal 恢复（TEE 密封存储），KeyManager 负责轮换与派生。
// masterKey 长度必须为 32 字节；KeyManager 接管其生命周期（轮换时销毁）。
func NewKeyManagerWithMaster(ttl time.Duration, masterKey []byte) (*KeyManager, error) {
	if len(masterKey) != 32 {
		return nil, fmt.Errorf("teecore: 主密钥长度须为 32 字节（got %d）", len(masterKey))
	}
	if ttl <= 0 {
		ttl = DefaultMasterTTL
	}
	km := &KeyManager{
		masterKey: masterKey,
		masterID:  1,
		masterGen: time.Now(),
		masterTTL: ttl,
		keys:      make(map[string]keyRecord),
		stop:      make(chan struct{}),
	}
	go km.rotateLoop()
	return km, nil
}

// Close 停止轮换 goroutine。
func (km *KeyManager) Close() { close(km.stop) }

// rotateLocked 生成新主密钥并递增版本（须持锁）。
func (km *KeyManager) rotateLocked() error {
	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		return fmt.Errorf("teecore: 生成主密钥失败: %w", err)
	}
	km.masterKey = mk
	km.masterID++
	km.masterGen = time.Now()
	return nil
}

// rotateLoop 定时轮换主密钥；旧密钥在 InFlightWindow 内仍可回溯（防在途请求失效）。
func (km *KeyManager) rotateLoop() {
	ticker := time.NewTicker(km.masterTTL)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			km.mu.Lock()
			oldID := km.masterID
			oldKey := km.masterKey
			if err := km.rotateLocked(); err != nil {
				km.mu.Unlock()
				continue
			}
			// 保留旧主密钥窗口：记录过期请求密钥并销毁旧主密钥
			now := time.Now()
			for nonce, rec := range km.keys {
				// 旧主密钥签发的请求密钥，超过在途窗口后删除
				if rec.masterID == oldID && now.Sub(rec.issuedAt) > InFlightWindow {
					wipe(rec.seed)
					delete(km.keys, nonce)
				}
			}
			wipe(oldKey) // 销毁旧主密钥（前向保密）
			km.mu.Unlock()
		case <-km.stop:
			return
		}
	}
}

// Issue 派生并签发请求密钥。
// 返回请求密钥（即掩码 seed）与关联 nonce（hex）。
func (km *KeyManager) Issue(requestID, model string) (seed []byte, nonceHex string, err error) {
	nonce := make([]byte, 16)
	if _, err = rand.Read(nonce); err != nil {
		return nil, "", fmt.Errorf("teecore: 生成 nonce 失败: %w", err)
	}
	nonceHex = hexEncode(nonce)

	km.mu.Lock()
	defer km.mu.Unlock()
	ts := time.Now().UnixNano()
	derived := km.deriveLocked(requestID, model, ts)
	km.keys[nonceHex] = keyRecord{
		seed:     derived,
		masterID: km.masterID,
		issuedAt: time.Now(),
	}
	return append([]byte(nil), derived...), nonceHex, nil
}

// deriveLocked 派生请求密钥（须持锁）。
func (km *KeyManager) deriveLocked(requestID, model string, ts int64) []byte {
	mac := hmac.New(sha256.New, km.masterKey)
	_, _ = mac.Write([]byte(requestID))
	_, _ = mac.Write([]byte("||"))
	_, _ = mac.Write([]byte(model))
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], uint64(ts))
	_, _ = mac.Write(tsb[:])
	return mac.Sum(nil)
}

// Lookup 按 nonce 回溯请求密钥（推理服务解密用）。返回副本。
func (km *KeyManager) Lookup(nonceHex string) ([]byte, bool) {
	km.mu.Lock()
	defer km.mu.Unlock()
	rec, ok := km.keys[nonceHex]
	if !ok {
		return nil, false
	}
	return append([]byte(nil), rec.seed...), true
}

// MasterID 当前主密钥版本（观测/审计用）。
func (km *KeyManager) MasterID() uint64 {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.masterID
}

// wipe 清零敏感内存（统一使用 internal/memzero，防止 dead-store elimination）。
func wipe(b []byte) {
	memzero.Bytes(b)
}

func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexDigits[v>>4]
		out[i*2+1] = hexDigits[v&0x0F]
	}
	return string(out)
}
