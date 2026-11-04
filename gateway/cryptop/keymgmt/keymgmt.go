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
package keymgmt

import (
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
	seed     []byte
	masterID uint64
	issuedAt time.Time
}

// KeyManager 主密钥 + 请求密钥派生管理器（模拟 TEE 飞地内安全存储）。
//
// 并发安全；所有密钥仅内存驻留，轮换后旧主密钥在在途窗口内保留后销毁。
//
// deriveMaster（§6 三级链，P0-4 B6#9）：非 nil 时每次轮换的 master 不再随机，
// 而由二级租户 KEK 经 KDF 按 epoch 派生（KEK 来自 TenantKeyManager）；
// nil = 旧路径（随机/密封恢复实例级 master），行为不变。
type KeyManager struct {
	mu           sync.Mutex
	masterKey    []byte
	masterID     uint64
	masterGen    time.Time
	keys         map[string]keyRecord // nonce(hex) → 请求密钥
	masterTTL    time.Duration
	stop         chan struct{}
	closeOnce    sync.Once
	deriveMaster func(epoch uint64) []byte
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

// Close 停止轮换 goroutine（幂等：重复调用安全）。
func (km *KeyManager) Close() {
	km.closeOnce.Do(func() { close(km.stop) })
}

// rotateLocked 生成新主密钥并递增版本（须持锁）。
func (km *KeyManager) rotateLocked() error {
	if km.deriveMaster != nil {
		// 三级链：master = KDF(租户 KEK, epoch)——长度固定 32（KDF 输出弱约束，随 KEK 所属 profile 均可）。
		km.masterID++
		km.masterKey = km.deriveMaster(km.masterID)
		km.masterGen = time.Now()
		return nil
	}
	mk, err := cryptoProvider.Rand(32)
	if err != nil {
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
	nonce, err := cryptoProvider.Rand(16)
	if err != nil {
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
//
// 字节布局与现役**逐字节一致**：`requestID ‖ "||" ‖ model ‖ BE64(ts)`，MAC 经 cryptop
// （intl=HMAC-SHA256 逐字节等价；sm=HMAC-SM3）。
//
// ⚠️ **与 §5.4.4 映射的偏差（有意）**：该表原写"改为 `cryptop.KDF`"。`KDF`（HKDF-SHA256）会**改变
// 派生值**，而该值即 `/key/issue` 下发、TEE `/v1/infer` 回溯、插件侧掩码共用的**跨进程请求 seed**
// ⇒ 属 intl 行为变更。故本批**保留 HMAC 语义**、仅把求值下沉 Provider；是否切 KDF 需按"双读/迁移"
// 单独裁决（B5 批次）。
func (km *KeyManager) deriveLocked(requestID, model string, ts int64) []byte {
	buf := make([]byte, 0, len(requestID)+2+len(model)+8)
	buf = append(buf, requestID...)
	buf = append(buf, "||"...)
	buf = append(buf, model...)
	var tsb [8]byte
	binary.BigEndian.PutUint64(tsb[:], uint64(ts))
	buf = append(buf, tsb[:]...)
	return cryptoProvider.HMAC(km.masterKey, buf)
}

// Lookup 按 nonce 回溯请求密钥（推理服务解密用）。返回副本。
func (km *KeyManager) Lookup(nonceHex string) ([]byte, bool) {
	seed, _, ok := km.lookupDetail(nonceHex)
	return seed, ok
}

// lookupDetail 同 Lookup，额外返回签发时的 master 版本。
func (km *KeyManager) lookupDetail(nonceHex string) (seed []byte, masterID uint64, ok bool) {
	km.mu.Lock()
	defer km.mu.Unlock()
	rec, ok := km.keys[nonceHex]
	if !ok {
		return nil, 0, false
	}
	return append([]byte(nil), rec.seed...), rec.masterID, true
}

// MasterID 当前主密钥版本（观测/审计用）。
func (km *KeyManager) MasterID() uint64 {
	km.mu.Lock()
	defer km.mu.Unlock()
	return km.masterID
}

// wipeAll 零化当前 master 与全部请求种子并清空登记表（供 TenantKeyManager.DestroyTenant）。
// 调用后本实例不得再用（调用方须已先 Close 或保证无新 Issue）。
func (km *KeyManager) wipeAll() {
	km.mu.Lock()
	defer km.mu.Unlock()
	wipe(km.masterKey)
	for nonce, rec := range km.keys {
		wipe(rec.seed)
		delete(km.keys, nonce)
	}
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
