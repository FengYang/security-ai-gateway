// Package cryptoops — 段① 信封**密码求值**（P0-4 §5.4.5「拆包」）。
//
// 从 `protocol/go` 拆出的**求值部分**：AEAD（AES-256-GCM / SM4-GCM）、HKDF 子密钥派生、
// 密码套件注册，以及协议消息的 HMAC 签名（见 sign.go）。
//
// **链接约束（R-11 / §9.1 门禁 1）**：本包**仅 Go 服务与 cryptop sidecar 可链接**；
// Wasm 插件**禁止**链入（`protocol/go/cryptoops` 在门禁 1 拦截模式内）。
// framing（`Envelope` 结构、`Encode`/`Decode`、`CounterWindow`、`CheckStreamSequence`、
// 常量、AAD/nonce 序列化）留在 `protocol/go`（插件允许链入，见 §5.4.5 注）。
package cryptoops

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"sync"

	protocol "security-ai-gateway/protocol/go"
)

// ---------- 密码套件敏捷接缝（国密预留，不做双实现） ----------

// CryptoSuite 密码套件接口。默认 AES-256-GCM（protocol.SuiteAESGCM）；
// SM4-GCM 套件见 sm.go（suite↔provider 绑死，仅 sm-* provider 可构造）。
// 双端同步升级，旧套件信封在新套件下显式拒绝。
type CryptoSuite interface {
	SuiteID() byte
	Seal(key, nonce, aad, plaintext []byte) ([]byte, error)
	Open(key, nonce, aad, ciphertext []byte) ([]byte, error)
}

// aesGCMSuite 标准库 AES 实现（profile 无关；intl/sm 两档皆可解 AES wire——双读）。
type aesGCMSuite struct{}

func (aesGCMSuite) SuiteID() byte { return protocol.SuiteAESGCM }

func (aesGCMSuite) Seal(key, nonce, aad, plaintext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plaintext, aad), nil
}

func (aesGCMSuite) Open(key, nonce, aad, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertext, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("envelope: AES 密钥无效: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("envelope: GCM 初始化失败: %w", err)
	}
	return gcm, nil
}

var (
	suiteMu   sync.RWMutex
	suiteByID = map[byte]CryptoSuite{protocol.SuiteAESGCM: aesGCMSuite{}}
)

// RegisterSuite 注册密码套件（国密敏捷接缝；套件 ID 进程内唯一）。
func RegisterSuite(s CryptoSuite) error {
	suiteMu.Lock()
	defer suiteMu.Unlock()
	if _, exists := suiteByID[s.SuiteID()]; exists {
		return fmt.Errorf("envelope: 套件 %d 已注册", s.SuiteID())
	}
	suiteByID[s.SuiteID()] = s
	return nil
}

func suiteFor(id byte) (CryptoSuite, error) {
	suiteMu.RLock()
	defer suiteMu.RUnlock()
	s, ok := suiteByID[id]
	if !ok {
		return nil, fmt.Errorf("envelope: 未知密码套件 %d", id)
	}
	return s, nil
}

// suiteKeySize 子密钥长度随 suite（§5.1.2 不变式 3）：AES-256-GCM→32；SM4-GCM→16；
// 未知 suite→0（调用点据 0 返回协议错误，**fail-closed**——不得默认 32，否则 sm 档解 SM4 wire 不可实现）。
func suiteKeySize(suite byte) int {
	switch suite {
	case protocol.SuiteAESGCM:
		return 32
	case protocol.SuiteSM4GCM:
		return sm4GCMSuiteKeyLen
	default:
		return 0
	}
}

// subkeyInfo 方向子密钥 HKDF info（域分离标签）。
// 标签随**方向**不随 suite（§7.2：KDF 域标签保持不变，算法随 profile）——故 AES 与 SM4
// 子密钥**前缀相同属预期**（HKDF-Expand 截断）；二者算法不同且长度分派由 suiteKeySize 保证。
var subkeyInfo = map[protocol.Direction][]byte{
	protocol.DirectionC2S: []byte("otpmask/kdf/enc/c2s/v1"),
	protocol.DirectionS2C: []byte("otpmask/kdf/enc/s2c/v1"),
}

// DeriveSubkey 从会话 K_enc 派生方向子密钥（HKDF-SHA256 域分离），**输出长度随 suite**。
// K_enc 仅存在于两端（插件内存 / tee-infer 会话）；子密钥由调用方用后零化。
//
// v1.2 修复 N-P0-1：签名增 `suite` 形参——v1.1 硬编码 32B 时，sm 档进程解 AES wire（需 32B）
// 与解 SM4 wire（需 16B）无法同时成立 ⇒ 双读不可实现。**open 侧须先读 wire `Envelope.Suite` 再派生**。
func DeriveSubkey(kEnc []byte, dir protocol.Direction, suite byte) ([]byte, error) {
	info, ok := subkeyInfo[dir]
	if !ok {
		return nil, fmt.Errorf("envelope: 未知方向 %d", byte(dir))
	}
	n := suiteKeySize(suite)
	if n == 0 {
		return nil, fmt.Errorf("envelope: 未知密码套件 %d（无法派生密钥）", suite)
	}
	return hkdfSHA256(kEnc, nil, info, n), nil
}

// ---------- 加解密入口 ----------

// SealEnvelope 以会话 K_enc 加密明文（默认 AES-256-GCM）并编码信封 wire。
// counter 由发送方保证同一方向下唯一（单调递增即可）。
func SealEnvelope(kEnc []byte, sessionID, endpoint string, dir protocol.Direction, counter uint64, plaintext []byte) ([]byte, error) {
	return SealEnvelopeWithSuite(kEnc, protocol.SuiteAESGCM, sessionID, endpoint, dir, counter, plaintext)
}

// SealEnvelopeWithSuite 以调用者指定的 suite 加密明文并编码信封 wire（国密 S2 §5.1.2）。
//
// suite = 本端本次会话协商出的套件（AES→32B / SM4→16B 密钥），密钥长度随 suite 派生
// （`suiteKeySize`）。该 suite 必须已 `RegisterSuite`，否则 fail-closed。
// 既有 `SealEnvelope` 即 `SealEnvelopeWithSuite(..., protocol.SuiteAESGCM, ...)`（保 wire 语义不变）。
func SealEnvelopeWithSuite(kEnc []byte, suite byte, sessionID, endpoint string, dir protocol.Direction, counter uint64, plaintext []byte) ([]byte, error) {
	s, err := suiteFor(suite)
	if err != nil {
		return nil, err
	}
	subkey, err := DeriveSubkey(kEnc, dir, suite)
	if err != nil {
		return nil, err
	}
	defer wipeSlice(subkey)
	ct, err := s.Seal(subkey, protocol.EnvelopeNonce(counter), protocol.EnvelopeAAD(sessionID, dir, counter, endpoint), plaintext)
	if err != nil {
		return nil, err
	}
	return protocol.EncodeEnvelope(&protocol.Envelope{
		Version:    protocol.EnvelopeVersion,
		Suite:      suite,
		Direction:  dir,
		Counter:    counter,
		Ciphertext: ct,
	})
}

// OpenEnvelope 解码信封并解密；版本/方向/套件/密钥/AAD 任一不匹配即失败（fail-closed）。
// 返回明文与信封计数器（供接收侧反重放窗口校验）。
func OpenEnvelope(kEnc []byte, sessionID, endpoint string, expectDir protocol.Direction, data []byte) ([]byte, uint64, error) {
	e, err := protocol.DecodeEnvelope(data)
	if err != nil {
		return nil, 0, err
	}
	if e.Version != protocol.EnvelopeVersion {
		return nil, 0, fmt.Errorf("envelope: 版本不匹配（got %d want %d）", e.Version, protocol.EnvelopeVersion)
	}
	if e.Direction != expectDir {
		return nil, 0, fmt.Errorf("envelope: 方向不匹配（got %s want %s）", e.Direction, expectDir)
	}
	suite, err := suiteFor(e.Suite)
	if err != nil {
		return nil, 0, err
	}
	// 先按 wire suite 派生（长度随 suite：AES 32B / SM4 16B），再解密——
	// sm 档进程据此可解 AES(Suite=1) 与 SM4(Suite=2) 两种 wire（双读，§5.1.3；未知 suite 已在 suiteFor 拒绝）。
	subkey, err := DeriveSubkey(kEnc, expectDir, e.Suite)
	if err != nil {
		return nil, 0, err
	}
	defer wipeSlice(subkey)
	pt, err := suite.Open(subkey, protocol.EnvelopeNonce(e.Counter), protocol.EnvelopeAAD(sessionID, expectDir, e.Counter, endpoint), e.Ciphertext)
	if err != nil {
		return nil, 0, fmt.Errorf("envelope: 解密失败（密钥/AAD/密文不匹配）: %w", err)
	}
	return pt, e.Counter, nil
}

// ---------- 辅助 ----------

func hkdfSHA256(ikm, salt, info []byte, length int) []byte {
	// RFC 5869 extract+expand
	prk := hmac.New(sha256.New, salt)
	prk.Write(ikm)
	prkBytes := prk.Sum(nil)
	out := make([]byte, 0, length)
	var t []byte
	counter := byte(1)
	for len(out) < length {
		mac := hmac.New(sha256.New, prkBytes)
		mac.Write(t)
		mac.Write(info)
		mac.Write([]byte{counter})
		t = mac.Sum(nil)
		out = append(out, t...)
		counter++
	}
	wipeSlice(prkBytes)
	return out[:length]
}

func wipeSlice(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
