// 段① 载荷加密信封（P1a，GA-路线1发布规划）。
//
// 证明会话建立后，南向载荷以会话 K_enc 做 AEAD 信封加密：
//   - 方向子密钥：HKDF-SHA256(K_enc, info="otpmask/kdf/enc/{c2s|s2c}/v1")，
//     双方向密钥独立，防反射与跨方向重放
//   - nonce：12 字节 = 4 字节前缀 "OTPE" + 8 字节大端计数器；
//     同一方向子密钥下计数器唯一 ⇒ nonce 唯一（GCM 安全前提）
//   - AAD：sessionID/方向/计数器/endpoint 的规范化序列化，绑定传输上下文，
//     防跨会话/跨端点重放与乱序
//   - 反重放：接收侧 CounterWindow（64 槽滑动窗口，请求场景）或
//     CheckStreamSequence（SSE 分片严格递增）
//
// 信封 wire（Varint + length-prefixed，与既有消息风格一致）：
//
//	varint version      信封格式版本（当前 1）
//	varint suite        密码套件 ID（1 = AES-256-GCM；2 = SM4-GCM，国密 S2 §5.1.2）
//	byte  direction     1 = c2s（网关→TEE），2 = s2c（TEE→网关）
//	8 字节大端 counter  64bit 单调计数器
//	bytes ciphertext    varint 长度 + AEAD 密文（含 16 字节 GCM tag）

package protocol

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// Direction 信封传输方向。
type Direction byte

const (
	// DirectionC2S 客户端（网关 wasm 插件）→ TEE。
	DirectionC2S Direction = 1
	// DirectionS2C TEE → 客户端（网关 wasm 插件）。
	DirectionS2C Direction = 2
)

func (d Direction) String() string {
	switch d {
	case DirectionC2S:
		return "c2s"
	case DirectionS2C:
		return "s2c"
	default:
		return fmt.Sprintf("direction(%d)", byte(d))
	}
}

// EnvelopeVersion 信封 wire 格式版本。
const EnvelopeVersion byte = 1

// SuiteAESGCM 默认密码套件：AES-256-GCM。
const SuiteAESGCM byte = 1

// envelopeNoncePrefix nonce 固定前缀（与其他 GCM 用途的 nonce 空间域分离）。
var envelopeNoncePrefix = []byte("OTPE")

// 段① 信封绑定的南向端点（AAD endpoint 字段取值）。
// 双端常量对齐，不随网关路由别名漂移（如 tee-infer 的 /infer 别名仍绑定 /v1/infer）。
const (
	// EndpointKeyIssue 密钥签发端点（请求/响应均入信封）。
	EndpointKeyIssue = "/key/issue"
	// EndpointInfer 推理端点（请求、单响应与 SSE 分片均入信封）。
	EndpointInfer = "/v1/infer"
)

// subkeyInfo 方向子密钥 HKDF info（域分离标签）。
var subkeyInfo = map[Direction][]byte{
	DirectionC2S: []byte("otpmask/kdf/enc/c2s/v1"),
	DirectionS2C: []byte("otpmask/kdf/enc/s2c/v1"),
}

// suiteKeySize 子密钥长度随 suite（§5.1.2 不变式 3）：AES-256-GCM→32；SM4-GCM→16；
// 未知 suite→0（调用点据 0 返回协议错误，**fail-closed**——不得默认 32，否则 sm 档解 SM4 wire 不可实现）。
func suiteKeySize(suite byte) int {
	switch suite {
	case SuiteAESGCM:
		return 32
	case SuiteSM4GCM:
		return sm4GCMSuiteKeyLen
	default:
		return 0
	}
}

// DeriveSubkey 从会话 K_enc 派生方向子密钥（HKDF-SHA256 域分离），**输出长度随 suite**。
// K_enc 仅存在于两端（插件内存 / tee-infer 会话）；子密钥由调用方用后零化。
//
// v1.2 修复 N-P0-1：签名增 `suite` 形参——v1.1 硬编码 32B 时，sm 档进程解 AES wire（需 32B）
// 与解 SM4 wire（需 16B）无法同时成立 ⇒ 双读不可实现。**open 侧须先读 wire `Envelope.Suite` 再派生**。
func DeriveSubkey(kEnc []byte, dir Direction, suite byte) ([]byte, error) {
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

// envelopeNonce 由计数器确定性派生 12 字节 GCM nonce。
func envelopeNonce(counter uint64) []byte {
	nonce := make([]byte, 12)
	copy(nonce, envelopeNoncePrefix)
	binary.BigEndian.PutUint64(nonce[4:], counter)
	return nonce
}

// EnvelopeAAD 构造规范化 AAD（sessionID/方向/计数器/endpoint）。
// 双端独立构造相同 AAD，不随 wire 传输。
func EnvelopeAAD(sessionID string, dir Direction, counter uint64, endpoint string) []byte {
	buf := make([]byte, 0, 14+len(sessionID)+1+8+len(endpoint)+4)
	buf = append(buf, []byte("otpmask/aad/v1")...)
	buf = putString(buf, sessionID)
	buf = append(buf, byte(dir))
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	buf = append(buf, ctr[:]...)
	buf = putString(buf, endpoint)
	return buf
}

// ---------- 密码套件敏捷接缝（国密预留，不做双实现） ----------

// CryptoSuite 密码套件接口。默认 AES-256-GCM（SuiteAESGCM）；
// 落地国密时以新 SuiteID 注册 SM4-GCM 套件（wire 上 suite 字段随之切换），
// 双端同步升级，旧套件信封在新套件下显式拒绝。
type CryptoSuite interface {
	SuiteID() byte
	Seal(key, nonce, aad, plaintext []byte) ([]byte, error)
	Open(key, nonce, aad, ciphertext []byte) ([]byte, error)
}

type aesGCMSuite struct{}

func (aesGCMSuite) SuiteID() byte { return SuiteAESGCM }

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
	suiteByID = map[byte]CryptoSuite{SuiteAESGCM: aesGCMSuite{}}
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

// ---------- 信封结构与 wire 编解码 ----------

// Envelope 段① 加密信封。
type Envelope struct {
	Version    byte      // 信封格式版本
	Suite      byte      // 密码套件 ID
	Direction  Direction // 传输方向
	Counter    uint64    // 64bit 单调计数器（nonce 与 AAD 的来源）
	Ciphertext []byte    // AEAD 密文（含 16 字节 GCM tag）
}

// EncodeEnvelope 信封 wire 编码。
func EncodeEnvelope(e *Envelope) ([]byte, error) {
	if e.Direction != DirectionC2S && e.Direction != DirectionS2C {
		return nil, fmt.Errorf("envelope: 非法方向 %d", byte(e.Direction))
	}
	buf := putVarint(nil, uint64(e.Version))
	buf = putVarint(buf, uint64(e.Suite))
	buf = append(buf, byte(e.Direction))
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], e.Counter)
	buf = append(buf, ctr[:]...)
	buf = putBytes(buf, e.Ciphertext)
	return buf, nil
}

// DecodeEnvelope 信封 wire 解码（严格模式：拒绝尾部冗余字节）。
func DecodeEnvelope(data []byte) (*Envelope, error) {
	pos := 0
	var v, s uint64
	var err error
	if v, pos, err = readVarint(data, pos); err != nil {
		return nil, err
	}
	if s, pos, err = readVarint(data, pos); err != nil {
		return nil, err
	}
	if pos >= len(data) {
		return nil, errors.New("envelope: direction 截断")
	}
	dir := Direction(data[pos])
	pos++
	if pos+8 > len(data) {
		return nil, errors.New("envelope: counter 截断")
	}
	counter := binary.BigEndian.Uint64(data[pos : pos+8])
	pos += 8
	ct, pos, err := readLenBytes(data, pos)
	if err != nil {
		return nil, err
	}
	if pos != len(data) {
		return nil, errors.New("envelope: 存在尾部冗余字节")
	}
	return &Envelope{Version: byte(v), Suite: byte(s), Direction: dir, Counter: counter, Ciphertext: ct}, nil
}

// ---------- 加解密入口 ----------

// SealEnvelope 以会话 K_enc 加密明文（默认 AES-256-GCM）并编码信封 wire。
// counter 由发送方保证同一方向下唯一（单调递增即可）。
func SealEnvelope(kEnc []byte, sessionID, endpoint string, dir Direction, counter uint64, plaintext []byte) ([]byte, error) {
	return SealEnvelopeWithSuite(kEnc, SuiteAESGCM, sessionID, endpoint, dir, counter, plaintext)
}

// SealEnvelopeWithSuite 以调用者指定的 suite 加密明文并编码信封 wire（国密 S2 §5.1.2）。
//
// suite = 本端本次会话协商出的套件（AES→32B / SM4→16B 密钥），密钥长度随 suite 派生
// （`suiteKeySize`）。该 suite 必须已 `RegisterSuite`，否则 fail-closed。
// 既有 `SealEnvelope` 即 `SealEnvelopeWithSuite(..., SuiteAESGCM, ...)`（保 wire 语义不变）。
func SealEnvelopeWithSuite(kEnc []byte, suite byte, sessionID, endpoint string, dir Direction, counter uint64, plaintext []byte) ([]byte, error) {
	s, err := suiteFor(suite)
	if err != nil {
		return nil, err
	}
	subkey, err := DeriveSubkey(kEnc, dir, suite)
	if err != nil {
		return nil, err
	}
	defer wipeSlice(subkey)
	ct, err := s.Seal(subkey, envelopeNonce(counter), EnvelopeAAD(sessionID, dir, counter, endpoint), plaintext)
	if err != nil {
		return nil, err
	}
	return EncodeEnvelope(&Envelope{
		Version:    EnvelopeVersion,
		Suite:      suite,
		Direction:  dir,
		Counter:    counter,
		Ciphertext: ct,
	})
}

// OpenEnvelope 解码信封并解密；版本/方向/套件/密钥/AAD 任一不匹配即失败（fail-closed）。
// 返回明文与信封计数器（供接收侧反重放窗口校验）。
func OpenEnvelope(kEnc []byte, sessionID, endpoint string, expectDir Direction, data []byte) ([]byte, uint64, error) {
	e, err := DecodeEnvelope(data)
	if err != nil {
		return nil, 0, err
	}
	if e.Version != EnvelopeVersion {
		return nil, 0, fmt.Errorf("envelope: 版本不匹配（got %d want %d）", e.Version, EnvelopeVersion)
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
	pt, err := suite.Open(subkey, envelopeNonce(e.Counter), EnvelopeAAD(sessionID, expectDir, e.Counter, endpoint), e.Ciphertext)
	if err != nil {
		return nil, 0, fmt.Errorf("envelope: 解密失败（密钥/AAD/密文不匹配）: %w", err)
	}
	return pt, e.Counter, nil
}

// ---------- 接收侧反重放 ----------

// CounterWindow 64 槽计数器反重放滑动窗口（RFC 4303 思路）。
// 窗口覆盖 [highest-63, highest]：窗口内重复计数器（重放）与落后窗口的
// 计数器（过期乱序）拒绝，窗口内有界乱序容忍（并发请求共享会话场景）。
// 非并发安全：每个（会话 × 方向）独立持有一个实例并串行 Check。
type CounterWindow struct {
	highest uint64
	seen    uint64 // 位图：bit 63 ↔ highest，bit i ↔ highest-(63-i)
	started bool
}

// Check 校验并登记计数器；重放/越窗返回错误。
func (w *CounterWindow) Check(counter uint64) error {
	if !w.started {
		w.started = true
		w.highest = counter
		w.seen = 1 << 63
		return nil
	}
	if counter > w.highest {
		d := counter - w.highest
		if d >= 64 {
			w.seen = 0
		} else {
			w.seen >>= d
		}
		w.highest = counter
		w.seen |= 1 << 63
		return nil
	}
	if w.highest-counter >= 64 {
		return fmt.Errorf("envelope: 计数器 %d 落后窗口（highest=%d），拒绝（重放/过期）", counter, w.highest)
	}
	bit := uint64(1) << (63 - (w.highest - counter))
	if w.seen&bit != 0 {
		return fmt.Errorf("envelope: 计数器 %d 重复，拒绝（重放）", counter)
	}
	w.seen |= bit
	return nil
}

// CheckStreamSequence SSE 流式分片序号校验：严格递增（got == last+1）。
// 跳号/回退/重复一律拒绝——流内容顺序被破坏即 fail-closed。
func CheckStreamSequence(last, got uint64) error {
	if got != last+1 {
		return fmt.Errorf("envelope: 流序号乱序（last=%d got=%d），拒绝", last, got)
	}
	return nil
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
