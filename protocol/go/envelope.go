// 段① 载荷加密信封——**framing / 编码部分**（P0-4 §5.4.5「拆包」）。
//
// 本文件只保留**纯字典/编码**：信封 wire 结构、Encode/Decode、计数器反重放窗口、
// 流式序号校验、方向/套件/端点常量、AAD 与 nonce 的确定性序列化。
// **密码求值（AEAD / HKDF / 密码套件注册）已下沉 `protocol/go/cryptoops`**——
// 仅 Go 服务与 cryptop sidecar 可链接；Wasm 插件**只**链入本包（R-11 / §9.1 门禁 1）。
//
// 证明会话建立后，南向载荷以会话 K_enc 做 AEAD 信封加密：
//   - 方向子密钥：HKDF-SHA256(K_enc, info="otpmask/kdf/enc/{c2s|s2c}/v1")，
//     双方向密钥独立，防反射与跨方向重放（派生实现见 cryptoops.DeriveSubkey）
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
	"encoding/binary"
	"errors"
	"fmt"
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

// SuiteSM4GCM 国密密码套件：SM4-GCM。
// wire suite 字节恒为 2（`SuiteAESGCM=1` 已冻结，B-5.1-3——新增 suite 不得改变既有 suite 的字节值）。
// 注：套件**求值实现**（`sm4GCMSuite`/`RegisterSM4Suite`）在 `protocol/go/cryptoops`（§5.4.5 拆包）。
const SuiteSM4GCM byte = 2

// envelopeNoncePrefix nonce 固定前缀（与其他 GCM 用途的 nonce 空间域分离）。
var envelopeNoncePrefix = []byte("OTPE")

// 方向子密钥 HKDF info 域分离标签（wire 常量，双端必须逐字一致）。
//
// **单一事实源**：`cryptoops.DeriveSubkey`（Go 服务/sidecar 内联派生）与插件侧
// `cryptop sidecar /v1/kdf`（R8-P1-1：插件经本 info 派生方向子密钥 KeyRef）**共同引用**本函数，
// 避免两处字面量漂移导致插件信封与 tee-infer `OpenEnvelope` 不可互通。
const (
	// subkeyInfoC2S 客户端→TEE 方向子密钥 info。
	subkeyInfoC2S = "otpmask/kdf/enc/c2s/v1"
	// subkeyInfoS2C TEE→客户端方向子密钥 info。
	subkeyInfoS2C = "otpmask/kdf/enc/s2c/v1"
)

// EnvelopeSubkeyInfo 返回方向子密钥的 HKDF info 标签字节（B-5.1-3 冻结）。
// 两个合法方向恒返回非 nil；未知方向返回 nil（调用方应 fail-closed 拒绝）。
func EnvelopeSubkeyInfo(dir Direction) []byte {
	switch dir {
	case DirectionC2S:
		return []byte(subkeyInfoC2S)
	case DirectionS2C:
		return []byte(subkeyInfoS2C)
	default:
		return nil
	}
}

// 段① 信封绑定的南向端点（AAD endpoint 字段取值）。
// 双端常量对齐，不随网关路由别名漂移（如 tee-infer 的 /infer 别名仍绑定 /v1/infer）。
const (
	// EndpointKeyIssue 密钥签发端点（请求/响应均入信封）。
	EndpointKeyIssue = "/key/issue"
	// EndpointInfer 推理端点（请求、单响应与 SSE 分片均入信封）。
	EndpointInfer = "/v1/infer"
)

// EnvelopeNonce 由计数器确定性派生 12 字节 GCM nonce。
// 发包侧与解包侧（cryptoops）共用同一派生式，保证 nonce 一致。
func EnvelopeNonce(counter uint64) []byte {
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
	buf = PutString(buf, sessionID)
	buf = append(buf, byte(dir))
	var ctr [8]byte
	binary.BigEndian.PutUint64(ctr[:], counter)
	buf = append(buf, ctr[:]...)
	buf = PutString(buf, endpoint)
	return buf
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
	buf = PutBytes(buf, e.Ciphertext)
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
