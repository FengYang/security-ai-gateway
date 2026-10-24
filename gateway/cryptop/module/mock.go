package cryptopmodule

// mock.go —— MockBackend：内存密钥对象 + 软件国密委托的功能验证后端。
//
// **合规声明（务必如实）**：mock 后端**不满足密评**——密钥对象存于进程内存、
// 运算由软件国密库（gmsm）执行。仅用于：① 适配层单测（句柄生命周期/错误映射/
// 会话池/KAT 交叉验签）；② 无硬件环境的联调。**禁止用于生产合规声明**；
// 生产路径由 NewBackend 选择 sdf/pkcs11（厂商 SDK 随 S3-a 接入）。
//
// 与真实后端的行为对齐点（使测试有意义）：
//   - KeyRef 为不透明 token（mock:<seq>），密钥字节不返回给调用方（B-6.1-4）；
//   - 会话池语义同 B-6.1-7（max/queue/排队/耗尽）；
//   - 能力探测与 R-S3-11 启动校验同生产路径；
//   - 故障注入字段（Fail*）供故障切换/错误映射测试使用。

import (
	"encoding/hex"
	"fmt"
	"sync"

	"github.com/emmansun/gmsm/sm2"
)

// MockBackend 内存 mock 后端（实现 ModuleBackend）。
type MockBackend struct {
	mu   sync.RWMutex
	cfg  *Config
	caps Capabilities

	pool *SessionPool

	keys map[string]*mockKey // token(hex) → 密钥对象
	seq  uint64

	health HealthLevel

	// ---- 故障注入（测试用；nil = 不注入）----
	FailSeal   error
	FailOpen   error
	FailSign   error
	FailVerify error
	FailRand   error
	FailECDH   error
	FailKDF    error
	FailInit   error
	FailHealth bool // true = Health() 恒返回 HealthDown
}

type mockKey struct {
	bytes []byte
	usage string // sign|ecdh|kek|dek|""（未标注）
	alg   string // sm2|sm4
}

// NewMockBackend 构造 mock 后端（未 Init；配置经 Init 应用）。
func NewMockBackend() *MockBackend {
	return &MockBackend{
		keys:   map[string]*mockKey{},
		caps:   Capabilities{Backend: BackendMock, Vendor: "mock", Model: "in-memory", Mechanisms: DefaultRequiredMechanisms()},
		health: HealthOK,
	}
}

// NewBackend 按配置构造后端（生产入口）。
//
// 当前可用：mock（功能验证）、pkcs11（M4-1：cgo 绑定，须 -tags pkcs11 构建；
// 生命周期与 Rand 已实现，密码运算方法 M4-2 起逐步接入，未实现即 fail-closed）。
// sdf 的厂商 cgo 绑定随 S3-a 采购 SDK 后接入——未接入前返回明确错误
// （fail-closed 启动拒），**绝不静默回退 mock/软件**冒充合规（C-3/P4）。
func NewBackend(cfg *Config) (ModuleBackend, error) {
	if cfg == nil {
		return nil, fmt.Errorf("module: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	switch cfg.Backend {
	case BackendMock:
		return NewMockBackend(), nil
	case BackendPKCS11:
		return newPKCS11Backend(cfg)
	case BackendSDF:
		return nil, fmt.Errorf("%w: backend=sdf 的厂商 SDK 绑定未随源码提供（S3-a 采购到位后接入 sdf.go；当前 fail-closed 启动拒）",
			ErrNotImplemented)
	default:
		return nil, fmt.Errorf("module: 未知 backend=%q", cfg.Backend)
	}
}

// ---- 生命周期 ----

func (m *MockBackend) Init(cfg *Config) error {
	if cfg == nil {
		return fmt.Errorf("mock: nil config")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}
	if m.FailInit != nil {
		return m.FailInit
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	// R-S3-11：能力须覆盖 RequiredMechanisms（mock 恒全覆盖，但保留校验路径
	// 使真实后端接入时行为一致；同时验证配置里的机制名合法）。
	if err := CheckCapabilities(m.caps, cfg.RequiredMechanisms); err != nil {
		return err
	}
	var seq uintptr
	pool, err := NewSessionPool(cfg.MaxSessions, cfg.SessionQueueSize,
		func() (Session, error) {
			seq++
			return Session(seq), nil
		},
		func(s Session) error { return nil })
	if err != nil {
		return err
	}
	if m.pool != nil {
		_ = m.pool.Close() // 重复 Init：关旧池（测试场景）
	}
	m.pool = pool
	return nil
}

func (m *MockBackend) Capabilities() Capabilities {
	m.mu.RLock()
	defer m.mu.RUnlock()
	caps := m.caps
	caps.Mechanisms = append([]string(nil), m.caps.Mechanisms...)
	return caps
}

func (m *MockBackend) AcquireSession() (Session, error) {
	m.mu.RLock()
	pool := m.pool
	m.mu.RUnlock()
	if pool == nil {
		return 0, ErrModuleUnavailable
	}
	return pool.Acquire()
}

func (m *MockBackend) ReleaseSession(s Session) error {
	m.mu.RLock()
	pool := m.pool
	m.mu.RUnlock()
	if pool == nil {
		return ErrModuleUnavailable
	}
	return pool.Release(s)
}

func (m *MockBackend) Health() HealthLevel {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.FailHealth {
		return HealthDown
	}
	return m.health
}

// PoolStats 会话池状态快照（测试与 cryptop_module_sessions_active 指标用）。
func (m *MockBackend) PoolStats() PoolStats {
	m.mu.RLock()
	pool := m.pool
	m.mu.RUnlock()
	if pool == nil {
		return PoolStats{}
	}
	return pool.Stats()
}

func (m *MockBackend) Close() error {
	m.mu.Lock()
	pool := m.pool
	m.pool = nil
	keys := m.keys
	m.keys = map[string]*mockKey{}
	m.mu.Unlock()
	for _, k := range keys { // 零化后丢弃（mock 语义；真实后端由模块销毁）
		for i := range k.bytes {
			k.bytes[i] = 0
		}
	}
	if pool != nil {
		return pool.Close()
	}
	return nil
}

// ---- 内部辅助 ----

func (m *MockBackend) lookup(keyRef KeyRef) (*mockKey, error) {
	if len(keyRef) == 0 {
		return nil, ErrKeyNotFound
	}
	m.mu.RLock()
	k, ok := m.keys[hex.EncodeToString(keyRef)]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: ref=%s", ErrKeyNotFound, hex.EncodeToString(keyRef))
	}
	return k, nil
}

func (m *MockBackend) register(k *mockKey, alias string) KeyRef {
	m.mu.Lock()
	defer m.mu.Unlock()
	if alias == "" {
		m.seq++
		alias = fmt.Sprintf("mock:%d", m.seq)
	} else {
		alias = "mock:" + alias
	}
	token := []byte(alias)
	m.keys[hex.EncodeToString(token)] = k
	return KeyRef(token)
}

func (m *MockBackend) newSymmetricKey() ([]byte, error) {
	return mockRand(mockSymKeySize)
}

// ---- 对称运算 ----

func (m *MockBackend) Seal(keyRef KeyRef, nonce, plaintext, aad []byte) ([]byte, error) {
	if m.FailSeal != nil {
		return nil, m.FailSeal
	}
	k, err := m.lookup(keyRef)
	if err != nil {
		return nil, err
	}
	if k.alg != "sm4" {
		return nil, fmt.Errorf("mock: ref=%s 非对称密钥（alg=%s）", keyRef, k.alg)
	}
	return mockSeal(k.bytes, nonce, plaintext, aad)
}

func (m *MockBackend) Open(keyRef KeyRef, nonce, ciphertext, aad []byte) ([]byte, error) {
	if m.FailOpen != nil {
		return nil, m.FailOpen
	}
	k, err := m.lookup(keyRef)
	if err != nil {
		return nil, err
	}
	if k.alg != "sm4" {
		return nil, fmt.Errorf("mock: ref=%s 非对称密钥（alg=%s）", keyRef, k.alg)
	}
	return mockOpen(k.bytes, nonce, ciphertext, aad)
}

func (m *MockBackend) Hash(data []byte) ([]byte, error) { return mockHash(data) }

func (m *MockBackend) HMAC(keyRef KeyRef, data []byte) ([]byte, error) {
	k, err := m.lookup(keyRef)
	if err != nil {
		return nil, err
	}
	return mockHMAC(k.bytes, data)
}

func (m *MockBackend) KDF(parentRef KeyRef, salt, info []byte, outLen int, alias string) ([]byte, error) {
	if m.FailKDF != nil {
		return nil, m.FailKDF
	}
	k, err := m.lookup(parentRef)
	if err != nil {
		return nil, err
	}
	out, err := mockKDF(k.bytes, salt, info, outLen)
	if err != nil {
		return nil, err
	}
	if alias != "" {
		// D-4：派生结果同时登记为模块内对象（模块内 KDF 路径的 mock 等价）。
		cp := append([]byte(nil), out...)
		m.register(&mockKey{bytes: cp, alg: "sm4", usage: "dek"}, alias)
	}
	return out, nil
}

func (m *MockBackend) Rand(n int) ([]byte, error) {
	if m.FailRand != nil {
		return nil, m.FailRand
	}
	// mock 语义：软件随机源（真实后端须模块 CSPRNG + R-S3-12 启动自检）。
	return mockRand(n)
}

// ---- 非对称运算 ----

func (m *MockBackend) Sign(privRef KeyRef, msg []byte, uid string) ([]byte, error) {
	if m.FailSign != nil {
		return nil, m.FailSign
	}
	k, err := m.lookup(privRef)
	if err != nil {
		return nil, err
	}
	if k.alg != "sm2" || k.usage != UsageSign {
		return nil, fmt.Errorf("mock: ref=%s 非 SM2 签名密钥（usage=%s）", privRef, k.usage)
	}
	return mockSign(k.bytes, msg, uid)
}

func (m *MockBackend) Verify(pub, msg, sig []byte, uid string) error {
	if m.FailVerify != nil {
		return m.FailVerify
	}
	return mockVerify(pub, msg, sig, uid)
}

func (m *MockBackend) GenerateKeyPair(usage string) (KeyRef, []byte, error) {
	if usage != UsageSign && usage != UsageECDH {
		return nil, nil, fmt.Errorf("mock: 未知 usage=%q（sign|ecdh）", usage)
	}
	priv, pub, err := mockGenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	ref := m.register(&mockKey{bytes: priv, alg: "sm2", usage: usage}, "")
	return ref, pub, nil
}

func (m *MockBackend) ECDH(privRef KeyRef, peerPub []byte) ([]byte, error) {
	if m.FailECDH != nil {
		return nil, m.FailECDH
	}
	k, err := m.lookup(privRef)
	if err != nil {
		return nil, err
	}
	if k.alg != "sm2" || k.usage != UsageECDH {
		return nil, fmt.Errorf("mock: ref=%s 非 SM2 协商密钥（usage=%s）", privRef, k.usage)
	}
	// B-6.1-9：共享秘密为三级会话域材料，用后由调用方零化。
	return mockECDH(k.bytes, peerPub)
}

// ---- 密钥管理 ----

func (m *MockBackend) WrapKey(kekRef KeyRef, dek []byte) ([]byte, error) {
	k, err := m.lookup(kekRef)
	if err != nil {
		return nil, err
	}
	if k.alg != "sm4" {
		return nil, fmt.Errorf("mock: ref=%s 非 SM4 KEK", kekRef)
	}
	nonce, err := mockRand(mockNonceSize)
	if err != nil {
		return nil, err
	}
	ct, err := mockSeal(k.bytes, nonce, dek, []byte(mockWrapAAD))
	if err != nil {
		return nil, err
	}
	return append(nonce, ct...), nil
}

func (m *MockBackend) UnwrapKey(kekRef KeyRef, wrapped []byte) ([]byte, error) {
	k, err := m.lookup(kekRef)
	if err != nil {
		return nil, err
	}
	if k.alg != "sm4" {
		return nil, fmt.Errorf("mock: ref=%s 非 SM4 KEK", kekRef)
	}
	if len(wrapped) <= mockNonceSize {
		return nil, fmt.Errorf("mock: wrapped 长度非法")
	}
	return mockOpen(k.bytes, wrapped[:mockNonceSize], wrapped[mockNonceSize:], []byte(mockWrapAAD))
}

func (m *MockBackend) GenerateKey(spec, alias string) (KeyRef, error) {
	alg := "sm4"
	switch spec {
	case "", "sm4-128", "sm4":
		// 默认 SM4-128
	case "sm2-sign":
		alg = "sm2"
	default:
		return nil, fmt.Errorf("mock: 未知 spec=%q", spec)
	}
	if alg == "sm2" {
		priv, _, err := mockGenerateKeyPair()
		if err != nil {
			return nil, err
		}
		return m.register(&mockKey{bytes: priv, alg: "sm2", usage: UsageSign}, alias), nil
	}
	b, err := m.newSymmetricKey()
	if err != nil {
		return nil, err
	}
	return m.register(&mockKey{bytes: b, alg: alg, usage: "dek"}, alias), nil
}

// ImportKey 导入外部密钥字节（M4：静态密钥/仪式导入路径）。
// 字节仅瞬态经适配层进入模块内对象，不缓存（B-6.1-1）。
func (m *MockBackend) ImportKey(spec string, key []byte, alias string) (KeyRef, error) {
	switch spec {
	case "", "sm4-128", "sm4":
		if len(key) != mockSymKeySize {
			return nil, fmt.Errorf("mock: SM4 密钥长度 %d != %d", len(key), mockSymKeySize)
		}
		cp := append([]byte(nil), key...)
		return m.register(&mockKey{bytes: cp, alg: "sm4", usage: "dek"}, alias), nil
	case "sm2-sign", "sm2-ecdh":
		if len(key) != mockPrivSize {
			return nil, fmt.Errorf("mock: SM2 私钥长度 %d != %d", len(key), mockPrivSize)
		}
		// 校验可解析（fail-fast；不缓存明文于适配层）。
		if _, err := sm2.NewPrivateKey(append([]byte(nil), key...)); err != nil {
			return nil, fmt.Errorf("mock: SM2 私钥不可解析: %w", err)
		}
		cp := append([]byte(nil), key...)
		return m.register(&mockKey{bytes: cp, alg: "sm2", usage: UsageSign}, alias), nil
	default:
		return nil, fmt.Errorf("mock: 未知 spec=%q", spec)
	}
}

func (m *MockBackend) DestroyKey(keyRef KeyRef) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := hex.EncodeToString(keyRef)
	k, ok := m.keys[key]
	if !ok {
		return fmt.Errorf("%w: ref=%s", ErrKeyNotFound, key)
	}
	for i := range k.bytes {
		k.bytes[i] = 0
	}
	delete(m.keys, key)
	return nil
}

func (m *MockBackend) RotateKey(oldRef KeyRef, spec string) (KeyRef, error) {
	m.mu.RLock()
	old, ok := m.keys[hex.EncodeToString(oldRef)]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("%w: ref=%s", ErrKeyNotFound, hex.EncodeToString(oldRef))
	}
	// mock 轮换语义：同规格生成新对象并登记（旧对象保留由调用方归档——R2-06 的
	// "只解不封"编排在 M4/keystore 层，不在后端）。
	if spec == "" {
		spec = old.alg + "-128"
		if old.alg == "sm2" {
			spec = "sm2-sign"
		}
	}
	return m.GenerateKey(spec, "")
}

// 编译期契约保证。
var _ ModuleBackend = (*MockBackend)(nil)
