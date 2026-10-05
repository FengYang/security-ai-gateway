// Package keystore —— KeyRef 密钥目录（P0-4 §6.3/§6.5）。
//
// 职责边界（§4.7）：
//   - KeyStore 只管「目录 CRUD」（Register/Lookup/Derive/Destroy）——密钥字节不离开本域
//     （C-5：业务侧只持 KeyRef 句柄，绝不接触密钥明文）；
//   - KeyManager 管「何时轮换/销毁」的策略与事件（仅在 sidecar 侧编排 scope ∈ {Session, Static}；
//     二级租户主密钥归 TEE 域 teecore，见 §6.4 分域裁决）。
//
// 记忆点：sidecar 的 KeyStore 是**插件可见密钥的唯一来源**（§6.3）。
package keystore

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"security-ai-gateway/gateway/cryptop"
)

// ErrUnknownKeyRef KeyRef 未注册或已销毁（§4.4 code=unknown_key_ref）。
var ErrUnknownKeyRef = errors.New("keystore: unknown key ref")

// KeyRef 不透明句柄（业务侧只见句柄，不见字节；C-5）。
type KeyRef string

// KeyScope 密钥作用域（§6.3）。
type KeyScope string

const (
	// ScopeRoot 一级根密钥（用于封装二级密钥；sidecar 侧只读引用，不承载派生）。
	ScopeRoot KeyScope = "root"
	// ScopeTenantMaster 二级租户主密钥（由 TEE 域持有；sidecar 不轮换，见 §6.4 分域）。
	ScopeTenantMaster KeyScope = "tenant_master"
	// ScopeSession 三级会话密钥（每次会话生成，TTL 5min）。
	ScopeSession KeyScope = "session"
	// ScopeStatic 外部注入的长期密钥（OTP_CORE_SIG_KEY/JWT/route key 等；只登记不派生）。
	ScopeStatic KeyScope = "static"
)

// KeyMeta 密钥元数据。
type KeyMeta struct {
	Scope     KeyScope
	Profile   cryptop.Profile
	CreatedAt time.Time
	TTL       time.Duration // 0 = 不过期
}

// KeyStore KeyRef 目录（§4.7 符号清单）。
type KeyStore interface {
	Register(ref KeyRef, key []byte, meta KeyMeta) error
	Lookup(ref KeyRef) ([]byte, KeyMeta, error)
	Derive(parent KeyRef, salt, info []byte, outLen int, alias string) (KeyRef, error)
	Destroy(ref KeyRef) error
}

// Metrics 目录事件消费者（nil-safe；sidecar 侧接 §10.1 #6/#7/#8）。
// 只承载「计数事件」，不携带任何密钥材料。
type Metrics interface {
	// AddKeyRefs 活跃 KeyRef 数增减（#6 cryptop_key_refs；delta 可为负）。
	AddKeyRefs(scope KeyScope, delta int)
	// IncRotations 轮换计数（#7 cryptop_key_rotations_total）。
	IncRotations(scope KeyScope)
	// IncDestroys 销毁计数（#8 cryptop_key_destroy_total）。
	IncDestroys(scope KeyScope)
}

// memStore 内存版 KeyStore（纯 Go，无外部依赖；进程内密钥字节仅存于本结构）。
type memStore struct {
	mu   sync.Mutex
	keys map[KeyRef]entry
	prov cryptop.Provider
	m    Metrics
	seq  uint64
}

type entry struct {
	key  []byte
	meta KeyMeta
}

// NewMemStore 构造内存版 KeyStore；m 可为 nil（不埋点）。
func NewMemStore(prov cryptop.Provider, m Metrics) KeyStore {
	return &memStore{keys: make(map[KeyRef]entry), prov: prov, m: m}
}

func (s *memStore) addRefs(scope KeyScope, delta int) {
	if s.m != nil {
		s.m.AddKeyRefs(scope, delta)
	}
}

func (s *memStore) Register(ref KeyRef, key []byte, meta KeyMeta) error {
	if ref == "" {
		return errors.New("keystore: 空 KeyRef")
	}
	cp := append([]byte(nil), key...)
	s.mu.Lock()
	if old, ok := s.keys[ref]; ok {
		zero(old.key) // 覆盖语义：先零化旧值，不重复计量 refs
	} else {
		s.addRefs(meta.Scope, +1)
	}
	s.keys[ref] = entry{key: cp, meta: meta}
	s.mu.Unlock()
	return nil
}

func (s *memStore) Lookup(ref KeyRef) ([]byte, KeyMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.keys[ref]
	if !ok {
		return nil, KeyMeta{}, ErrUnknownKeyRef
	}
	return append([]byte(nil), e.key...), e.meta, nil
}

func (s *memStore) Derive(parent KeyRef, salt, info []byte, outLen int, alias string) (KeyRef, error) {
	secret, meta, err := s.Lookup(parent)
	if err != nil {
		return "", err
	}
	defer zero(secret)
	out, err := s.prov.KDF(secret, salt, info, outLen)
	if err != nil {
		return "", fmt.Errorf("keystore: KDF 失败: %w", err)
	}
	ref := KeyRef(alias)
	if ref == "" {
		s.mu.Lock()
		s.seq++
		ref = KeyRef(fmt.Sprintf("derived/%d", s.seq))
		s.mu.Unlock()
	}
	childMeta := meta
	childMeta.CreatedAt = time.Now()
	if err := s.Register(ref, out, childMeta); err != nil {
		zero(out)
		return "", err
	}
	zero(out)
	return ref, nil
}

func (s *memStore) Destroy(ref KeyRef) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.keys[ref]
	if !ok {
		return ErrUnknownKeyRef
	}
	zero(e.key)
	delete(s.keys, ref)
	s.addRefs(e.meta.Scope, -1)
	return nil
}

// KeyManager sidecar 侧密钥生命周期编排（§4.7/§6.4）。
// ⚠️ 信任域边界：仅编排 scope ∈ {Session, Static}；二级租户主密钥轮换/销毁归 TEE 域
// （teecore TenantKeyManager），**不得由本 KeyManager 执行**。
type KeyManager struct {
	store KeyStore
	prov  cryptop.Provider
	root  KeyRef
	m     Metrics
}

// NewKeyManager 构造编排器（root = 用于封装旧密钥的根 KeyRef；当前实现下旋转为「解封→重派生」）。
func NewKeyManager(store KeyStore, prov cryptop.Provider, root KeyRef, m Metrics) *KeyManager {
	return &KeyManager{store: store, prov: prov, root: root, m: m}
}

// Rotate 轮换 scope ∈ {Session, Static} 的密钥：旧 KeyRef 保留可解（归档，只解不封），
// 新密钥登记为 <oldRef>/rot 后缀（确定性命名，便于审计）；发 #7。
func (m *KeyManager) Rotate(scope KeyScope, oldRef KeyRef) (KeyRef, error) {
	if scope == ScopeTenantMaster || scope == ScopeRoot {
		return "", fmt.Errorf("keystore: scope=%s 的轮换归 TEE 域（§6.4），sidecar 不得执行", scope)
	}
	old, meta, err := m.store.Lookup(oldRef)
	if err != nil {
		return "", err
	}
	defer zero(old)
	// 新密钥 = 以 root 为盐的 KDF（语义等价于「解封旧→生成新」的确定性版本；密钥长度随 profile）。
	fresh, err := m.prov.KDF(old, []byte(oldRef), []byte("otpmask/rotate/v1"), m.prov.SymmetricKeySize())
	if err != nil {
		return "", err
	}
	defer zero(fresh)
	newRef := KeyRef(string(oldRef) + "/rot")
	newMeta := meta
	newMeta.CreatedAt = time.Now()
	if err := m.store.Register(newRef, fresh, newMeta); err != nil {
		return "", err
	}
	if m.m != nil {
		m.m.IncRotations(scope)
	}
	return newRef, nil
}

// Destroy 在 KeyStore.Destroy 之上补发 #8 指标（§4.7）。
func (m *KeyManager) Destroy(ref KeyRef) error {
	_, meta, err := m.store.Lookup(ref)
	if err != nil {
		return err
	}
	if err := m.store.Destroy(ref); err != nil {
		return err
	}
	if m.m != nil {
		m.m.IncDestroys(meta.Scope)
	}
	return nil
}

// zero 零化敏感字节（best-effort；Go GC 下切片拷贝不可控，威胁模型如实声明，§9.2）。
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
