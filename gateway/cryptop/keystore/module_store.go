package keystore

// module_store.go —— sm-module 档 KeyStore 实现（P1-5 M4，B-6.1-4/B-6.1-5）。
//
// 契约（B-6.1-5）：moduleStore **不持有、不返回任何密钥字节**——
//   - Register：把外部密钥字节**导入模块**（ImportKey），仅登记 token ↔ KeyRef 映射；
//   - Lookup：返回 B-6.1-4 的**不透明 token**（可序列化为 []byte，不是密钥字节）；
//     sm-module 档下 cryptop.Provider 各方法的 []byte 密钥形参即本 token；
//   - Derive：父 token 经模块内 KDF 派生，新 token 登记（D-4 的模块内派生路径）；
//   - Destroy：模块内对象销毁 + 映射删除。
//
// 与 memStore 的分工：intl/sm-software 档与三级会话软件路径用 memStore；
// sm-module 档的 Root/TenantMaster/Static 一律走 moduleStore，**严禁退回
// memStore 在进程内存保存长期密钥**（B-6.1-5）。

import (
	"fmt"
	"sync"

	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

// moduleStore 模块档 KeyStore（只存 token 映射，不存密钥字节）。
type moduleStore struct {
	mu      sync.RWMutex
	backend cryptopmodule.ModuleBackend
	refs    map[KeyRef]moduleEntry
	seq     uint64
	m       Metrics
}

type moduleEntry struct {
	token []byte // 模块对象句柄 token（B-6.1-4；非密钥字节）
	meta  KeyMeta
}

// 编译期契约保证。
var _ KeyStore = (*moduleStore)(nil)

// NewModuleStore 构造模块档 KeyStore（backend 为 sm-module 模块后端）。
func NewModuleStore(backend cryptopmodule.ModuleBackend, m Metrics) KeyStore {
	return &moduleStore{
		backend: backend,
		refs:    make(map[KeyRef]moduleEntry),
		m:       m,
	}
}

func (s *moduleStore) addRefs(scope KeyScope, delta int) {
	if s.m != nil {
		s.m.AddKeyRefs(scope, delta)
	}
}

// Register 导入密钥入模块并登记 token（覆盖语义：先销毁旧模块对象再导入，
// 不重复计量；导入失败且旧对象已毁 → 清理映射，避免悬空 token）。
func (s *moduleStore) Register(ref KeyRef, key []byte, meta KeyMeta) error {
	if ref == "" {
		return fmt.Errorf("keystore: 空 KeyRef")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, ok := s.refs[ref]; ok {
		// 覆盖：先销毁旧模块对象（real 后端同名 alias 替换语义；mock 同名同 token，
		// 若先导入后销毁会误删新对象——故必须"先毁后导"）。
		if err := s.backend.DestroyKey(old.token); err != nil {
			return fmt.Errorf("keystore: 销毁旧模块对象失败 ref=%s: %w", ref, err)
		}
	} else {
		s.addRefs(meta.Scope, +1)
	}
	token, err := s.backend.ImportKey(specForKey(key), key, string(ref))
	if err != nil {
		if _, ok := s.refs[ref]; ok {
			delete(s.refs, ref)
			s.addRefs(meta.Scope, -1)
		}
		return fmt.Errorf("keystore: 导入模块失败 ref=%s: %w", ref, err)
	}
	s.refs[ref] = moduleEntry{token: append([]byte(nil), token...), meta: meta}
	return nil
}

// Lookup 返回**模块对象 token**（B-6.1-4；不是密钥字节）。
func (s *moduleStore) Lookup(ref KeyRef) ([]byte, KeyMeta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.refs[ref]
	if !ok {
		return nil, KeyMeta{}, ErrUnknownKeyRef
	}
	return append([]byte(nil), e.token...), e.meta, nil
}

// Derive 经模块内 KDF 派生（D-4 的模块内路径）。
//
// 实现口径：KDF 在模块内执行（父 token 不出模块），派生结果经 ImportKey 登记为
// 模块内对象——统一走"字节经适配层瞬态进入模块"的导入语义（B-6.1-1 不缓存）。
// 后端若支持"KDF 直接派生为模块内对象"（alias 路径，mock 已验证），可作为
// S3-b 真机期的优化（减少一次明文往返），两条路径均满足 C-4/C-5（D-4 边界澄清）。
func (s *moduleStore) Derive(parent KeyRef, salt, info []byte, outLen int, alias string) (KeyRef, error) {
	s.mu.RLock()
	parentEntry, ok := s.refs[parent]
	s.mu.RUnlock()
	if !ok {
		return "", ErrUnknownKeyRef
	}
	out, err := s.backend.KDF(parentEntry.token, salt, info, outLen, "")
	if err != nil {
		return "", fmt.Errorf("keystore: 模块内 KDF 失败: %w", err)
	}
	if alias == "" {
		s.mu.Lock()
		s.seq++
		alias = fmt.Sprintf("derived/%d", s.seq)
		s.mu.Unlock()
	}
	ref := KeyRef(alias)
	childMeta := parentEntry.meta // 派生继承父血缘（scope/profile）
	token, err := s.backend.ImportKey(specForLen(outLen), out, alias)
	if err != nil {
		return "", fmt.Errorf("keystore: 派生结果登记失败: %w", err)
	}
	s.mu.Lock()
	if _, exists := s.refs[ref]; !exists {
		s.addRefs(childMeta.Scope, +1)
	}
	s.refs[ref] = moduleEntry{token: append([]byte(nil), token...), meta: childMeta}
	s.mu.Unlock()
	return ref, nil
}

// Destroy 销毁模块内对象并删除映射。
func (s *moduleStore) Destroy(ref KeyRef) error {
	s.mu.Lock()
	e, ok := s.refs[ref]
	if !ok {
		s.mu.Unlock()
		return ErrUnknownKeyRef
	}
	delete(s.refs, ref)
	s.mu.Unlock()
	if err := s.backend.DestroyKey(e.token); err != nil {
		return err
	}
	s.addRefs(e.meta.Scope, -1)
	return nil
}

// specForKey 按密钥长度推断导入规格（sm-module 档对称键 16B = SM4-128；
// 32B = SM2 私钥标量）。长度不符 → ImportKey 层报错（fail-closed）。
func specForKey(key []byte) string {
	switch len(key) {
	case 16:
		return "sm4-128"
	case 32:
		return "sm2-sign"
	default:
		return "" // 交由后端校验拒绝
	}
}

// specForLen 派生结果长度 → 规格（KDF 输出 16B = SM4；32B = SM2 私钥形态）。
func specForLen(n int) string {
	switch n {
	case 16:
		return "sm4-128"
	case 32:
		return "sm2-sign"
	default:
		return ""
	}
}
