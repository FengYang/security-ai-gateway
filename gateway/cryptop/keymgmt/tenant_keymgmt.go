package keymgmt

// tenant_keymgmt.go —— 二级租户主密钥（Tenant Master, KEK）生命周期（P0-4 §6，B6 子任务 #9）。
//
// 三级链（§6.1/§6.4，方案 A）：
//
//	一级 Root（Enclave seal key，宿主进程持有）
//	  └─WrapKey─▶ 二级 KEK（每租户一枚，90 天轮换，旧 KEK 归档只解不封）
//	       └─KDF(epoch)─▶ 三级会话 master（5min 轮换；即 KeyManager.masterKey）
//	            └─HMAC─▶ request seed（派生布局与现役逐字节一致）
//
// 分域裁决：KEK 在 TEE 域持有，其轮换/销毁唯一生产者 = 本类型；
// 指标 #7/#8 的 scope=tenant_master 行由 tee 进程发射（sidecar 不接触 KEK）。
//
// 持久化（裁决 P1）：宿主进程经 ChangeHook 触发 Snapshot（KEK 由 RootWrapper 封装）
// 后做 Enclave 密封落盘；重启经 Restore 恢复，90 天年龄跨重启累计。
//
// 并发：Ensure/Rotate/Destroy/Restore 共用同一互斥锁 ⇒ 天然单飞；
// epoch 在锁内单调递增，即幂等键 (tenant, epoch)。

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"security-ai-gateway/gateway/cryptop"
)

// KEK 生命周期审计动作（写审计链；宿主适配）。
const (
	KeyActionCreated   = "key_created"
	KeyActionRotated   = "key_rotated"
	KeyActionDestroyed = "key_destroyed"
)

// ErrTenantNotFound 租户 KEK 不存在（Destroy 未知租户）。
var ErrTenantNotFound = errors.New("teecore: 租户 KEK 不存在")

// defaultTenant 未指定租户时的默认租户（与 tee-infer 进程口径一致）。
const defaultTenant = "default"

// RootWrapper 一级根密钥封装原语（§6.4：K_root ──WrapKey──▶ w(KEK)）。
// 由宿主进程以 Enclave seal key 适配；封装包离开 TEE 域前的最后一层保护。
type RootWrapper interface {
	Wrap(plain []byte) ([]byte, error)
	Unwrap(wrapped []byte) ([]byte, error)
}

// TenantMetrics KEK 事件指标（§10.1 #7/#8 的 tenant_master 行，tee 进程发射）。
type TenantMetrics interface {
	IncTenantRotation()
	IncTenantDestroy()
}

// AuditSink KEK 生命周期审计；epoch = 事件发生时的 KEK 版本。
type AuditSink interface {
	KeyLifecycle(tenant, action string, epoch uint64)
}

// ChangeHook KEK 状态变更后回调（宿主用于 Snapshot→Enclave 密封落盘；nil = 不落盘）。
// 实现须快速返回（异步落盘），不得回调本管理器的加锁方法。
type ChangeHook interface {
	KeysChanged()
}

// TenantKeyManager 二级租户主密钥管理器。
type TenantKeyManager struct {
	prov       cryptop.Provider
	sessionTTL time.Duration
	m          TenantMetrics
	audit      AuditSink
	hook       ChangeHook

	mu      sync.Mutex
	tenants map[string]*tenantState
}

// tenantState 单租户 KEK 状态。
type tenantState struct {
	kek        []byte        // 当前 KEK
	history    [][]byte      // 旧 KEK（归档，只解不封）
	epoch      uint64        // KEK 版本（1 起）
	lastRotate time.Time     // 最近轮换时间（90 天扫描判据）
	km         *KeyManager   // 当前三级会话管理器
	kmHistory  []*KeyManager // 轮换前的会话管理器（在途请求 seed 回溯；已 Close）
}

// NewTenantKeyManager 构造管理器；sessionTTL<=0 用 DefaultMasterTTL；m/audit/hook 均可 nil。
func NewTenantKeyManager(prov cryptop.Provider, sessionTTL time.Duration, m TenantMetrics, audit AuditSink, hook ChangeHook) *TenantKeyManager {
	return &TenantKeyManager{
		prov:       prov,
		sessionTTL: sessionTTL,
		m:          m,
		audit:      audit,
		hook:       hook,
		tenants:    make(map[string]*tenantState),
	}
}

// EnsureTenant 惰性创建租户 KEK（U-10：首次使用密态能力时建）；已存在 = no-op。
func (k *TenantKeyManager) EnsureTenant(tenant string) error {
	tenant = normalizeTenant(tenant)
	k.mu.Lock()
	if _, ok := k.tenants[tenant]; ok {
		k.mu.Unlock()
		return nil
	}
	kek, err := k.prov.Rand(k.prov.SymmetricKeySize())
	if err != nil {
		k.mu.Unlock()
		return fmt.Errorf("teecore: 生成租户 KEK 失败: %w", err)
	}
	st := &tenantState{
		kek:        kek,
		epoch:      1,
		lastRotate: time.Now(),
		km:         newTenantKM(k.sessionTTL, kek, tenant),
	}
	k.tenants[tenant] = st
	k.mu.Unlock()

	k.emitAudit(tenant, KeyActionCreated, 1)
	k.notifyChanged()
	return nil
}

// RotateTenant 轮换指定租户的 KEK：新 KEK 随机生成；旧 KEK 归档（只解不封）；
// 旧会话管理器 Close 后保留在 kmHistory 供在途请求回溯。返回新 KeyRef（tenant/<t>/kek/v<n>）。
// 未知租户先惰性创建（创建即首轮，不立即二次轮换）。
func (k *TenantKeyManager) RotateTenant(tenant string) (string, error) {
	tenant = normalizeTenant(tenant)
	k.mu.Lock()
	st, ok := k.tenants[tenant]
	if !ok {
		k.mu.Unlock()
		if err := k.EnsureTenant(tenant); err != nil {
			return "", err
		}
		// 创建已含 epoch=1 KEK；本轮扫描不再对其做第二次轮换。
		return tenantKeyRef(tenant, 1), nil
	}
	newKEK, err := k.prov.Rand(k.prov.SymmetricKeySize())
	if err != nil {
		k.mu.Unlock()
		return "", fmt.Errorf("teecore: 生成新租户 KEK 失败: %w", err)
	}
	oldKM := st.km
	oldKM.Close() // 停止轮换 goroutine；seed 表保留供回溯
	newKM := newTenantKM(k.sessionTTL, newKEK, tenant)
	st.kmHistory = append(st.kmHistory, oldKM)
	st.history = append(st.history, st.kek)
	st.kek = newKEK
	st.km = newKM
	st.epoch++
	st.lastRotate = time.Now()
	epoch := st.epoch
	k.mu.Unlock()

	k.emitAudit(tenant, KeyActionRotated, epoch)
	if k.m != nil {
		k.m.IncTenantRotation()
	}
	k.notifyChanged()
	return tenantKeyRef(tenant, epoch), nil
}

// DestroyTenant 销毁租户全部 KEK（当前+历史）与会话 seed；销毁后其加密数据不可解。
func (k *TenantKeyManager) DestroyTenant(tenant string) error {
	tenant = normalizeTenant(tenant)
	k.mu.Lock()
	st, ok := k.tenants[tenant]
	if !ok {
		k.mu.Unlock()
		return ErrTenantNotFound
	}
	for _, oldKM := range st.kmHistory {
		oldKM.wipeAll()
	}
	st.km.Close()
	st.km.wipeAll()
	for _, oldKEK := range st.history {
		wipe(oldKEK)
	}
	wipe(st.kek)
	epoch := st.epoch
	delete(k.tenants, tenant)
	k.mu.Unlock()

	k.emitAudit(tenant, KeyActionDestroyed, epoch)
	if k.m != nil {
		k.m.IncTenantDestroy()
	}
	k.notifyChanged()
	return nil
}

// Issue 为租户签发请求 seed（内部 EnsureTenant）；返回 seed、nonce(hex) 与当前会话 master 版本。
func (k *TenantKeyManager) Issue(tenant, requestID, model string) (seed []byte, nonceHex string, masterID uint64, err error) {
	tenant = normalizeTenant(tenant)
	if err = k.EnsureTenant(tenant); err != nil {
		return nil, "", 0, err
	}
	k.mu.Lock()
	km := k.tenants[tenant].km
	k.mu.Unlock()
	seed, nonceHex, err = km.Issue(requestID, model)
	if err != nil {
		return nil, "", 0, err
	}
	return seed, nonceHex, km.MasterID(), nil
}

// Lookup 按 nonce 回溯租户的请求 seed（先当前会话管理器，再逐代历史）。
func (k *TenantKeyManager) Lookup(tenant, nonceHex string) ([]byte, bool) {
	seed, _, ok := k.LookupDetail(tenant, nonceHex)
	return seed, ok
}

// LookupDetail 同 Lookup，额外返回签发该 seed 的会话 master 版本（日志/审计归因）。
func (k *TenantKeyManager) LookupDetail(tenant, nonceHex string) (seed []byte, masterID uint64, ok bool) {
	tenant = normalizeTenant(tenant)
	k.mu.Lock()
	st, exists := k.tenants[tenant]
	if !exists {
		k.mu.Unlock()
		return nil, 0, false
	}
	km := st.km
	kmHistory := st.kmHistory
	k.mu.Unlock()

	if seed, mid, ok := km.lookupDetail(nonceHex); ok {
		return seed, mid, true
	}
	for _, oldKM := range kmHistory {
		if seed, mid, ok := oldKM.lookupDetail(nonceHex); ok {
			return seed, mid, true
		}
	}
	return nil, 0, false
}

// Tenants 返回全部已知租户（确定序）。
func (k *TenantKeyManager) Tenants() []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]string, 0, len(k.tenants))
	for t := range k.tenants {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// DueTenants 返回 lastRotate 距今 ≥ maxAge 的租户（轮换扫描器输入；确定序）。
func (k *TenantKeyManager) DueTenants(now time.Time, maxAge time.Duration) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	var due []string
	for t, st := range k.tenants {
		if now.Sub(st.lastRotate) >= maxAge {
			due = append(due, t)
		}
	}
	sort.Strings(due)
	return due
}

// Epoch 返回租户当前 KEK 版本（不存在返回 0）。
func (k *TenantKeyManager) Epoch(tenant string) uint64 {
	tenant = normalizeTenant(tenant)
	k.mu.Lock()
	defer k.mu.Unlock()
	if st, ok := k.tenants[tenant]; ok {
		return st.epoch
	}
	return 0
}

// TenantSnapshot 单租户持久化快照（KEK 已由一级根封装）。
type TenantSnapshot struct {
	Tenant         string
	Epoch          uint64
	LastRotate     time.Time
	WrappedKEK     []byte
	WrappedHistory [][]byte // 旧 KEK 封装包（顺序与归档一致）
}

// Snapshot 导出全部租户快照（锁内逐个 Wrap；快照不含任何明文密钥）。
func (k *TenantKeyManager) Snapshot(root RootWrapper) ([]TenantSnapshot, error) {
	if root == nil {
		return nil, errors.New("teecore: Snapshot 需要 RootWrapper")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	out := make([]TenantSnapshot, 0, len(k.tenants))
	for tenant, st := range k.tenants {
		wk, err := root.Wrap(st.kek)
		if err != nil {
			return nil, fmt.Errorf("teecore: 封装当前 KEK 失败（tenant=%s）: %w", tenant, err)
		}
		wh := make([][]byte, 0, len(st.history))
		for i, old := range st.history {
			b, err := root.Wrap(old)
			if err != nil {
				return nil, fmt.Errorf("teecore: 封装历史 KEK 失败（tenant=%s, idx=%d）: %w", tenant, i, err)
			}
			wh = append(wh, b)
		}
		out = append(out, TenantSnapshot{
			Tenant:         tenant,
			Epoch:          st.epoch,
			LastRotate:     st.lastRotate,
			WrappedKEK:     wk,
			WrappedHistory: wh,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tenant < out[j].Tenant })
	return out, nil
}

// Restore 从快照恢复全部租户（启动期；KEK 经一级根解封）。与现有状态冲突即报错。
func (k *TenantKeyManager) Restore(snaps []TenantSnapshot, root RootWrapper) error {
	if root == nil {
		return errors.New("teecore: Restore 需要 RootWrapper")
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	for _, sn := range snaps {
		tenant := normalizeTenant(sn.Tenant)
		if _, dup := k.tenants[tenant]; dup {
			return fmt.Errorf("teecore: 恢复冲突，租户已存在: %s", tenant)
		}
		kek, err := root.Unwrap(sn.WrappedKEK)
		if err != nil {
			return fmt.Errorf("teecore: 解封当前 KEK 失败（tenant=%s）: %w", tenant, err)
		}
		history := make([][]byte, 0, len(sn.WrappedHistory))
		for i, wb := range sn.WrappedHistory {
			old, err := root.Unwrap(wb)
			if err != nil {
				wipe(kek)
				for _, h := range history {
					wipe(h)
				}
				return fmt.Errorf("teecore: 解封历史 KEK 失败（tenant=%s, idx=%d）: %w", tenant, i, err)
			}
			history = append(history, old)
		}
		st := &tenantState{
			kek:        kek,
			history:    history,
			epoch:      sn.Epoch,
			lastRotate: sn.LastRotate,
			km:         newTenantKM(k.sessionTTL, kek, tenant),
		}
		k.tenants[tenant] = st
	}
	return nil
}

// ---- 内部辅助 ----

func (k *TenantKeyManager) emitAudit(tenant, action string, epoch uint64) {
	if k.audit != nil {
		k.audit.KeyLifecycle(tenant, action, epoch)
	}
}

func (k *TenantKeyManager) notifyChanged() {
	if k.hook != nil {
		k.hook.KeysChanged()
	}
}

func normalizeTenant(tenant string) string {
	if tenant == "" {
		return defaultTenant
	}
	return tenant
}

func tenantKeyRef(tenant string, epoch uint64) string {
	return fmt.Sprintf("tenant/%s/kek/v%d", tenant, epoch)
}

// newTenantKM 构造由租户 KEK 派生会话 master 的三级 KeyManager（构造即 epoch 1，并启动轮换）。
func newTenantKM(ttl time.Duration, kek []byte, tenant string) *KeyManager {
	if ttl <= 0 {
		ttl = DefaultMasterTTL
	}
	km := &KeyManager{
		masterTTL:    ttl,
		keys:         make(map[string]keyRecord),
		stop:         make(chan struct{}),
		deriveMaster: sessionMasterDeriver(kek, tenant),
	}
	if err := km.rotateLocked(); err != nil {
		panic("teecore: 派生首个会话 master 失败: " + err.Error())
	}
	go km.rotateLoop()
	return km
}

// sessionMasterDeriver 返回 epoch→会话 master 派生函数：
// KDF(secret=KEK, salt=tenant, info="otpmask/session/master/v1/"+BE64(epoch), outLen=32)。
// 同一 KEK 同 epoch 恒得同一 master（确定性，跨重启可重算）。
func sessionMasterDeriver(kek []byte, tenant string) func(epoch uint64) []byte {
	return func(epoch uint64) []byte {
		info := make([]byte, 0, len("otpmask/session/master/v1/")+8)
		info = append(info, "otpmask/session/master/v1/"...)
		var eb [8]byte
		binary.BigEndian.PutUint64(eb[:], epoch)
		info = append(info, eb[:]...)
		m, err := cryptoProvider.KDF(kek, []byte(tenant), info, 32)
		if err != nil {
			panic("teecore: KEK→会话 master KDF 失败: " + err.Error())
		}
		return m
	}
}
