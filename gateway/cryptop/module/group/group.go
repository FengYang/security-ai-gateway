package group

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// ControlStore 组控制存储契约（T-0 冻结；对齐 testkit.MemoryControlStore）。
//
// Wave A 仅消费内存参考实现；真机 etcd 实现（testkit/poc.EtcdControlStore）签名带
// context，需 Wave B 适配器（EtcdControlStoreAdapter）实现本接口后注入，不改动本包逻辑。
// 所有写路径的 CAS / 租约 / epoch 语义由实现侧保证原子性（R3-P0-01 / D-17）。
type ControlStore interface {
	GetOwnerState() testkit.OwnerState
	SetDesired() uint64
	AcquireOwner(req testkit.OwnerAcquireRequest) (testkit.LeaseStatus, error)
	RenewOwner(member, bootID string, epoch uint64, ttl time.Duration) error
	ReleaseOwner(member, bootID string, epoch uint64) error
	CreateKeyOp(op testkit.KeyOp) (int64, error)
	CASKeyOp(opID string, expectedVersion int64, expectedStatus string, op testkit.KeyOp) (int64, error)
	GetKeyOp(opID string) (testkit.KeyOp, int64, error)
	WatchKeyOps(fromRevision int64) []testkit.KeyOp
	CASKeyDirectory(keyID string, expectedVersion int64, writerEpoch uint64, writerBootID string, kd testkit.KeyDirectory) (int64, error)
	GetKeyDirectory(keyID string) (testkit.KeyDirectory, int64)
}

// Member 组内成员运行时视图（封装一个已初始化的 ModuleBackend）。
type Member struct {
	ID         string
	Partition  string
	DC         string
	MaxSessions int
	Weight     int
	Backend    module.ModuleBackend
}

// ModuleGroup 把多个成员后端组合为一个逻辑 ModuleBackend（组合模式），实现 T-1 Wave A
// 的「组抽象」：数据面多成员并行 + 生命周期写受组主约束（两级模型）。
//
// 关键不变量（务必如实）：
//   - 数据面（Seal/Open/Sign/Verify/HMAC/KDF/Rand/Hash/Verify）只需成员健康 + 分区匹配，
//     组主缺失时仍可用；
//   - 生命周期写（GenerateKey/GenerateKeyPair/ImportKey/DestroyKey/RotateKey）必须当前进程是
//     组主，否则 ErrNotLeader（陈旧主/被 fence 进程 100% 拒绝）；
//   - 组内密钥以 GroupKeyRef 信封路由到具体成员（testkit §6.2.2），信封不含密钥材料。
type ModuleGroup struct {
	mu      sync.RWMutex
	cfg     testkit.GroupConfig
	members map[string]*Member
	order   []string // 稳定顺序（会话打包 / 确定性选择）
	partOf  map[string]string // memberID → partition
	partMem map[string][]string

	coord   *Coordinator
	store   ControlStore
	self    string
	bootID  string
	metrics *gmetrics
}

// NewGroupProvider 构造组抽象（不立即启动协调器；Init 内启动）。
//
// 参数：
//   - cfg：已通过 testkit.GroupConfig.Validate 的组配置（调用方负责启动前校验）；
//   - members：成员 ID → 已 Init 的 ModuleBackend（本包不重复 Init 成员，仅启动协调器）；
//   - self：本 sidecar 对应的成员 ID（生命周期写要求其持有组主租约）；
//   - store：控制存储（Wave A 用 testkit.MemoryControlStore）；
//   - bootID：本进程启动标识（fence 用，区分陈旧主）。
func NewGroupProvider(cfg testkit.GroupConfig, members map[string]module.ModuleBackend, self string, store ControlStore, bootID string) (*ModuleGroup, error) {
	if len(members) < 2 {
		return nil, fmt.Errorf("group: 组模式成员数 %d < 2（D-1 至少双成员）", len(members))
	}
	if _, ok := members[self]; !ok {
		return nil, fmt.Errorf("group: self 成员 %q 不在成员集合内", self)
	}
	caps := map[string]testkit.Capabilities{}
	g := &ModuleGroup{
		cfg:     cfg,
		members: map[string]*Member{},
		order:   nil,
		partOf:  map[string]string{},
		partMem: map[string][]string{},
		store:   store,
		self:    self,
		bootID:  bootID,
		metrics: newGmetrics(),
	}
	for id, b := range members {
		mc := findMemberConfig(cfg, id)
		if mc == nil {
			return nil, fmt.Errorf("group: 成员 %q 在组配置中缺失", id)
		}
		g.members[id] = &Member{
			ID: id, Partition: mc.Partition, DC: mc.DC,
			MaxSessions: mc.MaxSessions, Weight: weightOf(mc.Weight), Backend: b,
		}
		g.order = append(g.order, id)
		g.partOf[id] = mc.Partition
		g.partMem[mc.Partition] = append(g.partMem[mc.Partition], id)
		caps[id] = toTestkitCaps(b.Capabilities())
	}
	if v := cfg.Validate(testkit.ProfileTest, caps); len(v) != 0 {
		return nil, fmt.Errorf("group: 组配置校验未通过: %v", v)
	}
	ttl := time.Duration(cfg.Leader.LeaseTTLMS) * time.Millisecond
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	g.coord = NewCoordinator(store, self, bootID, selfDC(cfg, self), ttl,
		cfg.BootstrapOwner == self, cfg.BootstrapOwner, cfg.Failover.AutoFailoverIntraDC)
	return g, nil
}

func findMemberConfig(cfg testkit.GroupConfig, id string) *testkit.MemberConfig {
	for i := range cfg.Members {
		if cfg.Members[i].ID == id {
			return &cfg.Members[i]
		}
	}
	return nil
}

func weightOf(w int) int {
	if w <= 0 {
		return 1
	}
	return w
}

func selfDC(cfg testkit.GroupConfig, self string) string {
	if mc := findMemberConfig(cfg, self); mc != nil {
		return mc.DC
	}
	return ""
}

func toTestkitCaps(c module.Capabilities) testkit.Capabilities {
	return testkit.Capabilities{Backend: c.Backend, Vendor: c.Vendor, Model: c.Model, Mechanisms: c.Mechanisms}
}

// ---- 生命周期 ----

// Init 启动协调器（抢占/维持组主租约）。成员后端由调用方预先 Init，本包不再 Init。
func (g *ModuleGroup) Init(cfg *module.Config) error {
	g.mu.Lock()
	if g.coord == nil {
		g.mu.Unlock()
		return fmt.Errorf("group: 协调器未构造")
	}
	g.coord.Start()
	g.mu.Unlock()
	g.refreshMetrics()
	return nil
}

// Capabilities 聚合能力（GroupID 作为 Model；机制取健康成员并集）。
func (g *ModuleGroup) Capabilities() module.Capabilities {
	g.mu.RLock()
	defer g.mu.RUnlock()
	mechs := map[string]bool{}
	for _, id := range g.order {
		if g.members[id].Backend.Health() != module.HealthDown {
			for _, m := range g.members[id].Backend.Capabilities().Mechanisms {
				mechs[m] = true
			}
		}
	}
	out := make([]string, 0, len(mechs))
	for m := range mechs {
		out = append(out, m)
	}
	return module.Capabilities{Backend: "group", Vendor: "group", Model: g.cfg.GroupID, Mechanisms: out}
}

// AcquireSession 从某健康成员获取会话，会话句柄编码成员索引以便释放时定位。
func (g *ModuleGroup) AcquireSession() (module.Session, error) {
	g.mu.RLock()
	m, err := g.selectMemberLocked("")
	g.mu.RUnlock()
	if err != nil {
		g.metrics.recordOp("acquire_session", "err")
		return 0, err
	}
	s, err := m.Backend.AcquireSession()
	if err != nil {
		g.metrics.recordOp("acquire_session", "err")
		return 0, err
	}
	g.metrics.recordOp("acquire_session", "ok")
	return packSession(g.indexLocked(m.ID), s), nil
}

// ReleaseSession 释放会话（按编码定位成员）。
func (g *ModuleGroup) ReleaseSession(s module.Session) error {
	idx, inner := unpackSession(s)
	g.mu.RLock()
	var m *Member
	if int(idx) < len(g.order) {
		m = g.members[g.order[idx]]
	}
	g.mu.RUnlock()
	if m == nil {
		return fmt.Errorf("group: 会话句柄无法定位到成员")
	}
	if err := m.Backend.ReleaseSession(inner); err != nil {
		g.metrics.recordOp("release_session", "err")
		return err
	}
	g.metrics.recordOp("release_session", "ok")
	return nil
}

// Health 聚合健康：任一分区无健康成员 → Down；部分成员 Down → Degraded；否则 OK。
func (g *ModuleGroup) Health() module.HealthLevel {
	g.mu.RLock()
	defer g.mu.RUnlock()
	healthy := 0
	for _, id := range g.order {
		if g.members[id].Backend.Health() != module.HealthDown {
			healthy++
		}
	}
	if healthy == 0 {
		g.metrics.recordOp("health", "down")
		return module.HealthDown
	}
	for _, ids := range g.partMem {
		any := false
		for _, id := range ids {
			if g.members[id].Backend.Health() != module.HealthDown {
				any = true
				break
			}
		}
		if !any {
			g.metrics.recordOp("health", "down")
			return module.HealthDown
		}
	}
	if healthy < len(g.order) {
		g.metrics.recordOp("health", "degraded")
		return module.HealthDegraded
	}
	g.metrics.recordOp("health", "ok")
	return module.HealthOK
}

// Close 停止协调器并关闭所有成员后端。
func (g *ModuleGroup) Close() error {
	g.mu.Lock()
	coord := g.coord
	members := make([]module.ModuleBackend, 0, len(g.members))
	for _, m := range g.members {
		members = append(members, m.Backend)
	}
	g.mu.Unlock()
	if coord != nil {
		coord.Stop()
	}
	var firstErr error
	for _, b := range members {
		if err := b.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ---- 对称运算（数据面；组主缺失时仍可用） ----

func (g *ModuleGroup) Seal(keyRef module.KeyRef, nonce, plaintext, aad []byte) ([]byte, error) {
	m, inner, err := g.routeKey(keyRef)
	if err != nil {
		g.metrics.recordOp("seal", "err")
		return nil, err
	}
	out, err := m.Backend.Seal(inner, nonce, plaintext, aad)
	g.recordDataOp("seal", err)
	return out, err
}

func (g *ModuleGroup) Open(keyRef module.KeyRef, nonce, ciphertext, aad []byte) ([]byte, error) {
	m, inner, err := g.routeKey(keyRef)
	if err != nil {
		g.metrics.recordOp("open", "err")
		return nil, err
	}
	out, err := m.Backend.Open(inner, nonce, ciphertext, aad)
	g.recordDataOp("open", err)
	return out, err
}

func (g *ModuleGroup) Hash(data []byte) ([]byte, error) {
	g.mu.RLock()
	m, err := g.selectMemberLocked("")
	g.mu.RUnlock()
	if err != nil {
		g.metrics.recordOp("hash", "err")
		return nil, err
	}
	out, err := m.Backend.Hash(data)
	g.recordDataOp("hash", err)
	return out, err
}

func (g *ModuleGroup) HMAC(keyRef module.KeyRef, data []byte) ([]byte, error) {
	m, inner, err := g.routeKey(keyRef)
	if err != nil {
		g.metrics.recordOp("hmac", "err")
		return nil, err
	}
	out, err := m.Backend.HMAC(inner, data)
	g.recordDataOp("hmac", err)
	return out, err
}

func (g *ModuleGroup) KDF(parentRef module.KeyRef, salt, info []byte, outLen int, alias string) ([]byte, error) {
	m, inner, err := g.routeKey(parentRef)
	if err != nil {
		g.metrics.recordOp("kdf", "err")
		return nil, err
	}
	out, err := m.Backend.KDF(inner, salt, info, outLen, alias)
	g.recordDataOp("kdf", err)
	return out, err
}

func (g *ModuleGroup) Rand(n int) ([]byte, error) {
	g.mu.RLock()
	m, err := g.selectMemberLocked("")
	g.mu.RUnlock()
	if err != nil {
		g.metrics.recordOp("rand", "err")
		return nil, err
	}
	out, err := m.Backend.Rand(n)
	g.recordDataOp("rand", err)
	return out, err
}

// ---- 非对称运算（数据面） ----

func (g *ModuleGroup) Sign(privRef module.KeyRef, msg []byte, uid string) ([]byte, error) {
	m, inner, err := g.routeKey(privRef)
	if err != nil {
		g.metrics.recordOp("sign", "err")
		return nil, err
	}
	out, err := m.Backend.Sign(inner, msg, uid)
	g.recordDataOp("sign", err)
	return out, err
}

func (g *ModuleGroup) Verify(pub, msg, sig []byte, uid string) error {
	g.mu.RLock()
	m, err := g.selectMemberLocked("")
	g.mu.RUnlock()
	if err != nil {
		g.metrics.recordOp("verify", "err")
		return err
	}
	err = m.Backend.Verify(pub, msg, sig, uid)
	g.recordDataOp("verify", err)
	return err
}

func (g *ModuleGroup) GenerateKeyPair(usage string) (module.KeyRef, []byte, error) {
	if err := g.requireLeader(); err != nil {
		g.metrics.recordOp("generate_keypair", "no_leader")
		return nil, nil, err
	}
	g.mu.RLock()
	m := g.members[g.self]
	g.mu.RUnlock()
	ref, pub, err := m.Backend.GenerateKeyPair(usage)
	if err != nil {
		g.metrics.recordOp("generate_keypair", "err")
		return nil, nil, err
	}
	env, err := g.wrapKeyRef(ref)
	if err != nil {
		g.metrics.recordOp("generate_keypair", "err")
		return nil, nil, err
	}
	g.metrics.recordOp("generate_keypair", "ok")
	return env, pub, nil
}

func (g *ModuleGroup) ECDH(privRef module.KeyRef, peerPub []byte) ([]byte, error) {
	m, inner, err := g.routeKey(privRef)
	if err != nil {
		g.metrics.recordOp("ecdh", "err")
		return nil, err
	}
	out, err := m.Backend.ECDH(inner, peerPub)
	g.recordDataOp("ecdh", err)
	return out, err
}

// ---- 密钥管理（生命周期写：必须组主） ----

func (g *ModuleGroup) WrapKey(kekRef module.KeyRef, dek []byte) ([]byte, error) {
	m, inner, err := g.routeKey(kekRef)
	if err != nil {
		g.metrics.recordOp("wrap_key", "err")
		return nil, err
	}
	out, err := m.Backend.WrapKey(inner, dek)
	g.recordDataOp("wrap_key", err)
	return out, err
}

func (g *ModuleGroup) UnwrapKey(kekRef module.KeyRef, wrapped []byte) ([]byte, error) {
	m, inner, err := g.routeKey(kekRef)
	if err != nil {
		g.metrics.recordOp("unwrap_key", "err")
		return nil, err
	}
	out, err := m.Backend.UnwrapKey(inner, wrapped)
	g.recordDataOp("unwrap_key", err)
	return out, err
}

func (g *ModuleGroup) GenerateKey(spec, alias string) (module.KeyRef, error) {
	if err := g.requireLeader(); err != nil {
		g.metrics.recordOp("generate_key", "no_leader")
		return nil, err
	}
	g.mu.RLock()
	m := g.members[g.self]
	g.mu.RUnlock()
	ref, err := m.Backend.GenerateKey(spec, alias)
	if err != nil {
		g.metrics.recordOp("generate_key", "err")
		return nil, err
	}
	env, err := g.wrapKeyRef(ref)
	if err != nil {
		g.metrics.recordOp("generate_key", "err")
		return nil, err
	}
	g.metrics.recordOp("generate_key", "ok")
	return env, nil
}

func (g *ModuleGroup) ImportKey(spec string, key []byte, alias string) (module.KeyRef, error) {
	if err := g.requireLeader(); err != nil {
		g.metrics.recordOp("import_key", "no_leader")
		return nil, err
	}
	g.mu.RLock()
	m := g.members[g.self]
	g.mu.RUnlock()
	ref, err := m.Backend.ImportKey(spec, key, alias)
	if err != nil {
		g.metrics.recordOp("import_key", "err")
		return nil, err
	}
	env, err := g.wrapKeyRef(ref)
	if err != nil {
		g.metrics.recordOp("import_key", "err")
		return nil, err
	}
	g.metrics.recordOp("import_key", "ok")
	return env, nil
}

func (g *ModuleGroup) DestroyKey(keyRef module.KeyRef) error {
	if err := g.requireLeader(); err != nil {
		g.metrics.recordOp("destroy_key", "no_leader")
		return err
	}
	m, inner, err := g.routeKey(keyRef)
	if err != nil {
		g.metrics.recordOp("destroy_key", "err")
		return err
	}
	if err := m.Backend.DestroyKey(inner); err != nil {
		g.metrics.recordOp("destroy_key", "err")
		return err
	}
	g.metrics.recordOp("destroy_key", "ok")
	return nil
}

func (g *ModuleGroup) RotateKey(oldRef module.KeyRef, spec string) (module.KeyRef, error) {
	if err := g.requireLeader(); err != nil {
		g.metrics.recordOp("rotate_key", "no_leader")
		return nil, err
	}
	m, inner, err := g.routeKey(oldRef)
	if err != nil {
		g.metrics.recordOp("rotate_key", "err")
		return nil, err
	}
	newRef, err := m.Backend.RotateKey(inner, spec)
	if err != nil {
		g.metrics.recordOp("rotate_key", "err")
		return nil, err
	}
	env, err := g.wrapKeyRef(newRef)
	if err != nil {
		g.metrics.recordOp("rotate_key", "err")
		return nil, err
	}
	g.metrics.recordOp("rotate_key", "ok")
	return env, nil
}

// ---- 路由与成员选择 ----

// selectMemberLocked 在 RLock 下选择某分区的健康成员（首个健康，按 order 稳定）。
// partition 为空 → 取首个分区。无健康成员 → ErrModuleUnavailable（fail-closed）。
func (g *ModuleGroup) selectMemberLocked(partition string) (*Member, error) {
	ids := g.partMem[partition]
	if len(ids) == 0 {
		// 回退：任意分区首个健康成员。
		for _, p := range g.partMem {
			ids = p
			break
		}
	}
	for _, id := range ids {
		m := g.members[id]
		if m.Backend.Health() != module.HealthDown {
			return m, nil
		}
	}
	return nil, fmt.Errorf("%w: 分区 %q 无健康成员（fail-closed）", module.ErrModuleUnavailable, partition)
}

// routeKey 解析密钥路由：GroupKeyRef 信封 → 定位成员 + 内部句柄；普通 token → 默认分区选择。
func (g *ModuleGroup) routeKey(keyRef module.KeyRef) (*Member, module.KeyRef, error) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if decoded, err := testkit.DecodeGroupKeyRef(keyRef); err == nil {
		m, ok := g.members[decoded.Member]
		if !ok {
			return nil, nil, fmt.Errorf("%w: 信封路由到未知成员 %s", module.ErrKeyNotFound, decoded.Member)
		}
		if m.Backend.Health() == module.HealthDown {
			return nil, nil, fmt.Errorf("%w: 持有密钥的成员 %s 不可用（fail-closed）", module.ErrModuleUnavailable, decoded.Member)
		}
		return m, module.KeyRef(decoded.Inner), nil
	}
	m, err := g.selectMemberLocked("")
	if err != nil {
		return nil, nil, err
	}
	return m, keyRef, nil
}

// requireLeader 生命周期写前置：当前进程必须持有有效组主租约（陈旧主/被 fence → 拒绝）。
func (g *ModuleGroup) requireLeader() error {
	g.mu.RLock()
	coord := g.coord
	g.mu.RUnlock()
	if coord == nil || !coord.IsLeader() {
		return ErrNotLeader
	}
	return nil
}

// wrapKeyRef 把成员内句柄包装为 GroupKeyRef 信封（携带 member/partition，供后续路由）。
// 同时以组主身份写入目录项（version 0→1，单副本；跨成员复制属 T-2 Wave B），
// 使目录写路径受 leader epoch/boot_id 约束（陈旧主 CAS 失败）。
func (g *ModuleGroup) wrapKeyRef(inner module.KeyRef) (module.KeyRef, error) {
	g.mu.RLock()
	selfM := g.members[g.self]
	coord := g.coord
	store := g.store
	cfg := g.cfg
	g.mu.RUnlock()

	keyID := newKeyID()
	env, err := testkit.EncodeGroupKeyRef(keyID, g.self, selfM.Partition, inner)
	if err != nil {
		return nil, err
	}
	ls, ok := coord.LeaderLease()
	if !ok {
		return nil, ErrNotLeader
	}
	kd := testkit.KeyDirectory{
		Version:      0,
		KeyID:        hexKeyID(keyID),
		KeyMode:      cfg.KeyMode,
		Replicas:     []testkit.KeyReplica{{Member: g.self, Partition: selfM.Partition, InnerB64: b64(inner), State: "active"}},
		State:        "active",
		CreatedBy:    g.self,
		WriterEpoch:  ls.Epoch,
		WriterBootID: ls.HolderBootID,
		LeaseEpoch:   ls.Epoch,
		UpdatedAt:    time.Now().UTC(),
	}
	if _, err := store.CASKeyDirectory(hexKeyID(keyID), 0, ls.Epoch, ls.HolderBootID, kd); err != nil {
		return nil, fmt.Errorf("group: 目录写失败（leader 约束）: %w", err)
	}
	return env, nil
}

func (g *ModuleGroup) indexLocked(id string) uint16 {
	for i, o := range g.order {
		if o == id {
			return uint16(i)
		}
	}
	return 0
}

func (g *ModuleGroup) recordDataOp(op string, err error) {
	if err != nil {
		g.metrics.recordOp(op, "err")
	} else {
		g.metrics.recordOp(op, "ok")
	}
}

func (g *ModuleGroup) refreshMetrics() {
	g.mu.RLock()
	total := len(g.order)
	healthy := 0
	for _, id := range g.order {
		if g.members[id].Backend.Health() != module.HealthDown {
			healthy++
		}
	}
	leaderHeld := g.coord != nil && g.coord.IsLeader()
	epoch := uint64(0)
	if g.coord != nil {
		epoch = g.coord.Epoch()
	}
	g.mu.RUnlock()
	g.metrics.snapshot(epoch, total, healthy, leaderHeld)
}

// Leader 暴露协调器状态（测试 / 端点用）。
func (g *ModuleGroup) Leader() (testkit.LeaseStatus, bool) {
	g.mu.RLock()
	c := g.coord
	g.mu.RUnlock()
	if c == nil {
		return testkit.LeaseStatus{}, false
	}
	return c.LeaderLease()
}

// IsLeader 当前是否组主。
func (g *ModuleGroup) IsLeader() bool {
	g.mu.RLock()
	c := g.coord
	g.mu.RUnlock()
	return c != nil && c.IsLeader()
}

// Epoch 当前组 epoch。
func (g *ModuleGroup) Epoch() uint64 {
	g.mu.RLock()
	c := g.coord
	g.mu.RUnlock()
	if c == nil {
		return 0
	}
	return c.Epoch()
}

// RenderMetrics 输出组级指标（Prometheus 文本）。
func (g *ModuleGroup) RenderMetrics(w io.Writer) {
	g.refreshMetrics()
	g.metrics.Render(w)
}

// ---- 会话句柄编码 ----

// packSession 把成员索引（高 16 位）与成员内会话（低 48 位）打包为不透明 Session。
func packSession(idx uint16, s module.Session) module.Session {
	return module.Session((uintptr(idx) << 48) | (uintptr(s) & ((1 << 48) - 1)))
}

// unpackSession 反向解析。
func unpackSession(s module.Session) (uint16, module.Session) {
	return uint16(uintptr(s) >> 48), module.Session(uintptr(s) & ((1 << 48) - 1))
}

func newKeyID() [16]byte {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return b
}

// 编译期契约保证：ModuleGroup 实现 ModuleBackend 全部 22 方法。
var _ module.ModuleBackend = (*ModuleGroup)(nil)
