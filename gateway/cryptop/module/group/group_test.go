package group

import (
	"bytes"
	"testing"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// testGroupConfig 一个合法的两成员 isolated 组配置（对齐 §6.1 示例，memory 控制存储 + mock 成员）。
func testGroupConfig() testkit.GroupConfig {
	return testkit.GroupConfig{
		GroupID: "fin-hsm-a", KeyMode: "isolated", KeyReplication: "single",
		Members: []testkit.MemberConfig{
			{ID: "dc1-hsm-a", Vendor: "vendor-x", Model: "hsm-9000", Firmware: "3.2.1",
				Backend: "mock", Partition: "tenant-a", DC: "dc1", MaxSessions: 16, TimeoutMS: 50},
			{ID: "dc2-hsm-a", Vendor: "vendor-x", Model: "hsm-9000", Firmware: "3.2.1",
				Backend: "mock", Partition: "tenant-a", DC: "dc2", MaxSessions: 16, TimeoutMS: 50},
		},
		Partitions: []testkit.PartitionConfig{
			{Tenant: "tenant-a", Partition: "tenant-a", Members: []string{"dc1-hsm-a", "dc2-hsm-a"}, QuotaSessions: 24},
		},
		Leader:         testkit.LeaderConfig{Store: "memory", BootstrapOwner: "dc1-hsm-a", LeaseTTLMS: 30000},
		Control:        testkit.ControlConfig{Store: "memory", DirectoryMACKeyRef: "secret://dir-mac", DirectoryCacheTTLMS: 15000, DirectoryCacheMaxStale: 30000, DirectoryWriter: "lease"},
		Policy:         testkit.PolicyConfig{Affinity: "none", DcOrder: []string{"dc1", "dc2"}},
		Failover:       testkit.FailoverConfig{Mode: "failover", AutoFailoverIntraDC: true, StartupMinHealthyPerPartition: 1, AutoSwitchBack: false},
		BootstrapOwner: "dc1-hsm-a",
	}
}

func newMockMember() *module.MockBackend {
	m := module.NewMockBackend()
	cfg := &module.Config{Backend: module.BackendMock, MaxSessions: 16, SessionQueueSize: 64,
		HealthInterval: 10 * time.Second, HealthFailCount: 3, FailoverMode: module.FailoverFailClosed,
		TimeoutMS: 50, RequiredMechanisms: module.DefaultRequiredMechanisms(), SM2UID: "1234567812345678"}
	if err := m.Init(cfg); err != nil {
		panic(err)
	}
	return m
}

func newTestGroup(t *testing.T, self string) (*ModuleGroup, *module.MockBackend, *module.MockBackend, *testkit.MemoryControlStore) {
	t.Helper()
	cfg := testGroupConfig()
	m1 := newMockMember()
	m2 := newMockMember()
	members := map[string]module.ModuleBackend{"dc1-hsm-a": m1, "dc2-hsm-a": m2}
	store := testkit.NewMemoryControlStore("fin-hsm-a")
	g, err := NewGroupProvider(cfg, members, self, store, "boot-"+self, nil)
	if err != nil {
		t.Fatalf("NewGroupProvider: %v", err)
	}
	return g, m1, m2, store
}

func TestGroupBootstrapLeader(t *testing.T) {
	g, _, _, _ := newTestGroup(t, "dc1-hsm-a")
	g.Init(nil)
	defer g.Close()
	if !g.IsLeader() {
		t.Fatalf("dc1 应为组主（bootstrap）")
	}
	if g.Epoch() < 1 {
		t.Fatalf("epoch 应 >=1，实际 %d", g.Epoch())
	}
	ls, ok := g.Leader()
	if !ok || ls.Holder != "dc1-hsm-a" {
		t.Fatalf("组主租约应为 dc1-hsm-a，实际 %+v", ls)
	}
}

func TestGroupDataPlaneWorksWithoutLeader(t *testing.T) {
	// 不 Init（协调器未启动 → 非组主）；数据面仍应可用。
	g, m1, _, _ := newTestGroup(t, "dc1-hsm-a")
	defer g.Close()
	// 直接在成员 dc1 上造一个密钥，手动包成 GroupKeyRef 信封。
	inner, _ := m1.GenerateKey("sm4-128", "")
	keyID := newKeyID()
	env, err := testkit.EncodeGroupKeyRef(keyID, "dc1-hsm-a", "tenant-a", inner)
	if err != nil {
		t.Fatalf("编码信封失败: %v", err)
	}
	nonce := []byte("0123456789ab")
	pt := []byte("plaintext")
	ct, err := g.Seal(env, nonce, pt, nil)
	if err != nil {
		t.Fatalf("无组主时 Seal 应成功: %v", err)
	}
	got, err := g.Open(env, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("明文不一致: %q vs %q", got, pt)
	}
}

func TestGroupLifecycleRequiresLeader(t *testing.T) {
	g, _, _, _ := newTestGroup(t, "dc1-hsm-a")
	defer g.Close()
	// 未 Init → 非组主。
	if _, err := g.GenerateKey("sm4-128", ""); err != ErrNotLeader {
		t.Fatalf("非组主 GenerateKey 应返 ErrNotLeader，实际 %v", err)
	}
	if _, _, err := g.GenerateKeyPair("sign"); err != ErrNotLeader {
		t.Fatalf("非组主 GenerateKeyPair 应返 ErrNotLeader，实际 %v", err)
	}
	if err := g.DestroyKey([]byte("mock:1")); err != ErrNotLeader {
		t.Fatalf("非组主 DestroyKey 应返 ErrNotLeader，实际 %v", err)
	}
}

func TestGroupGenerateKeyAsLeaderWrapsEnvelope(t *testing.T) {
	g, m1, _, _ := newTestGroup(t, "dc1-hsm-a")
	g.Init(nil)
	defer g.Close()
	env, err := g.GenerateKey("sm4-128", "")
	if err != nil {
		t.Fatalf("组主 GenerateKey 失败: %v", err)
	}
	// 信封应路由回 dc1 并可用于 Seal/Open。
	nonce := []byte("0123456789ab")
	pt := []byte("secret-data")
	ct, err := g.Seal(env, nonce, pt, nil)
	if err != nil {
		t.Fatalf("用组主生成的信封 Seal 失败: %v", err)
	}
	got, err := g.Open(env, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
	if string(got) != string(pt) {
		t.Fatalf("明文不一致")
	}
	_ = m1
}

func TestGroupTwoCoordinatorsOneLeader(t *testing.T) {
	cfg := testGroupConfig()
	m1 := newMockMember()
	m2a := newMockMember()
	m2b := newMockMember()
	// 同一控制存储，两个 sidecar：dc1 与 dc2（分属不同 DC）。
	store := testkit.NewMemoryControlStore("fin-hsm-a")
	gA, err := NewGroupProvider(cfg, map[string]module.ModuleBackend{"dc1-hsm-a": m1, "dc2-hsm-a": m2a}, "dc1-hsm-a", store, "boot-a", nil)
	if err != nil {
		t.Fatalf("gA: %v", err)
	}
	gB, err := NewGroupProvider(cfg, map[string]module.ModuleBackend{"dc1-hsm-a": m1, "dc2-hsm-a": m2b}, "dc2-hsm-a", store, "boot-b", nil)
	if err != nil {
		t.Fatalf("gB: %v", err)
	}
	gA.Init(nil)
	gB.Init(nil)
	defer gA.Close()
	defer gB.Close()

	if !gA.IsLeader() {
		t.Fatalf("gA(dc1) 应为组主")
	}
	if gB.IsLeader() {
		t.Fatalf("gB(dc2, 跨 DC 无 promotion) 不应成为组主")
	}
	// gB 生命周期写必须被拒（非组主）。
	if _, err := gB.GenerateKey("sm4-128", ""); err != ErrNotLeader {
		t.Fatalf("gB 跨 DC 非组主 GenerateKey 应返 ErrNotLeader，实际 %v", err)
	}
}

func TestGroupHealthAggregation(t *testing.T) {
	g, _, m2, _ := newTestGroup(t, "dc1-hsm-a")
	g.Init(nil)
	defer g.Close()
	if g.Health() != module.HealthOK {
		t.Fatalf("初始应 OK，实际 %v", g.Health())
	}
	m2.FailHealth = true // dc2 下线
	if g.Health() != module.HealthDegraded {
		t.Fatalf("单成员下线应 Degraded，实际 %v", g.Health())
	}
}

func TestGroupFailClosedAllDown(t *testing.T) {
	g, m1, m2, _ := newTestGroup(t, "dc1-hsm-a")
	g.Init(nil)
	defer g.Close()
	m1.FailHealth = true
	m2.FailHealth = true
	// 数据面无健康成员 → fail-closed（即便有组主，路由也会拒）。
	if _, err := g.Rand(16); err == nil {
		t.Fatalf("全下线 Rand 应失败")
	}
}

func TestGroupStaleLeaderCannotWrite(t *testing.T) {
	g, _, _, _ := newTestGroup(t, "dc1-hsm-a")
	g.Init(nil)
	// 停止协调器 → 失去组主身份（模拟陈旧主/fence）。
	g.Close()
	// 再次生成应先 Start 才合法；此处直接验证停止后非组主。
	if g.IsLeader() {
		t.Fatalf("停止后不应是组主")
	}
}

func TestGroupEnvelopeRoutesToMember(t *testing.T) {
	g, m1, m2, _ := newTestGroup(t, "dc1-hsm-a")
	defer g.Close()
	// 给 dc2 注入 Seal 故障，验证信封能精确路由到 dc1（而非被 dc2 影响）。
	m2.FailSeal = module.ErrModuleUnavailable
	inner, _ := m1.GenerateKey("sm4-128", "")
	keyID := newKeyID()
	env, err := testkit.EncodeGroupKeyRef(keyID, "dc1-hsm-a", "tenant-a", inner)
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}
	nonce := []byte("0123456789ab")
	ct, err := g.Seal(env, nonce, []byte("x"), nil)
	if err != nil {
		t.Fatalf("路由到健康 dc1 的 Seal 应成功，实际 %v", err)
	}
	_, err = g.Open(env, nonce, ct, nil)
	if err != nil {
		t.Fatalf("Open 失败: %v", err)
	}
}

func TestGroupSessionPackUnpack(t *testing.T) {
	for idx := uint16(0); idx < 5; idx++ {
		s := module.Session(0x1234)
		pk := packSession(idx, s)
		gotIdx, gotS := unpackSession(pk)
		if gotIdx != idx || gotS != s {
			t.Fatalf("pack/unpack 不一致: in(%d,%x) out(%d,%x)", idx, uintptr(s), gotIdx, uintptr(gotS))
		}
	}
}

func TestGroupMetricsRender(t *testing.T) {
	g, _, _, _ := newTestGroup(t, "dc1-hsm-a")
	g.Init(nil)
	defer g.Close()
	var buf bytes.Buffer
	g.RenderMetrics(&buf)
	if buf.Len() == 0 {
		t.Fatalf("指标渲染应为非空")
	}
	if !bytes.Contains(buf.Bytes(), []byte("gateway_group_leader_epoch")) {
		t.Fatalf("指标应包含 leader_epoch")
	}
}
