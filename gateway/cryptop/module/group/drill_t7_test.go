package group

import (
	"errors"
	"testing"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// T-7 演练与整体验收：**故障注入矩阵 + 红线回归**（§7.2 T-7）。
//
// **边界（重要）**：本文件是代码研发阶段的故障注入矩阵与红线回归用例，
// 对着 **mock 成员 + 内存控制存储** 执行。**真机故障注入**（拔卡 / 断网 /
// 脑裂 / 网络抖动）、跨 DC 演练与演练报告（含 RTO 实测、证据归档）属 Wave B，
// 需借测硬件与真实集群环境。因此本文件**不宣称 T-7 演练通过、不宣称 V-7 达标**。
//
// 矩阵覆盖（红线优先，任一条失败即阻断交付）：
//  ① 单成员失效（拔卡/断网模拟）→ 健康度降级，不得仍报全绿；
//  ② 全成员失效 → 数据面 **fail-closed**，绝不静默降级（R-6）；
//  ③ 故障期间生命周期写仍受组主约束（不得因故障绕过 fencing，D-8）；
//  ④ 单主红线：同一组内不得同时存在两个组主。

// ErrDrillMemberDown 故障注入：成员不可用（模拟拔卡/断网）。
var ErrDrillMemberDown = errors.New("drill: member down (injected)")

// drillFailingBackend 故障注入包装器：模拟成员不可用。
//
// 嵌入 module.ModuleBackend 继承其余能力，仅覆写健康度与数据面运算，
// 避免为实现 22 个方法而复制大量样板。
type drillFailingBackend struct {
	module.ModuleBackend
}

func (d *drillFailingBackend) Health() module.HealthLevel { return module.HealthDown }

func (d *drillFailingBackend) Seal(keyRef module.KeyRef, nonce, plaintext, aad []byte) ([]byte, error) {
	return nil, ErrDrillMemberDown
}

func (d *drillFailingBackend) Open(keyRef module.KeyRef, nonce, ciphertext, aad []byte) ([]byte, error) {
	return nil, ErrDrillMemberDown
}

// newDrillGroup 构造带故障注入的组：failMembers 中列出的成员被注入"不可用"。
func newDrillGroup(t *testing.T, self string, failMembers map[string]bool) (*ModuleGroup, *module.MockBackend, *module.MockBackend) {
	t.Helper()
	cfg := testGroupConfig()
	m1 := newMockMember()
	m2 := newMockMember()

	var b1, b2 module.ModuleBackend = m1, m2
	if failMembers["dc1-hsm-a"] {
		b1 = &drillFailingBackend{ModuleBackend: m1}
	}
	if failMembers["dc2-hsm-a"] {
		b2 = &drillFailingBackend{ModuleBackend: m2}
	}
	members := map[string]module.ModuleBackend{"dc1-hsm-a": b1, "dc2-hsm-a": b2}
	store := testkit.NewMemoryControlStore("fin-hsm-a")
	g, err := NewGroupProvider(cfg, members, self, store, "boot-"+self, nil)
	if err != nil {
		t.Fatalf("NewGroupProvider: %v", err)
	}
	return g, m1, m2
}

func drillEnvelope(t *testing.T, m *module.MockBackend) module.KeyRef {
	t.Helper()
	inner, err := m.GenerateKey("sm4-128", "")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	env, err := testkit.EncodeGroupKeyRef(newKeyID(), "dc1-hsm-a", "tenant-a", inner)
	if err != nil {
		t.Fatalf("EncodeGroupKeyRef: %v", err)
	}
	return env
}

// ① 单成员失效 → 健康度降级（不得掩盖故障）
func TestDrillSingleMemberDownDegradesHealth(t *testing.T) {
	g, _, _ := newDrillGroup(t, "dc1-hsm-a", nil)
	g.Init(nil)
	defer g.Close()

	if g.Health() != module.HealthOK {
		t.Fatalf("无故障时健康度应为 OK，实际 %v", g.Health())
	}
	g.Close()

	// 注入：dc1 成员不可用
	g2, _, _ := newDrillGroup(t, "dc1-hsm-a", map[string]bool{"dc1-hsm-a": true})
	g2.Init(nil)
	defer g2.Close()

	if g2.Health() == module.HealthOK {
		t.Fatal("单成员失效后健康度不应仍为 OK（应降级，不得掩盖故障）")
	}
}

// ② 全成员失效 → 数据面 fail-closed（R-6：绝不静默降级）
func TestDrillAllMembersDownFailClosed(t *testing.T) {
	g, m1, _ := newDrillGroup(t, "dc1-hsm-a", map[string]bool{
		"dc1-hsm-a": true, "dc2-hsm-a": true,
	})
	g.Init(nil)
	defer g.Close()

	if g.Health() != module.HealthDown {
		t.Fatalf("全成员失效后应 Down，实际 %v", g.Health())
	}

	env := drillEnvelope(t, m1)
	nonce := []byte("0123456789ab")

	if _, err := g.Seal(env, nonce, []byte("plaintext"), nil); err == nil {
		t.Fatal("全成员失效时 Seal 应 fail-closed（拒绝），不得静默降级")
	}
	if _, err := g.Open(env, nonce, []byte("ciphertext"), nil); err == nil {
		t.Fatal("全成员失效时 Open 应 fail-closed（拒绝），不得静默降级")
	}
}

// ③ 故障期间生命周期写仍受组主约束（不得因故障绕过 fencing，D-8）
func TestDrillLifecycleWriteStillLeaderGuardedUnderFault(t *testing.T) {
	// dc1（bootstrap owner）注入失效；dc2 非组主，仍不得执行生命周期写
	g, _, _ := newDrillGroup(t, "dc2-hsm-a", map[string]bool{"dc1-hsm-a": true})
	g.Init(nil)
	defer g.Close()

	if g.IsLeader() {
		t.Fatal("dc2-hsm-a 非 bootstrap owner，不应成为组主")
	}
	if _, err := g.GenerateKey("sm4-128", ""); err != ErrNotLeader {
		t.Fatalf("故障场景下非组主生命周期写应仍返回 ErrNotLeader，实际 %v", err)
	}
	if _, _, err := g.GenerateKeyPair("sign"); err != ErrNotLeader {
		t.Fatalf("故障场景下非组主 GenerateKeyPair 应仍返回 ErrNotLeader，实际 %v", err)
	}
}

// ④ 单主红线：同一组内不得同时存在两个组主
func TestDrillSingleLeaderRedline(t *testing.T) {
	cfg := testGroupConfig()
	store := testkit.NewMemoryControlStore("fin-hsm-a")

	mk := func(self string) *ModuleGroup {
		m1 := newMockMember()
		m2 := newMockMember()
		members := map[string]module.ModuleBackend{"dc1-hsm-a": m1, "dc2-hsm-a": m2}
		g, err := NewGroupProvider(cfg, members, self, store, "boot-"+self, nil)
		if err != nil {
			t.Fatalf("NewGroupProvider(%s): %v", self, err)
		}
		g.Init(nil)
		return g
	}

	g1 := mk("dc1-hsm-a")
	defer g1.Close()
	g2 := mk("dc2-hsm-a")
	defer g2.Close()

	if g1.IsLeader() && g2.IsLeader() {
		t.Fatal("同一组内不得同时存在两个组主（单主红线被破坏）")
	}
	if !g1.IsLeader() {
		t.Fatal("bootstrap owner（dc1-hsm-a）应成为组主")
	}
	if g2.IsLeader() {
		t.Fatal("dc2-hsm-a 不应成为组主")
	}
}
