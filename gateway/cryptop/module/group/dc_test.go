package group

import (
	"errors"
	"testing"
	"time"

	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// ---------------------------------------------------------------------------
// T-3 跨机房容灾骨架测试（对着内存控制存储 + mock，不接真机/真实 DC）
// ---------------------------------------------------------------------------

func TestDCTopology(t *testing.T) {
	topo := NewDCTopology(map[string]string{
		"m1": "dc1", "m2": "dc1", "m3": "dc2",
	})

	// 跨 DC 判定
	if topo.IsCrossDC("m1", "m3") != true {
		t.Fatal("m1(dc1) 与 m3(dc2) 应判定为跨机房")
	}
	if topo.IsCrossDC("m1", "m2") != false {
		t.Fatal("m1/m2 同在 dc1，不应判定为跨机房")
	}
	// 未知成员：保守返回 false（拓扑不完整时不走 promotion 路径）
	if topo.IsCrossDC("m1", "unknown") != false {
		t.Fatal("未知 DC 应保守返回 false")
	}

	// 机房列表去重升序
	dcs := topo.DCs()
	if len(dcs) != 2 || dcs[0] != "dc1" || dcs[1] != "dc2" {
		t.Fatalf("DCs() = %v，期望 [dc1 dc2]", dcs)
	}
	// 成员归属
	in := topo.MembersIn("dc1")
	if len(in) != 2 || in[0] != "m1" || in[1] != "m2" {
		t.Fatalf("MembersIn(dc1) = %v，期望 [m1 m2]", in)
	}
	if topo.DC("m3") != "dc2" {
		t.Fatalf("DC(m3) = %s，期望 dc2", topo.DC("m3"))
	}
}

func TestLatencyBudgetValidate(t *testing.T) {
	b := DefaultLatencyBudget()

	// ① 正常：本机形态、同 DC，实测 10ms < 50ms 预算
	if err := b.Validate(AccessLocal, false, 10*time.Millisecond); err != nil {
		t.Fatalf("本机同 DC 正常场景不应报错: %v", err)
	}

	// ② 跨 DC 叠加附加 RTT：本机跨 DC 预算 = 50+100 = 150ms
	if err := b.Validate(AccessLocal, true, 120*time.Millisecond); err != nil {
		t.Fatalf("跨 DC 120ms 应低于预算 150ms: %v", err)
	}
	if err := b.Validate(AccessLocal, true, 180*time.Millisecond); err == nil {
		t.Fatal("跨 DC 180ms 应超预算 150ms")
	} else if !errors.Is(err, ErrLatencyBudgetExceeded) {
		t.Fatalf("应返回 ErrLatencyBudgetExceeded，实际 %v", err)
	}

	// ③ R-5：网络形态不得套用 localhost 50ms 口径（配置层硬伤直接拒）
	bad := DefaultLatencyBudget()
	bad.NetworkRTT = 50 * time.Millisecond
	if err := bad.Validate(AccessNetwork, false, 10*time.Millisecond); !errors.Is(err, ErrLocalhostCaliberOnNetwork) {
		t.Fatalf("网络形态套用 50ms 口径应返回 ErrLocalhostCaliberOnNetwork，实际 %v", err)
	}

	// ④ 网络形态正常：200ms 预算
	if err := b.Validate(AccessNetwork, false, 150*time.Millisecond); err != nil {
		t.Fatalf("网络形态 150ms 应低于预算 200ms: %v", err)
	}
	// ⑤ 网络 + 跨 DC：200+100=300ms
	if err := b.Validate(AccessNetwork, true, 350*time.Millisecond); !errors.Is(err, ErrLatencyBudgetExceeded) {
		t.Fatalf("网络跨 DC 350ms 应超预算 300ms，实际 %v", err)
	}
}

func TestPromoteRequiresDualApproval(t *testing.T) {
	ctrl := testkit.NewMemoryControlStore("g1")
	c := NewCoordinator(ctrl, "m1", "boot1", "dc1", time.Minute, true, "m1", true)

	// 缺双签审批 → 拒绝（D-8：跨 DC promotion 必须双签）
	if _, err := c.Promote("", ""); !errors.Is(err, ErrPromotionApprovalRequired) {
		t.Fatalf("缺双签应返回 ErrPromotionApprovalRequired，实际 %v", err)
	}
	if _, err := c.Promote("ap-1", ""); !errors.Is(err, ErrPromotionApprovalRequired) {
		t.Fatalf("缺 digest 应返回 ErrPromotionApprovalRequired，实际 %v", err)
	}
	if _, err := c.Promote("", "digest-1"); !errors.Is(err, ErrPromotionApprovalRequired) {
		t.Fatalf("缺 approvalID 应返回 ErrPromotionApprovalRequired，实际 %v", err)
	}
}

func TestCrossDCAutoSwitchForbidden(t *testing.T) {
	ctrl := testkit.NewMemoryControlStore("g1")

	// m1（dc1）bootstrap 成主后释放租约
	c1 := NewCoordinator(ctrl, "m1", "boot1", "dc1", time.Minute, true, "m1", true)
	c1.Start()
	if !c1.IsLeader() {
		t.Fatal("m1 应成为组主")
	}
	c1.Stop()

	// m2（dc2）尝试自动接管：**跨 DC 禁止自动切换**（D-8 / V-1）
	c2 := NewCoordinator(ctrl, "m2", "boot2", "dc2", time.Minute, false, "m1", true)
	c2.Start()
	defer c2.Stop()
	if c2.IsLeader() {
		t.Fatal("跨 DC 不得自动接管组主（必须人工 promotion）")
	}

	// 人工 promotion + 双签 → 成功
	if _, err := c2.Promote("ap-cross-dc", "digest-cross-dc"); err != nil {
		t.Fatalf("跨 DC promotion（双签）应成功: %v", err)
	}
	if !c2.IsLeader() {
		t.Fatal("promotion 后 m2 应成为组主")
	}
	// epoch 应递增
	if c2.Epoch() <= c1.Epoch() {
		t.Fatalf("promotion 后 epoch 应递增（c1=%d c2=%d）", c1.Epoch(), c2.Epoch())
	}
}

type mockRevoker struct {
	calls      map[string]bool
	failProbe  bool
	failRevoke bool
}

func newMockRevoker() *mockRevoker {
	return &mockRevoker{calls: map[string]bool{}}
}

func (m *mockRevoker) RevokePartition(member, partition string) error {
	// 空参数 = 仅探测可达性
	if member == "" && partition == "" {
		if m.failProbe {
			return ErrVendorAdminUnsupported
		}
		return nil
	}
	if m.failRevoke {
		return ErrVendorAdminUnsupported
	}
	m.calls[member+"|"+partition] = true
	return nil
}

func TestVendorAdminProbeUnsupportedWhenNoEndpoint(t *testing.T) {
	// endpoint 空 = 不支持，按降级登记（L382/L453），不得静默当作支持
	va := NewVendorAdmin(VendorAdminConfig{}, newMockRevoker())
	if va.Probe() {
		t.Fatal("endpoint 为空时应探测为不支持")
	}
	if va.Supported() {
		t.Fatal("Supported() 应为 false")
	}
	if err := va.Revoke("m1", "p1"); !errors.Is(err, ErrVendorAdminUnsupported) {
		t.Fatalf("不支持时 Revoke 应返回 ErrVendorAdminUnsupported，实际 %v", err)
	}
}

func TestVendorAdminProbeFailsDegradesGracefully(t *testing.T) {
	// 探测失败 → 按"不支持"降级并告警，不得静默当作支持（L453）
	r := newMockRevoker()
	r.failProbe = true
	va := NewVendorAdmin(VendorAdminConfig{Endpoint: "https://vendor-admin", CredentialRef: "secret"}, r)
	if va.Probe() {
		t.Fatal("探测失败应返回不支持")
	}
	if va.Supported() {
		t.Fatal("探测失败后 Supported() 应为 false")
	}
}

func TestVendorAdminRevokeSucceeds(t *testing.T) {
	r := newMockRevoker()
	va := NewVendorAdmin(VendorAdminConfig{Endpoint: "https://vendor-admin", CredentialRef: "secret"}, r)
	if !va.Probe() {
		t.Fatal("endpoint 非空且探测可达时应支持")
	}
	if err := va.Revoke("m-old", "part-1"); err != nil {
		t.Fatalf("Revoke 失败: %v", err)
	}
	if !r.calls["m-old|part-1"] {
		t.Fatal("撤销未下达到厂商管理面")
	}
}

func TestVendorAdminNotProbedIsUnsupported(t *testing.T) {
	// 未探测前一律不支持（保守，避免未探测即当支持）
	va := NewVendorAdmin(VendorAdminConfig{Endpoint: "https://vendor-admin"}, newMockRevoker())
	if va.Supported() {
		t.Fatal("未探测前 Supported() 应为 false")
	}
}

func TestRTOBudget(t *testing.T) {
	b := DefaultRTOBudget()
	// 默认是**占位**阈值（U-4 提议基线），不是已确认判据——G-0② 仍挂起（S-32）。
	if b.MaxRTO != PlaceholderMaxRTO {
		t.Fatalf("默认 RTO 预算应为占位值 %v（U-4 提议基线），实际 %v", PlaceholderMaxRTO, b.MaxRTO)
	}
	if b.Confirmed {
		t.Fatal("默认预算必须为未确认（占位）状态")
	}
	// 未实测/未确认 → 不得宣称达标
	if b.WithinRTO() {
		t.Fatal("未实测且未确认时 WithinRTO() 应为 false")
	}
	// 确认后实测达标
	b.ConfirmMaxRTO(30 * time.Second)
	start := time.Now()
	b.Record(start, start.Add(12*time.Second))
	if !b.WithinRTO() {
		t.Fatalf("确认后实测 12s 应达标（预算 30s），实际 %v", b.Measured)
	}
	// 实测超标
	b2 := DefaultRTOBudget()
	b2.ConfirmMaxRTO(30 * time.Second)
	s := time.Now()
	b2.Record(s, s.Add(45*time.Second))
	if b2.WithinRTO() {
		t.Fatalf("实测 45s 应超预算 30s，不得判达标")
	}
}

// 占位符口径（U-4 / S-32）：客户书面确认前，RTO 阈值只是占位值，
// 不得据此判达标——即使实测值远小于占位阈值。
func TestRTOBudgetPlaceholderIsNotVerdict(t *testing.T) {
	b := DefaultRTOBudget()
	if b.MaxRTO != PlaceholderMaxRTO {
		t.Fatalf("占位阈值应为 %v，实际 %v", PlaceholderMaxRTO, b.MaxRTO)
	}
	if b.Confirmed {
		t.Fatal("默认预算必须是未确认状态（占位符）")
	}

	// 实测远小于占位阈值，也不得判达标（占位值不是判据）。
	start := time.Now()
	b.Record(start, start.Add(10*time.Millisecond))
	if b.WithinRTO() {
		t.Fatal("未确认时 WithinRTO 恒应为 false（不得把占位阈值当验收判据）")
	}
	if got := b.Verdict(); got != "pending" {
		t.Fatalf("未确认时判据应为 pending，实际 %q", got)
	}

	// 客户书面确认后才可判达标。
	b.ConfirmMaxRTO(30 * time.Second)
	if !b.Confirmed || b.MaxRTO != 30*time.Second {
		t.Fatalf("确认后阈值应为 30s 且 Confirmed=true，实际 %v/%v", b.MaxRTO, b.Confirmed)
	}
	if !b.WithinRTO() || b.Verdict() != "pass" {
		t.Fatalf("确认且实测达标应判 pass，实际 WithinRTO=%v Verdict=%q", b.WithinRTO(), b.Verdict())
	}
}

// 确认后实测超阈值 → fail（不是 pending，也不是静默通过）。
func TestRTOBudgetConfirmedButExceeded(t *testing.T) {
	b := DefaultRTOBudget()
	b.ConfirmMaxRTO(30 * time.Second)
	start := time.Now()
	b.Record(start, start.Add(2*time.Minute))
	if b.WithinRTO() {
		t.Fatal("实测超阈值不应判达标")
	}
	if got := b.Verdict(); got != "fail" {
		t.Fatalf("确认且超阈值应判 fail，实际 %q", got)
	}
}

// 无效确认（d<=0）不得把判据清掉或置为已确认。
func TestRTOBudgetInvalidConfirmIgnored(t *testing.T) {
	b := DefaultRTOBudget()
	b.ConfirmMaxRTO(0)
	b.ConfirmMaxRTO(-time.Second)
	if b.Confirmed {
		t.Fatal("d<=0 的确认应被忽略（避免空值清掉判据）")
	}
}
