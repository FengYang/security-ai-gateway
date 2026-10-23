package testkit

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func bootReq(member, dc, boot string, epoch, dv uint64) OwnerAcquireRequest {
	return OwnerAcquireRequest{
		Member: member, DC: dc, BootID: boot, ExpectedEpoch: epoch,
		ExpectedDesiredVersion: dv, TTL: 30 * time.Second,
	}
}

// TestAcquireOwnerConcurrentOnlyOneWins N 个成员并发竞争，必须恰好 1 个成功。
func TestAcquireOwnerConcurrentOnlyOneWins(t *testing.T) {
	s := NewMemoryControlStore("fin-hsm-a")
	dv := s.DesiredVersion()
	const n = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	errs := 0
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req := bootReq("m"+string(rune('a'+i)), "dc1", "boot-"+string(rune('a'+i)), 0, dv)
			req.AllowBootstrap = true
			req.BootstrapOwner = "m" + string(rune('a'+i))
			_, err := s.AcquireOwner(req)
			mu.Lock()
			if err == nil {
				wins++
			} else {
				errs++
			}
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if wins != 1 || errs != n-1 {
		t.Fatalf("并发竞争应恰好 1 个成功：成功 %d 失败 %d", wins, errs)
	}
	if st := s.GetOwnerState(); st.Epoch != 1 {
		t.Fatalf("epoch 应为 1，实测 %d", st.Epoch)
	}
}

// TestAcquireOwnerDesiredVersionChange desired 在竞争窗口变化必须返回 group_stale_epoch。
func TestAcquireOwnerDesiredVersionChange(t *testing.T) {
	s := NewMemoryControlStore("g")
	old := s.DesiredVersion()
	s.SetDesired() // admin 在窗口内改了 desired
	req := bootReq("m1", "dc1", "boot-1", 0, old)
	req.AllowBootstrap = true
	req.BootstrapOwner = "m1"
	if _, err := s.AcquireOwner(req); err == nil {
		t.Fatalf("desired 版本变化应被拒绝")
	} else if !errors.Is(err, ErrGroupStaleEpoch) {
		t.Fatalf("错误应为 ErrGroupStaleEpoch，实测 %v", err)
	}
}

// TestAcquireOwnerCrossDCRequiresPromotion 跨 DC 必须人工 promotion，禁止自动 takeover。
func TestAcquireOwnerCrossDCRequiresPromotion(t *testing.T) {
	s := NewMemoryControlStore("g")
	dv := s.DesiredVersion()
	first := bootReq("dc1-hsm-a", "dc1", "boot-1", 0, dv)
	first.AllowBootstrap = true
	first.BootstrapOwner = "dc1-hsm-a"
	if _, err := s.AcquireOwner(first); err != nil {
		t.Fatalf("首主应成功: %v", err)
	}
	s.ExpireLeaseForTest()

	// 跨 DC 且无 promotion -> 拒绝
	second := bootReq("dc2-hsm-a", "dc2", "boot-2", 1, dv)
	second.AllowAutoIntraDC = true
	if _, err := s.AcquireOwner(second); err == nil {
		t.Fatalf("跨 DC 无 promotion 应被拒绝")
	} else if !errors.Is(err, ErrGroupStaleEpoch) {
		t.Fatalf("错误应为 ErrGroupStaleEpoch，实测 %v", err)
	}

	// 带 promotion（双签）-> 通过
	promoted := bootReq("dc2-hsm-a", "dc2", "boot-2", 1, dv)
	promoted.Promotion = &Promotion{TargetMember: "dc2-hsm-a", ExpectedEpoch: 1,
		ApprovalID: "ap-1", Digest: "sha256:..."}
	if _, err := s.AcquireOwner(promoted); err != nil {
		t.Fatalf("带双签 promotion 的跨 DC 切换应成功: %v", err)
	}
	if st := s.GetOwnerState(); st.LastOwner != "dc2-hsm-a" || st.LastDC != "dc2" {
		t.Fatalf("组主未切换到 dc2: %+v", st)
	}

	// 同 DC 自动接管 -> 通过（无 promotion）
	s.ExpireLeaseForTest()
	auto := bootReq("dc2-hsm-b", "dc2", "boot-3", 2, dv)
	auto.AllowAutoIntraDC = true
	if _, err := s.AcquireOwner(auto); err != nil {
		t.Fatalf("同 DC 自动接管应成功: %v", err)
	}
}

// TestAcquireOwnerPromotionMissingApproval promotion 缺双签必须拒绝。
func TestAcquireOwnerPromotionMissingApproval(t *testing.T) {
	s := NewMemoryControlStore("g")
	dv := s.DesiredVersion()
	req := bootReq("dc1-hsm-a", "dc1", "boot-1", 0, dv)
	req.AllowBootstrap = true
	req.BootstrapOwner = "dc1-hsm-a"
	if _, err := s.AcquireOwner(req); err != nil {
		t.Fatalf("首主应成功: %v", err)
	}
	s.ExpireLeaseForTest()
	bad := bootReq("dc2-hsm-a", "dc2", "boot-2", 1, dv)
	bad.Promotion = &Promotion{TargetMember: "dc2-hsm-a", ExpectedEpoch: 1} // 无审批
	if _, err := s.AcquireOwner(bad); err == nil {
		t.Fatalf("缺双签的 promotion 应被拒绝")
	}
}

// TestRenewOwnerBootIDAndEpoch 续租必须 boot_id 与 epoch 同时匹配。
func TestRenewOwnerBootIDAndEpoch(t *testing.T) {
	s := NewMemoryControlStore("g")
	dv := s.DesiredVersion()
	req := bootReq("m1", "dc1", "boot-1", 0, dv)
	req.AllowBootstrap = true
	req.BootstrapOwner = "m1"
	lease, err := s.AcquireOwner(req)
	if err != nil {
		t.Fatalf("首主应成功: %v", err)
	}
	if err := s.RenewOwner("m1", "boot-1", lease.Epoch, 30*time.Second); err != nil {
		t.Fatalf("正常续租应成功: %v", err)
	}
	if err := s.RenewOwner("m1", "boot-OTHER", lease.Epoch, 30*time.Second); err == nil {
		t.Fatalf("boot_id 不匹配应失败")
	}
	if err := s.RenewOwner("m1", "boot-1", lease.Epoch+1, 30*time.Second); err == nil {
		t.Fatalf("epoch 不匹配应失败")
	}
	if err := s.RenewOwner("m2", "boot-1", lease.Epoch, 30*time.Second); err == nil {
		t.Fatalf("非持有者续租应失败")
	}
}

// TestCASKeyOpOldOwnerCannotOverwrite 旧主不得用旧版本覆盖新终态。
func TestCASKeyOpOldOwnerCannotOverwrite(t *testing.T) {
	s := NewMemoryControlStore("g")
	if _, err := s.CreateKeyOp(KeyOp{OpID: "op-1", Action: "destroy", Status: "pending"}); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	// 新主 claim 并把状态推到 running（版本 1 -> 2）
	if _, err := s.CASKeyOp("op-1", 1, "pending", KeyOp{OpID: "op-1", Action: "destroy",
		Status: "running", ClaimOwner: "m2", ClaimEpoch: 2}); err != nil {
		t.Fatalf("CAS 应成功: %v", err)
	}
	// 旧主仍按版本 1/pending 尝试写终态 -> 必须失败
	if _, err := s.CASKeyOp("op-1", 1, "pending", KeyOp{OpID: "op-1", Action: "destroy",
		Status: "succeeded", ClaimOwner: "m1", ClaimEpoch: 1}); err == nil {
		t.Fatalf("旧主用旧版本覆盖新终态应被拒绝")
	} else if !errors.Is(err, ErrGroupCASConflict) {
		t.Fatalf("错误应为 ErrGroupCASConflict，实测 %v", err)
	}
	// 读取到的仍是新主写的值
	op, _, err := s.GetKeyOp("op-1")
	if err != nil {
		t.Fatalf("读取失败: %v", err)
	}
	if op.Status != "running" || op.ClaimOwner != "m2" {
		t.Fatalf("终态被污染: %+v", op)
	}
}

// TestWatchKeyOpsFromRevision 切换窗口内按 fromRevision 续传，不丢事件。
func TestWatchKeyOpsFromRevision(t *testing.T) {
	s := NewMemoryControlStore("g")
	if _, err := s.CreateKeyOp(KeyOp{OpID: "op-1", Action: "backup", Status: "pending"}); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	op1, _, _ := s.GetKeyOp("op-1")
	rev := op1.StoreRevision
	// 组主在"切换窗口"之后又创建了 op-2
	if _, err := s.CreateKeyOp(KeyOp{OpID: "op-2", Action: "rotate", Status: "pending"}); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	// 新主从 rev 续 watch：应只见 op-2，不重复 op-1
	got := s.WatchKeyOps(rev)
	if len(got) != 1 || got[0].OpID != "op-2" {
		t.Fatalf("续传结果错误: %+v", got)
	}
	// 从 0 续传应见全部
	if all := s.WatchKeyOps(0); len(all) != 2 {
		t.Fatalf("全量续传应见 2 条，实测 %d", len(all))
	}
}

// TestCASKeyDirectoryRequiresCurrentLease 目录写必须是当前组主（epoch + boot_id 双重校验）。
func TestCASKeyDirectoryRequiresCurrentLease(t *testing.T) {
	s := NewMemoryControlStore("g")
	dv := s.DesiredVersion()
	req := bootReq("m1", "dc1", "boot-1", 0, dv)
	req.AllowBootstrap = true
	req.BootstrapOwner = "m1"
	lease, err := s.AcquireOwner(req)
	if err != nil {
		t.Fatalf("首主应成功: %v", err)
	}
	kd := KeyDirectory{Version: 1, KeyID: "0123456789abcdef0123456789abcdef", State: "ready"}
	// 非当前组主（epoch 不符）-> 拒绝
	if _, err := s.CASKeyDirectory(kd.KeyID, 0, lease.Epoch+9, "boot-1", kd); err == nil {
		t.Fatalf("epoch 不符的目录写应被拒绝")
	}
	// boot_id 不符 -> 拒绝
	if _, err := s.CASKeyDirectory(kd.KeyID, 0, lease.Epoch, "boot-OTHER", kd); err == nil {
		t.Fatalf("boot_id 不符的目录写应被拒绝")
	}
	// 当前组主 -> 通过，版本递增
	if v, err := s.CASKeyDirectory(kd.KeyID, 0, lease.Epoch, "boot-1", kd); err != nil || v != 1 {
		t.Fatalf("当前组主目录写应成功且版本为 1: v=%d err=%v", v, err)
	}
	// 版本不匹配 -> 拒绝（防并发覆盖）
	if _, err := s.CASKeyDirectory(kd.KeyID, 0, lease.Epoch, "boot-1", kd); err == nil {
		t.Fatalf("版本不匹配的目录写应被拒绝")
	}
}
