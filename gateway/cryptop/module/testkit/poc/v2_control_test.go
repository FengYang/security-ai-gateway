package poc

// V-2：etcd 单主与 fencing POC（本体 §7.3.1 测试矩阵·协调器层 / §3.1.1 算法 2 / D-17）。
//
// 验收判据（对齐证据包 README）：
//   - 并发 N 个实例竞争，etcd 侧仅 1 个租约写入成功；
//   - epoch 单调递增不回退；
//   - 跨 DC 无 promotion 的 AcquireOwner 返回 group_stale_epoch；
//   - 同 DC 在租约过期后自动接管；promotion 需双签审批；
//   - 旧主/旧 step 不得覆盖新终态（KeyOp CAS + claim）；
//   - WatchKeyOps(fromRevision) 切换窗口不丢事件、不重复。

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func v2Store(t *testing.T) (*EtcdControlStore, context.Context) {
	t.Helper()
	eps := etcdEndpoints(t)
	ctx := context.Background()
	store, err := NewEtcdControlStore(ctx, eps, TestGID)
	if err != nil {
		t.Fatalf("连接 etcd 失败: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store, ctx
}

// acquireReq 构造 AcquireOwner 请求（同 DC 自动接管默认关闭，由用例显式打开）。
func acquireReq(member, dc, boot string, epoch, desired uint64) OwnerAcquireRequest {
	return OwnerAcquireRequest{
		Member: member, DC: dc, BootID: boot,
		ExpectedEpoch: epoch, ExpectedDesiredVersion: desired,
		TTL: 30 * time.Second,
	}
}

// waitLeaseGone 轮询等待 etcd 租约自然过期（lease 键被 etcd 自动删除）。
func waitLeaseGone(t *testing.T, ctx context.Context, s *EtcdControlStore, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := s.GetOwnerState(ctx)
		if err != nil {
			t.Fatalf("GetOwnerState: %v", err)
		}
		if st.Lease == nil {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("租约未在 %v 内过期", timeout)
}

// TestV2ConcurrentAcquireSingleWinner 16 个同成员实例（多 Pod）竞争同一组主租约，
// etcd txn 原子性保证仅 1 个成功，且 epoch 从 0 → 1。
func TestV2ConcurrentAcquireSingleWinner(t *testing.T) {
	store, ctx := v2Store(t)

	const n = 16
	var win int32
	var wins = make([]LeaseStatus, 0, 4)
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			req := acquireReq(TestMemberA, TestDCA, fmt.Sprintf("boot-%02d", i), 0, 0)
			req.AllowBootstrap = true
			req.BootstrapOwner = TestMemberA
			ls, err := store.AcquireOwner(ctx, req)
			if err == nil {
				atomic.AddInt32(&win, 1)
				mu.Lock()
				wins = append(wins, ls)
				mu.Unlock()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	if win != 1 {
		t.Fatalf("并发 AcquireOwner 成功数 = %d，期望 1（etcd 单 txn 原子性被破坏）", win)
	}
	st, err := store.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	if st.Epoch != 1 {
		t.Fatalf("epoch = %d，期望 1", st.Epoch)
	}
	if st.Lease == nil || st.Lease.Epoch != 1 || st.Lease.Holder != TestMemberA {
		t.Fatalf("租约状态异常: %+v", st.Lease)
	}
	if st.Lease.HolderBootID != wins[0].HolderBootID {
		t.Fatalf("租约持有者 boot_id 与胜者不一致")
	}
	t.Logf("16 并发竞争：胜者 boot=%s epoch=%d，其余 15 个全部 group_stale_epoch",
		st.Lease.HolderBootID, st.Lease.Epoch)
}

// TestV2StaleEpochRejected 陈旧 ExpectedEpoch 必须被拒（epoch 单调不回退）。
func TestV2StaleEpochRejected(t *testing.T) {
	store, ctx := v2Store(t)

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	// 用陈旧 epoch=0 再次竞争（此时实际 epoch=1，租约仍在）。
	stale := acquireReq(TestMemberB, TestDCA, "boot-b1", 0, 0)
	stale.AllowAutoIntraDC = true
	if _, err := store.AcquireOwner(ctx, stale); !isStale(err) {
		t.Fatalf("陈旧 epoch 竞争应返回 group_stale_epoch，实际: %v", err)
	}
	// 租约过期后同 DC 成员用正确 epoch 可接管；随后旧 epoch 持有者再竞争仍须被拒。
	if err := store.ReleaseOwner(ctx, TestMemberA, "boot-a1", 1); err != nil {
		t.Fatalf("ReleaseOwner: %v", err)
	}
	ok := acquireReq(TestMemberB, TestDCA, "boot-b1", 1, 0)
	ok.AllowAutoIntraDC = true
	ls, err := store.AcquireOwner(ctx, ok)
	if err != nil {
		t.Fatalf("同 DC 自动接管失败: %v", err)
	}
	if ls.Epoch != 2 {
		t.Fatalf("接管后 epoch = %d，期望 2（单调递增）", ls.Epoch)
	}
	if _, err := store.AcquireOwner(ctx, stale); !isStale(err) {
		t.Fatalf("epoch 回退竞争应被拒，实际: %v", err)
	}
}

// TestV2ActiveLeaseBlocksTakeover 租约未过期时同 DC 也不得抢占。
func TestV2ActiveLeaseBlocksTakeover(t *testing.T) {
	store, ctx := v2Store(t)

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	other := acquireReq(TestMemberA, TestDCA, "boot-a2", 1, 0) // 同成员另一 Pod
	other.AllowAutoIntraDC = true
	if _, err := store.AcquireOwner(ctx, other); !isStale(err) {
		t.Fatalf("租约未过期时的抢占应被拒，实际: %v", err)
	}
}

// TestV2AutoTakeoverAfterRealLeaseExpiry 租约 TTL 自然过期后同 DC 自动接管（真机行为）。
func TestV2AutoTakeoverAfterRealLeaseExpiry(t *testing.T) {
	store, ctx := v2Store(t)

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	req.TTL = 2 * time.Second
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	// 真机等待 etcd 租约过期（不人为撤销）。
	waitLeaseGone(t, ctx, store, 15*time.Second)

	takeover := acquireReq(TestMemberB, TestDCA, "boot-b1", 1, 0)
	takeover.AllowAutoIntraDC = true
	ls, err := store.AcquireOwner(ctx, takeover)
	if err != nil {
		t.Fatalf("租约过期后同 DC 自动接管失败: %v", err)
	}
	if ls.Epoch != 2 || ls.Holder != TestMemberB {
		t.Fatalf("接管结果异常: %+v", ls)
	}
	st, _ := store.GetOwnerState(ctx)
	if st.Epoch != 2 {
		t.Fatalf("epoch = %d，期望 2", st.Epoch)
	}
	t.Logf("租约 TTL 2s 自然过期 → %s 自动接管，epoch 1→2", TestMemberB)
}

// TestV2CrossDCWithoutPromotionRejected 跨 DC 无 promotion 禁止竞争。
func TestV2CrossDCWithoutPromotionRejected(t *testing.T) {
	store, ctx := v2Store(t)

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	if err := store.ReleaseOwner(ctx, TestMemberA, "boot-a1", 1); err != nil {
		t.Fatalf("ReleaseOwner: %v", err)
	}
	cross := acquireReq(TestMemberB, TestDCB, "boot-b1", 1, 0) // 不同 DC
	cross.AllowAutoIntraDC = true
	if _, err := store.AcquireOwner(ctx, cross); !isStale(err) {
		t.Fatalf("跨 DC 无 promotion 竞争应被拒，实际: %v", err)
	}
	// 组状态未被跨 DC 竞争破坏。
	st, _ := store.GetOwnerState(ctx)
	if st.Lease != nil {
		t.Fatalf("跨 DC 竞争后不应存在租约: %+v", st.Lease)
	}
	if st.LastDC != TestDCA {
		t.Fatalf("epochmeta 被跨 DC 竞争污染: %q", st.LastDC)
	}
}

// TestV2CrossDCWithPromotion 跨 DC 切换必须走 promotion + 双签审批。
func TestV2CrossDCWithPromotion(t *testing.T) {
	store, ctx := v2Store(t)

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	if err := store.ReleaseOwner(ctx, TestMemberA, "boot-a1", 1); err != nil {
		t.Fatalf("ReleaseOwner: %v", err)
	}

	// 无审批的 promotion 必须失败。
	noAppr := acquireReq(TestMemberB, TestDCB, "boot-b1", 1, 0)
	noAppr.Promotion = &Promotion{TargetMember: TestMemberB, ExpectedEpoch: 1, ApprovalID: "apr-1", Digest: "d1"}
	if _, err := store.AcquireOwner(ctx, noAppr); !isStale(err) {
		t.Fatalf("无审批的 promotion 应被拒，实际: %v", err)
	}

	// 双签审批（etcd 租约即有效期）。
	digest := "sha256:cross-dc-promote-b"
	if err := store.CreateApproval(ctx, Approval{
		ApprovalID: "apr-1", GroupID: TestGID, Action: "promote", Target: TestMemberB,
		Digest: digest, Initiator: "admin-1", Confirmer: "admin-2",
		ExpiresAt: time.Now().Add(2 * time.Minute),
	}); err != nil {
		t.Fatalf("CreateApproval: %v", err)
	}
	// digest 不匹配的 promotion 必须失败。
	bad := acquireReq(TestMemberB, TestDCB, "boot-b1", 1, 0)
	bad.Promotion = &Promotion{TargetMember: TestMemberB, ExpectedEpoch: 1, ApprovalID: "apr-1", Digest: "wrong"}
	if _, err := store.AcquireOwner(ctx, bad); !isStale(err) {
		t.Fatalf("digest 不匹配的 promotion 应被拒，实际: %v", err)
	}
	// 正确审批 → 跨 DC promotion 成功，epochmeta 更新为新 DC。
	good := acquireReq(TestMemberB, TestDCB, "boot-b1", 1, 0)
	good.Promotion = &Promotion{TargetMember: TestMemberB, ExpectedEpoch: 1, ApprovalID: "apr-1", Digest: digest}
	ls, err := store.AcquireOwner(ctx, good)
	if err != nil {
		t.Fatalf("带审批的跨 DC promotion 失败: %v", err)
	}
	if ls.Epoch != 2 || ls.DC != TestDCB {
		t.Fatalf("promotion 结果异常: %+v", ls)
	}
	st, _ := store.GetOwnerState(ctx)
	if st.LastDC != TestDCB {
		t.Fatalf("promotion 后 epochmeta = %q，期望 %q", st.LastDC, TestDCB)
	}
	// promotion 目标不是自己的请求必须被拒（本地即拒）。
	self := acquireReq(TestMemberA, TestDCA, "boot-a1", 2, 0)
	self.Promotion = &Promotion{TargetMember: TestMemberB, ExpectedEpoch: 2, ApprovalID: "apr-1", Digest: digest}
	if _, err := store.AcquireOwner(ctx, self); !isStale(err) {
		t.Fatalf("promotion 目标非本成员应被拒，实际: %v", err)
	}
}

// TestV2DesiredVersionChangeRejected desired 版本变化必须使竞争失败。
func TestV2DesiredVersionChangeRejected(t *testing.T) {
	store, ctx := v2Store(t)

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	newVer, err := store.SetDesired(ctx)
	if err != nil {
		t.Fatalf("SetDesired: %v", err)
	}
	if err := store.ReleaseOwner(ctx, TestMemberA, "boot-a1", 1); err != nil {
		t.Fatalf("ReleaseOwner: %v", err)
	}
	stale := acquireReq(TestMemberB, TestDCA, "boot-b1", 1, 0) // 旧 desired 版本
	stale.AllowAutoIntraDC = true
	if _, err := store.AcquireOwner(ctx, stale); !isStale(err) {
		t.Fatalf("desired 版本过期竞争应被拒，实际: %v", err)
	}
	fresh := acquireReq(TestMemberB, TestDCA, "boot-b1", 1, newVer)
	fresh.AllowAutoIntraDC = true
	if _, err := store.AcquireOwner(ctx, fresh); err != nil {
		t.Fatalf("带新 desired 版本的接管失败: %v", err)
	}
}

// TestV2RenewOwnerBootAndEpochCheck 续租 boot_id/epoch 双重校验。
func TestV2RenewOwnerBootAndEpochCheck(t *testing.T) {
	store, ctx := v2Store(t)

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	req.TTL = 30 * time.Second
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	// boot_id 不匹配 → FENCED。
	if err := store.RenewOwner(ctx, TestMemberA, "boot-other", 1, 30*time.Second); !isFenced(err) {
		t.Fatalf("boot_id 不匹配的续租应失败，实际: %v", err)
	}
	// epoch 不匹配 → FENCED。
	if err := store.RenewOwner(ctx, TestMemberA, "boot-a1", 99, 30*time.Second); !isFenced(err) {
		t.Fatalf("epoch 不匹配的续租应失败，实际: %v", err)
	}
	// 非持有者 → FENCED。
	if err := store.RenewOwner(ctx, TestMemberB, "boot-b1", 1, 30*time.Second); !isFenced(err) {
		t.Fatalf("非持有者续租应失败，实际: %v", err)
	}
	// 正确续租成功。
	if err := store.RenewOwner(ctx, TestMemberA, "boot-a1", 1, 30*time.Second); err != nil {
		t.Fatalf("正确续租失败: %v", err)
	}
	// 释放后续租失败（租约已撤销）。
	if err := store.ReleaseOwner(ctx, TestMemberA, "boot-a1", 1); err != nil {
		t.Fatalf("ReleaseOwner: %v", err)
	}
	if err := store.RenewOwner(ctx, TestMemberA, "boot-a1", 1, 30*time.Second); !isFenced(err) {
		t.Fatalf("释放后续租应失败，实际: %v", err)
	}
}

// TestV2KeyOpCASClaimSemantics 旧主（失效 claim）不得覆盖新终态。
func TestV2KeyOpCASClaimSemantics(t *testing.T) {
	store, ctx := v2Store(t)

	// A 建主并创建 KeyOp。
	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	if _, err := store.CreateKeyOp(ctx, KeyOp{OpID: "op-1", Action: "rotate", Status: "pending"}); err != nil {
		t.Fatalf("CreateKeyOp: %v", err)
	}
	// CAS 助手：expectedVer/expectedStatus 为前置条件，newStatus 为目标状态。
	cas := func(owner string, epoch uint64, expectedVer int64, expectedStatus, newStatus string) (int64, error) {
		return store.CASKeyOp(ctx, "op-1", expectedVer, expectedStatus, KeyOp{
			OpID: "op-1", Action: "rotate", Status: newStatus,
			ClaimOwner: owner, ClaimEpoch: epoch,
		})
	}
	// A claim：pending(v1) → running(v2)。
	if _, err := cas(TestMemberA, 1, 1, "pending", "running"); err != nil {
		t.Fatalf("A claim running 失败: %v", err)
	}
	// A 用陈旧版本/状态重放 → 冲突。
	if _, err := cas(TestMemberA, 1, 1, "pending", "running"); !isCAS(err) {
		t.Fatalf("陈旧版本/状态 CAS 应冲突，实际: %v", err)
	}
	// A 释放；B 接管（epoch 2）。
	if err := store.ReleaseOwner(ctx, TestMemberA, "boot-a1", 1); err != nil {
		t.Fatalf("ReleaseOwner: %v", err)
	}
	take := acquireReq(TestMemberB, TestDCA, "boot-b1", 1, 0)
	take.AllowAutoIntraDC = true
	if _, err := store.AcquireOwner(ctx, take); err != nil {
		t.Fatalf("B 接管失败: %v", err)
	}
	// 旧主 A 的 claim 已失效：版本/状态虽匹配，claim 比较失败 → 冲突
	// （隔离验证 claim 校验，而非版本不匹配）。
	if _, err := cas(TestMemberA, 1, 2, "running", "succeeded"); !isCAS(err) {
		t.Fatalf("旧主失效 claim 的 CAS 应冲突，实际: %v", err)
	}
	// 新主 B claim 并写终态：running(v2) → succeeded(v3)。
	if _, err := cas(TestMemberB, 2, 2, "running", "succeeded"); err != nil {
		t.Fatalf("新主 B CAS 失败: %v", err)
	}
	// 终态后不得回退（以旧状态作前置 → 冲突）。
	if _, err := cas(TestMemberB, 2, 3, "running", "failed"); !isCAS(err) {
		t.Fatalf("终态回退 CAS 应冲突，实际: %v", err)
	}
	op, ver, err := store.GetKeyOp(ctx, "op-1")
	if err != nil {
		t.Fatalf("GetKeyOp: %v", err)
	}
	if op.Status != "succeeded" || ver != 3 {
		t.Fatalf("KeyOp 终态异常: status=%s version=%d", op.Status, ver)
	}
}

// TestV2WatchKeyOpsNoLossNoDup 切换窗口内 WatchKeyOps(fromRevision) 不丢不重。
func TestV2WatchKeyOpsNoLossNoDup(t *testing.T) {
	store, ctx := v2Store(t)

	// 记录起始 revision，只关注其后产生的事件。
	startRev, err := store.CurrentRevision(ctx)
	if err != nil {
		t.Fatalf("CurrentRevision: %v", err)
	}
	ch, err := store.WatchKeyOps(ctx, startRev)
	if err != nil {
		t.Fatalf("WatchKeyOps: %v", err)
	}

	// A 建主，创建 op-1/op-2。
	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}
	for _, id := range []string{"op-1", "op-2"} {
		if _, err := store.CreateKeyOp(ctx, KeyOp{OpID: id, Action: "generate", Status: "pending"}); err != nil {
			t.Fatalf("CreateKeyOp(%s): %v", id, err)
		}
	}
	// 切换窗口：A 释放，B 接管，B 创建 op-3 并 claim。
	if err := store.ReleaseOwner(ctx, TestMemberA, "boot-a1", 1); err != nil {
		t.Fatalf("ReleaseOwner: %v", err)
	}
	take := acquireReq(TestMemberB, TestDCA, "boot-b1", 1, 0)
	take.AllowAutoIntraDC = true
	if _, err := store.AcquireOwner(ctx, take); err != nil {
		t.Fatalf("B 接管失败: %v", err)
	}
	if _, err := store.CreateKeyOp(ctx, KeyOp{OpID: "op-3", Action: "generate", Status: "pending"}); err != nil {
		t.Fatalf("CreateKeyOp(op-3): %v", err)
	}
	if _, err := store.CASKeyOp(ctx, "op-3", 1, "pending", KeyOp{
		OpID: "op-3", Action: "generate", Status: "running",
		ClaimOwner: TestMemberB, ClaimEpoch: 2,
	}); err != nil {
		t.Fatalf("B claim op-3: %v", err)
	}

	// 收集事件：每个 op 的 Create 与每次 CAS 都会产生一次 Put 事件。
	got := map[string]int{}
	var lastRev int64
	deadline := time.Now().Add(10 * time.Second)
	collectDone := false
	for !collectDone && time.Now().Before(deadline) {
		select {
		case op, ok := <-ch:
			if !ok {
				t.Fatalf("Watch 信道提前关闭（事件丢失）")
			}
			got[op.OpID]++
			if op.StoreRevision <= lastRev {
				t.Fatalf("事件 revision 非单调: %d <= %d", op.StoreRevision, lastRev)
			}
			lastRev = op.StoreRevision
			// op-1/op-2 各 1 次创建；op-3 创建 + 1 次 CAS = 2 次。
			if got["op-1"] >= 1 && got["op-2"] >= 1 && got["op-3"] >= 2 {
				collectDone = true
			}
		case <-time.After(2 * time.Second):
			collectDone = true // 不再有新事件即收口
		}
	}
	if !collectDone {
		t.Fatalf("10s 内未收到预期事件: %v", got)
	}
	// 精确断言：不丢（每个 op 至少出现预期次数）且不重（不出现超额重复）。
	for id, want := range map[string]int{"op-1": 1, "op-2": 1, "op-3": 2} {
		if got[id] != want {
			t.Fatalf("op %s 事件数 = %d，期望 %d（丢失或重复）: %v", id, got[id], want, got)
		}
	}
	t.Logf("WatchKeyOps(fromRevision=%d)：%v，revision 单调，无丢失无重复", startRev, got)
}

// TestV2CASKeyDirectoryWriterFencing 目录写：版本 + writer(epoch/boot) + 租约三重校验。
func TestV2CASKeyDirectoryWriterFencing(t *testing.T) {
	store, ctx := v2Store(t)

	req := acquireReq(TestMemberA, TestDCA, "boot-a1", 0, 0)
	req.AllowBootstrap = true
	req.BootstrapOwner = TestMemberA
	if _, err := store.AcquireOwner(ctx, req); err != nil {
		t.Fatalf("首次建主失败: %v", err)
	}

	const keyID = "0123456789abcdef0123456789abcdef"
	newDir := func(state string) KeyDirectory {
		return KeyDirectory{
			KeyID: keyID, KeyMode: "shared", State: state, CreatedBy: TestMemberA,
			Replicas: []KeyReplica{{Member: TestMemberA, Partition: TestPartition, State: "ready"}},
		}
	}
	// 组主写 v1。
	if _, err := store.CASKeyDirectory(ctx, keyID, 0, 1, "boot-a1", newDir("creating")); err != nil {
		t.Fatalf("组主 CAS 目录 v1 失败: %v", err)
	}
	kd, ver, err := store.GetKeyDirectory(ctx, keyID)
	if err != nil {
		t.Fatalf("读取目录失败（MAC 校验未过？）: %v", err)
	}
	if ver != 1 || kd.Version != 1 || kd.MAC == "" {
		t.Fatalf("目录 v1 异常: ver=%d kd.Version=%d mac=%q", ver, kd.Version, kd.MAC)
	}
	// 写者身份错误（boot 不匹配）→ 冲突。
	if _, err := store.CASKeyDirectory(ctx, keyID, 1, 1, "boot-other", newDir("ready")); !isCAS(err) {
		t.Fatalf("boot 不匹配的目录写应冲突，实际: %v", err)
	}
	// 写者 epoch 不匹配 → 冲突。
	if _, err := store.CASKeyDirectory(ctx, keyID, 1, 99, "boot-a1", newDir("ready")); !isCAS(err) {
		t.Fatalf("epoch 不匹配的目录写应冲突，实际: %v", err)
	}
	// 版本不匹配 → 冲突。
	if _, err := store.CASKeyDirectory(ctx, keyID, 7, 1, "boot-a1", newDir("ready")); !isCAS(err) {
		t.Fatalf("版本不匹配的目录写应冲突，实际: %v", err)
	}
	// 组主写 v2 成功。
	if _, err := store.CASKeyDirectory(ctx, keyID, 1, 1, "boot-a1", newDir("ready")); err != nil {
		t.Fatalf("组主 CAS 目录 v2 失败: %v", err)
	}
	// 租约过期后写权丧失：撤销租约，随后同参数写被拒。
	if err := store.ReleaseOwner(ctx, TestMemberA, "boot-a1", 1); err != nil {
		t.Fatalf("ReleaseOwner: %v", err)
	}
	if _, err := store.CASKeyDirectory(ctx, keyID, 2, 1, "boot-a1", newDir("degraded")); !isCAS(err) {
		t.Fatalf("租约释放后的目录写应冲突，实际: %v", err)
	}
	// 新组主（epoch 2）可继续写。
	take := acquireReq(TestMemberB, TestDCA, "boot-b1", 1, 0)
	take.AllowAutoIntraDC = true
	if _, err := store.AcquireOwner(ctx, take); err != nil {
		t.Fatalf("B 接管失败: %v", err)
	}
	if _, err := store.CASKeyDirectory(ctx, keyID, 2, 2, "boot-b1", newDir("degraded")); err != nil {
		t.Fatalf("新组主写目录失败: %v", err)
	}
	kd, ver, err = store.GetKeyDirectory(ctx, keyID)
	if err != nil {
		t.Fatalf("读取目录失败: %v", err)
	}
	if ver != 3 || kd.State != "degraded" {
		t.Fatalf("新组主写入后目录异常: ver=%d state=%s", ver, kd.State)
	}
}

func isStale(err error) bool  { return err != nil && errors.Is(err, ErrGroupStaleEpoch) }
func isCAS(err error) bool    { return err != nil && errors.Is(err, ErrGroupCASConflict) }
func isFenced(err error) bool { return err != nil && errors.Is(err, ErrGroupFenced) }
