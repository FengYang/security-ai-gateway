package ctrlstore

// etcd 真机行为测试：用 **embed 模式在测试进程内启动真实 etcd**（go.etcd.io/etcd/server/v3），
// 不依赖 docker、外部 etcd 服务或 cgo——本机即可运行。
//
// 覆盖 P2-3 本体 §3.1.1 / D-17 / §6.2.2 的关键安全属性：
//   ① 租约互斥（并发抢占只有一个赢家）
//   ② 陈旧主 fencing（旧 epoch / 异 bootID 一律拒）
//   ③ 目录 CAS 并发（同 keyID 只有一个写成功，版本严格递增）
//   ④ 目录 MAC 篡改检测（改 etcd 原值即拒读）
//   ⑤ 多数派丢失 fail-closed（etcd 不可达时写不得静默成功）
//   ⑥ 跨 DC promotion 必须双签
//
// 与 POC（testkit/poc）的分工：POC 继续作为独立参考实现与验证基线；
// 本文件是**产品实现**的真机判据。两者键布局一致，可互相约束。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"go.etcd.io/etcd/server/v3/embed"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// testMACKey 测试用目录 MAC 密钥（仅测试；生产由构造函数从 HSM 注入）。
var testMACKey = []byte("p2-3-test-directory-mac-key-32b")

// startEmbedEtcd 在进程内启动真实 etcd，返回客户端 URL 与停止函数。
//
// 两个易踩的坑：
//  1. **peer 与 client 必须用不同端口**——同端口会被 bind 两次，Windows 上直接报
//     "Only one usage of each socket address"；
//  2. 预留端口关闭后可能未立即释放（尤其 Windows），故带重试。
func startEmbedEtcd(t *testing.T) (string, func()) {
	t.Helper()

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
		}
		clientURL, stop, err := tryStartEmbedEtcd(t)
		if err == nil {
			return clientURL, stop
		}
		lastErr = err
	}
	t.Fatalf("启动 embed etcd 失败（重试 3 次）: %v", lastErr)
	return "", nil
}

func tryStartEmbedEtcd(t *testing.T) (string, func(), error) {
	dir := t.TempDir()
	peer := url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", freePort(t))}
	client := url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", freePort(t))}

	cfg := embed.NewConfig()
	cfg.Dir = dir
	cfg.Logger = "zap"
	cfg.LogLevel = "error" // 不写日志文件：避免 TempDir 清理时文件仍被 etcd 占用
	cfg.ListenPeerUrls = []url.URL{peer}
	cfg.ListenClientUrls = []url.URL{client}
	cfg.AdvertisePeerUrls = []url.URL{peer}
	cfg.AdvertiseClientUrls = []url.URL{client}
	cfg.InitialCluster = cfg.InitialClusterFromName(cfg.Name)

	e, err := embed.StartEtcd(cfg)
	if err != nil {
		return "", nil, err
	}
	select {
	case <-e.Server.ReadyNotify():
	case <-time.After(60 * time.Second):
		e.Close()
		return "", nil, fmt.Errorf("embed etcd 启动超时")
	}
	return client.String(), func() { e.Close() }, nil
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("分配空闲端口失败: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newLiveStore 连上 embed etcd 并构造控制存储（gid 每用例独立，避免相互干扰）。
func newLiveStore(t *testing.T, url, gid string) *EtcdControlStore {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := NewEtcdControlStore(ctx, []string{url}, gid, testMACKey)
	if err != nil {
		t.Fatalf("NewEtcdControlStore(%s): %v", gid, err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func acquireReq(member, dc, bootID string, epoch, desired uint64, bootstrap bool, bootstrapOwner string, autoIntra bool) testkit.OwnerAcquireRequest {
	return testkit.OwnerAcquireRequest{
		Member: member, DC: dc, BootID: bootID,
		ExpectedEpoch: epoch, ExpectedDesiredVersion: desired,
		AllowBootstrap: bootstrap, BootstrapOwner: bootstrapOwner,
		AllowAutoIntraDC: autoIntra, TTL: 30 * time.Second,
	}
}

// ① 租约互斥：bootstrap 成功后，同 DC 其他成员的自动接管必须失败。
func TestEtcdLeaseMutualExclusion(t *testing.T) {
	url, stop := startEmbedEtcd(t)
	defer stop()

	s := newLiveStore(t, url, "g-lease")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	stBefore, err := s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	if _, err := s.AcquireOwner(ctx, acquireReq("m1", "dc1", "boot-1", stBefore.Epoch, stBefore.DesiredVersion, true, "m1", true)); err != nil {
		t.Fatalf("bootstrap owner m1 应抢占成功: %v", err)
	}

	st, err := s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	if _, err := s.AcquireOwner(ctx, acquireReq("m2", "dc1", "boot-2", st.Epoch, st.DesiredVersion, false, "", true)); err == nil {
		t.Fatal("租约已被 m1 持有时，m2 同 DC 自动接管不应成功（单主语义）")
	} else {
		t.Logf("m2 接管被拒（符合预期）: %v", err)
	}

	// epoch 应已递增
	after, gerr := s.GetOwnerState(ctx)
	if gerr != nil {
		t.Fatalf("GetOwnerState: %v", gerr)
	}
	if after.Epoch <= stBefore.Epoch {
		t.Fatalf("抢占成功后 epoch 应递增：旧 %d 新 %d", stBefore.Epoch, after.Epoch)
	}
}

// ② 陈旧主 fencing：异 bootID / 旧 epoch 的续租与抢占一律拒。
func TestEtcdStaleLeaderFenced(t *testing.T) {
	url, stop := startEmbedEtcd(t)
	defer stop()

	s := newLiveStore(t, url, "g-fence")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	st, err := s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	if _, err := s.AcquireOwner(ctx, acquireReq("m1", "dc1", "boot-1", st.Epoch, st.DesiredVersion, true, "m1", true)); err != nil {
		t.Fatalf("bootstrap 失败: %v", err)
	}

	// 陈旧主：同一 member，但 bootID 不同（进程重启场景）→ 续租必须失败
	if err := s.RenewOwner(ctx, "m1", "boot-stale", 999, 30*time.Second); err == nil {
		t.Fatal("异 bootID 的续租应被拒（陈旧主 fencing）")
	} else {
		t.Logf("陈旧 bootID 续租被拒（符合预期）: %v", err)
	}

	// 陈旧主：用旧 epoch 抢占 → 必须失败
	st2, err := s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	if _, err := s.AcquireOwner(ctx, acquireReq("m3", "dc1", "boot-3", st2.Epoch-1, st2.DesiredVersion, false, "", true)); err == nil {
		t.Fatal("旧 epoch 的抢占应被拒（group_stale_epoch）")
	} else {
		t.Logf("旧 epoch 抢占被拒（符合预期）: %v", err)
	}
}

// ③ 目录 CAS 并发：同一 keyID 的并发 CAS 只有一个成功，版本严格递增。
func TestEtcdDirectoryCASConcurrent(t *testing.T) {
	url, stop := startEmbedEtcd(t)
	defer stop()

	s := newLiveStore(t, url, "g-cas")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	st, err := s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	ls, err := s.AcquireOwner(ctx, acquireReq("m1", "dc1", "boot-1", st.Epoch, st.DesiredVersion, true, "m1", true))
	if err != nil {
		t.Fatalf("bootstrap 失败: %v", err)
	}

	const keyID = "k-cas"
	const workers = 4
	var wg sync.WaitGroup
	var mu sync.Mutex
	oks := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			d := testkit.KeyDirectory{
				KeyID: keyID, KeyMode: "shared", State: "active", CreatedBy: "m1",
				Replicas: []testkit.KeyReplica{{Member: fmt.Sprintf("m%d", i), State: "active"}},
			}
			if _, err := s.CASKeyDirectory(ctx, keyID, 0, ls.Epoch, ls.HolderBootID, d); err == nil {
				mu.Lock()
				oks++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if oks != 1 {
		t.Fatalf("并发 CAS（同 expectedVersion=0）应恰好 1 个成功，实际 %d", oks)
	}
	if _, ver, err := s.GetKeyDirectory(ctx, keyID); err != nil {
		t.Fatalf("读取目录失败: %v", err)
	} else if ver != 1 {
		t.Fatalf("CAS 成功后目录版本应为 1，实际 %d", ver)
	}
}

// ④ 目录 MAC 篡改检测：绕过 CAS 直接改 etcd 原值 → 读取必须被拒。
func TestEtcdDirectoryMACTamperDetected(t *testing.T) {
	url, stop := startEmbedEtcd(t)
	defer stop()

	s := newLiveStore(t, url, "g-mac")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	st, err := s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	ls, err := s.AcquireOwner(ctx, acquireReq("m1", "dc1", "boot-1", st.Epoch, st.DesiredVersion, true, "m1", true))
	if err != nil {
		t.Fatalf("bootstrap 失败: %v", err)
	}

	const keyID = "k-mac"
	kd := testkit.KeyDirectory{
		KeyID: keyID, KeyMode: "shared", State: "active", CreatedBy: "m1",
		Replicas: []testkit.KeyReplica{{Member: "m1", State: "active"}},
	}
	if _, err := s.CASKeyDirectory(ctx, keyID, 0, ls.Epoch, ls.HolderBootID, kd); err != nil {
		t.Fatalf("CAS 写目录失败: %v", err)
	}

	// 绕过 CAS 与 MAC，直接篡改 etcd 中的原值（格式合法但无有效 MAC）。
	tampered := `{"key_id":"k-mac","key_mode":"shared","state":"active","created_by":"attacker","version":1,"mac":"deadbeef"}`
	if _, err := s.cli.Put(ctx, s.k(kKeys, keyID), tampered); err != nil {
		t.Fatalf("写入篡改值失败: %v", err)
	}

	if _, _, err := s.GetKeyDirectory(ctx, keyID); err == nil {
		t.Fatal("篡改后的目录应被拒读（MAC 校验失败）")
	} else if !errors.Is(err, ErrDirectoryMACInvalid) {
		t.Fatalf("应返回 ErrDirectoryMACInvalid，实际 %v", err)
	} else {
		t.Logf("篡改被拒（符合预期）: %v", err)
	}
}

// ⑤ 多数派丢失 / 存储不可达：写路径必须 fail-closed，不得静默成功。
func TestEtcdMajorityLostFailClosed(t *testing.T) {
	url, stop := startEmbedEtcd(t)

	s := newLiveStore(t, url, "g-majority")
	// stop 会被调用两次（用例中途停 etcd + defer 收尾），embed 的 Close 不耐双调，
	// 故包一层 sync.Once。
	var stopOnce sync.Once
	stopFn := func() { stopOnce.Do(stop) }
	defer stopFn()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	st, err := s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	ls, err := s.AcquireOwner(ctx, acquireReq("m1", "dc1", "boot-1", st.Epoch, st.DesiredVersion, true, "m1", true))
	if err != nil {
		t.Fatalf("bootstrap 失败: %v", err)
	}
	const keyID = "k-majority"
	kd := testkit.KeyDirectory{KeyID: keyID, KeyMode: "shared", State: "active", CreatedBy: "m1"}
	if _, err := s.CASKeyDirectory(ctx, keyID, 0, ls.Epoch, ls.HolderBootID, kd); err != nil {
		t.Fatalf("CAS 写目录失败: %v", err)
	}

	// 停掉 etcd：模拟多数派丢失 / 控制存储不可达。
	stopFn()

	shortCtx, cancelShort := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelShort()

	// 注意：etcd 不可达时 GetOwnerState 返回零值（契约无 error 通道，见 adapter.go 说明）。
	stLost, _ := s.GetOwnerState(shortCtx)
	if _, err := s.AcquireOwner(shortCtx, acquireReq("m9", "dc1", "boot-9", stLost.Epoch, stLost.DesiredVersion, true, "m9", true)); err == nil {
		t.Fatal("etcd 不可达时 AcquireOwner 应失败（不得静默成功）")
	} else {
		t.Logf("不可达时抢占被拒（符合预期）: %v", err)
	}
	if _, err := s.CASKeyDirectory(shortCtx, keyID, 1, ls.Epoch, ls.HolderBootID, kd); err == nil {
		t.Fatal("etcd 不可达时目录写应失败（不得静默成功）")
	} else {
		t.Logf("不可达时目录写被拒（符合预期）: %v", err)
	}
}

// ⑥ 跨 DC promotion 必须双签：无审批拒；带审批（approval 键 + digest）才成功。
func TestEtcdPromotionRequiresDualApproval(t *testing.T) {
	url, stop := startEmbedEtcd(t)
	defer stop()

	s := newLiveStore(t, url, "g-promo")
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	st, err := s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	if _, err := s.AcquireOwner(ctx, acquireReq("m1", "dc1", "boot-1", st.Epoch, st.DesiredVersion, true, "m1", true)); err != nil {
		t.Fatalf("bootstrap 失败: %v", err)
	}

	// 模拟旧主租约过期（删除 lease 键），否则 promotion 分支要求 lease 不存在。
	if _, err := s.cli.Delete(ctx, s.k(kLease)); err != nil {
		t.Fatalf("删除 lease 键失败: %v", err)
	}
	st, err = s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}

	// 无审批 → 拒
	noAppr := &testkit.Promotion{TargetMember: "m2", ExpectedEpoch: st.Epoch}
	if _, err := s.AcquireOwner(ctx, acquireReqPromo("m2", "dc2", "boot-2", st.Epoch, st.DesiredVersion, noAppr)); err == nil {
		t.Fatal("跨 DC promotion 无审批应被拒（D-8：跨 DC 只能人工 promotion 且须双签）")
	} else {
		t.Logf("无审批 promotion 被拒（符合预期）: %v", err)
	}

	// 造审批键（模拟双签已批准）：approval 键存在且值 == digest
	const approvalID, digest = "ap-cross-dc", "digest-cross-dc"
	if _, err := s.cli.Put(ctx, s.k(kApprovals, approvalID), digest); err != nil {
		t.Fatalf("写入审批键失败: %v", err)
	}
	st, err = s.GetOwnerState(ctx)
	if err != nil {
		t.Fatalf("GetOwnerState: %v", err)
	}
	withAppr := &testkit.Promotion{
		TargetMember: "m2", ExpectedEpoch: st.Epoch,
		ApprovalID: approvalID, Digest: digest,
	}
	ls, err := s.AcquireOwner(ctx, acquireReqPromo("m2", "dc2", "boot-2", st.Epoch, st.DesiredVersion, withAppr))
	if err != nil {
		t.Fatalf("带双签的跨 DC promotion 应成功: %v", err)
	}
	if ls.Holder != "m2" || ls.DC != "dc2" {
		t.Fatalf("promotion 后持有者应为 m2/dc2，实际 %s/%s", ls.Holder, ls.DC)
	}
}

// acquireReqPromo 带 promotion 的抢占请求（跨 DC 人工切换）。
func acquireReqPromo(member, dc, bootID string, epoch, desired uint64, promo *testkit.Promotion) testkit.OwnerAcquireRequest {
	r := acquireReq(member, dc, bootID, epoch, desired, false, "", false)
	r.Promotion = promo
	return r
}
