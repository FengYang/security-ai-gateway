package group

// 并发压力测试：在**没有 race detector** 的环境（本机 cgo 不可用）下，仍能暴露
// 最危险的一类并发缺陷——并发 map 写（Go 运行时会直接 panic 崩溃，非偶发错误），
// 并作为长期回归资产。
//
// 覆盖路径：数据面多成员并行、指标并发累加 + 渲染、协调器启停与租约读取交织、
// 生命周期写在非组主下的 fail-closed 一致性。
//
// 建议以 `go test -count=10 ./gateway/cryptop/module/group/ -run TestConcurrent` 运行，
// 多轮重复提高暴露概率；有 gcc 的环境另跑 `go test -race` 做精确认证。

import (
	"bytes"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// nonceAt 生成第 i 轮的 12 字节 nonce（mockNonceSize=12；同密钥重复 nonce 无意义，
// 故逐轮变化，避免把"测试构造问题"误判成产品缺陷）。
func nonceAt(i int) []byte {
	n := make([]byte, 12)
	copy(n, []byte(fmt.Sprintf("n%011d", i)))
	return n
}

// 并发数据面：多成员并行 Seal/Open/Hash/Rand，验证无 panic、无错误、指标可渲染。
func TestConcurrentDataPlaneNoPanic(t *testing.T) {
	g, _, _, _ := newTestGroup(t, "dc1-hsm-a")
	if err := g.Init(nil); err != nil {
		t.Fatalf("Init: %v", err)
	}
	ref, err := g.GenerateKey("sm4", "conc-dp")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	const workers, iters = 16, 50
	var wg sync.WaitGroup
	errCh := make(chan error, workers*iters*2)

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				n := nonceAt(base*iters + i)
				ct, err := g.Seal(ref, n, []byte("plaintext"), []byte("aad"))
				if err != nil {
					errCh <- fmt.Errorf("Seal: %w", err)
					continue
				}
				pt, err := g.Open(ref, n, ct, []byte("aad"))
				if err != nil {
					errCh <- fmt.Errorf("Open: %w", err)
					continue
				}
				if string(pt) != "plaintext" {
					errCh <- fmt.Errorf("Open 往返不一致: %q", pt)
				}
				if _, err := g.Hash([]byte("data")); err != nil {
					errCh <- fmt.Errorf("Hash: %w", err)
				}
				if _, err := g.Rand(16); err != nil {
					errCh <- fmt.Errorf("Rand: %w", err)
				}
			}
		}(w)
	}
	wg.Wait()
	close(errCh)

	n := 0
	for err := range errCh {
		if n < 3 {
			t.Errorf("并发数据面错误: %v", err)
		}
		n++
	}
	if n > 0 {
		t.Fatalf("并发数据面共 %d 次错误（前 3 条已列出）", n)
	}

	// 渲染指标：若 ops map 存在并发写，此前早已 panic；此处验证渲染不炸。
	var buf bytes.Buffer
	g.RenderMetrics(&buf)
	if buf.Len() == 0 {
		t.Fatal("RenderMetrics 输出为空")
	}
}

// 并发指标累加 + 渲染：最可能触发并发 map write 的组合（gmetrics.ops）。
func TestConcurrentMetricsRenderWhileOperating(t *testing.T) {
	g, _, _, _ := newTestGroup(t, "dc1-hsm-a")
	if err := g.Init(nil); err != nil {
		t.Fatalf("Init: %v", err)
	}

	stop := make(chan struct{})
	var renderWg, opsWg sync.WaitGroup

	// 渲染方（持续读）
	renderWg.Add(1)
	go func() {
		defer renderWg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				var b bytes.Buffer
				g.RenderMetrics(&b)
			}
		}
	}()

	// 操作方（持续写指标 + 读组主状态）
	const workers = 8
	for w := 0; w < workers; w++ {
		opsWg.Add(1)
		go func() {
			defer opsWg.Done()
			for i := 0; i < 200; i++ {
				_, _ = g.Hash([]byte("x"))
				_ = g.IsLeader()
				_ = g.Epoch()
				_, _ = g.Leader()
			}
		}()
	}
	opsWg.Wait()
	close(stop)
	renderWg.Wait()

	var buf bytes.Buffer
	g.RenderMetrics(&buf)
	if buf.Len() == 0 {
		t.Fatal("RenderMetrics 输出为空")
	}
}

// 并发协调器生命周期：反复 Start/Stop 与并发读 IsLeader/Epoch/LeaderLease 交织。
//
// 直接用 Coordinator 而非 ModuleGroup：ModuleGroup.Close 会关闭成员后端，
// 反复启停会让后续操作失去成员，测不到协调器本身。
func TestConcurrentCoordinatorStartStop(t *testing.T) {
	store := testkit.NewMemoryControlStore("fin-hsm-a")
	c1 := NewCoordinator(store, "dc1-hsm-a", "boot-a", "dc1", time.Minute, true, "dc1-hsm-a", true)
	c2 := NewCoordinator(store, "dc2-hsm-a", "boot-b", "dc2", time.Minute, false, "dc1-hsm-a", true)

	var wg sync.WaitGroup
	for _, c := range []*Coordinator{c1, c2} {
		wg.Add(1)
		go func(c *Coordinator) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				c.Start()
				c.Stop()
			}
		}(c)
	}
	// 读取方：与启停方真正并发
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				_ = c1.IsLeader()
				_ = c1.Epoch()
				_, _ = c1.LeaderLease()
			}
		}()
	}
	wg.Wait()

	// 收尾后状态必须自洽：Stop 之后不得仍自称组主。
	if c1.IsLeader() {
		t.Fatal("Stop 之后 IsLeader 仍为 true（陈旧主/fence 语义被破坏）")
	}
}

// 并发生命周期写 fail-closed：未启动协调器（非组主）时，所有并发写必须被拒。
func TestConcurrentLifecycleWritesFailClosed(t *testing.T) {
	g, _, _, _ := newTestGroup(t, "dc1-hsm-a")
	// 故意不 Init：协调器未启动 → 非组主。

	const workers, iters = 16, 50
	var wg sync.WaitGroup
	var succeeded, refused int64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				if _, err := g.GenerateKey("sm4", "conc-lw"); err != nil {
					atomic.AddInt64(&refused, 1)
				} else {
					atomic.AddInt64(&succeeded, 1)
				}
			}
		}()
	}
	wg.Wait()

	if succeeded != 0 {
		t.Fatalf("非组主下竟有 %d 次生命周期写成功（fail-closed / 单主语义被破坏）", succeeded)
	}
	if refused == 0 {
		t.Fatal("预期全部被拒，实际一次都没有")
	}
	t.Logf("并发拒写 %d 次，fail-closed 一致", refused)
}

// 回归测试：Stop 之后再次 Start 必须能真正重新工作。
//
// 曾存在的缺陷：Start 不重建 stopCh，导致 ① Stop 后 Start 的续租 goroutine 立即退出
// （协调器静默失效，租约无人续）；② 再次 Stop 时 close 已关闭的 channel 直接 panic。
// 本用例由并发压测触发发现（panic: close of closed channel）。
func TestCoordinatorRestartAfterStop(t *testing.T) {
	store := testkit.NewMemoryControlStore("fin-hsm-a")
	c := NewCoordinator(store, "hsm-r1", "boot-1", "dc1", time.Minute, true, "hsm-r1", true)

	c.Start()
	if !c.IsLeader() {
		t.Fatal("首次 Start 后应成为组主（bootstrap owner）")
	}
	firstEpoch := c.Epoch()
	c.Stop()
	if c.IsLeader() {
		t.Fatal("Stop 后不得仍自称组主")
	}

	// 再次 Start：不得 panic；且必须真的重新抢占到租约。
	c.Start()
	defer c.Stop()
	if !c.IsLeader() {
		t.Fatal("Stop 后重新 Start 应能重新成为组主（旧 stopCh 已关闭导致 goroutine 静默退出的缺陷回归）")
	}
	if c.Epoch() <= firstEpoch {
		t.Fatalf("重新抢占后 epoch 应递增（旧 %d，新 %d）", firstEpoch, c.Epoch())
	}

	// 反复启停多轮，确保稳定（对应生产上 Init/Close 可被多次调用的路径）。
	for i := 0; i < 5; i++ {
		c.Stop()
		c.Start()
		if !c.IsLeader() {
			t.Fatalf("第 %d 轮重启后未恢复组主", i)
		}
	}
}

// 编译期依赖占位：确保 module 包被引用（本文件其余用例经 newTestGroup 间接使用）。
var _ = module.HealthDown
