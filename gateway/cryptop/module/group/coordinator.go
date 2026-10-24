// Package group —— P2-3 T-1「模块组 / 协调器抽象与调度」（Wave A 交付：组抽象 + 协调器 + 指标 + mock 验证）。
//
// 定位（本体 §7.2 T-1 / §6.2.6 / 评审报告 §16 Wave A）：
//
//	本包是**进程内库**（协调器内嵌 sidecar，不新建集中式 cryptopsvc），把多个
//	已初始化的 ModuleBackend 成员组合为一个逻辑 ModuleBackend（组合模式），
//	实现两级模型：
//	  - 组主租约（GroupCoordinator）：仅约束**生命周期写**与拓扑变更（密钥生成/导入/
//	    销毁/轮换/目录写）；陈旧主/被 fence 的进程生命周期写 100% 拒绝；
//	  - 成员数据面 fence 独立：Seal/Open/Sign/Verify/HMAC/KDF/Rand 等多成员可并行，
//	    组主缺失时数据面仍可用（本体 §3.1.1 / §3.3 / D-8 / D-16）。
//
// Wave A 边界（重要，务必如实）：
//   - 仅对着**冻结的 T-0 契约 + mock 成员/内存控制存储**开发；单测/mock 验证；
//   - 不宣称真机通过、不宣称 S3-b/密评、不宣称 G-0 闭合；
//   - 真机集成验收（V-1..V-7 中依赖真机项）留 Wave B；
//   - 组模式密钥跨成员复制（T-2）、跨 DC 切换编排（T-3）、性能标定（T-5）、
//     演练与验收（T-7）均不在 Wave A 范围；本包为这些后续任务提供可装配骨架。
//
// 控制存储契约（ControlStore 接口）对齐 testkit.MemoryControlStore（内存参考实现）；
// 真机 etcd 实现（testkit/poc.EtcdControlStore）签名不同（携带 context），其适配层
// 属 Wave B（见 coordinator 注释中的适配器约定）。
package group

import (
	"errors"
	"sync"
	"time"

	module "security-ai-gateway/gateway/cryptop/module"
	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// ErrNotLeader 生命周期写/拓扑变更被拒：当前进程不是组主或租约已失效（fencing）。
var ErrNotLeader = errors.New("group: 当前非组主或租约已失效（生命周期写被拒）")

// Coordinator 组主协调器：在单个控制存储上竞争/维持组主租约，并对外暴露
// 当前 epoch 与 leader 身份。租约续租与失租后再抢占均在本进程内完成。
//
// 两级模型：
//   - 组主租约只保护生命周期写与拓扑变更（AcquireOwner 单临界区比较 epoch/desired/lease，
//     禁止调用方"先判后写"，TOCTOU 由控制存储保证）；
//   - 数据面 fence 由成员各自健康 + 分区匹配决定，不等待组主。
//
// 真机适配：Wave A 只接 testkit.MemoryControlStore（无 context）。Wave B 接入
// poc.EtcdControlStore 时，新增一个 EtcdCoordinatorStore 适配器实现本 ControlStore
// 接口（把 ctx 注入、把 etcd 错误映射到 group 错误码），不改动本协调器逻辑。
type Coordinator struct {
	mu             sync.RWMutex
	store          ControlStore
	self           string
	bootID         string
	dc             string
	TTL            time.Duration
	bootstrap      bool
	bootstrapOwner string
	autoIntra      bool

	epoch uint64
	lease *testkit.LeaseStatus

	running bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	onLeadership func(held bool)
}

// NewCoordinator 构造协调器（不立即抢占租约；Start 后才竞争）。
func NewCoordinator(store ControlStore, self, bootID, dc string, ttl time.Duration, bootstrap bool, bootstrapOwner string, autoIntra bool) *Coordinator {
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return &Coordinator{
		store:          store,
		self:           self,
		bootID:         bootID,
		dc:             dc,
		TTL:            ttl,
		bootstrap:      bootstrap,
		bootstrapOwner: bootstrapOwner,
		autoIntra:      autoIntra,
		stopCh:         make(chan struct{}),
	}
}

// Start 启动协调器：先尝试抢占（首次 bootstrap / 同 DC 自动接管），随后周期续租；
// 租约丢失（TTL 过期 / KeepAlive 失败）后按同 DC 自动接管规则再抢占。
//
// 阻塞安全：在独立 goroutine 内续租，不阻塞调用方。
func (c *Coordinator) Start() {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return
	}
	c.running = true
	c.mu.Unlock()

	_, _ = c.acquireLocked(true, nil)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		tick := time.NewTicker(c.TTL / 3)
		defer tick.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-tick.C:
				c.mu.RLock()
				running := c.running
				c.mu.RUnlock()
				if !running {
					return
				}
				c.renewOrReacquire()
			}
		}
	}()
}

// Stop 停止协调器并主动释放租约（仅持有者本人可释放）。
func (c *Coordinator) Stop() {
	c.mu.Lock()
	if !c.running {
		c.mu.Unlock()
		return
	}
	c.running = false
	close(c.stopCh)
	ls := c.lease
	c.lease = nil // 同步清除本地租约引用：使 IsLeader 立即停止返回 true（陈旧主/fence 语义）。
	c.mu.Unlock()

	if ls != nil && ls.Holder == c.self && ls.HolderBootID == c.bootID {
		// 释放失败（如控制存储不可达）不影响退出；留待租约自然过期。
		_ = c.store.ReleaseOwner(c.self, c.bootID, ls.Epoch)
	}
	c.wg.Wait()
}

// IsLeader 当前进程是否持有有效（未过期）组主租约。
func (c *Coordinator) IsLeader() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.isLeaderRL()
}

func (c *Coordinator) isLeaderRL() bool {
	if c.lease == nil || c.lease.Holder != c.self || c.lease.HolderBootID != c.bootID {
		return false
	}
	return time.Now().Before(c.lease.ExpiresAt)
}

// LeaderLease 返回当前持有的租约（bool=false 表示非组主或已失效）。
func (c *Coordinator) LeaderLease() (testkit.LeaseStatus, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if !c.isLeaderRL() {
		return testkit.LeaseStatus{}, false
	}
	cp := *c.lease
	return cp, true
}

// Epoch 当前感知到的组 epoch（组主写成功后才递增；陈旧主看到的是旧值）。
func (c *Coordinator) Epoch() uint64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.epoch
}

// acquireLocked 尝试抢占/接管租约；首次调用（first）时允许 bootstrap。
//
// promo 非空即表示本次为**跨 DC 人工 promotion**（D-8：跨 DC 只能人工 promotion，
// 且必须携带双签审批）；同 DC 接管与 bootstrap 传 nil。
func (c *Coordinator) acquireLocked(first bool, promo *testkit.Promotion) (testkit.LeaseStatus, error) {
	st := c.store.GetOwnerState()
	req := testkit.OwnerAcquireRequest{
		Member:                 c.self,
		DC:                     c.dc,
		BootID:                 c.bootID,
		ExpectedEpoch:          st.Epoch,
		ExpectedDesiredVersion: st.DesiredVersion,
		AllowBootstrap:         first && c.bootstrap,
		AllowAutoIntraDC:       c.autoIntra,
		BootstrapOwner:         c.bootstrapOwner,
		Promotion:              promo,
		TTL:                    c.TTL,
	}
	ls, err := c.store.AcquireOwner(req)
	if err != nil {
		// 抢占失败（已有租约 / 跨 DC 需 promotion / 版本变化）：保持非组主。
		c.epoch = st.Epoch
		c.lease = nil
		c.notify(false)
		return testkit.LeaseStatus{}, err
	}
	c.epoch = ls.Epoch
	c.lease = &ls
	c.notify(true)
	return ls, nil
}

// renewOrReacquire 续租；续租失败（租约被夺/过期）则按规则再抢占。
func (c *Coordinator) renewOrReacquire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lease == nil || c.lease.Holder != c.self {
		_, _ = c.acquireLocked(false, nil)
		return
	}
	if err := c.store.RenewOwner(c.self, c.bootID, c.lease.Epoch, c.TTL); err != nil {
		// 续租失败：租约可能已被他人抢占或过期，释放本地引用后重新竞争。
		c.lease = nil
		c.notify(false)
		_, _ = c.acquireLocked(false, nil)
		return
	}
	// 续租成功：刷新本地过期时间（内存实现的 ExpiresAt 已更新，这里同步镜像）。
	if st := c.store.GetOwnerState(); st.Lease != nil {
		cp := *st.Lease
		c.lease = &cp
	}
}

func (c *Coordinator) notify(held bool) {
	if c.onLeadership != nil {
		c.onLeadership(held)
	}
}

var _ = module.ModuleBackend(nil) // 确保对 module 包类型的依赖被编译期校验（便于后续装配）。
