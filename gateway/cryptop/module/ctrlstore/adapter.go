package ctrlstore

// 本文件把带 context 的 EtcdControlStore 适配为 group.ControlStore（无 context 签名）。
//
// ⚠️ 契约缺口（评审已登记，此处不掩盖）：
// group.ControlStore 的 GetOwnerState / SetDesired / GetKeyDirectory 三个方法**没有 error
// 返回通道**，而真机 etcd 会返回错误（网络分区 / 租约过期 / 目录 MAC 校验失败）。
// 本适配器对这三个方法采用「失败侧保守值 + LastError 可观测」：
//   - GetOwnerState 失败 → 零值（协调器按"无主"处理 → 不抢主，fail-closed）；
//   - GetKeyDirectory 失败 → 空目录（编排器按"未找到"处理 → 不覆写）；
//   - SetDesired 失败 → 0。
// 这保证**不把错误静默当成成功**，但真要做到向上 fail-closed，仍需 T-1 契约补 error 通道
// （会改 coordinator 调用点，属契约变更，另立）。
//
// 装配方式（U-6 落地路径）：
//
//	st, _ := ctrlstore.NewEtcdControlStore(ctx, endpoints, gid, dirMACKey)
//	cs := ctrlstore.NewAdapter(st, 0)   // 默认 3s 单操作超时
//	g, _ := group.NewGroupProvider(cfg, members, self, cs, bootID, deps)

import (
	"context"
	"sync"
	"time"

	"security-ai-gateway/gateway/cryptop/module/testkit"
)

// defaultOpTimeout 单操作默认超时：契约无 context，适配器必须兜底防止请求悬挂。
const defaultOpTimeout = 3 * time.Second

// ControlStoreAdapter 把 EtcdControlStore（带 context）适配为无 context 的组契约。
type ControlStoreAdapter struct {
	inner   *EtcdControlStore
	timeout time.Duration

	mu      sync.Mutex
	lastErr error
}

// NewAdapter 构造适配器。timeout<=0 时用默认 3s。
func NewAdapter(inner *EtcdControlStore, timeout time.Duration) *ControlStoreAdapter {
	if timeout <= 0 {
		timeout = defaultOpTimeout
	}
	return &ControlStoreAdapter{inner: inner, timeout: timeout}
}

// LastError 最近一次适配层错误（供指标/巡检观测真机存储故障）。
func (a *ControlStoreAdapter) LastError() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.lastErr
}

func (a *ControlStoreAdapter) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), a.timeout)
}

func (a *ControlStoreAdapter) note(err error) {
	if err == nil {
		return
	}
	a.mu.Lock()
	a.lastErr = err
	a.mu.Unlock()
}

// ---- 组主租约 ----

func (a *ControlStoreAdapter) GetOwnerState() testkit.OwnerState {
	ctx, cancel := a.ctx()
	defer cancel()
	st, err := a.inner.GetOwnerState(ctx)
	a.note(err)
	if err != nil {
		return testkit.OwnerState{} // 保守：按无主处理，协调器不抢主
	}
	return st
}

func (a *ControlStoreAdapter) SetDesired() uint64 {
	ctx, cancel := a.ctx()
	defer cancel()
	v, err := a.inner.SetDesired(ctx)
	a.note(err)
	if err != nil {
		return 0
	}
	return v
}

func (a *ControlStoreAdapter) AcquireOwner(req testkit.OwnerAcquireRequest) (testkit.LeaseStatus, error) {
	ctx, cancel := a.ctx()
	defer cancel()
	ls, err := a.inner.AcquireOwner(ctx, req)
	a.note(err)
	if err != nil {
		return testkit.LeaseStatus{}, err
	}
	return ls, nil
}

func (a *ControlStoreAdapter) RenewOwner(member, bootID string, epoch uint64, ttl time.Duration) error {
	ctx, cancel := a.ctx()
	defer cancel()
	err := a.inner.RenewOwner(ctx, member, bootID, epoch, ttl)
	a.note(err)
	return err
}

func (a *ControlStoreAdapter) ReleaseOwner(member, bootID string, epoch uint64) error {
	ctx, cancel := a.ctx()
	defer cancel()
	err := a.inner.ReleaseOwner(ctx, member, bootID, epoch)
	a.note(err)
	return err
}

// ---- KeyOps ----

func (a *ControlStoreAdapter) CreateKeyOp(op testkit.KeyOp) (int64, error) {
	ctx, cancel := a.ctx()
	defer cancel()
	rev, err := a.inner.CreateKeyOp(ctx, op)
	a.note(err)
	return rev, err
}

func (a *ControlStoreAdapter) CASKeyOp(opID string, expectedVersion int64, expectedStatus string, op testkit.KeyOp) (int64, error) {
	ctx, cancel := a.ctx()
	defer cancel()
	rev, err := a.inner.CASKeyOp(ctx, opID, expectedVersion, expectedStatus, op)
	a.note(err)
	return rev, err
}

func (a *ControlStoreAdapter) GetKeyOp(opID string) (testkit.KeyOp, int64, error) {
	ctx, cancel := a.ctx()
	defer cancel()
	op, ver, err := a.inner.GetKeyOp(ctx, opID)
	a.note(err)
	if err != nil {
		return testkit.KeyOp{}, 0, err
	}
	return op, ver, nil
}

// WatchKeyOps 快照语义桥接：etcd 侧为流式（chan），契约为快照（slice）。
func (a *ControlStoreAdapter) WatchKeyOps(fromRevision int64) []testkit.KeyOp {
	ctx, cancel := a.ctx()
	defer cancel()
	ops, err := a.inner.ListKeyOps(ctx, fromRevision)
	a.note(err)
	if err != nil {
		return nil
	}
	return ops
}

// ---- 密钥目录 ----

func (a *ControlStoreAdapter) CASKeyDirectory(keyID string, expectedVersion int64,
	writerEpoch uint64, writerBootID string, kd testkit.KeyDirectory) (int64, error) {
	ctx, cancel := a.ctx()
	defer cancel()
	rev, err := a.inner.CASKeyDirectory(ctx, keyID, expectedVersion, writerEpoch, writerBootID, kd)
	a.note(err)
	return rev, err
}

func (a *ControlStoreAdapter) GetKeyDirectory(keyID string) (testkit.KeyDirectory, int64) {
	ctx, cancel := a.ctx()
	defer cancel()
	kd, ver, err := a.inner.GetKeyDirectory(ctx, keyID)
	a.note(err)
	if err != nil {
		return testkit.KeyDirectory{}, 0 // 保守：按未找到处理，调用方不覆写
	}
	return kd, ver
}
