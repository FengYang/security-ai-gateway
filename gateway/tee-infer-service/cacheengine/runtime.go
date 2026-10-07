package cacheengine

import (
	"context"
	"time"
)

// slowLookupThreshold 查询耗时观测阈值（B-6.11-3：仅观测、不中断）。
// 取值 100ms：显著高于 §8.1 命中路径预算（<25ms），避免噪声。
const slowLookupThreshold = 100 * time.Millisecond

// SetNow 注入时间源（§6.11#8）：fn 返回 Unix 毫秒。
// 会同步注入 L0/L2 各组件的时钟（存储侧亦按注入时间判定过期），
// 用于确定性 TTL 验证（避免真实等待）；非 *engine 实现时为空操作。
func SetNow(e CacheEngine, fn func() int64) {
	eng, ok := e.(*engine)
	if !ok || fn == nil {
		return
	}
	nf := func() time.Time { return time.UnixMilli(fn()) }
	eng.nowFn = nf
	if s, ok := eng.exact.(*lruExactStore); ok {
		s.nowFn = nf
	}
	if s, ok := eng.neg.(*lruNegativeStore); ok {
		s.nowFn = nf
	}
	if s, ok := eng.sem.(*semanticStore); ok {
		s.nowFn = nf
		if fi, ok := s.index.(*flatIndex); ok {
			fi.mu.Lock()
			fi.nowFn = nf
			fi.mu.Unlock()
		}
	}
}

// StartInvalidation 启动失效广播消费（§6.8.3）：
// 订阅 og:c:inv:{policyVersion}，收到指令后在本副本执行同一失效
// （形态 B 各副本独立 L0，故必须本地失效；不触 L1、不再广播，避免跨副本回环）。
// 幂等：重复调用先停掉上一次订阅。未注入 L1 时返回 ErrRedisDisabled。
func (e *engine) StartInvalidation(ctx context.Context) error {
	if e.l1 == nil {
		return ErrRedisDisabled
	}
	ctx, cancel := context.WithCancel(ctx)
	e.invCancelMu.Lock()
	if e.invCancel != nil {
		e.invCancel()
	}
	e.invCancel = cancel
	e.invCancelMu.Unlock()

	go func() {
		// 订阅退出（ctx 取消/连接断开）即结束，不重试（§6.11#5）。
		_ = e.l1.Subscribe(ctx, func(ev InvalidateEvent) { e.applyInvalidation(ev) })
	}()
	return nil
}

// applyInvalidation 在本副本执行失效（与 Invalidate 的 L0 语义一致）。
func (e *engine) applyInvalidation(ev InvalidateEvent) {
	switch ev.Op {
	case "key":
		if e.exact != nil {
			e.exact.Delete(ev.Target)
		}
		if e.neg != nil {
			e.neg.Delete(ev.Target)
		}
	case "tenant":
		if e.exact != nil {
			e.exact.DeleteByTenant(ev.Target)
		}
		if e.neg != nil {
			e.neg.DeleteByTenant(ev.Target)
		}
	case "model":
		// L0 按模型删除（§6.8.1）；L1 侧已由发起方删除。
		if e.exact != nil {
			e.exact.DeleteByModel(ev.Target)
		}
	case "all":
		// 原地 Clear（不重建对象，避免并发读侧无锁访问 e.exact/e.neg 的数据竞争）。
		if e.exact != nil {
			e.exact.Clear()
		}
		if e.neg != nil {
			e.neg.Clear()
		}
	}
}
