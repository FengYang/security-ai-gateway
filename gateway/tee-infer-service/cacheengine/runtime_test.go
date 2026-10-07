package cacheengine

import (
	"context"
	"testing"
	"time"
)

// panicScanner 在读时快审阶段 panic（模拟缓存模块内部异常，验证边界 recover）。
type panicScanner struct{}

func (panicScanner) Scan(string) (ScanVerdict, error) { panic("boom: cache internal") }

// slowScanner 在读时快审阶段耗时超阈值（验证 slow_lookup 观测）。
type slowScanner struct{}

func (slowScanner) Scan(string) (ScanVerdict, error) {
	time.Sleep(150 * time.Millisecond)
	return ScanVerdict{Allow: true}, nil
}

func runtimeCfg(readFastCheck bool) CacheConfig {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = readFastCheck
	cfg.WriteLimit.Enabled = false // 单测聚焦各自特性；写入限流的专项用例在 throttle_test.go 显式开启
	return cfg
}

// TestRuntime_PanicRecoveredInLookup §6.11#9 / B-6.11-1：panic 被 recover，主链返回 miss。
func TestRuntime_PanicRecoveredInLookup(t *testing.T) {
	cfg := runtimeCfg(true)
	eng := NewCacheEngine(cfg, WithFastScanner(panicScanner{}))
	sc := l1StoreCtx()
	if out := eng.Store(sc, InferResult{Text: "answer", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store: %+v", out)
	}
	r := eng.Lookup(sc.LookupContext)
	if r.Hit {
		t.Fatal("panic must be converted to miss")
	}
	if r.RejectReason != "panic" {
		t.Fatalf("reject reason = %q, want panic", r.RejectReason)
	}
	e := eng.(*engine)
	if e.stats.panicCount() != 1 {
		t.Fatalf("panic_total = %d, want 1", e.stats.panicCount())
	}
}

// TestRuntime_TimeInjection §6.11#8：注入时间源后 TTL 到期无需真实等待。
func TestRuntime_TimeInjection(t *testing.T) {
	cfg := runtimeCfg(false)
	eng := NewCacheEngine(cfg)
	var nowMs int64 = 1_700_000_000_000
	SetNow(eng, func() int64 { return nowMs })

	sc := l1StoreCtx()
	if out := eng.Store(sc, InferResult{Text: "ttl-check", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store: %+v", out)
	}
	if r := eng.Lookup(sc.LookupContext); !r.Hit {
		t.Fatalf("expected hit before expiry, got reason=%s", r.RejectReason)
	}
	nowMs += 3600*1000 + 1000 // 越过默认 exact.ttl (1h)
	if r := eng.Lookup(sc.LookupContext); r.Hit {
		t.Fatal("expected miss after injected expiry (no real wait)")
	}
}

// TestRuntime_SlowLookupObserved B-6.11-3：超阈值查询仅观测、不中断。
func TestRuntime_SlowLookupObserved(t *testing.T) {
	cfg := runtimeCfg(true)
	eng := NewCacheEngine(cfg, WithFastScanner(slowScanner{}))
	sc := l1StoreCtx()
	if out := eng.Store(sc, InferResult{Text: "answer", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store: %+v", out)
	}
	r := eng.Lookup(sc.LookupContext)
	if !r.Hit {
		t.Fatalf("slow scanner must still allow hit, got reason=%s", r.RejectReason)
	}
	e := eng.(*engine)
	if e.stats.slowLookupSnapshot()["overall"] < 1 {
		t.Fatal("expected slow_lookup observation")
	}
}

// TestRuntime_StartInvalidation_NoL1 未注入 L1 时返回 ErrRedisDisabled。
func TestRuntime_StartInvalidation_NoL1(t *testing.T) {
	eng := NewCacheEngine(runtimeCfg(false))
	if err := eng.(*engine).StartInvalidation(context.Background()); err != ErrRedisDisabled {
		t.Fatalf("err = %v, want ErrRedisDisabled", err)
	}
}

// TestRuntime_InvalidationConsumerApplies §6.8.3：订阅消费在本副本执行同一失效。
func TestRuntime_InvalidationConsumerApplies(t *testing.T) {
	cfg, l1, ops := newTestL1Config(t)
	eng := NewCacheEngine(cfg, WithRedisBackend(l1))
	e := eng.(*engine)

	sc := l1StoreCtx()
	if out := eng.Store(sc, InferResult{Text: "to-invalidate", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store: %+v", out)
	}
	if r := eng.Lookup(sc.LookupContext); !r.Hit {
		t.Fatal("expected L0 hit before invalidation")
	}

	if err := e.StartInvalidation(context.Background()); err != nil {
		t.Fatalf("StartInvalidation: %v", err)
	}
	waitSubscribed(t, ops)

	// 其它副本广播 "tenant" 失效 → 本副本 L0 应被清空
	// 注：消费侧仅失效 L0（不触 L1、不再广播，避免回环）；因此断言 L0 条目数归零，
	// 而非 Lookup miss（L1 仍持有密文，会读穿命中，属预期行为）。
	if err := l1.Publish(context.Background(), InvalidateEvent{Op: "tenant", Target: "t1"}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if e.exact.Len() == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("expected local L0 invalidation applied by consumer, len=%d", e.exact.Len())
}

// TestRuntime_GracefulClose B-6.11-4：关闭时停止消费并释放 L1 连接。
func TestRuntime_GracefulClose(t *testing.T) {
	cfg, l1, ops := newTestL1Config(t)
	eng := NewCacheEngine(cfg, WithRedisBackend(l1))
	e := eng.(*engine)

	if err := e.StartInvalidation(context.Background()); err != nil {
		t.Fatalf("StartInvalidation: %v", err)
	}
	waitSubscribed(t, ops)

	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !ops.closed {
		t.Fatal("expected L1 closed on engine Close")
	}
	if e.invCancel != nil {
		t.Fatal("expected invalidation consumer cancelled on Close")
	}
	// 关闭后查询返回 miss（不 panic）
	if r := eng.Lookup(l1StoreCtx().LookupContext); r.Hit {
		t.Fatal("closed engine must not hit")
	}
	// 幂等
	if err := eng.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// waitSubscribed 等待失效订阅注册完成（fakeOps）。
func waitSubscribed(t *testing.T, f *fakeOps) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		ok := f.subFn != nil
		f.mu.Unlock()
		if ok {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("subscriber not registered in time")
}
