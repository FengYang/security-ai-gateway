package cacheengine

import (
	"bytes"
	"context"
	"testing"
)

// newTestL1Config 构造启用精确缓存 + Redis L1 的测试配置。
func newTestL1Config(t *testing.T) (CacheConfig, RedisBackend, *fakeOps) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false

	kp, err := NewStaticKeyProvider(bytes.Repeat([]byte{5}, 32))
	if err != nil {
		t.Fatalf("key provider: %v", err)
	}
	ops := newFakeOps()
	b, err := NewRedisBackend(&cfg, ops, kp)
	if err != nil {
		t.Fatalf("NewRedisBackend: %v", err)
	}
	return cfg, b, ops
}

func l1StoreCtx() StoreContext {
	return StoreContext{
		LookupContext: LookupContext{
			TenantID: "t1", EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
			TransformedHash: "h1", PromptText: "prompt long enough for cache",
			PolicyVer: "1", GuardVer: "v1",
		},
		Writable: true,
	}
}

// TestEngine_L1_ReadThrough 写穿 L1；空 L0 的新引擎从 L1 读穿命中并回填 L0。
func TestEngine_L1_ReadThrough(t *testing.T) {
	cfg, l1, ops := newTestL1Config(t)

	eng1 := NewCacheEngine(cfg, WithRedisBackend(l1))
	sc := l1StoreCtx()
	if out := eng1.Store(sc, InferResult{Text: "cached-answer", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store: %+v", out)
	}
	// 明文不得落 L1
	for k, v := range ops.data {
		if bytes.Contains(v, []byte("cached-answer")) {
			t.Fatalf("plaintext leaked into L1 key %s", k)
		}
	}

	// 新引擎：空 L0，应命中 L1（读穿）
	eng2 := NewCacheEngine(cfg, WithRedisBackend(l1))
	r := eng2.Lookup(sc.LookupContext)
	if !r.Hit || r.Entry == nil || r.Entry.Text != "cached-answer" {
		t.Fatalf("expected L1 read-through hit, got hit=%v reason=%s", r.Hit, r.RejectReason)
	}
	// 读穿后回填 L0 → 再次查询仍命中
	if r2 := eng2.Lookup(sc.LookupContext); !r2.Hit {
		t.Fatal("expected L0 backfill hit on second lookup")
	}
}

// TestEngine_L1_Invalidate 失效：删除 L1 密文并广播失效事件。
func TestEngine_L1_Invalidate(t *testing.T) {
	cfg, l1, ops := newTestL1Config(t)
	eng := NewCacheEngine(cfg, WithRedisBackend(l1))
	sc := l1StoreCtx()
	if out := eng.Store(sc, InferResult{Text: "to-be-invalidated", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store: %+v", out)
	}
	if len(ops.data) == 0 {
		t.Fatal("expected L1 writes before invalidate")
	}

	var got InvalidateEvent
	if err := l1.Subscribe(context.Background(), func(ev InvalidateEvent) { got = ev }); err != nil {
		t.Fatalf("subscribe: %v", err)
	}

	if _, err := eng.Invalidate(InvalidateSelector{TenantID: "t1"}); err != nil {
		t.Fatalf("Invalidate: %v", err)
	}
	if len(ops.data) != 0 {
		t.Fatalf("expected L1 cleared, remaining=%v", keysOf(ops))
	}
	if got.Op != "tenant" || got.Target != "t1" {
		t.Fatalf("broadcast event = %+v, want {tenant t1}", got)
	}
}

// TestEngine_L1_DisabledByDefault 未注入 L1 时行为与纯 L0 一致（零回归）。
func TestEngine_L1_DisabledByDefault(t *testing.T) {
	cfg, _, _ := newTestL1Config(t)
	eng := NewCacheEngine(cfg) // 无 WithRedisBackend
	sc := l1StoreCtx()
	if out := eng.Store(sc, InferResult{Text: "l0-only", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store: %+v", out)
	}
	if r := eng.Lookup(sc.LookupContext); !r.Hit || r.Entry.Text != "l0-only" {
		t.Fatalf("expected L0 hit, got hit=%v", r.Hit)
	}
}
