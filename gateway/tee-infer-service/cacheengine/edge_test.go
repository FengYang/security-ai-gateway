package cacheengine

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// TestConcurrent_LookupStore 并发读写不会崩溃（竞态间接验证）。
func TestConcurrent_LookupStore(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MaxEntries = 1000
	cfg.Exact.MaxEntryBytes = ByteSize(1024)
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)

	var wg sync.WaitGroup
	nGoroutines := 20
	nOps := 200
	var hits uint64
	var stores uint64

	for g := 0; g < nGoroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < nOps; i++ {
				tenant := string(rune('a' + (id % 5)))
				hash := fmt.Sprintf("hash-%d-%d", id, i%50) // 重复 key 制造碰撞
				ctx := LookupContext{
					TenantID:        tenant,
					EngineType:      "cmaas",
					Model:           "m1",
					MaxNewTokens:    100,
					TransformedHash: hash,
					PromptText:      "prompt text long enough for cache",
					PolicyVer:       "1",
					GuardVer:        "v1",
				}

				r := eng.Lookup(ctx)
				if r.Hit {
					atomic.AddUint64(&hits, 1)
				}

				// 偶发写入
				if i%3 == 0 {
					eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
						Text:      "answer text answer text",
						TokensOut: 20,
						Finish:    "stop",
					})
					atomic.AddUint64(&stores, 1)
				}
			}
		}(g)
	}
	wg.Wait()

	t.Logf("hits=%d stores=%d", atomic.LoadUint64(&hits), atomic.LoadUint64(&stores))
}

// TestConcurrent_Invalidate 并发失效 + 查询。
func TestConcurrent_Invalidate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MaxEntries = 500
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)

	// 先预填一些数据
	for i := 0; i < 100; i++ {
		ctx := StoreContext{
			LookupContext: LookupContext{
				TenantID:        "t1",
				EngineType:      "cmaas",
				Model:           "m1",
				MaxNewTokens:    100,
				TransformedHash: fmt.Sprintf("h%d", i),
				PromptText:      "long enough prompt",
				PolicyVer:       "1",
				GuardVer:        "v1",
			},
			Writable: true,
		}
		eng.Store(ctx, InferResult{Text: "answer", TokensOut: 10, Finish: "stop"})
	}

	var wg sync.WaitGroup
	done := make(chan struct{})

	// 读者
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
				ctx := LookupContext{
					TenantID:        "t1",
					EngineType:      "cmaas",
					Model:           "m1",
					MaxNewTokens:    100,
					TransformedHash: fmt.Sprintf("h%d", i%100),
					PromptText:      "long enough prompt",
					PolicyVer:       "1",
					GuardVer:        "v1",
				}
				eng.Lookup(ctx)
			}
		}
	}()

	// 失效者
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-done:
				return
			default:
				if i%10 == 0 {
					eng.Invalidate(InvalidateSelector{TenantID: "t1"})
				}
				ctx := StoreContext{
					LookupContext: LookupContext{
						TenantID:        "t1",
						EngineType:      "cmaas",
						Model:           "m1",
						MaxNewTokens:    100,
						TransformedHash: fmt.Sprintf("h%d", i%100),
						PromptText:      "long enough prompt",
						PolicyVer:       "1",
						GuardVer:        "v1",
					},
					Writable: true,
				}
				eng.Store(ctx, InferResult{Text: "answer", TokensOut: 10, Finish: "stop"})
			}
		}
	}()

	// 运行一小段时间
	for i := 0; i < 5000; i++ {
		eng.Lookup(LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: fmt.Sprintf("h%d", i%100),
			PromptText:      "long enough prompt",
			PolicyVer:       "1",
			GuardVer:        "v1",
		})
	}
	close(done)
	wg.Wait()
}

// TestEdge_EmptyPrompt 空 prompt → 不可缓存。
func TestEdge_EmptyPrompt(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	eng := NewCacheEngine(cfg)

	r := eng.Lookup(LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		TransformedHash: "h1",
		PromptText:      "",
	})
	if r.Hit {
		t.Fatal("empty prompt should not be cacheable")
	}
	if r.RejectReason == "" {
		t.Fatal("should have reject reason")
	}
}

// TestEdge_VeryLongResponse 超长响应 → 不写入。
func TestEdge_VeryLongResponse(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MaxEntryBytes = ByteSize(100)
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	eng := NewCacheEngine(cfg)

	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "h1",
			PromptText:      "long enough prompt text",
			PolicyVer:       "1",
			GuardVer:        "v1",
		},
		Writable: true,
	}

	longText := make([]byte, 200)
	for i := range longText {
		longText[i] = 'x'
	}

	outcome := eng.Store(ctx, InferResult{
		Text:      string(longText),
		TokensOut: 200,
		Finish:    "stop",
	})

	if outcome.Stored {
		t.Fatal("too long response should not be stored")
	}
	if outcome.Skipped != "too_long" {
		t.Fatalf("expected 'too_long', got '%s'", outcome.Skipped)
	}
}

// TestEdge_LRUCapacity 达到容量后淘汰最旧。
func TestEdge_LRUCapacity(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MaxEntries = 10
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	eng := NewCacheEngine(cfg)

	// 写入 20 条（超过容量）
	for i := 0; i < 20; i++ {
		ctx := StoreContext{
			LookupContext: LookupContext{
				TenantID:        "t1",
				EngineType:      "cmaas",
				Model:           "m1",
				MaxNewTokens:    100,
				TransformedHash: fmt.Sprintf("h%d", i),
				PromptText:      fmt.Sprintf("prompt %d long enough", i),
				PolicyVer:       "1",
				GuardVer:        "v1",
			},
			Writable: true,
		}
		eng.Store(ctx, InferResult{
			Text:      fmt.Sprintf("answer %d", i),
			TokensOut: 10,
			Finish:    "stop",
		})
	}

	// 前 10 条（0-9）应已被淘汰
	for i := 0; i < 10; i++ {
		r := eng.Lookup(LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: fmt.Sprintf("h%d", i),
			PromptText:      fmt.Sprintf("prompt %d long enough", i),
			PolicyVer:       "1",
			GuardVer:        "v1",
		})
		if r.Hit {
			t.Fatalf("entry %d should have been evicted", i)
		}
	}

	// 后 10 条（10-19）应仍在
	for i := 10; i < 20; i++ {
		r := eng.Lookup(LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: fmt.Sprintf("h%d", i),
			PromptText:      fmt.Sprintf("prompt %d long enough", i),
			PolicyVer:       "1",
			GuardVer:        "v1",
		})
		if !r.Hit {
			t.Fatalf("entry %d should still exist, reason=%s", i, r.RejectReason)
		}
	}
}

// TestEdge_InvalidateAll 全量失效。
func TestEdge_InvalidateAll(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	eng := NewCacheEngine(cfg)

	for i := 0; i < 10; i++ {
		ctx := StoreContext{
			LookupContext: LookupContext{
				TenantID:        "t1",
				EngineType:      "cmaas",
				Model:           "m1",
				MaxNewTokens:    100,
				TransformedHash: fmt.Sprintf("h%d", i),
				PromptText:      "long enough prompt",
				PolicyVer:       "1",
				GuardVer:        "v1",
			},
			Writable: true,
		}
		eng.Store(ctx, InferResult{Text: "answer", TokensOut: 10, Finish: "stop"})
	}

	count, err := eng.Invalidate(InvalidateSelector{All: true})
	if err != nil {
		t.Fatalf("invalidate failed: %v", err)
	}
	if count < 10 {
		t.Fatalf("expected at least 10 invalidated, got %d", count)
	}

	// 验证都失效了
	for i := 0; i < 10; i++ {
		r := eng.Lookup(LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: fmt.Sprintf("h%d", i),
			PromptText:      "long enough prompt",
			PolicyVer:       "1",
			GuardVer:        "v1",
		})
		if r.Hit {
			t.Fatalf("entry %d should be invalidated", i)
		}
	}
}

// TestEdge_ToolCallNotCacheable 工具调用始终不可缓存。
func TestEdge_ToolCallNotCacheable(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	eng := NewCacheEngine(cfg)

	r := eng.Lookup(LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		TransformedHash: "h1",
		PromptText:      "call the function",
		HasToolCall:     true,
	})
	if r.Hit {
		t.Fatal("tool call should not be cacheable")
	}
}

// TestEdge_NoCacheBypassHeader no-cache header 绕过（通过 NoCache 字段）。
func TestEdge_NoCacheFlag(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	eng := NewCacheEngine(cfg)

	// 先写入
	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "h1",
			PromptText:      "long enough prompt",
			PolicyVer:       "1",
			GuardVer:        "v1",
		},
		Writable: true,
	}
	eng.Store(ctx, InferResult{Text: "answer", TokensOut: 10, Finish: "stop"})

	// 正常查询 → 命中
	r1 := eng.Lookup(ctx.LookupContext)
	if !r1.Hit {
		t.Fatal("expected hit without no-cache")
	}

	// 带 NoCache → 不命中
	noCacheCtx := ctx.LookupContext
	noCacheCtx.NoCache = true
	r2 := eng.Lookup(noCacheCtx)
	if r2.Hit {
		t.Fatal("expected miss with no-cache flag")
	}
}
