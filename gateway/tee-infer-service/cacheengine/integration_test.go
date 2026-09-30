package cacheengine

import (
	"testing"
	"time"
)

// testConfig 返回一份用于测试的配置（放宽 min_prompt_tokens 等限制）。
func testConfig() CacheConfig {
	cfg := DefaultConfig()
	cfg.Exact.MinPromptTokens = 0
	return cfg
}

// TestEngine_ModeOff 关闭模式下永不命中。
func TestEngine_ModeOff(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeOff

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:     "t1",
		RequestID:    "r1",
		EngineType:   "cmaas",
		Model:        "gpt-4",
		MaxNewTokens: 100,
		Stream:       false,
		TransformedHash: "abc123",
		PromptText:   "什么是缓存？",
		PolicyVer:    "1",
		GuardVer:     "v1",
	}

	result := eng.Lookup(ctx)
	if result.Hit {
		t.Fatal("mode=off should never hit")
	}
	if result.RejectReason != "disabled" {
		t.Fatalf("expected disabled, got %s", result.RejectReason)
	}
}

// TestEngine_ExactHit 精确缓存命中。
func TestEngine_ExactHit(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = false // 关掉快审，专注测试精确命中

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:     "t1",
		RequestID:    "r1",
		EngineType:   "cmaas",
		Model:        "gpt-4",
		MaxNewTokens: 100,
		Stream:       false,
		TransformedHash: "abc123",
		PromptText:   "什么是缓存？",
		PolicyVer:    "1",
		GuardVer:     "v1",
	}

	// 第一次：miss
	r1 := eng.Lookup(ctx)
	if r1.Hit {
		t.Fatal("first lookup should miss")
	}

	// 写入
	storeCtx := StoreContext{LookupContext: ctx, Writable: true}
	res := InferResult{
		Text:      "缓存是...",
		TokensIn:  5,
		TokensOut: 10,
		Finish:    "stop",
	}
	outcome := eng.Store(storeCtx, res)
	if !outcome.Stored {
		t.Fatalf("store should succeed, skipped: %s", outcome.Skipped)
	}
	if outcome.Layer != "exact" {
		t.Fatalf("expected layer=exact, got %s", outcome.Layer)
	}

	// 第二次：hit
	r2 := eng.Lookup(ctx)
	if !r2.Hit {
		t.Fatalf("second lookup should hit, reason: %s", r2.RejectReason)
	}
	if r2.Kind != KindExact {
		t.Fatalf("expected exact hit, got %s", r2.Kind)
	}
	if r2.Entry.Text != "缓存是..." {
		t.Fatalf("unexpected text: %s", r2.Entry.Text)
	}
}

// TestEngine_ExactKeyIsolation 不同参数不互相命中。
func TestEngine_ExactKeyIsolation(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = false
	cfg.Exact.MinPromptTokens = 0

	eng := NewCacheEngine(cfg)

	store := func(prompt, text, model string) {
		ctx := LookupContext{
			TenantID:     "t1",
			EngineType:   "cmaas",
			Model:        model,
			MaxNewTokens: 100,
			TransformedHash: prompt,
			PromptText:   prompt,
			PolicyVer:    "1",
			GuardVer:     "v1",
		}
		eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
			Text:      text,
			TokensOut: len(text),
			Finish:    "stop",
		})
	}

	// 写入两条：不同 model，相同 prompt
	store("q1", "answer-m1", "model1")
	store("q1", "answer-m2", "model2")

	// 查询 model1
	r := eng.Lookup(LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "model1",
		MaxNewTokens:    100,
		TransformedHash: "q1",
		PromptText:      "q1",
		PolicyVer:       "1",
		GuardVer:        "v1",
	})
	if !r.Hit {
		t.Fatal("model1 should hit")
	}
	if r.Entry.Text != "answer-m1" {
		t.Fatalf("unexpected text: %s", r.Entry.Text)
	}
}

// TestEngine_Invalidate 主动失效。
func TestEngine_Invalidate(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = false
	cfg.Exact.MinPromptTokens = 0

	eng := NewCacheEngine(cfg)

	// 写入 t1 的两条
	for i := 0; i < 3; i++ {
		ctx := LookupContext{
			TenantID:     "t1",
			EngineType:   "cmaas",
			Model:        "m1",
			MaxNewTokens: 100,
			TransformedHash: string(rune('a' + i)),
			PromptText:   "prompt " + string(rune('a'+i)),
			PolicyVer:    "1",
			GuardVer:     "v1",
		}
		eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
			Text:      "answer",
			TokensOut: 6,
			Finish:    "stop",
		})
	}
	// 写入 t2 的一条
	ctx := LookupContext{
		TenantID:     "t2",
		EngineType:   "cmaas",
		Model:        "m1",
		MaxNewTokens: 100,
		TransformedHash: "x",
		PromptText:   "hello",
		PolicyVer:    "1",
		GuardVer:     "v1",
	}
	eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
		Text:      "hello there",
		TokensOut: 11,
		Finish:    "stop",
	})

	s := eng.Stats()
	if s.ExactEntries != 4 {
		t.Fatalf("expected 4 entries, got %d", s.ExactEntries)
	}

	// 按租户删除 t1
	count, err := eng.Invalidate(InvalidateSelector{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("expected 3 invalidated, got %d", count)
	}

	s = eng.Stats()
	if s.ExactEntries != 1 {
		t.Fatalf("expected 1 entry left, got %d", s.ExactEntries)
	}

	// 全量清空
	count, err = eng.Invalidate(InvalidateSelector{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("expected 1 invalidated (all), got %d", count)
	}

	s = eng.Stats()
	if s.ExactEntries != 0 {
		t.Fatalf("expected 0 entries after all, got %d", s.ExactEntries)
	}
}

// TestEngine_NegativeCache 负向缓存。
func TestEngine_NegativeCache(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = false
	cfg.Exact.MinPromptTokens = 0
	cfg.Negative.Enabled = true
	cfg.Negative.TTL = time.Hour

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:     "t1",
		EngineType:   "cmaas",
		Model:        "m1",
		MaxNewTokens: 100,
		TransformedHash: "bad-prompt",
		PromptText:   "这是个坏问题",
		PolicyVer:    "1",
		GuardVer:     "v1",
	}

	// 写入负向
	storeCtx := StoreContext{LookupContext: ctx, Writable: true}
	res := InferResult{
		Finish: "stop",
		Negative: &NegativePayload{
			Reason:    "injection",
			Stage:     "guardrail",
			PolicyVer: "1",
			GuardVer:  "v1",
		},
	}
	outcome := eng.Store(storeCtx, res)
	if !outcome.Stored || outcome.Layer != "negative" {
		t.Fatalf("expected negative store, got %v", outcome)
	}

	// 查询负向命中
	r := eng.Lookup(ctx)
	if !r.Hit {
		t.Fatalf("expected negative hit, reason: %s", r.RejectReason)
	}
	if !r.IsNegative() {
		t.Fatal("should be negative")
	}
	if r.Entry.Negative.Reason != "injection" {
		t.Fatalf("unexpected reason: %s", r.Entry.Negative.Reason)
	}
}

// TestEngine_Stats 统计指标。
func TestEngine_Stats(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = false
	cfg.Exact.MinPromptTokens = 0

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:     "t1",
		EngineType:   "cmaas",
		Model:        "m1",
		MaxNewTokens: 100,
		TransformedHash: "abc",
		PromptText:   "hello world test prompt long enough",
		PolicyVer:    "1",
		GuardVer:     "v1",
	}

	// 3 次 miss
	for i := 0; i < 3; i++ {
		eng.Lookup(ctx)
	}

	// 写入
	eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
		Text:      "answer",
		TokensOut: 6,
		Finish:    "stop",
	})

	// 1 次 hit
	eng.Lookup(ctx)

	s := eng.Stats()
	if s.Lookups["exact:miss"] != 3 {
		t.Errorf("expected 3 exact:miss, got %d", s.Lookups["exact:miss"])
	}
	if s.Lookups["exact:hit"] != 1 {
		t.Errorf("expected 1 exact:hit, got %d", s.Lookups["exact:hit"])
	}
}
