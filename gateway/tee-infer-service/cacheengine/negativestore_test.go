package cacheengine

import (
	"testing"
	"time"
)

// TestNegativeStore_Basic 负向缓存基本操作。
func TestNegativeStore_Basic(t *testing.T) {
	s := NewLRUNegativeStore(10)
	if !s.Enabled() {
		t.Fatal("should be enabled")
	}

	p := &NegativePayload{
		Reason:    "injection",
		Stage:     "guardrail",
		PolicyVer: "1",
		GuardVer:  "v1",
	}

	// 未命中
	if _, ok := s.Get("k1"); ok {
		t.Fatal("expected miss")
	}

	// 写入
	s.Put("k1", p, time.Hour)

	// 命中
	if got, ok := s.Get("k1"); !ok {
		t.Fatal("expected hit")
	} else if got.Reason != "injection" {
		t.Fatalf("unexpected reason: %s", got.Reason)
	}

	// 删除
	if !s.Delete("k1") {
		t.Fatal("expected delete success")
	}
	if _, ok := s.Get("k1"); ok {
		t.Fatal("expected miss after delete")
	}
}

// TestNegativeStore_Eviction 负向缓存 LRU 淘汰。
func TestNegativeStore_Eviction(t *testing.T) {
	s := NewLRUNegativeStore(3)

	for i := 0; i < 5; i++ {
		key := string(rune('a' + i))
		s.Put(key, &NegativePayload{Reason: key, Stage: "guardrail"}, time.Hour)
	}

	if s.Len() != 3 {
		t.Fatalf("expected len=3, got %d", s.Len())
	}
}

// TestNegativeStore_Clear 全量清空（§6.8.1）。
func TestNegativeStore_Clear(t *testing.T) {
	s := NewLRUNegativeStore(10)
	s.Put("k1", &NegativePayload{Reason: "r", Stage: "guardrail"}, time.Hour)
	s.Put("k2", &NegativePayload{Reason: "r", Stage: "guardrail"}, time.Hour)

	if n := s.Clear(); n != 2 {
		t.Fatalf("Clear() = %d, want 2", n)
	}
	if s.Len() != 0 {
		t.Fatalf("expected len=0 after clear, got %d", s.Len())
	}
	if _, ok := s.Get("k1"); ok {
		t.Fatal("k1 should be cleared")
	}
}

// TestNegativeStore_NegativeHitEngine 引擎层负向命中完整流程。
func TestNegativeStore_NegativeHitEngine(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Negative.Enabled = true
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "bad-input",
		PromptText:      "bad input prompt",
		PolicyVer:       "1",
		GuardVer:        "v1",
	}

	// 写入负向
	eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
		Finish: "stop",
		Negative: &NegativePayload{
			Reason:    "prompt_injection",
			Stage:     "guardrail",
			PolicyVer: "1",
			GuardVer:  "v1",
		},
	})

	// 查询负向命中
	r := eng.Lookup(ctx)
	if !r.Hit {
		t.Fatalf("expected negative hit, reason: %s", r.RejectReason)
	}
	if !r.IsNegative() {
		t.Fatal("should be negative")
	}
	if r.Entry.Negative.Reason != "prompt_injection" {
		t.Fatalf("unexpected reason: %s", r.Entry.Negative.Reason)
	}
}

// TestNegativeStore_VersionMismatch 版本不一致时负向缓存失效。
func TestNegativeStore_VersionMismatch(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Negative.Enabled = true
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "bad-input",
		PromptText:      "bad input",
		PolicyVer:       "1",
		GuardVer:        "v1",
	}

	// 用 v1 写入
	eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
		Finish: "stop",
		Negative: &NegativePayload{
			Reason:    "injection",
			Stage:     "guardrail",
			PolicyVer: "1",
			GuardVer:  "v1",
		},
	})

	// 用 v2 查询 → 不应命中（词库升级后旧负向失效）
	ctx2 := ctx
	ctx2.GuardVer = "v2"
	r := eng.Lookup(ctx2)
	if r.Hit && r.IsNegative() {
		t.Fatal("should not hit with different guard version")
	}
}
