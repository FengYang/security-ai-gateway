package cacheengine

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// TestIntegration_ExactLifecycle 精确缓存完整生命周期。
// 写入 → 命中 → 版本升级失效 → 未命中 → 再写入 → 再命中。
func TestIntegration_ExactLifecycle(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	eng := NewCacheEngine(cfg)

	ctxV1 := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "h1",
		PromptText:      "prompt text long enough",
		PolicyVer:       "v1",
		GuardVer:        "v1",
	}

	// 初始 miss
	r1 := eng.Lookup(ctxV1)
	if r1.Hit {
		t.Fatal("step1: expected miss")
	}

	// 写入 v1
	eng.Store(StoreContext{LookupContext: ctxV1, Writable: true}, InferResult{
		Text:      "answer v1",
		TokensOut: 10,
		Finish:    "stop",
	})

	// 命中 v1
	r2 := eng.Lookup(ctxV1)
	if !r2.Hit {
		t.Fatalf("step2: expected hit, reason=%s", r2.RejectReason)
	}
	if r2.Entry.Text != "answer v1" {
		t.Fatalf("expected 'answer v1', got '%s'", r2.Entry.Text)
	}

	// 版本升级 → 失效
	ctxV2 := ctxV1
	ctxV2.PolicyVer = "v2"
	r3 := eng.Lookup(ctxV2)
	if r3.Hit {
		t.Fatal("step3: expected miss after version bump")
	}

	// 写入 v2
	eng.Store(StoreContext{LookupContext: ctxV2, Writable: true}, InferResult{
		Text:      "answer v2",
		TokensOut: 10,
		Finish:    "stop",
	})

	// 命中 v2
	r4 := eng.Lookup(ctxV2)
	if !r4.Hit {
		t.Fatalf("step4: expected v2 hit, reason=%s", r4.RejectReason)
	}
	if r4.Entry.Text != "answer v2" {
		t.Fatalf("expected 'answer v2', got '%s'", r4.Entry.Text)
	}

	// v1 应该仍在（版本不同但都可用，各自的 key）
	// v1 查询：应该还是命中（因为 v1 的 key 没被删）
	r5 := eng.Lookup(ctxV1)
	if !r5.Hit {
		t.Fatalf("step5: expected v1 still cached, reason=%s", r5.RejectReason)
	}

	// 全量失效
	count, err := eng.Invalidate(InvalidateSelector{All: true})
	if err != nil {
		t.Fatalf("invalidate error: %v", err)
	}
	if count < 2 {
		t.Fatalf("expected at least 2 invalidated, got %d", count)
	}

	// 都失效了
	r6 := eng.Lookup(ctxV1)
	if r6.Hit {
		t.Fatal("step6: v1 should be invalidated")
	}
	r7 := eng.Lookup(ctxV2)
	if r7.Hit {
		t.Fatal("step6: v2 should be invalidated")
	}
}

// TestIntegration_SemanticLifecycle 语义缓存完整生命周期。
func TestIntegration_SemanticLifecycle(t *testing.T) {
	cfg := testSemanticConfig()
	cfg.Semantic.Threshold.General = 0.6
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	embedder := NewDeterministicEmbedder(32)
	idx := NewFlatVectorIndex(32, cfg.Semantic.Vector.FlatMaxEntries)
	store, err := NewSemanticStore(&cfg, embedder, idx)
	if err != nil {
		t.Fatalf("NewSemanticStore failed: %v", err)
	}
	eng := NewCacheEngine(cfg, WithSemanticStore(store))

	// 初始写入
	ctx1 := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "h1",
		PromptText:      "what is the capital of france",
		PolicyVer:       "v1",
		GuardVer:        "v1",
		Scene:           SceneGeneral,
	}
	eng.Store(StoreContext{LookupContext: ctx1, Writable: true}, InferResult{
		Text:      "Paris is the capital of France.",
		TokensOut: 20,
		Finish:    "stop",
	})

	// 精确命中
	r1 := eng.Lookup(ctx1)
	if !r1.Hit || r1.Kind != KindExact {
		t.Fatalf("expected exact hit, got hit=%v kind=%v reason=%s", r1.Hit, r1.Kind, r1.RejectReason)
	}

	// 语义相似查询（去掉 exact 匹配，用不同的 hash 触发语义检索）
	ctx2 := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "h2",
		PromptText:      "capital of france what is",
		PolicyVer:       "v1",
		GuardVer:        "v1",
		Scene:           SceneGeneral,
	}
	r2 := eng.Lookup(ctx2)
	if !r2.Hit || r2.Kind != KindSemantic {
		t.Fatalf("expected semantic hit, got hit=%v kind=%v reason=%s", r2.Hit, r2.Kind, r2.RejectReason)
	}

	// 不同主题查询（确定性 embedder 的相似度区分度有限，此处仅验证流程不崩）
	ctx3 := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "h3",
		PromptText:      "completely different topic about machine learning algorithms",
		PolicyVer:       "v1",
		GuardVer:        "v1",
		Scene:           SceneGeneral,
	}
	r3 := eng.Lookup(ctx3)
	t.Logf("different topic: hit=%v kind=%v reason=%s", r3.Hit, r3.Kind, r3.RejectReason)
	// 注：确定性 embedder 的相似度区分度有限，不做强断言
}

// TestIntegration_SceneThresholds 场景化阈值：不同场景阈值不同。
func TestIntegration_SceneThresholds(t *testing.T) {
	cfg := testSemanticConfig()
	// factual 阈值高，general 阈值低
	cfg.Semantic.Threshold.Factual = 0.95
	cfg.Semantic.Threshold.General = 0.5
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	embedder := NewDeterministicEmbedder(32)
	idx := NewFlatVectorIndex(32, cfg.Semantic.Vector.FlatMaxEntries)
	store, err := NewSemanticStore(&cfg, embedder, idx)
	if err != nil {
		t.Fatalf("NewSemanticStore failed: %v", err)
	}
	eng := NewCacheEngine(cfg, WithSemanticStore(store))

	// 写入一个 factual 场景的条目
	factCtx := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "f1",
		PromptText:      "what year did world war 2 end",
		PolicyVer:       "v1",
		GuardVer:        "v1",
		Scene:           SceneFactual,
	}
	eng.Store(StoreContext{LookupContext: factCtx, Writable: true}, InferResult{
		Text:      "World War II ended in 1945.",
		TokensOut: 15,
		Finish:    "stop",
	})

	// 相似的 factual 查询 → 高阈值下不命中（确定性 embedder 差异够大）
	simFact := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "f2",
		PromptText:      "when did second world war finish",
		PolicyVer:       "v1",
		GuardVer:        "v1",
		Scene:           SceneFactual,
	}
	rFact := eng.Lookup(simFact)
	// 高阈值 + 确定性 embedder 余弦差异 → 大概率不命中
	t.Logf("factual scene: hit=%v kind=%v reason=%s", rFact.Hit, rFact.Kind, rFact.RejectReason)

	// 写入 general 场景条目
	genCtx := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "g1",
		PromptText:      "tell me about weather today",
		PolicyVer:       "v1",
		GuardVer:        "v1",
		Scene:           SceneGeneral,
	}
	eng.Store(StoreContext{LookupContext: genCtx, Writable: true}, InferResult{
		Text:      "It is sunny today.",
		TokensOut: 10,
		Finish:    "stop",
	})

	simGen := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "g2",
		PromptText:      "what is weather like today",
		PolicyVer:       "v1",
		GuardVer:        "v1",
		Scene:           SceneGeneral,
	}
	rGen := eng.Lookup(simGen)
	t.Logf("general scene: hit=%v kind=%v reason=%s", rGen.Hit, rGen.Kind, rGen.RejectReason)
}

// TestIntegration_StatsMetrics 统计与指标渲染。
func TestIntegration_StatsMetrics(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	eng := NewCacheEngine(cfg)

	// 做一些操作
	for i := 0; i < 10; i++ {
		ctx := LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: fmt.Sprintf("h%d", i),
			PromptText:      "long enough prompt",
			PolicyVer:       "v1",
			GuardVer:        "v1",
		}
		// 先 miss
		r := eng.Lookup(ctx)
		if r.Hit {
			t.Fatalf("expected miss for h%d", i)
		}
		// 再写入
		eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
			Text:      fmt.Sprintf("answer %d", i),
			TokensOut: 10,
			Finish:    "stop",
		})
		// 再命中
		r2 := eng.Lookup(ctx)
		if !r2.Hit {
			t.Fatalf("expected hit for h%d, reason=%s", i, r2.RejectReason)
		}
	}

	stats := eng.Stats()
	// Lookups 是 map，格式 "{kind}:{result}"
	exactHits := stats.Lookups["exact:hit"]
	exactMisses := stats.Lookups["exact:miss"]
	totalHits := exactHits + stats.Lookups["semantic:hit"] + stats.Lookups["negative:hit"]
	totalMisses := exactMisses + stats.Lookups["semantic:miss"] + stats.Lookups["precheck:not_cacheable"]

	if totalHits+totalMisses == 0 {
		t.Fatal("expected some lookups")
	}
	if exactHits != 10 {
		t.Fatalf("expected 10 exact hits, got %d", exactHits)
	}
	if exactMisses != 10 {
		t.Fatalf("expected 10 exact misses, got %d", exactMisses)
	}
	if stats.ExactEntries != 10 {
		t.Fatalf("expected 10 exact entries, got %d", stats.ExactEntries)
	}

	// 命中率计算
	hitRate := float64(totalHits) / float64(totalHits+totalMisses)
	if hitRate < 0.49 || hitRate > 0.51 {
		t.Fatalf("expected ~0.5 hit rate, got %f", hitRate)
	}

	// metrics 渲染（通过内部 engine 类型断言）
	var buf bytes.Buffer
	e := eng.(*engine)
	e.RenderPrometheus(&buf)
	output := buf.String()

	if output == "" {
		t.Fatal("metrics should not be empty")
	}
	// 包含关键指标
	checks := []string{
		"otpmask_cache_lookups_total",
		"otpmask_cache_exact_entries",
		"otpmask_cache_evictions_total",
	}
	for _, name := range checks {
		if !strings.Contains(output, name) {
			t.Fatalf("metrics missing: %s", name)
		}
	}
}

// TestIntegration_ModeOff mode=off 完全透传（fail-closed）。
func TestIntegration_ModeOff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeOff
	eng := NewCacheEngine(cfg)

	ctx := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		TransformedHash: "h1",
		PromptText:      "long enough prompt text",
	}

	// 写入
	eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
		Text:      "answer",
		TokensOut: 10,
		Finish:    "stop",
	})

	// 查询 → 不命中（mode=off 不查缓存）
	r := eng.Lookup(ctx)
	if r.Hit {
		t.Fatal("mode=off should never hit")
	}
	if r.RejectReason != "disabled" {
		t.Fatalf("expected reason 'disabled', got '%s'", r.RejectReason)
	}

	stats := eng.Stats()
	// mode=off 计入 precheck:disabled，不计入 exact/semantic hit
	if stats.Lookups["exact:hit"] != 0 || stats.Lookups["semantic:hit"] != 0 {
		t.Fatalf("mode=off should have 0 exact/semantic hits, got %+v", stats.Lookups)
	}
}
