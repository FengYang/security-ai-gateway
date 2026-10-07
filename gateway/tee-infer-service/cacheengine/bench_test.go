package cacheengine

import (
	"fmt"
	"testing"
)

// ===== 精确缓存基准 =====

// BenchmarkExact_Hit 精确命中。
func BenchmarkExact_Hit(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)

	// 预填 1000 条
	for i := 0; i < 1000; i++ {
		ctx := StoreContext{
			LookupContext: LookupContext{
				TenantID:        "t1",
				EngineType:      "cmaas",
				Model:           "m1",
				MaxNewTokens:    100,
				TransformedHash: fmt.Sprintf("hash-%d", i),
				PromptText:      "benchmark prompt long enough",
				PolicyVer:       "v1",
				GuardVer:        "v1",
			},
			Writable: true,
		}
		eng.Store(ctx, InferResult{
			Text:      "this is a benchmark response with enough content",
			TokensOut: 20,
			Finish:    "stop",
		})
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ctx := LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: fmt.Sprintf("hash-%d", i%1000),
			PromptText:      "benchmark prompt long enough",
			PolicyVer:       "v1",
			GuardVer:        "v1",
		}
		r := eng.Lookup(ctx)
		if !r.Hit {
			b.Fatalf("expected hit at i=%d, reason=%s", i, r.RejectReason)
		}
	}
}

// BenchmarkExact_Miss 精确未命中。
func BenchmarkExact_Miss(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ctx := LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: fmt.Sprintf("miss-%d", i),
			PromptText:      "benchmark prompt long enough",
			PolicyVer:       "v1",
			GuardVer:        "v1",
		}
		r := eng.Lookup(ctx)
		if r.Hit {
			b.Fatalf("expected miss at i=%d", i)
		}
	}
}

// BenchmarkExact_Store 精确写入。
func BenchmarkExact_Store(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Exact.MaxEntries = 100000
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ctx := StoreContext{
			LookupContext: LookupContext{
				TenantID:        "t1",
				EngineType:      "cmaas",
				Model:           "m1",
				MaxNewTokens:    100,
				TransformedHash: fmt.Sprintf("store-%d", i),
				PromptText:      "benchmark prompt long enough",
				PolicyVer:       "v1",
				GuardVer:        "v1",
			},
			Writable: true,
		}
		outcome := eng.Store(ctx, InferResult{
			Text:      "this is a benchmark response with enough content",
			TokensOut: 20,
			Finish:    "stop",
		})
		if !outcome.Stored {
			b.Fatalf("expected stored at i=%d, reason=%s", i, outcome.Skipped)
		}
	}
}

// ===== 语义缓存基准 =====

// BenchmarkSemantic_FlatSearch FLAT 暴力检索（1000 条向量，32 维）。
func BenchmarkSemantic_FlatSearch(b *testing.B) {
	dim := 32
	idx := NewFlatVectorIndex(dim, 10000)

	meta := VectorMeta{TenantID: "t1", Model: "m1"}
	for i := 0; i < 1000; i++ {
		vec := make([]float32, dim)
		for j := 0; j < dim; j++ {
			vec[j] = float32(i) / float32(j+1)
		}
		idx.Upsert(fmt.Sprintf("k%d", i), vec, meta)
	}

	query := make([]float32, dim)
	for j := 0; j < dim; j++ {
		query[j] = 0.5
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_, err := idx.Search(query, 5, VectorFilter{})
		if err != nil {
			b.Fatalf("search error: %v", err)
		}
	}
}

// BenchmarkSemantic_Lookup 语义层完整查询（embed + 检索 + 精确加载）。
func BenchmarkSemantic_Lookup(b *testing.B) {
	cfg := testSemanticConfig()
	cfg.Semantic.Threshold.General = 0.5
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	embedder := NewDeterministicEmbedder(32)
	idx := NewFlatVectorIndex(32, 10000)
	store, err := NewSemanticStore(&cfg, embedder, idx)
	if err != nil {
		b.Fatalf("NewSemanticStore failed: %v", err)
	}
	eng := NewCacheEngine(cfg, WithSemanticStore(store))

	// 预填 500 条
	for i := 0; i < 500; i++ {
		ctx := StoreContext{
			LookupContext: LookupContext{
				TenantID:        "t1",
				EngineType:      "cmaas",
				Model:           "m1",
				MaxNewTokens:    100,
				TransformedHash: fmt.Sprintf("sem-%d", i),
				PromptText:      fmt.Sprintf("semantic query benchmark number %d with enough text", i),
				PolicyVer:       "v1",
				GuardVer:        "v1",
				Scene:           SceneGeneral,
			},
			Writable: true,
		}
		eng.Store(ctx, InferResult{
			Text:      "semantic benchmark response text content",
			TokensOut: 20,
			Finish:    "stop",
		})
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ctx := LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: fmt.Sprintf("query-%d", i),
			PromptText:      fmt.Sprintf("semantic query benchmark number %d with enough text", i%500),
			PolicyVer:       "v1",
			GuardVer:        "v1",
			Scene:           SceneGeneral,
		}
		eng.Lookup(ctx)
	}
}

// ===== 组件级基准 =====

// BenchmarkSceneClassifier 场景分类。
func BenchmarkSceneClassifier(b *testing.B) {
	c := NewRuleSceneClassifier()
	prompt := "这是一个关于 Go 语言的编程问题，请看下面的代码：func main() { fmt.Println(\"hello\") }"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Classify(prompt)
	}
}

// BenchmarkCacheability 可缓存性判定。
func BenchmarkCacheability(b *testing.B) {
	cfg := DefaultConfig()
	ce := newCacheabilityEngine(&cfg, NewRuleSceneClassifier())

	ctx := &LookupContext{
		TenantID:     "t1",
		PromptText:   "这是一个足够长的查询问题用于性能测试基准",
		PolicyVer:    "v1",
		GuardVer:     "v1",
		EngineType:   "cmaas",
		Model:        "gpt-4",
		MaxNewTokens: 100,
	}
	ctx.Scene = SceneFactual

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ce.Cacheable(ctx)
	}
}

// BenchmarkFingerprint 实体指纹提取。
func BenchmarkFingerprint(b *testing.B) {
	text := "张三在 2024 年 3 月 15 日使用身份证号 110101199001011234 在北京市朝阳区注册了账号 zhangsan@example.com，手机号 13800138000。"

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ExtractEntities(text)
	}
}

// BenchmarkCanary_Allowed 灰度判定（白名单命中）。
func BenchmarkCanary_Allowed(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.CanaryTenants = []string{"t1", "t2", "t3"}

	c := NewConfigCanaryController(&cfg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Allow("t1", SceneGeneral, "m1")
	}
}

// BenchmarkCanary_Traffic 灰度判定（流量比例，hash 计算）。
func BenchmarkCanary_Traffic(b *testing.B) {
	cfg := DefaultConfig()
	cfg.Gray.Enabled = true
	cfg.Gray.TrafficPercent = 30

	c := NewConfigCanaryController(&cfg)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		c.Allow("benchmark-tenant-id-for-perf-test", SceneGeneral, "m1")
	}
}
