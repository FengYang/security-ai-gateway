package cacheengine

import (
	"errors"
	"testing"
)

// ===== §6.10 配置热更新（B′：新引擎 + 复用 store）=====

// reloadCtx 构造热更用例用查询上下文。
func reloadCtx(hash string) StoreContext {
	return StoreContext{
		LookupContext: LookupContext{
			TenantID: "t1", EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
			TransformedHash: hash, PromptText: "long enough prompt for cacheability",
			PolicyVer: "1", GuardVer: "v1",
		},
		Writable: true,
	}
}

// TestStructuralDiff_HotVsStructural 结构维度判定：容量/后端/key_format/scope/embedder 属结构；
// threshold/ttl/gray 属可热更。
func TestStructuralDiff_HotVsStructural(t *testing.T) {
	base := testConfig()

	// 纯阈值变更 → 无结构差异（可热更）
	hot := base
	hot.Semantic.Threshold.Factual = base.Semantic.Threshold.Factual + 0.01
	if d := StructuralDiff(&base, &hot); len(d) != 0 {
		t.Fatalf("阈值变更应可热更，got %v", d)
	}

	cases := []struct {
		name string
		mut  func(c *CacheConfig)
	}{
		{"embedder.dim", func(c *CacheConfig) { c.Semantic.Embedder.Dim++ }},
		{"embedder.model_id", func(c *CacheConfig) { c.Semantic.Embedder.ModelID = "other" }},
		{"vector.backend", func(c *CacheConfig) { c.Semantic.Vector.Backend = "flat" }},
		{"exact.max_entries", func(c *CacheConfig) { c.Exact.MaxEntries++ }},
		{"negative.max_entries", func(c *CacheConfig) { c.Negative.MaxEntries++ }},
		{"hnsw.max_entries", func(c *CacheConfig) { c.Semantic.Vector.HNSW.MaxEntries++ }},
		{"redis.addr", func(c *CacheConfig) { c.Redis.Addr = "other:6379" }},
		{"key_format", func(c *CacheConfig) { c.KeyFormat = "v1" }},
		{"scope", func(c *CacheConfig) { c.Scope = "global" }},
	}
	for _, tc := range cases {
		m := base
		tc.mut(&m)
		if d := StructuralDiff(&base, &m); len(d) == 0 {
			t.Fatalf("%s 变更应判为结构性（需重启）", tc.name)
		}
	}
}

// TestHotReload_RejectEmbedderChange T-6.10-2：模型/维度变更被拒绝（需重启）。
func TestHotReload_RejectEmbedderChange(t *testing.T) {
	cfg := testConfig()
	eng := NewCacheEngine(cfg)

	changed := cfg
	changed.Semantic.Embedder.Dim = cfg.Semantic.Embedder.Dim + 64
	_, err := eng.Rebuild(changed)
	if !errors.Is(err, ErrReloadRestartRequired) {
		t.Fatalf("维度变更应返回 ErrReloadRestartRequired，got %v", err)
	}
}

// TestHotReload_InvalidConfigAllOrNothing T-6.10-4：非法配置整体拒绝，旧引擎继续服务。
func TestHotReload_InvalidConfigAllOrNothing(t *testing.T) {
	cfg := testConfig()
	eng := NewCacheEngine(cfg)

	sc := reloadCtx("h-keep")
	if out := eng.Store(sc, InferResult{Text: "cached answer", TokensOut: 10, Finish: "stop"}); !out.Stored {
		t.Fatalf("precondition store failed: %+v", out)
	}

	bad := cfg
	bad.Memory.WatermarkHigh = 0.5
	bad.Memory.WatermarkLow = 0.9 // 违反规则 23（低水位须 < 高水位）→ 校验失败
	if _, err := eng.Rebuild(bad); err == nil {
		t.Fatal("非法配置应被拒绝")
	}

	// 旧引擎仍可命中（all-or-nothing：未切换）
	if r := eng.Lookup(sc.LookupContext); !r.Hit {
		t.Fatalf("拒绝热更后旧引擎应继续服务，got hit=false reason=%s", r.RejectReason)
	}
}

// TestHotReload_ModeOffKeepsEntries T-6.10-3 / B-6.10-4：mode off 保留条目（复用同一 store）。
func TestHotReload_ModeOffKeepsEntries(t *testing.T) {
	cfg := testConfig()
	eng := NewCacheEngine(cfg)
	sc := reloadCtx("h-off")
	if out := eng.Store(sc, InferResult{Text: "kept answer", TokensOut: 10, Finish: "stop"}); !out.Stored {
		t.Fatalf("precondition store failed: %+v", out)
	}

	off := cfg
	off.Mode = ModeOff
	ne, err := eng.Rebuild(off)
	if err != nil {
		t.Fatalf("mode=off 应允许热更：%v", err)
	}

	// 条目保留：复用同一 exact store 实例
	if ne.(*engine).exact != eng.(*engine).exact {
		t.Fatal("mode=off 应复用同一 exact store（条目保留以便回滚）")
	}
	if _, ok := ne.Inspect(eng.(*engine).exactKey(sc.LookupContext)); !ok {
		t.Fatal("mode=off 后条目应仍可取回（便于快速回滚）")
	}
	// 语义/查询停止：mode=off → 不命中
	if r := ne.Lookup(sc.LookupContext); r.Hit {
		t.Fatal("mode=off 后不应命中")
	}
}

// TestHotReload_MetricsRetained 指标计数器在热更后不归零（复用同一 stats 门面）。
func TestHotReload_MetricsRetained(t *testing.T) {
	cfg := testConfig()
	eng := NewCacheEngine(cfg)
	ne, err := eng.Rebuild(cfg)
	if err != nil {
		t.Fatalf("等价配置应允许热更：%v", err)
	}
	if ne.(*engine).stats != eng.(*engine).stats {
		t.Fatal("热更应复用同一指标门面（避免 Prometheus 计数归零）")
	}
}

// TestHotReload_ThresholdImmediate T-6.10-6 / §6.10.1：阈值变更即时生效（旧条目索引复用）。
func TestHotReload_ThresholdImmediate(t *testing.T) {
	cfg := testSemanticConfig()
	// 合法阈值（规则 4：∈(0.5,1.0] 且 code/math ≥ factual ≥ general）
	cfg.Semantic.Threshold.Factual = 0.51
	cfg.Semantic.Threshold.General = 0.51
	cfg.Semantic.Threshold.Code = 0.51
	cfg.Semantic.Threshold.Math = 0.51
	// 用 512 维（降低哈希桶碰撞噪声，使 bigram 余弦接近理论值 ≈0.96）
	cfg.Semantic.Embedder.Dim = 512
	sem, err := NewSemanticStore(&cfg, newSemanticTestEmbedder(512), NewFlatVectorIndex(512, 1000))
	if err != nil {
		t.Fatalf("new semantic store: %v", err)
	}
	eng := NewCacheEngine(cfg, WithSemanticStore(sem))

	const prompt = "请介绍一下机器学习的基本概念"
	base := LookupContext{TenantID: "t1", EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
		TransformedHash: "h-base", PromptText: prompt, PolicyVer: "1", GuardVer: "v1"}
	// 注：语义层 embedding 取自响本文本（`sem.Store(key, res.Text)`），查询侧取 PromptText；
	// 故用例令响应与查询文本高度重叠（仅尾部差一字），使 bigram 余弦 ≈0.96。
	if out := eng.Store(StoreContext{LookupContext: base, Writable: true},
		InferResult{Text: prompt + "。", TokensIn: 20, TokensOut: 15, Finish: "stop"}); !out.Stored {
		t.Fatalf("store 失败: %+v", out)
	}
	near := base
	near.TransformedHash = "h-near" // 不同 hash → 精确 miss → 走语义

	if r := eng.Lookup(near); !r.Hit || r.Kind != KindSemantic {
		t.Fatalf("阈值 0.51 下应语义命中，got hit=%v kind=%s reason=%s sim=%.3f",
			r.Hit, r.Kind, r.RejectReason, r.Similarity)
	}

	// 调高阈值 → 热更后同一近义查询应 miss（阈值即时生效，索引条目保留）
	strict := cfg
	strict.Semantic.Threshold.Factual = 0.99
	strict.Semantic.Threshold.Code = 0.99
	strict.Semantic.Threshold.Math = 0.99 // 维持规则 4 的顺序（code/math ≥ factual ≥ general）
	ne, err := eng.Rebuild(strict)
	if err != nil {
		t.Fatalf("阈值变更应允许热更：%v", err)
	}
	if r := ne.Lookup(near); r.Hit {
		t.Fatal("阈值调高后应不再命中（阈值即时生效）")
	}
	// 旧引擎仍按旧阈值命中（未切换者不受影响）
	if r := eng.Lookup(near); !r.Hit {
		t.Fatal("旧引擎应仍按旧阈值命中")
	}
}
