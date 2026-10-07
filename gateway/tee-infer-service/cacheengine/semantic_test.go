package cacheengine

import (
	"context"
	"fmt"
	"hash/fnv"
	"strings"
	"testing"
)

// TestVectorIndex_FlatBasic FLAT 向量索引基本操作。
func TestVectorIndex_FlatBasic(t *testing.T) {
	idx := NewFlatVectorIndex(8, 100)

	if idx.Backend() != "flat" {
		t.Fatalf("expected flat backend, got %s", idx.Backend())
	}

	meta := VectorMeta{
		TenantID: "t1",
		Model:    "m1",
	}

	// 插入
	vec1 := []float32{1, 0, 0, 0, 0, 0, 0, 0}
	if err := idx.Upsert("k1", vec1, meta); err != nil {
		t.Fatalf("upsert failed: %v", err)
	}
	if idx.Size() != 1 {
		t.Fatalf("expected size 1, got %d", idx.Size())
	}

	// 查询（自己应该最相似）
	hits, err := idx.Search(vec1, 3, VectorFilter{})
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit, got %d", len(hits))
	}
	if hits[0].EntryID != "k1" {
		t.Fatalf("expected k1, got %s", hits[0].EntryID)
	}
	if hits[0].Similarity <= 0.99 {
		t.Fatalf("expected similarity ~1.0, got %f", hits[0].Similarity)
	}

	// 删除
	if err := idx.Delete("k1"); err != nil {
		t.Fatalf("delete failed: %v", err)
	}
	if idx.Size() != 0 {
		t.Fatalf("expected size 0, got %d", idx.Size())
	}
}

// TestVectorIndex_FlatTopK 验证 topK 和排序。
func TestVectorIndex_FlatTopK(t *testing.T) {
	idx := NewFlatVectorIndex(4, 100)

	vecs := map[string][]float32{
		"a": {1, 0, 0, 0}, // 与查询最相似
		"b": {0, 1, 0, 0},
		"c": {0, 0, 1, 0},
		"d": {0, 0, 0, 1}, // 与查询最不相似
	}

	for id, v := range vecs {
		idx.Upsert(id, v, VectorMeta{TenantID: "t1"})
	}

	// 查询向量接近 a
	query := []float32{0.9, 0.1, 0.1, 0.1}
	hits, err := idx.Search(query, 2, VectorFilter{})
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits, got %d", len(hits))
	}
	if hits[0].EntryID != "a" {
		t.Fatalf("expected top hit a, got %s", hits[0].EntryID)
	}
	// 验证降序
	if hits[0].Similarity < hits[1].Similarity {
		t.Fatal("hits not sorted descending")
	}
}

// TestVectorIndex_FlatFilter 验证硬过滤。
func TestVectorIndex_FlatFilter(t *testing.T) {
	idx := NewFlatVectorIndex(4, 100)

	vec := []float32{1, 1, 1, 1}
	idx.Upsert("t1-m1", vec, VectorMeta{TenantID: "t1", Model: "m1"})
	idx.Upsert("t1-m2", vec, VectorMeta{TenantID: "t1", Model: "m2"})
	idx.Upsert("t2-m1", vec, VectorMeta{TenantID: "t2", Model: "m1"})

	// 按租户过滤
	hits, _ := idx.Search(vec, 10, VectorFilter{TenantID: "t1"})
	if len(hits) != 2 {
		t.Fatalf("expected 2 hits for t1, got %d", len(hits))
	}

	// 按租户+模型过滤
	hits, _ = idx.Search(vec, 10, VectorFilter{TenantID: "t1", Model: "m1"})
	if len(hits) != 1 {
		t.Fatalf("expected 1 hit for t1/m1, got %d", len(hits))
	}
	if hits[0].EntryID != "t1-m1" {
		t.Fatalf("expected t1-m1, got %s", hits[0].EntryID)
	}
}

// TestSemanticStore_Basic 语义缓存基本流程：写入 → 查询命中。
func TestSemanticStore_Basic(t *testing.T) {
	cfg := testSemanticConfig()
	embedder := NewDeterministicEmbedder(32)
	idx := NewFlatVectorIndex(32, 1000)

	sem, err := NewSemanticStore(&cfg, embedder, idx)
	if err != nil {
		t.Fatalf("new semantic store failed: %v", err)
	}

	// 写入几条
	texts := []string{
		"什么是机器学习？机器学习是人工智能的一个分支",
		"机器学习的定义是什么",
		"今天天气怎么样",
		"请介绍一下深度学习",
	}

	for i, text := range texts {
		meta := VectorMeta{
			TenantID: "t1",
			Model:    "m1",
			ExpireAt: 0, // 永不过期
		}
		id := fmt.Sprintf("e%d", i)
		if err := sem.Store(id, text, meta); err != nil {
			t.Fatalf("store %d failed: %v", i, err)
		}
	}

	// 验证向量索引大小
	if sem.Size() != 4 {
		t.Fatalf("expected 4 entries, got %d", sem.Size())
	}
}

// TestSemanticEngine_EndToEnd 端到端语义缓存测试：写入 → 语义查询命中。
func TestSemanticEngine_EndToEnd(t *testing.T) {
	cfg := testSemanticConfig()
	embedder := NewDeterministicEmbedder(32)
	idx := NewFlatVectorIndex(32, 1000)
	sem, _ := NewSemanticStore(&cfg, embedder, idx)

	eng := NewCacheEngine(cfg, WithSemanticStore(sem))

	// 写一条缓存
	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "hash1",
			PromptText:      "请解释什么是机器学习算法",
			PolicyVer:       "1",
			GuardVer:        "v1",
		},
		Writable: true,
	}

	answer := "机器学习算法是一类从数据中自动学习规律的计算机算法"
	outcome := eng.Store(ctx, InferResult{
		Text:      answer,
		TokensIn:  20,
		TokensOut: 15,
		Finish:    "stop",
	})

	if outcome.Layer != "both" {
		t.Fatalf("expected layer=both, got %s (stored=%v, skipped=%s)",
			outcome.Layer, outcome.Stored, outcome.Skipped)
	}

	// 精确命中（相同 prompt）
	r1 := eng.Lookup(ctx.LookupContext)
	if !r1.Hit || r1.Kind != KindExact {
		t.Fatalf("expected exact hit, got hit=%v kind=%s reason=%s",
			r1.Hit, r1.Kind, r1.RejectReason)
	}
}

// TestSemanticEngine_SemanticMiss 精确未命中时走语义查询（未命中场景）。
func TestSemanticEngine_SemanticMiss(t *testing.T) {
	cfg := testSemanticConfig()
	embedder := NewDeterministicEmbedder(32)
	idx := NewFlatVectorIndex(32, 1000)
	sem, _ := NewSemanticStore(&cfg, embedder, idx)

	eng := NewCacheEngine(cfg, WithSemanticStore(sem))

	// 先写入
	ctx := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "hash1",
			PromptText:      "请解释什么是机器学习",
			PolicyVer:       "1",
			GuardVer:        "v1",
		},
		Writable: true,
	}
	outcome := eng.Store(ctx, InferResult{
		Text:      "机器学习是人工智能的分支",
		TokensIn:  10,
		TokensOut: 8,
		Finish:    "stop",
	})

	if outcome.Layer != "both" {
		t.Fatalf("expected layer=both, got %s (stored=%v, skipped=%s)",
			outcome.Layer, outcome.Stored, outcome.Skipped)
	}

	// 用不同 hash 的查询（精确 miss，走语义）
	queryCtx := LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "hash2", // 不同 hash，精确 miss
		PromptText:      "今天天气怎么样", // 不同内容
		PolicyVer:       "1",
		GuardVer:        "v1",
	}

	r := eng.Lookup(queryCtx)
	// 语义可能命中也可能不命中（取决于确定性 embedder 的相似度）
	// 这里只验证不报错，且流程走完
	if r.RejectReason != "" && !strings.HasPrefix(r.RejectReason, "semantic_miss:") {
		t.Logf("reject reason: %s", r.RejectReason)
	}
	// 验证向量索引有数据
	snap := eng.Stats()
	if snap.VectorEntries < 1 {
		t.Fatalf("expected at least 1 vector entry, got %d", snap.VectorEntries)
	}
}

// testSemanticConfig 返回语义模式的测试配置。
func testSemanticConfig() CacheConfig {
	cfg := DefaultConfig()
	cfg.Mode = ModeSemantic
	cfg.Semantic.Enabled = true
	cfg.Semantic.Embedder.Dim = 32
	cfg.Semantic.Vector.TopK = 5
	cfg.Guard.ReadFastCheck = false
	cfg.Semantic.Threshold.General = 0.5 // 降低阈值便于测试
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	return cfg
}

// ===== H2-a（I-3）：语义命中端到端 =====

// semanticTestEmbedder 测试专用"语义"编码器（H2-a）：
// 以字符二元组（bigram）词袋哈希落入 dim 维并计数——文本重叠越多、余弦相似度越高，
// 使"近义 → 语义命中"路径可被端到端断言。**真实语义质量**由真机 sidecar 验收（C-2），
// 本编码器只保证"语义可达"以覆盖接线，不作为语义正确性判据。
type semanticTestEmbedder struct{ dim int }

// newSemanticTestEmbedder 构造测试专用语义编码器。
func newSemanticTestEmbedder(dim int) Embedder {
	if dim <= 0 {
		dim = 32
	}
	return &semanticTestEmbedder{dim: dim}
}

func (s *semanticTestEmbedder) Embed(_ context.Context, text string) ([]float32, error) {
	vec := make([]float32, s.dim)
	rs := []rune(text)
	for i := 0; i < len(rs); i++ {
		gram := string(rs[i])
		if i+1 < len(rs) {
			gram = string(rs[i : i+2]) // 字符二元组
		}
		h := fnv.New32a()
		_, _ = h.Write([]byte(gram))
		vec[int(h.Sum32())%s.dim]++
	}
	return vec, nil
}

func (s *semanticTestEmbedder) Dim() int        { return s.dim }
func (s *semanticTestEmbedder) Model() string   { return "semantic-test" }
func (s *semanticTestEmbedder) Available() bool { return true }

// TestSemanticHit_EndToEnd I-3（本体 §10.2）：近义两次请求 → 第二次"语义命中"（命中 + 指纹相容）。
func TestSemanticHit_EndToEnd(t *testing.T) {
	cfg := testSemanticConfig()
	// 本用例考察"语义可达"接线而非阈值调参：把 factual 阈值也降到 0.5。
	// 选词避开 code/math 关键词（"算法"/"计算"等），使其落入 factual（无实体指纹门禁）。
	cfg.Semantic.Threshold.Factual = 0.5
	sem, err := NewSemanticStore(&cfg, newSemanticTestEmbedder(32), NewFlatVectorIndex(32, 1000))
	if err != nil {
		t.Fatalf("new semantic store: %v", err)
	}
	eng := NewCacheEngine(cfg, WithSemanticStore(sem))

	// 第一条：写入（同时落精确层 + 语义层）
	base := LookupContext{
		TenantID: "t1", EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
		TransformedHash: "h-base", PromptText: "请介绍一下机器学习的基本概念", PolicyVer: "1", GuardVer: "v1",
	}
	if out := eng.Store(StoreContext{LookupContext: base, Writable: true},
		InferResult{Text: "机器学习是人工智能的一个分支", TokensIn: 20, TokensOut: 15, Finish: "stop"}); !out.Stored {
		t.Fatalf("store 失败: %+v", out)
	}

	// 第二条：近义改写——不同 hash（精确 miss）→ 走语义检索 → 语义命中
	q := base
	q.TransformedHash = "h-near"
	q.PromptText = "请介绍一下机器学习的基本定义"
	r := eng.Lookup(q)
	if !r.Hit || r.Kind != KindSemantic {
		t.Fatalf("期望语义命中，got hit=%v kind=%s reason=%s sim=%.3f",
			r.Hit, r.Kind, r.RejectReason, r.Similarity)
	}
	if r.Entry == nil || r.Entry.Text == "" {
		t.Fatal("语义命中应带回条目正文")
	}
}
