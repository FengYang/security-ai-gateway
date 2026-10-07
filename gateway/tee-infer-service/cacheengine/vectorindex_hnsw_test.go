package cacheengine

import (
	"fmt"
	"math/rand"
	"sync"
	"testing"
	"time"
)

// ===== HNSW 专项用例（§4.1.2 / §4.2）=====
// 覆盖：与 flat 暴力的检索一致性（recall）、硬过滤、墓碑删除、容量与压实、维度校验、
//       同 ID 更新、过期过滤、并发安全、后端解析（默认 hnsw / 未知后端显式拒绝）。

const (
	hnswTestDim = 32
	hnswTestN   = 1000
)

func randVec(rng *rand.Rand, dim int) []float32 {
	v := make([]float32, dim)
	for i := range v {
		v[i] = rng.Float32()*2 - 1
	}
	return v
}

func hnswTestMeta(i int, tenant string) VectorMeta {
	return VectorMeta{
		TenantID:   tenant,
		EngineType: "cmaas",
		Model:      "m1",
		PolicyVer:  "v1",
		GuardVer:   "v1",
	}
}

// fillIndex 用同一数据源填充两个索引。
func fillIndex(t *testing.T, idx VectorIndex, rng *rand.Rand, n int, dim int, tenant func(i int) string) [][]float32 {
	t.Helper()
	vecs := make([][]float32, n)
	for i := 0; i < n; i++ {
		v := randVec(rng, dim)
		vecs[i] = v
		if err := idx.Upsert(fmt.Sprintf("id-%d", i), v, hnswTestMeta(i, tenant(i))); err != nil {
			t.Fatalf("upsert i=%d: %v", i, err)
		}
	}
	return vecs
}

func idsOf(hits []VectorHit) map[string]struct{} {
	m := make(map[string]struct{}, len(hits))
	for _, h := range hits {
		m[h.EntryID] = struct{}{}
	}
	return m
}

// TestHNSW_RecallVsFlat 检索一致性：top1 一致率与 top5 召回率对照 flat 暴力。
func TestHNSW_RecallVsFlat(t *testing.T) {
	dim := hnswTestDim
	src := rand.New(rand.NewSource(42))
	data := make([][]float32, hnswTestN)
	for i := range data {
		data[i] = randVec(src, dim)
	}

	flat := NewFlatVectorIndex(dim, hnswTestN)
	hn := newHNSWVectorIndex(dim, hnswTestN, 16, 200, 64, 7)
	for i, v := range data {
		m := hnswTestMeta(i, "t1")
		if err := flat.Upsert(fmt.Sprintf("id-%d", i), v, m); err != nil {
			t.Fatal(err)
		}
		if err := hn.Upsert(fmt.Sprintf("id-%d", i), v, m); err != nil {
			t.Fatal(err)
		}
	}
	if hn.Backend() != "hnsw" || flat.Backend() != "flat" {
		t.Fatalf("backend 标识异常: hnsw=%s flat=%s", hn.Backend(), flat.Backend())
	}

	q := rand.New(rand.NewSource(99))
	const queries = 200
	top1Match, recallSum := 0, 0.0
	for i := 0; i < queries; i++ {
		query := randVec(q, dim)
		fh, err := flat.Search(query, 5, VectorFilter{})
		if err != nil {
			t.Fatal(err)
		}
		hh, err := hn.Search(query, 5, VectorFilter{})
		if err != nil {
			t.Fatal(err)
		}
		if len(fh) > 0 && len(hh) > 0 && fh[0].EntryID == hh[0].EntryID {
			top1Match++
		}
		fs, hs := idsOf(fh), idsOf(hh)
		inter := 0
		for id := range fs {
			if _, ok := hs[id]; ok {
				inter++
			}
		}
		if len(fs) > 0 {
			recallSum += float64(inter) / float64(len(fs))
		}
	}
	top1Rate := float64(top1Match) / queries
	recall := recallSum / queries
	t.Logf("HNSW vs flat：top1 一致率=%.3f，top5 召回=%.3f（n=%d，queries=%d）", top1Rate, recall, hnswTestN, queries)
	if top1Rate < 0.95 {
		t.Fatalf("HNSW top1 一致率 %.3f < 0.95", top1Rate)
	}
	if recall < 0.90 {
		t.Fatalf("HNSW top5 召回 %.3f < 0.90", recall)
	}
}

// TestHNSW_FilteredSearch 硬过滤（租户隔离）：结果必须全部属于指定租户。
func TestHNSW_FilteredSearch(t *testing.T) {
	dim := hnswTestDim
	rng := rand.New(rand.NewSource(7))
	hn := newHNSWVectorIndex(dim, hnswTestN, 16, 200, 64, 11)
	fillIndex(t, hn, rng, 600, dim, func(i int) string {
		if i%2 == 0 {
			return "t1"
		}
		return "t2"
	})

	q := rand.New(rand.NewSource(13))
	for i := 0; i < 50; i++ {
		hits, err := hn.Search(randVec(q, dim), 5, VectorFilter{TenantID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) == 0 {
			t.Fatal("过滤查询无结果")
		}
		for _, h := range hits {
			if h.Meta.TenantID != "t1" {
				t.Fatalf("跨租户泄漏：%s 属于 %s", h.EntryID, h.Meta.TenantID)
			}
		}
	}
}

// TestHNSW_DeleteAndUpdate 墓碑删除（幂等）+ 同 ID 更新。
func TestHNSW_DeleteAndUpdate(t *testing.T) {
	dim := hnswTestDim
	rng := rand.New(rand.NewSource(3))
	hn := newHNSWVectorIndex(dim, 100, 16, 200, 64, 5)
	fillIndex(t, hn, rng, 20, dim, func(int) string { return "t1" })
	if hn.Size() != 20 {
		t.Fatalf("Size=%d，期望 20", hn.Size())
	}

	if err := hn.Delete("id-3"); err != nil {
		t.Fatal(err)
	}
	if hn.Size() != 19 {
		t.Fatalf("删除后 Size=%d，期望 19", hn.Size())
	}
	if err := hn.Delete("id-3"); err != nil {
		t.Fatalf("重复删除应幂等: %v", err)
	}
	if hn.Size() != 19 {
		t.Fatalf("重复删除后 Size=%d，期望 19", hn.Size())
	}

	// 更新同 ID：Size 不变
	v := randVec(rng, dim)
	if err := hn.Upsert("id-5", v, hnswTestMeta(5, "t1")); err != nil {
		t.Fatal(err)
	}
	if hn.Size() != 19 {
		t.Fatalf("更新同 ID 后 Size=%d，期望 19", hn.Size())
	}
	// 以新向量检索应能命中该 ID（topK 放大以降低偶发漏召影响）
	hits, err := hn.Search(v, 5, VectorFilter{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	if len(hits) == 0 || hits[0].EntryID != "id-5" {
		t.Fatalf("更新后检索未命中 id-5，实际=%v", hits)
	}
}

// TestHNSW_CapacityAndRebuild 容量上限与墓碑过半自动压实。
func TestHNSW_CapacityAndRebuild(t *testing.T) {
	dim := hnswTestDim
	rng := rand.New(rand.NewSource(21))
	const max = 50
	hn := newHNSWVectorIndex(dim, max, 8, 64, 32, 3)
	for i := 0; i < max; i++ {
		if err := hn.Upsert(fmt.Sprintf("id-%d", i), randVec(rng, dim), hnswTestMeta(i, "t1")); err != nil {
			t.Fatalf("i=%d: %v", i, err)
		}
	}
	// 满且墓碑未过半 → 报错
	if err := hn.Upsert("id-x", randVec(rng, dim), hnswTestMeta(0, "t1")); err == nil {
		t.Fatal("容量满且墓碑未过半时应报错")
	}
	// 删除过半 → 压实后可继续插入
	for i := 0; i < max/2+1; i++ {
		if err := hn.Delete(fmt.Sprintf("id-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := hn.Upsert("id-y", randVec(rng, dim), hnswTestMeta(1, "t1")); err != nil {
		t.Fatalf("压实后插入失败: %v", err)
	}
	want := max - (max/2 + 1) + 1
	if hn.Size() != want {
		t.Fatalf("Size=%d，期望 %d", hn.Size(), want)
	}
}

// TestHNSW_DimAndExpiry 维度校验 + 过期过滤。
func TestHNSW_DimAndExpiry(t *testing.T) {
	dim := hnswTestDim
	rng := rand.New(rand.NewSource(31))
	hn := newHNSWVectorIndex(dim, 10, 8, 64, 32, 2)

	if err := hn.Upsert("bad", make([]float32, dim+1), hnswTestMeta(0, "t1")); err == nil {
		t.Fatal("维度不符应报错")
	}
	if _, err := hn.Search(make([]float32, dim-1), 5, VectorFilter{}); err == nil {
		t.Fatal("查询维度不符应报错")
	}

	exp := hnswTestMeta(0, "t1")
	exp.ExpireAt = time.Now().Add(-time.Minute).UnixMilli()
	if err := hn.Upsert("expired", randVec(rng, dim), exp); err != nil {
		t.Fatal(err)
	}
	if err := hn.Upsert("live", randVec(rng, dim), hnswTestMeta(1, "t1")); err != nil {
		t.Fatal(err)
	}
	hits, err := hn.Search(randVec(rng, dim), 10, VectorFilter{TenantID: "t1"})
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if h.EntryID == "expired" {
			t.Fatal("过期条目不应被返回")
		}
	}
}

// TestHNSW_Concurrent 并发读写安全（配合 -race 运行）。
func TestHNSW_Concurrent(t *testing.T) {
	dim := 8
	hn := newHNSWVectorIndex(dim, 2000, 8, 64, 32, 4)
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			r := rand.New(rand.NewSource(int64(100 + w)))
			for i := 0; i < 200; i++ {
				id := fmt.Sprintf("w%d-%d", w, i)
				_ = hn.Upsert(id, randVec(r, dim), hnswTestMeta(i, "t1"))
				_, _ = hn.Search(randVec(r, dim), 5, VectorFilter{TenantID: "t1"})
				if i%3 == 0 {
					_ = hn.Delete(id)
				}
			}
		}(w)
	}
	wg.Wait()
	if hn.Size() < 0 {
		t.Fatal("Size 异常")
	}
}

// TestHNSW_ResolveVectorBackendDefaults 后端解析：默认 hnsw、flat 原样、未知显式拒绝。
func TestHNSW_ResolveVectorBackendDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Semantic.Vector.Backend != "hnsw" {
		t.Fatalf("默认后端=%q，期望 hnsw", cfg.Semantic.Vector.Backend)
	}

	// 空值 → hnsw
	empty := DefaultConfig()
	empty.Semantic.Vector.Backend = ""
	if bk, err := ResolveVectorBackend(&empty, Capabilities{}); err != nil || bk != "hnsw" {
		t.Fatalf("空值解析=%q err=%v，期望 hnsw", bk, err)
	}
	// flat 原样
	fl := DefaultConfig()
	fl.Semantic.Vector.Backend = "flat"
	if bk, err := ResolveVectorBackend(&fl, Capabilities{}); err != nil || bk != "flat" {
		t.Fatalf("flat 解析=%q err=%v", bk, err)
	}
	// 未知 → 显式报错（修静默降级）
	bad := DefaultConfig()
	bad.Semantic.Vector.Backend = "ivf"
	if _, err := ResolveVectorBackend(&bad, Capabilities{}); err == nil {
		t.Fatal("未知后端应显式报错")
	}
	// redis-vss 双条件不满足 → fail-closed
	rv := DefaultConfig()
	rv.Semantic.Vector.Backend = "redis-vss"
	if _, err := ResolveVectorBackend(&rv, Capabilities{}); err == nil {
		t.Fatal("redis-vss 未满足双条件应报错")
	}
}

// TestHNSWConfigValidation 规则 27：HNSW 参数区间校验。
func TestHNSWConfigValidation(t *testing.T) {
	cases := []struct {
		name  string
		mut   func(*CacheConfig)
		valid bool
	}{
		{"default", func(*CacheConfig) {}, true},
		{"m too small", func(c *CacheConfig) { c.Semantic.Vector.HNSW.M = 2 }, false},
		{"m too large", func(c *CacheConfig) { c.Semantic.Vector.HNSW.M = 128 }, false},
		{"ef_construction too small", func(c *CacheConfig) { c.Semantic.Vector.HNSW.EfConstruction = 8 }, false},
		{"ef_search too small", func(c *CacheConfig) { c.Semantic.Vector.HNSW.EfSearch = 2 }, false},
		{"max_entries zero", func(c *CacheConfig) { c.Semantic.Vector.HNSW.MaxEntries = 0 }, false},
		{"ef_search < top_k", func(c *CacheConfig) {
			c.Semantic.Vector.TopK = 100
			c.Semantic.Vector.HNSW.EfSearch = 64
		}, false},
		{"unknown backend", func(c *CacheConfig) { c.Semantic.Vector.Backend = "ivf" }, false},
		{"flat backend ignores hnsw params", func(c *CacheConfig) {
			c.Semantic.Vector.Backend = "flat"
			c.Semantic.Vector.HNSW.M = 1
		}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := DefaultConfig()
			tc.mut(&cfg)
			errs := cfg.Validate()
			got := len(errs) == 0
			if got != tc.valid {
				t.Fatalf("valid=%v，期望 %v，errs=%v", got, tc.valid, errs)
			}
		})
	}
}
