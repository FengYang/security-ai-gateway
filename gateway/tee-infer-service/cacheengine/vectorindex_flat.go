package cacheengine

import (
	"fmt"
	"math"
	"sync"
	"sync/atomic"
)

// VectorIndex 向量索引接口（§4.1.2）。
// 实现：flat（进程内暴力检索）/ hnsw（进程内图索引）/ redis-vss（Redis VSS）。
// 所有实现均须保证：Search 返回相似度降序的前 topK 个候选。
type VectorIndex interface {
	Upsert(id string, vec []float32, meta VectorMeta) error
	Search(vec []float32, topK int, filter VectorFilter) ([]VectorHit, error)
	Delete(id string) error
	Size() int
	Backend() string // flat | hnsw | redis-vss
}

// ===== FLAT 实现（进程内暴力检索，形态 A/B 默认） =====

// flatIndex 进程内 FLAT 索引（暴力检索，O(N·d)）。
// 向量归一化后用内积近似余弦相似度。
type flatIndex struct {
	mu           sync.RWMutex
	dim          int
	ids          []string
	vecs         [][]float32 // L2 归一化后的向量
	metas        []VectorMeta
	idx          map[string]int // entry_id -> 下标（O(1) 删除，swap-remove）
	flatMax      int
	nowFn        nowFunc
	totalUpserts uint64
}

// NewFlatVectorIndex 构造 FLAT 向量索引。
func NewFlatVectorIndex(dim, maxEntries int) VectorIndex {
	if dim <= 0 {
		dim = 512
	}
	if maxEntries <= 0 {
		maxEntries = 50000
	}
	return &flatIndex{
		dim:     dim,
		ids:     make([]string, 0, maxEntries),
		vecs:    make([][]float32, 0, maxEntries),
		metas:   make([]VectorMeta, 0, maxEntries),
		idx:     make(map[string]int, maxEntries),
		flatMax: maxEntries,
		nowFn:   defaultNow,
	}
}

func (f *flatIndex) Backend() string { return "flat" }

// Upsert 插入或更新向量。
func (f *flatIndex) Upsert(id string, vec []float32, meta VectorMeta) error {
	if len(vec) != f.dim {
		return fmt.Errorf("vector dim mismatch: got %d, expected %d", len(vec), f.dim)
	}

	// L2 归一化
	norm := float32(0)
	for _, v := range vec {
		norm += v * v
	}
	if norm > 0 {
		norm = float32(math.Sqrt(float64(norm)))
		normalized := make([]float32, f.dim)
		for i, v := range vec {
			normalized[i] = v / norm
		}
		vec = normalized
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	// 已存在 → 更新
	if i, ok := f.idx[id]; ok {
		f.vecs[i] = vec
		f.metas[i] = meta
		return nil
	}

	// 容量检查（超过上限返回错误——调用方决定告警/降级）
	if len(f.ids) >= f.flatMax {
		return fmt.Errorf("flat index at capacity: %d", f.flatMax)
	}

	f.ids = append(f.ids, id)
	f.vecs = append(f.vecs, vec)
	f.metas = append(f.metas, meta)
	f.idx[id] = len(f.ids) - 1
	atomic.AddUint64(&f.totalUpserts, 1)
	return nil
}

// Search 查询 topK 个最相似的向量（相似度降序）。
func (f *flatIndex) Search(query []float32, topK int, filter VectorFilter) ([]VectorHit, error) {
	if len(query) != f.dim {
		return nil, fmt.Errorf("query dim mismatch: got %d, expected %d", len(query), f.dim)
	}
	if topK <= 0 {
		topK = 5
	}

	// 归一化查询向量
	norm := float32(0)
	for _, v := range query {
		norm += v * v
	}
	var qvec []float32
	if norm > 0 {
		norm = float32(math.Sqrt(float64(norm)))
		qvec = make([]float32, f.dim)
		for i, v := range query {
			qvec[i] = v / norm
		}
	} else {
		qvec = query
	}

	now := f.nowFn().UnixMilli()

	f.mu.RLock()
	defer f.mu.RUnlock()

	// 收集 topK（选择排序方式，不做完整排序）
	type candidate struct {
		idx int
		sim float64
	}
	result := make([]VectorHit, 0, topK)

	for i := 0; i < len(f.ids); i++ {
		meta := f.metas[i]

		// 硬过滤：租户/引擎/模型/策略版本/词库版本
		if filter.TenantID != "" && meta.TenantID != filter.TenantID {
			continue
		}
		if filter.EngineType != "" && meta.EngineType != filter.EngineType {
			continue
		}
		if filter.Model != "" && meta.Model != filter.Model {
			continue
		}
		if filter.PolicyVer != "" && meta.PolicyVer != filter.PolicyVer {
			continue
		}
		if filter.GuardVer != "" && meta.GuardVer != filter.GuardVer {
			continue
		}

		// 过期过滤
		if meta.ExpireAt > 0 && now >= meta.ExpireAt {
			continue
		}

		// 计算余弦相似度（内积，因为已归一化）
		dot := float64(0)
		vec := f.vecs[i]
		for j := 0; j < f.dim; j++ {
			dot += float64(qvec[j] * vec[j])
		}

		hit := VectorHit{
			EntryID:    f.ids[i],
			Similarity: dot,
			Meta:       meta,
		}

		// 插入 topK
		if len(result) < topK {
			result = append(result, hit)
			for j := len(result) - 1; j > 0 && result[j].Similarity > result[j-1].Similarity; j-- {
				result[j], result[j-1] = result[j-1], result[j]
			}
		} else if dot > result[len(result)-1].Similarity {
			result[len(result)-1] = hit
			for j := len(result) - 1; j > 0 && result[j].Similarity > result[j-1].Similarity; j-- {
				result[j], result[j-1] = result[j-1], result[j]
			}
		}
	}

	if result == nil {
		result = []VectorHit{}
	}
	return result, nil
}

// Delete 删除指定 ID 的向量（swap-remove，O(1)）。
func (f *flatIndex) Delete(id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	i, ok := f.idx[id]
	if !ok {
		return nil
	}

	last := len(f.ids) - 1
	if i != last {
		f.ids[i] = f.ids[last]
		f.vecs[i] = f.vecs[last]
		f.metas[i] = f.metas[last]
		f.idx[f.ids[last]] = i
	}

	f.ids = f.ids[:last]
	f.vecs = f.vecs[:last]
	f.metas = f.metas[:last]
	delete(f.idx, id)
	return nil
}

// Size 当前条目数。
func (f *flatIndex) Size() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return len(f.ids)
}
