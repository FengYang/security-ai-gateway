package cacheengine

import (
	"fmt"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
)

// ===== HNSW 向量索引（进程内分层图，§4.1.2 / §8.2 / §4.2）=====
//
// 设计要点：
//   - 多层图：L0 含全量节点，上层稀疏；插入层级 ℓ = floor(-ln(U) / ln(M))；
//   - 检索：自顶层贪心下降 → L0 以 ef_search 候选池取 topK（相似度降序）；
//     硬过滤（租户/引擎/模型/策略/守卫/安全级/过期）在遍历中生效——过滤节点不参与结果但仍可穿越以保连通；
//   - 删除：墓碑标记 + 邻接摘除（幂等）；Size() 返回存活数；
//   - 容量：达到 max_entries 且墓碑占比 ≥ 50% 时自动重建压实，否则返回错误（避免长跑静默耗尽）；
//   - 并发：RWMutex（写独占 / 读共享）；层级采样使用固定种子 RNG（可注入）以便复现。
//
// 局限（登记）：ANN 近似检索可能漏召；漏召仅导致缓存 miss（非错误命中），召回率以单测对照 flat 量化。
type hnswIndex struct {
	mu  sync.RWMutex
	dim int
	max int

	m     int
	mmax  int // 上层每节点最大出边
	mmax0 int // L0 每节点最大出边
	efC   int
	efS   int
	ml    float64

	nowFn nowFunc

	ids     []string
	vecs    [][]float32 // L2 归一化后向量
	metas   []VectorMeta
	deleted []bool
	levels  []int
	adj     [][][]int32 // adj[node][layer] = 邻居节点下标

	idx      map[string]int
	entry    int
	maxLevel int
	delCount int

	totalUpserts uint64

	rngMu sync.Mutex
	rng   *rand.Rand
}

// NewHNSWVectorIndex 构造 HNSW 索引（生产路径，固定种子）。
func NewHNSWVectorIndex(dim, maxEntries, m, efConstruction, efSearch int) VectorIndex {
	return newHNSWVectorIndex(dim, maxEntries, m, efConstruction, efSearch, 1)
}

// newHNSWVectorIndex 构造 HNSW 索引（seed 可注入，便于单测复现）。
func newHNSWVectorIndex(dim, maxEntries, m, efConstruction, efSearch int, seed int64) *hnswIndex {
	if dim <= 0 {
		dim = 512
	}
	if maxEntries <= 0 {
		maxEntries = 50000
	}
	if m < 4 {
		m = 16
	}
	if efConstruction < 16 {
		efConstruction = 200
	}
	if efSearch < 4 {
		efSearch = 64
	}
	return &hnswIndex{
		dim:    dim,
		max:    maxEntries,
		m:      m,
		mmax:   m,
		mmax0:  2 * m,
		efC:    efConstruction,
		efS:    efSearch,
		ml:     1.0 / math.Log(float64(m)),
		nowFn:  defaultNow,
		idx:    make(map[string]int),
		entry:  -1,
		rng:    rand.New(rand.NewSource(seed)),
	}
}

func (h *hnswIndex) Backend() string { return "hnsw" }

// Size 存活条目数（不含墓碑）。
func (h *hnswIndex) Size() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.ids) - h.delCount
}

// Upsert 插入或更新向量。
func (h *hnswIndex) Upsert(id string, vec []float32, meta VectorMeta) error {
	if len(vec) != h.dim {
		return fmt.Errorf("vector dim mismatch: got %d, expected %d", len(vec), h.dim)
	}
	n := normalizeVec(vec, h.dim)

	h.mu.Lock()
	defer h.mu.Unlock()

	if i, ok := h.idx[id]; ok {
		if h.deleted[i] {
			h.deleted[i] = false
			h.delCount--
		}
		h.vecs[i] = n
		h.metas[i] = meta
		return nil
	}
	return h.insertLocked(id, n, meta)
}

// insertLocked 插入新节点（调用方须持写锁）。
func (h *hnswIndex) insertLocked(id string, vec []float32, meta VectorMeta) error {
	if len(h.ids) >= h.max {
		if h.delCount*2 >= len(h.ids) {
			h.rebuildLocked() // 墓碑过半 → 压实重建
		} else {
			return fmt.Errorf("hnsw: capacity reached (%d entries)", h.max)
		}
	}

	level := h.randomLevel()
	ni := len(h.ids)
	h.ids = append(h.ids, id)
	h.vecs = append(h.vecs, vec)
	h.metas = append(h.metas, meta)
	h.deleted = append(h.deleted, false)
	h.levels = append(h.levels, level)
	row := make([][]int32, level+1)
	for l := range row {
		row[l] = make([]int32, 0, h.mmaxFor(l))
	}
	h.adj = append(h.adj, row)
	h.idx[id] = ni
	atomic.AddUint64(&h.totalUpserts, 1)

	if h.entry < 0 {
		h.entry = ni
		h.maxLevel = level
		return nil
	}

	now := h.nowFn().UnixMilli()
	ep := h.entry
	for lc := h.maxLevel; lc > level; lc-- {
		ep = h.greedyLocked(vec, ep, lc)
	}
	for lc := imin(level, h.maxLevel); lc >= 0; lc-- {
		cands := h.searchLayerLocked(vec, []int{ep}, h.efC, lc, VectorFilter{}, now)
		nbrs := pickNeighbors(cands, h.m, ni)
		for _, nb := range nbrs {
			h.linkLocked(ni, nb, lc)
			h.linkLocked(int(nb), int32(ni), lc)
		}
		if len(cands) > 0 {
			ep = cands[0].idx
		}
	}
	if level > h.maxLevel {
		h.maxLevel = level
		h.entry = ni
	}
	return nil
}

// Search 查询 topK 个最相似向量（相似度降序）。
func (h *hnswIndex) Search(query []float32, topK int, filter VectorFilter) ([]VectorHit, error) {
	if len(query) != h.dim {
		return nil, fmt.Errorf("query dim mismatch: got %d, expected %d", len(query), h.dim)
	}
	if topK <= 0 {
		topK = 5
	}
	q := normalizeVec(query, h.dim)

	h.mu.RLock()
	defer h.mu.RUnlock()

	result := []VectorHit{}
	if h.entry < 0 {
		return result, nil
	}

	now := h.nowFn().UnixMilli()
	ep := h.entry
	for lc := h.maxLevel; lc > 0; lc-- {
		ep = h.greedyLocked(q, ep, lc)
	}

	ef := h.efS
	if ef < 4*topK {
		ef = 4 * topK
	}
	cands := h.searchLayerLocked(q, []int{ep}, ef, 0, filter, now)

	n := imin(topK, len(cands))
	for i := 0; i < n; i++ {
		c := cands[i]
		result = append(result, VectorHit{EntryID: h.ids[c.idx], Similarity: c.sim, Meta: h.metas[c.idx]})
	}
	return result, nil
}

// Delete 删除指定 ID（墓碑 + 邻接摘除，幂等）。
func (h *hnswIndex) Delete(id string) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	i, ok := h.idx[id]
	if !ok {
		return nil
	}
	delete(h.idx, id)
	if h.deleted[i] {
		return nil
	}
	h.deleted[i] = true
	h.delCount++

	for lc, nbrs := range h.adj[i] {
		for _, nb := range nbrs {
			h.removeLinkLocked(int(nb), int32(i), lc)
		}
	}
	return nil
}

// ===== 内部：图操作（调用方须持锁） =====

type hnswCand struct {
	idx int
	sim float64
}

// simNode 节点与查询的余弦相似度（均已归一化，等价内积）。
func (h *hnswIndex) simNode(q []float32, i int) float64 {
	dot := float64(0)
	v := h.vecs[i]
	for j := 0; j < h.dim; j++ {
		dot += float64(q[j] * v[j])
	}
	return dot
}

// passFilter 硬过滤 + 墓碑 + 过期。
func (h *hnswIndex) passFilter(i int, f VectorFilter, now int64) bool {
	if h.deleted[i] {
		return false
	}
	m := h.metas[i]
	if f.TenantID != "" && m.TenantID != f.TenantID {
		return false
	}
	if f.EngineType != "" && m.EngineType != f.EngineType {
		return false
	}
	if f.Model != "" && m.Model != f.Model {
		return false
	}
	if f.PolicyVer != "" && m.PolicyVer != f.PolicyVer {
		return false
	}
	if f.GuardVer != "" && m.GuardVer != f.GuardVer {
		return false
	}
	if f.SecurityLevel != "" && m.SecurityLevel != f.SecurityLevel {
		return false
	}
	if m.ExpireAt > 0 && now >= m.ExpireAt {
		return false
	}
	return true
}

// greedyLocked 在指定层自 ep 起点贪心下降到局部最近邻。
func (h *hnswIndex) greedyLocked(q []float32, ep int, layer int) int {
	cur := ep
	curSim := h.simNode(q, cur)
	for {
		improved := false
		for _, nb := range h.adj[cur][layer] {
			sim := h.simNode(q, int(nb))
			if sim > curSim {
				cur, curSim, improved = int(nb), sim, true
			}
		}
		if !improved {
			return cur
		}
	}
}

// searchLayerLocked 在指定层做 ef 近邻搜索，返回相似度降序候选（长度 ≤ ef）。
// 过滤：不通过的节点不进入结果，但仍参与遍历以维持连通性。
func (h *hnswIndex) searchLayerLocked(q []float32, entries []int, ef int, layer int, filter VectorFilter, now int64) []hnswCand {
	visited := make(map[int]struct{}, ef*4)
	best := make([]hnswCand, 0, ef)       // 降序，长度 ≤ ef
	frontier := make([]hnswCand, 0, ef*2) // 降序待扩展

	for _, e := range entries {
		if e < 0 || e >= len(h.ids) {
			continue
		}
		if _, ok := visited[e]; ok {
			continue
		}
		visited[e] = struct{}{}
		sim := h.simNode(q, e)
		if h.passFilter(e, filter, now) {
			best = insertDesc(best, hnswCand{e, sim}, ef)
		}
		frontier = insertDesc(frontier, hnswCand{e, sim}, ef*4)
	}

	for len(frontier) > 0 {
		c := frontier[0]
		frontier = frontier[1:]
		if len(best) >= ef && c.sim <= best[len(best)-1].sim {
			break
		}
		for _, nb32 := range h.adj[c.idx][layer] {
			nb := int(nb32)
			if _, ok := visited[nb]; ok {
				continue
			}
			visited[nb] = struct{}{}
			sim := h.simNode(q, nb)
			passes := h.passFilter(nb, filter, now)
			if passes && (len(best) < ef || sim > best[len(best)-1].sim) {
				best = insertDesc(best, hnswCand{nb, sim}, ef)
				frontier = insertDesc(frontier, hnswCand{nb, sim}, ef*4)
			} else if !passes {
				// 过滤节点不参与结果，但继续扩展以保持连通
				frontier = insertDesc(frontier, hnswCand{nb, sim}, ef*4)
			}
		}
	}
	return best
}

// linkLocked 建立 a→b 的边（去重；超 Mmax 时按与 a 的相似度剪枝）。
func (h *hnswIndex) linkLocked(a int, b int32, layer int) {
	if a == int(b) {
		return
	}
	for _, x := range h.adj[a][layer] {
		if x == b {
			return
		}
	}
	h.adj[a][layer] = append(h.adj[a][layer], b)
	mmax := h.mmaxFor(layer)
	if len(h.adj[a][layer]) <= mmax {
		return
	}
	// 剪枝：移除与 a 最不相似的邻居
	worst := 0
	worstSim := math.Inf(1)
	av := h.vecs[a]
	for i, nb := range h.adj[a][layer] {
		sim := dotF32(av, h.vecs[int(nb)], h.dim)
		if sim < worstSim {
			worstSim, worst = sim, i
		}
	}
	h.adj[a][layer] = append(h.adj[a][layer][:worst], h.adj[a][layer][worst+1:]...)
}

// removeLinkLocked 摘除 a→b 的边。
func (h *hnswIndex) removeLinkLocked(a int, b int32, layer int) {
	if a < 0 || a >= len(h.adj) || layer >= len(h.adj[a]) {
		return
	}
	nbrs := h.adj[a][layer]
	for i, x := range nbrs {
		if x == b {
			h.adj[a][layer] = append(nbrs[:i], nbrs[i+1:]...)
			return
		}
	}
}

// mmaxFor 返回该层的最大出边数（L0 = 2M，其余 = M）。
func (h *hnswIndex) mmaxFor(layer int) int {
	if layer == 0 {
		return h.mmax0
	}
	return h.mmax
}

// randomLevel 采样插入层级（固定种子 RNG）。
func (h *hnswIndex) randomLevel() int {
	h.rngMu.Lock()
	u := h.rng.Float64()
	h.rngMu.Unlock()
	if u <= 0 {
		u = 1e-12
	}
	return int(math.Floor(-math.Log(u) * h.ml))
}

// rebuildLocked 压实重建（丢弃墓碑节点）。
func (h *hnswIndex) rebuildLocked() {
	type node struct {
		id   string
		vec  []float32
		meta VectorMeta
	}
	live := make([]node, 0, len(h.ids)-h.delCount)
	for i := range h.ids {
		if !h.deleted[i] {
			live = append(live, node{h.ids[i], h.vecs[i], h.metas[i]})
		}
	}
	h.ids = h.ids[:0]
	h.vecs = h.vecs[:0]
	h.metas = h.metas[:0]
	h.deleted = h.deleted[:0]
	h.levels = h.levels[:0]
	h.adj = h.adj[:0]
	h.idx = make(map[string]int, len(live))
	h.entry = -1
	h.maxLevel = -1
	h.delCount = 0
	for _, n := range live {
		_ = h.insertLocked(n.id, n.vec, n.meta)
	}
}

// ===== 工具 =====

// normalizeVec 返回 L2 归一化副本（零向量原样返回）。
func normalizeVec(vec []float32, dim int) []float32 {
	norm := float32(0)
	for _, v := range vec {
		norm += v * v
	}
	if norm <= 0 {
		return vec
	}
	norm = float32(math.Sqrt(float64(norm)))
	out := make([]float32, dim)
	for i := range out {
		out[i] = vec[i] / norm
	}
	return out
}

func dotF32(a, b []float32, dim int) float64 {
	sum := float64(0)
	for i := 0; i < dim; i++ {
		sum += float64(a[i] * b[i])
	}
	return sum
}

// insertDesc 将 cand 按相似度降序插入（容量上限 cap）。
func insertDesc(list []hnswCand, c hnswCand, capN int) []hnswCand {
	if len(list) >= capN && c.sim <= list[len(list)-1].sim {
		return list
	}
	list = append(list, c)
	for i := len(list) - 1; i > 0 && list[i].sim > list[i-1].sim; i-- {
		list[i], list[i-1] = list[i-1], list[i]
	}
	if len(list) > capN {
		list = list[:capN]
	}
	return list
}

// pickNeighbors 从候选集中选出邻居（排除自身），简单取最近 M 个。
func pickNeighbors(cands []hnswCand, m int, self int) []int32 {
	out := make([]int32, 0, m)
	for _, c := range cands {
		if c.idx == self {
			continue
		}
		out = append(out, int32(c.idx))
		if len(out) >= m {
			break
		}
	}
	return out
}

func imin(a, b int) int {
	if a < b {
		return a
	}
	return b
}
