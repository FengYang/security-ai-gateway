package route

// ttft.go — P1-6 M3.1：TTFT 分片环形聚合器（§3.4）。
//
// 口径（本体 v1.5 §3.4/§4.1 M3.1）：
//   - 分片窗口 T 固定 25s（R2-08）；N = ceil(window_sec / 25)，N 上限 144（window_sec ≤ 3600）；
//   - 每分片只存「11 桶计数 + shard_start（分片起始秒）」；samples = Σ桶计数（合并时导出）；
//   - **时间驱动淘汰**（TT2-02）：Record/Merge 前先清零 shard_start < now - window_sec 的分片，
//     无流量端点样本随时间自然下滑 → 最终 valid=false（判定在 M3.5 下发层），避免统计粘滞；
//   - 落片按 reported_at（秒）取整：「整批归入 reported_at 所在分片」（跨边界不拆片）；
//   - sync.Mutex（控制面非热路径，M3.1 口径）。
//
// 本文件只负责环形机制；去重/值域钳制/白名单/条目上限属 M3.3，分位插值属 M3.2。

import (
	"math"
	"sync"
	"time"
)

// TTFTBucketCount 桶数量（11 桶；+Inf 为隐式兜底桶，不入数组，§3.4）。
const TTFTBucketCount = 11

// TTFTBucketUpperMs 桶上界（毫秒，逐边界对齐 tee-infer-service/metrics.go 的 ttftBuckets，§3.4）。
var TTFTBucketUpperMs = [TTFTBucketCount]int64{
	10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000,
}

// TTFTShardWindowSec 分片窗口 T（固定 25s；保证 ttft_poll_interval_seconds ≤ T 与
// stale_sec=3×T 的默认口径不随 window_sec 漂移，R2-08）。
const TTFTShardWindowSec = 25

// TTFTDefaultWindowSec 缺省总窗口（300s = 12×25s）。
const TTFTDefaultWindowSec = 300

// TTFTMaxShards N 上限（144，对应 window_sec ≤ 3600；越界配置由 Validate 拦截，
// 本层另做防御性归一化）。
const TTFTMaxShards = 144

// TTFTKey 聚合键（§6.2 上报粒度：tenant×model×endpoint×cache）。
type TTFTKey struct {
	Tenant   string
	Model    string
	Endpoint string
	Cache    string
}

// ttftShard 单分片：桶计数 + 分片起始秒（0 = 空片）。
type ttftShard struct {
	start   int64
	buckets [TTFTBucketCount]uint64
}

// ttftEntry 单键环形（N 个分片）。
type ttftEntry struct {
	windowSec int
	shards    []ttftShard
	updatedAt int64 // 最近落片 reported_at（秒；单调不回退；stale 判定由 M3.5 层使用）
}

// TTFTWindow 窗口合并视图（M3.2 分位插值 / M3.5 下发在其上计算）。
type TTFTWindow struct {
	Buckets   [TTFTBucketCount]uint64
	Samples   uint64
	UpdatedAt int64 // 0 = 从未有样本
}

// TTFTRing 分片环形聚合器（并发安全；时钟可注入以便测试复现）。
type TTFTRing struct {
	mu         sync.Mutex
	now        func() int64
	entries    map[TTFTKey]*ttftEntry
	maxEntries int // 条目数上限（TT2-08；仅约束新增键）
}

// NewTTFTRing 创建聚合器；now 为 nil 时使用 time.Now().Unix()（秒级）；条目上限取缺省。
func NewTTFTRing(now func() int64) *TTFTRing {
	return NewTTFTRingWithLimit(now, TTFTMaxEntries)
}

// NewTTFTRingWithLimit 创建聚合器并指定条目数上限（maxEntries ≤ 0 → 取缺省 10000）。
func NewTTFTRingWithLimit(now func() int64, maxEntries int) *TTFTRing {
	if now == nil {
		now = func() int64 { return time.Now().Unix() }
	}
	if maxEntries <= 0 {
		maxEntries = TTFTMaxEntries
	}
	return &TTFTRing{now: now, entries: make(map[TTFTKey]*ttftEntry), maxEntries: maxEntries}
}

// normalizeWindow 归一化窗口配置：< T（含 0）→ 缺省 300s；> 3600 → 144×25s；
// 返回 (有效 window_sec, N)。对齐 §3.4 参数联动（R2-08）。
func normalizeWindow(windowSec int) (int, int) {
	if windowSec < TTFTShardWindowSec {
		windowSec = TTFTDefaultWindowSec
	} else if windowSec > TTFTShardWindowSec*TTFTMaxShards {
		windowSec = TTFTShardWindowSec * TTFTMaxShards
	}
	n := (windowSec + TTFTShardWindowSec - 1) / TTFTShardWindowSec
	return windowSec, n
}

// evict 时间驱动淘汰：清零 shard_start < now - window_sec 的分片（§3.4；调用方持锁）。
func (e *ttftEntry) evict(now int64) {
	cut := now - int64(e.windowSec)
	for i := range e.shards {
		if e.shards[i].start != 0 && e.shards[i].start < cut {
			e.shards[i] = ttftShard{}
		}
	}
}

// TTFTIngestResult Record 落片结果（M3.3；供 M3.4/M3.8 计数映射）。
type TTFTIngestResult int

const (
	// TTFTIngestOK 正常落片。
	TTFTIngestOK TTFTIngestResult = iota
	// TTFTIngestEntryLimit 条目数达上限，新增键被拒（TT2-08；既有键不受影响）。
	TTFTIngestEntryLimit
	// TTFTIngestInvalid 非法输入（nil 桶 / reported_at ≤ 0，API 层已把关，防御性拒绝）。
	TTFTIngestInvalid
)

// Record 将一批桶计数按 reported_at（秒）落入对应分片（整批归入 reported_at 所在分片）。
// 落片前执行时间驱动淘汰；窗口配置变化 → 重建条目（统计清零，避免新旧窗口混算）。
// 返回落片结果（TTFTIngestOK / TTFTIngestEntryLimit / TTFTIngestInvalid，M3.3）。
func (r *TTFTRing) Record(k TTFTKey, buckets *[TTFTBucketCount]uint64, reportedAt int64, windowSec int) TTFTIngestResult {
	if buckets == nil || reportedAt <= 0 {
		return TTFTIngestInvalid
	}
	windowSec, n := normalizeWindow(windowSec)
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[k]
	if !ok {
		if len(r.entries) >= r.maxEntries {
			return TTFTIngestEntryLimit
		}
		e = &ttftEntry{windowSec: windowSec, shards: make([]ttftShard, n)}
		r.entries[k] = e
	} else if e.windowSec != windowSec {
		e.windowSec = windowSec
		e.shards = make([]ttftShard, n)
		e.updatedAt = 0
	}
	e.evict(r.now())
	idx := (reportedAt / TTFTShardWindowSec) % int64(n)
	if idx < 0 {
		idx += int64(n)
	}
	start := (reportedAt / TTFTShardWindowSec) * TTFTShardWindowSec
	sh := &e.shards[idx]
	if sh.start != start {
		*sh = ttftShard{start: start}
	}
	for i := range buckets {
		sh.buckets[i] += buckets[i]
	}
	if reportedAt > e.updatedAt {
		e.updatedAt = reportedAt
	}
	return TTFTIngestOK
}

// Merge 先执行时间驱动淘汰，再合并键内全部在窗分片（桶求和 + samples + updated_at）。
// 第二个返回值表示键是否存在（含已被淘汰清零的空壳；updAt 仍可读出以支持 stale 判定）。
func (r *TTFTRing) Merge(k TTFTKey) (TTFTWindow, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[k]
	if !ok {
		return TTFTWindow{}, false
	}
	e.evict(r.now())
	var w TTFTWindow
	for i := range e.shards {
		for j := range e.shards[i].buckets {
			w.Buckets[j] += e.shards[i].buckets[j]
		}
	}
	for j := range w.Buckets {
		w.Samples += w.Buckets[j]
	}
	w.UpdatedAt = e.updatedAt
	return w, true
}

// Reset 清空键的全部分片（M3.6 reset 端点复用；返回重置前是否存在条目）。
func (r *TTFTRing) Reset(k TTFTKey) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.entries[k]
	if ok {
		delete(r.entries, k)
	}
	return ok
}

// ============================================================
// M3.2 分位插值（桶内线性；精度=排序一致性口径，§3.4）
// ============================================================

// Quantile 计算窗口桶计数在分位 q（0<q≤1）处的桶内线性插值（毫秒，§3.4）：
//
//	p ≈ le_lo + (le_hi - le_lo) × (q - cum_before) / count_in_bucket
//
// 桶 i 覆盖上界 TTFTBucketUpperMs[i]（le 语义：首桶 le=10）；累积占比首次 ≥ q 的桶内插值。
//
// 精度口径（§3.4，如实）：用于**端点间相对排序**，不承诺绝对精度——同桶内取值不可分辨，
// 相邻桶宽约 2～2.5×，最坏绝对相对误差可达数十 %；排序可分辨性以「两 P95 分属不同桶」为前提。
// 返回 (p_ms, true)；samples==0 或 q 越界 → (0, false)。
func (w TTFTWindow) Quantile(q float64) (int64, bool) {
	if w.Samples == 0 || q <= 0 || q > 1 {
		return 0, false
	}
	target := q * float64(w.Samples)
	var cum float64
	for i := 0; i < TTFTBucketCount; i++ {
		c := float64(w.Buckets[i])
		if c == 0 {
			continue
		}
		if cum+c >= target || i == TTFTBucketCount-1 {
			lo := int64(0)
			if i > 0 {
				lo = TTFTBucketUpperMs[i-1]
			}
			hi := TTFTBucketUpperMs[i]
			inBucket := target - cum
			if inBucket < 0 {
				inBucket = 0 // 浮点防御
			}
			if inBucket > c {
				inBucket = c
			}
			p := float64(lo) + float64(hi-lo)*(inBucket/c)
			return int64(math.Round(p)), true
		}
		cum += c
	}
	return 0, false // 不可达（samples>0 时必命中）
}
