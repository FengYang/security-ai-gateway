package cacheengine

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

// ===== 指标枚举契约（详设 §9.1 #1） =====
//
// lookups_total{kind,result} 的标签取值必须落在下列枚举内；
// 发射时校验，非法即 panic（与详设 I-8 同类硬约束）。

var validLookupKinds = map[string]struct{}{
	"precheck": {},
	"exact":    {},
	"negative": {},
	"semantic": {},
}

var validLookupResults = map[string]struct{}{
	"hit":            {},
	"miss":           {},
	"disabled":       {},
	"not_cacheable":  {},
	"fastcheck_miss": {},
}

// lookupDurationBuckets 查询耗时直方图桶（秒），覆盖 §8.1 的预算量级。
var lookupDurationBuckets = []float64{
	0.0001, 0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0,
}

// durationHistogram 简易 Prometheus 直方图（固定桶 + sum/count）。
type durationHistogram struct {
	mu      sync.Mutex
	buckets []float64
	counts  []uint64 // 每个桶的累计计数（le 语义）
	sum     float64
	total   uint64
}

func newDurationHistogram(buckets []float64) *durationHistogram {
	return &durationHistogram{
		buckets: buckets,
		counts:  make([]uint64, len(buckets)),
	}
}

// observe 记录一次观测。
func (h *durationHistogram) observe(d time.Duration) {
	sec := d.Seconds()
	h.mu.Lock()
	defer h.mu.Unlock()
	h.sum += sec
	h.total++
	for i, b := range h.buckets {
		if sec <= b {
			h.counts[i]++
		}
	}
}

// statsCollector 指标统计收集器（内存态，用于 Prometheus 导出）。
// 对应设计文档 §9.1 的核心指标。
type statsCollector struct {
	// lookups: kind -> result -> count
	lookupsMu sync.Mutex
	lookups   map[string]map[string]uint64 // kind: result: count

	// 查询耗时直方图：kind -> histogram
	durMu  sync.Mutex
	durs   map[string]*durationHistogram

	fastCheckBlocks    uint64
	fastCheckErrors    uint64
	fastCheckVersion   uint64
	semanticFP         uint64
	savedTokens        int64
	savedCostEst       float64
	storeCount         uint64
	storeNegativeCount uint64
	invalidateAll      uint64
	invalidateCount    uint64
	streamDegraded     uint64
	singleflightTotal  uint64
	panicTotal         uint64

	// 慢查询观测（B-6.11-3）：kind -> count
	slowMu      sync.Mutex
	slowLookups map[string]uint64
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		lookups:     make(map[string]map[string]uint64),
		durs:        make(map[string]*durationHistogram),
		slowLookups: make(map[string]uint64),
	}
}

// observeLookup 记录一次查询结果。
// kind ∈ {precheck,exact,negative,semantic}；result ∈ {hit,miss,disabled,not_cacheable,fastcheck_miss}。
// 非法标签即 panic（详设 §9.1 硬约束）。
func (s *statsCollector) observeLookup(kind, result string) {
	if _, ok := validLookupKinds[kind]; !ok {
		panic(fmt.Sprintf("cacheengine: invalid metric label kind=%q (allowed: precheck|exact|negative|semantic)", kind))
	}
	if _, ok := validLookupResults[result]; !ok {
		panic(fmt.Sprintf("cacheengine: invalid metric label result=%q (allowed: hit|miss|disabled|not_cacheable|fastcheck_miss)", result))
	}

	s.lookupsMu.Lock()
	defer s.lookupsMu.Unlock()

	if s.lookups[kind] == nil {
		s.lookups[kind] = make(map[string]uint64)
	}
	s.lookups[kind][result]++
}

// observeLookupDuration 记录某一层的查询耗时（秒）。
func (s *statsCollector) observeLookupDuration(kind string, d time.Duration) {
	if _, ok := validLookupKinds[kind]; !ok {
		kind = "precheck" // 耗时观测的 kind 兜底，避免污染契约
	}
	s.durMu.Lock()
	h := s.durs[kind]
	if h == nil {
		h = newDurationHistogram(lookupDurationBuckets)
		s.durs[kind] = h
	}
	s.durMu.Unlock()
	h.observe(d)
}

// observeStore 记录一次写入。
func (s *statsCollector) observeStore(layer string) {
	atomic.AddUint64(&s.storeCount, 1)
	if layer == "negative" {
		atomic.AddUint64(&s.storeNegativeCount, 1)
	}
}

// observeReadFastCheck 记录读时快审结果。
func (s *statsCollector) observeReadFastCheck(reason string) {
	switch reason {
	case "block":
		atomic.AddUint64(&s.fastCheckBlocks, 1)
	case "error":
		atomic.AddUint64(&s.fastCheckErrors, 1)
	case "version_mismatch":
		atomic.AddUint64(&s.fastCheckVersion, 1)
	}
}

// observeInvalidate 记录失效。
func (s *statsCollector) observeInvalidate(kind string, count int) {
	if kind == "all" {
		atomic.AddUint64(&s.invalidateAll, 1)
	}
	atomic.AddUint64(&s.invalidateCount, uint64(count))
}

// addSavedTokens 累加节省的 token 数。
func (s *statsCollector) addSavedTokens(n int64) {
	atomic.AddInt64(&s.savedTokens, n)
}

// observeFP 记录一次误命中反馈。
func (s *statsCollector) observeFP() {
	atomic.AddUint64(&s.semanticFP, 1)
}

// observePanic 记录一次被 recover 的 panic（§6.11 / §9.1 #12）。
func (s *statsCollector) observePanic() {
	atomic.AddUint64(&s.panicTotal, 1)
}

// panicCount 读取 panic 计数（供指标渲染）。
func (s *statsCollector) panicCount() uint64 {
	return atomic.LoadUint64(&s.panicTotal)
}

// observeSlowLookup 记录一次耗时超阈值的查询（B-6.11-3：仅观测，不中断）。
func (s *statsCollector) observeSlowLookup(kind string) {
	s.slowMu.Lock()
	s.slowLookups[kind]++
	s.slowMu.Unlock()
}

// slowLookupSnapshot 返回慢查询计数快照（供指标渲染）。
func (s *statsCollector) slowLookupSnapshot() map[string]uint64 {
	s.slowMu.Lock()
	defer s.slowMu.Unlock()
	out := make(map[string]uint64, len(s.slowLookups))
	for k, v := range s.slowLookups {
		out[k] = v
	}
	return out
}

// fillSnapshot 填充统计快照。
func (s *statsCollector) fillSnapshot(snap *StatsSnapshot) {
	s.lookupsMu.Lock()
	snap.Lookups = make(map[string]uint64)
	for kind, results := range s.lookups {
		for result, count := range results {
			key := kind + ":" + result
			snap.Lookups[key] = count
		}
	}
	s.lookupsMu.Unlock()

	snap.FastCheckBlocks = atomic.LoadUint64(&s.fastCheckBlocks)
	snap.SemanticFP = atomic.LoadUint64(&s.semanticFP)
	snap.SavedTokens = atomic.LoadInt64(&s.savedTokens)
	snap.SavedCostEst = 0 // 一期不估费
}
