package cacheengine

import (
	"sync"
	"sync/atomic"
)

// statsCollector 指标统计收集器（内存态，用于 Prometheus 导出）。
// 对应设计文档 §9.1 的核心指标。
type statsCollector struct {
	// lookups: kind -> result -> count
	lookupsMu sync.Mutex
	lookups   map[string]map[string]uint64 // kind: result: count

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
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		lookups: make(map[string]map[string]uint64),
	}
}

// observeLookup 记录一次查询结果。
// kind: precheck|exact|negative|semantic
// result: hit|miss|fastcheck_miss|disabled|not_cacheable|...
func (s *statsCollector) observeLookup(kind, result string) {
	s.lookupsMu.Lock()
	defer s.lookupsMu.Unlock()

	if s.lookups[kind] == nil {
		s.lookups[kind] = make(map[string]uint64)
	}
	s.lookups[kind][result]++
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

// fillSnapshot 填充统计快照。
func (s *statsCollector) fillSnapshot(snap *StatsSnapshot) {
	s.lookupsMu.Lock()
	defer s.lookupsMu.Unlock()

	snap.Lookups = make(map[string]uint64)
	for kind, results := range s.lookups {
		for result, count := range results {
			key := kind + ":" + result
			snap.Lookups[key] = count
		}
	}
	snap.FastCheckBlocks = atomic.LoadUint64(&s.fastCheckBlocks)
	snap.SemanticFP = atomic.LoadUint64(&s.semanticFP)
	snap.SavedTokens = atomic.LoadInt64(&s.savedTokens)
	snap.SavedCostEst = 0 // 一期不估费
}
