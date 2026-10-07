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

// jitterBuckets 抖动注入量直方图桶（秒），覆盖 §7.3 默认 max_ms=20ms 量级。
var jitterBuckets = []float64{
	0.0005, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1,
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

	// 运行状态观测（§6.9）
	disabledMu  sync.Mutex
	disabled    map[string]uint64 // reason -> count（§9.1 #26）
	clockSkew   uint64            // 时钟回拨次数（§9.1 #27）

	// 抖动注入量直方图（§9.1 #11）：path(hit|miss) -> histogram
	jitterMu sync.Mutex
	jitters  map[string]*durationHistogram

	// 写入被拒（§9.1 #5）：reason -> count
	writeRejMu    sync.Mutex
	writeRejected map[string]uint64

	// 写入限流（§9.1 #6）：tenant -> count（基数受控）
	writeThrottledMu sync.Mutex
	writeThrottled   map[string]uint64

	// 附加耗时直方图（§9.1 #10 快审 / #39 embed 等）：shortName -> histogram
	extraDurMu sync.Mutex
	extraDur   map[string]*durationHistogram

	// 带标签计数（§9.1 #21 流式降级 / #33 场景 / #34 指纹拒绝 / #38 负向写入）
	streamDegradedC labelCounter // key: reason
	sceneC          labelCounter // key: scene|source
	fingerprintRejC labelCounter // key: scene
	negativeStoreC  labelCounter // key: result

	// 带标签计数（§9.1 #17 embed 无效 / #19 Redis 错误 / #28 embedder 错误 / #31 向量错误 / #37 语义拒绝）
	embedInvalidC labelCounter // key: reason
	embedderErrC  labelCounter // key: reason
	vectorErrC    labelCounter // key: op
	semanticRejC  labelCounter // key: reason
	redisErrC     labelCounter // key: op

	// 无标签计数（§9.1 #29 embed 超时 / #30 维度不匹配 / #16 审计写入失败）
	embedTimeout     uint64
	embedDimMismatch uint64
	auditFail        uint64

	// 带标签计数（§9.1 #22 回放 / #23 请求合并 / #35 条目损坏）
	replayC        labelCounter // key: mode|result
	singleflightC  labelCounter // key: result
	entryCorruptC  labelCounter // key: reason
}

// labelCounter 带标签计数（key 为标签按序以 ":" 拼接，与 metrics.writeCacheCounter 约定一致），可选枚举校验。
type labelCounter struct {
	mu    sync.Mutex
	m     map[string]uint64
	valid map[string]struct{} // nil = 不校验
}

func (c *labelCounter) inc(key string) {
	if c.valid != nil {
		if _, ok := c.valid[key]; !ok {
			panic(fmt.Sprintf("cacheengine: invalid metric label %q", key))
		}
	}
	c.mu.Lock()
	if c.m == nil {
		c.m = make(map[string]uint64)
	}
	c.m[key]++
	c.mu.Unlock()
}

func (c *labelCounter) snapshot() map[string]uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]uint64, len(c.m))
	for k, v := range c.m {
		out[k] = v
	}
	return out
}

// 枚举集合（§9.1 #21/#38）。
var (
	validStreamDegradedReasons = map[string]struct{}{
		"too_many_segments": {}, "too_large": {}, "disabled": {},
	}
	validNegativeStoreResults = map[string]struct{}{"ok": {}, "stage_excluded": {}}
	validScenes               = map[string]struct{}{
		"factual": {}, "general": {}, "code": {}, "math": {},
	}
	validEmbedInvalidReasons  = map[string]struct{}{"empty": {}, "bad_response": {}}
	validEmbedderErrReasons   = map[string]struct{}{"unreachable": {}, "timeout": {}, "bad_response": {}}
	validVectorOps            = map[string]struct{}{"upsert": {}, "search": {}, "delete": {}}
	validSemanticRejectReason = map[string]struct{}{"threshold": {}, "fingerprint": {}}
	validRedisOps             = map[string]struct{}{
		"get": {}, "put": {}, "delete": {}, "delete_by_tenant": {},
		"delete_by_model": {}, "publish": {}, "subscribe": {},
	}
	validSingleflightResults = map[string]struct{}{
		"leader": {}, "shared": {}, "timeout": {}, "fallback": {},
	}
	validEntryCorruptReasons = map[string]struct{}{
		"integrity_mismatch": {}, "segments_mismatch": {},
	}
	validReplayKeys = map[string]struct{}{} // 由 init 填充（mode×result 组合）
)

func init() {
	for _, m := range []string{"single", "segmented", "degraded_single"} {
		for _, r := range []string{"ok", "error", "canceled"} {
			validReplayKeys[m+":"+r] = struct{}{}
		}
	}
}

// validWriteRejectedReasons §9.1 #5 写入被拒 reason 枚举（发射时硬校验）。
var validWriteRejectedReasons = map[string]struct{}{
	"too_large": {}, "too_short": {}, "not_stop": {},
	"not_writable": {}, "not_cacheable": {}, "would_reject": {},
}

func newStatsCollector() *statsCollector {
	return &statsCollector{
		lookups:         make(map[string]map[string]uint64),
		durs:            make(map[string]*durationHistogram),
		slowLookups:     make(map[string]uint64),
		disabled:        make(map[string]uint64),
		jitters:         make(map[string]*durationHistogram),
		writeRejected:   make(map[string]uint64),
		extraDur:        make(map[string]*durationHistogram),
		streamDegradedC: labelCounter{valid: validStreamDegradedReasons},
		fingerprintRejC: labelCounter{valid: validScenes},
		negativeStoreC:  labelCounter{valid: validNegativeStoreResults},
		embedInvalidC:   labelCounter{valid: validEmbedInvalidReasons},
		embedderErrC:    labelCounter{valid: validEmbedderErrReasons},
		vectorErrC:      labelCounter{valid: validVectorOps},
		semanticRejC:    labelCounter{valid: validSemanticRejectReason},
		redisErrC:       labelCounter{valid: validRedisOps},
		replayC:         labelCounter{valid: validReplayKeys},
		singleflightC:   labelCounter{valid: validSingleflightResults},
		entryCorruptC:   labelCounter{valid: validEntryCorruptReasons},
	}
}

// observeReplay 记录命中回放（§9.1 #22）。
func (s *statsCollector) observeReplay(mode, result string) { s.replayC.inc(mode + ":" + result) }

// observeSingleflight 记录请求合并结果（§9.1 #23）。
func (s *statsCollector) observeSingleflight(result string) { s.singleflightC.inc(result) }

// observeEntryCorrupt 记录条目损坏（§9.1 #35）。
func (s *statsCollector) observeEntryCorrupt(reason string) { s.entryCorruptC.inc(reason) }

// observeEmbedInvalid 记录 embedding 无效（§9.1 #17）。
func (s *statsCollector) observeEmbedInvalid(reason string) { s.embedInvalidC.inc(reason) }

// observeEmbedderError 记录 embedding 侧车错误（§9.1 #28）。
func (s *statsCollector) observeEmbedderError(reason string) { s.embedderErrC.inc(reason) }

// observeEmbedTimeout 记录 embedding 超时（§9.1 #29）。
func (s *statsCollector) observeEmbedTimeout() { atomic.AddUint64(&s.embedTimeout, 1) }

// embedTimeoutCount 读取 embedding 超时累计（§9.1 #29）。
func (s *statsCollector) embedTimeoutCount() uint64 { return atomic.LoadUint64(&s.embedTimeout) }

// observeEmbedDimMismatch 记录向量维度不匹配（§9.1 #30）。
func (s *statsCollector) observeEmbedDimMismatch() { atomic.AddUint64(&s.embedDimMismatch, 1) }

// embedDimMismatchCount 读取维度不匹配累计（§9.1 #30）。
func (s *statsCollector) embedDimMismatchCount() uint64 {
	return atomic.LoadUint64(&s.embedDimMismatch)
}

// observeAuditFailure 记录审计链写入失败（§9.1 #16 / B-7.5-1）。
func (s *statsCollector) observeAuditFailure() { atomic.AddUint64(&s.auditFail, 1) }

// auditFailCount 读取审计写入失败累计（§9.1 #16）。
func (s *statsCollector) auditFailCount() uint64 { return atomic.LoadUint64(&s.auditFail) }

// observeVectorError 记录向量索引操作错误（§9.1 #31）。
func (s *statsCollector) observeVectorError(op string) { s.vectorErrC.inc(op) }

// observeSemanticReject 记录语义候选被拒（§9.1 #37；reason=threshold|fingerprint）。
func (s *statsCollector) observeSemanticReject(reason string) { s.semanticRejC.inc(reason) }

// observeRedisError 记录 Redis 操作错误（§9.1 #19）。
func (s *statsCollector) observeRedisError(op string) { s.redisErrC.inc(op) }

// observeStreamDegraded 记录流式分片缓存降级（§9.1 #21）。
func (s *statsCollector) observeStreamDegraded(reason string) { s.streamDegradedC.inc(reason) }

// observeScene 记录场景分类计数（§9.1 #33；key=scene:source）。
func (s *statsCollector) observeScene(scene, source string) { s.sceneC.inc(scene + ":" + source) }

// observeFingerprintReject 记录实体指纹不相容拒绝（§9.1 #34）。
func (s *statsCollector) observeFingerprintReject(scene string) { s.fingerprintRejC.inc(scene) }

// observeNegativeStore 记录负向缓存写入结果（§9.1 #38）。
func (s *statsCollector) observeNegativeStore(result string) { s.negativeStoreC.inc(result) }

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

// observeJitter 记录一次抖动注入量（§9.1 #11；path∈{hit,miss}）。
// 非法 path 兜底为 miss（避免污染契约）。
func (s *statsCollector) observeJitter(path string, d time.Duration) {
	if path != "hit" && path != "miss" {
		path = "miss"
	}
	s.jitterMu.Lock()
	h := s.jitters[path]
	if h == nil {
		h = newDurationHistogram(jitterBuckets)
		s.jitters[path] = h
	}
	s.jitterMu.Unlock()
	h.observe(d)
}

// jitterSnapshot 返回各 path 直方图的只读快照（供渲染，避免持锁）。
func (s *statsCollector) jitterSnapshot() map[string]*durationHistogram {
	s.jitterMu.Lock()
	defer s.jitterMu.Unlock()
	out := make(map[string]*durationHistogram, len(s.jitters))
	for k, v := range s.jitters {
		out[k] = v
	}
	return out
}

// observeWriteRejected 记录一次写入被拒（§9.1 #5）。非法 reason 即 panic（枚举硬约束）。
func (s *statsCollector) observeWriteRejected(reason string) {
	if _, ok := validWriteRejectedReasons[reason]; !ok {
		panic(fmt.Sprintf("cacheengine: invalid write_rejected reason=%q", reason))
	}
	s.writeRejMu.Lock()
	s.writeRejected[reason]++
	s.writeRejMu.Unlock()
}

// writeRejectedSnapshot 返回写入被拒计数的只读快照。
func (s *statsCollector) writeRejectedSnapshot() map[string]uint64 {
	s.writeRejMu.Lock()
	defer s.writeRejMu.Unlock()
	out := make(map[string]uint64, len(s.writeRejected))
	for k, v := range s.writeRejected {
		out[k] = v
	}
	return out
}

// writeThrottledMaxTenants 写入限流指标的租户基数上限（§9.1 基数控制）。
const writeThrottledMaxTenants = 1024

// observeWriteThrottled 记录一次写入被限流丢弃（§9.1 #6，按 tenant）。
// 基数控制：最多保留 writeThrottledMaxTenants 个租户，超出并入 "__other__"。
func (s *statsCollector) observeWriteThrottled(tenant string) {
	s.writeThrottledMu.Lock()
	if s.writeThrottled == nil {
		s.writeThrottled = make(map[string]uint64)
	}
	if _, ok := s.writeThrottled[tenant]; !ok && len(s.writeThrottled) >= writeThrottledMaxTenants {
		tenant = "__other__"
	}
	s.writeThrottled[tenant]++
	s.writeThrottledMu.Unlock()
}

// writeThrottledSnapshot 返回写入限流计数的只读快照（供指标渲染）。
func (s *statsCollector) writeThrottledSnapshot() map[string]uint64 {
	s.writeThrottledMu.Lock()
	defer s.writeThrottledMu.Unlock()
	out := make(map[string]uint64, len(s.writeThrottled))
	for k, v := range s.writeThrottled {
		out[k] = v
	}
	return out
}

// fastCheckErrorCount 读时快审分类器不可用累计次数（§9.1 #9）。
func (s *statsCollector) fastCheckErrorCount() uint64 {
	return atomic.LoadUint64(&s.fastCheckErrors)
}

// observeExtraDuration 记录附加耗时直方图（§9.1 #10 快审 / #39 embed）；
// name 为指标短名（如 "read_fast_check" / "embed"）。
func (s *statsCollector) observeExtraDuration(name string, d time.Duration) {
	s.extraDurMu.Lock()
	h := s.extraDur[name]
	if h == nil {
		h = newDurationHistogram(lookupDurationBuckets)
		s.extraDur[name] = h
	}
	s.extraDurMu.Unlock()
	h.observe(d)
}

// extraDurSnapshot 返回附加耗时直方图快照。
func (s *statsCollector) extraDurSnapshot() map[string]*durationHistogram {
	s.extraDurMu.Lock()
	defer s.extraDurMu.Unlock()
	out := make(map[string]*durationHistogram, len(s.extraDur))
	for k, v := range s.extraDur {
		out[k] = v
	}
	return out
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

// observeDisabled 记录一次"因整体关闭/只读被拒"（§9.1 #26 disabled_total{reason}）。
func (s *statsCollector) observeDisabled(reason string) {
	s.disabledMu.Lock()
	s.disabled[reason]++
	s.disabledMu.Unlock()
}

// disabledSnapshot 返回 disabled_total 快照（供指标渲染）。
func (s *statsCollector) disabledSnapshot() map[string]uint64 {
	s.disabledMu.Lock()
	defer s.disabledMu.Unlock()
	out := make(map[string]uint64, len(s.disabled))
	for k, v := range s.disabled {
		out[k] = v
	}
	return out
}

// observeClockSkew 记录一次时钟回拨（§9.1 #27）。
func (s *statsCollector) observeClockSkew() {
	atomic.AddUint64(&s.clockSkew, 1)
}

// clockSkewCount 读取时钟回拨计数。
func (s *statsCollector) clockSkewCount() uint64 {
	return atomic.LoadUint64(&s.clockSkew)
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
