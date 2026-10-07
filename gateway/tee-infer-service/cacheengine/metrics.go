package cacheengine

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// RenderPrometheus 以 Prometheus 文本格式输出缓存指标。
// 指标命名前缀：otpmask_cache_，对齐设计文档 §9.1 的指标登记表。
func (e *engine) RenderPrometheus(w io.Writer) {
	s := e.Stats()

	// #1 lookups_total（查询计数，按层级 kind 与结果 result）
	writeCacheCounter(w, "otpmask_cache_lookups_total",
		"缓存查询计数（每个请求在实际到达的每一层各计一次；kind=precheck|exact|negative|semantic；result=hit|miss|disabled|not_cacheable|fastcheck_miss）",
		s.Lookups, []string{"kind", "result"})

	// #2 lookup_duration_seconds（histogram，按 kind）
	e.renderLookupDuration(w)

	// #11 jitter_seconds（histogram，按 path=hit|miss；§7.3）
	e.renderJitter(w)

	// #5 write_rejected_total{reason}（§6.3.2 写入被拒）
	writeCacheCounter(w, "otpmask_cache_write_rejected_total",
		"缓存写入被拒次数（按原因：too_large|too_short|not_stop|not_writable|not_cacheable|would_reject）",
		e.stats.writeRejectedSnapshot(), []string{"reason"})

	// #6 write_throttled_total{tenant}（§7.4.2 写入限流丢弃）。
	// 注：tenant 可能含 ":"，故不走 writeCacheCounter 的 ":" 分隔拼接，改为直接渲染。
	if tw := e.stats.writeThrottledSnapshot(); len(tw) > 0 {
		fmt.Fprintf(w, "# HELP otpmask_cache_write_throttled_total 缓存写入被限流丢弃次数（按租户；§7.4.2）\n# TYPE otpmask_cache_write_throttled_total counter\n")
		tenants := make([]string, 0, len(tw))
		for k := range tw {
			tenants = append(tenants, k)
		}
		sort.Strings(tenants)
		for _, t := range tenants {
			fmt.Fprintf(w, "otpmask_cache_write_throttled_total{tenant=%q} %d\n", t, tw[t])
		}
	}

	// #9 read_fast_check_error_total（快审分类器不可用，fail-closed）
	fmt.Fprintf(w, "# HELP otpmask_cache_read_fast_check_error_total 读时快审分类器不可用次数（fail-closed）\n# TYPE otpmask_cache_read_fast_check_error_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_read_fast_check_error_total %d\n", e.stats.fastCheckErrorCount())

	// #10 read_fast_check_duration_seconds（histogram）
	e.renderExtraDuration(w, "read_fast_check",
		"otpmask_cache_read_fast_check_duration_seconds", "读时快审耗时（秒）")

	// #21 stream_degraded_total{reason}（§6.12 流式分片降级为单块）
	writeCacheCounter(w, "otpmask_cache_stream_degraded_total",
		"流式分片缓存降级为单块次数（reason=too_many_segments|too_large|disabled）",
		e.stats.streamDegradedC.snapshot(), []string{"reason"})

	// #33 scene_total{scene,source}（§6.5.2）
	writeCacheCounter(w, "otpmask_cache_scene_total",
		"场景分类计数（scene=factual|general|code|math；source=rule|hint）",
		e.stats.sceneC.snapshot(), []string{"scene", "source"})

	// #34 fingerprint_reject_total{scene}（§6.5.2 实体指纹不相容）
	writeCacheCounter(w, "otpmask_cache_fingerprint_reject_total",
		"实体指纹不相容拒绝次数（按场景）",
		e.stats.fingerprintRejC.snapshot(), []string{"scene"})

	// #38 negative_store_total{result}（§6.4.2 负向缓存写入）
	writeCacheCounter(w, "otpmask_cache_negative_store_total",
		"负向缓存写入次数（result=ok|stage_excluded）",
		e.stats.negativeStoreC.snapshot(), []string{"result"})

	// #18 warmup_items_total{result}（§6.7 预热条目；result=ok|fail）
	writeCacheCounter(w, "otpmask_cache_warmup_items_total",
		"预热条目计数（result=ok|fail；§6.7）",
		e.stats.warmupItemsC.snapshot(), []string{"result"})

	// #17 embed_invalid_total{reason}（embedding 无效）
	writeCacheCounter(w, "otpmask_cache_embed_invalid_total",
		"embedding 无效次数（reason=empty|bad_response）",
		e.stats.embedInvalidC.snapshot(), []string{"reason"})

	// #19 redis_errors_total{op}（形态 B/C Redis 操作错误）
	writeCacheCounter(w, "otpmask_cache_redis_errors_total",
		"Redis 操作错误次数（op=get|put|delete|delete_by_tenant|delete_by_model|publish|subscribe）",
		e.stats.redisErrC.snapshot(), []string{"op"})

	// #28 embedder_errors_total{reason}
	writeCacheCounter(w, "otpmask_cache_embedder_errors_total",
		"embedding 侧车错误次数（reason=unreachable|timeout|bad_response）",
		e.stats.embedderErrC.snapshot(), []string{"reason"})

	// #29 embed_timeout_total
	fmt.Fprintf(w, "# HELP otpmask_cache_embed_timeout_total embedding 侧车超时次数\n# TYPE otpmask_cache_embed_timeout_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_embed_timeout_total %d\n", e.stats.embedTimeoutCount())

	// #30 embedder_dim_mismatch_total
	fmt.Fprintf(w, "# HELP otpmask_cache_embedder_dim_mismatch_total 向量维度不匹配次数\n# TYPE otpmask_cache_embedder_dim_mismatch_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_embedder_dim_mismatch_total %d\n", e.stats.embedDimMismatchCount())

	// #31 vector_errors_total{op}
	writeCacheCounter(w, "otpmask_cache_vector_errors_total",
		"向量索引操作错误次数（op=upsert|search|delete）",
		e.stats.vectorErrC.snapshot(), []string{"op"})

	// #32 vector_capacity_ratio（gauge；向量条目数 / flat_max_entries）
	if e.sem != nil && e.cfg.Semantic.Vector.FlatMaxEntries > 0 {
		ratio := float64(e.sem.Size()) / float64(e.cfg.Semantic.Vector.FlatMaxEntries)
		fmt.Fprintf(w, "# HELP otpmask_cache_vector_capacity_ratio 向量容量占用率（条目数/上限）\n# TYPE otpmask_cache_vector_capacity_ratio gauge\n")
		fmt.Fprintf(w, "otpmask_cache_vector_capacity_ratio %g\n", ratio)
	}

	// #37 semantic_reject_total{reason}
	writeCacheCounter(w, "otpmask_cache_semantic_reject_total",
		"语义候选被拒次数（reason=threshold|fingerprint）",
		e.stats.semanticRejC.snapshot(), []string{"reason"})

	// #39 embed_duration_seconds（histogram）
	e.renderExtraDuration(w, "embed", "otpmask_cache_embed_duration_seconds", "embedding 侧车调用耗时（秒）")

	// #22 replay_total{mode,result}
	writeCacheCounter(w, "otpmask_cache_replay_total",
		"命中回放次数（mode=single|segmented|degraded_single；result=ok|error|canceled）",
		e.stats.replayC.snapshot(), []string{"mode", "result"})

	// #23 singleflight_total{result}
	writeCacheCounter(w, "otpmask_cache_singleflight_total",
		"请求合并次数（result=leader|shared|timeout|fallback）",
		e.stats.singleflightC.snapshot(), []string{"result"})

	// #35 entry_corrupt_total{reason}
	writeCacheCounter(w, "otpmask_cache_entry_corrupt_total",
		"条目损坏次数（reason=integrity_mismatch|segments_mismatch）",
		e.stats.entryCorruptC.snapshot(), []string{"reason"})

	// #16 audit_fail_total（§7.5 B-7.5-1：审计链写入失败，不阻塞缓存写入）
	fmt.Fprintf(w, "# HELP otpmask_cache_audit_fail_total 审计链写入失败次数（B-7.5-1；不阻塞缓存写入）\n# TYPE otpmask_cache_audit_fail_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_audit_fail_total %d\n", e.stats.auditFailCount())

	// #3 entries{store}
	fmt.Fprintf(w, "# HELP otpmask_cache_entries 当前缓存条目数（按 store）\n# TYPE otpmask_cache_entries gauge\n")
	fmt.Fprintf(w, "otpmask_cache_entries{store=\"exact\"} %d\n", s.ExactEntries)
	fmt.Fprintf(w, "otpmask_cache_entries{store=\"negative\"} %d\n", s.NegativeEntries)
	fmt.Fprintf(w, "otpmask_cache_entries{store=\"vector\"} %d\n", s.VectorEntries)

	// #4 evictions_total{store,reason}
	fmt.Fprintf(w, "# HELP otpmask_cache_evictions_total 缓存淘汰总次数（按 store 与原因）\n# TYPE otpmask_cache_evictions_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_evictions_total{store=\"exact\",reason=\"lru\"} %d\n", s.Evictions)

	// #12 panic_total（缓存模块 panic 被 recover）
	fmt.Fprintf(w, "# HELP otpmask_cache_panic_total 缓存模块 panic 被 recover 的次数\n# TYPE otpmask_cache_panic_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_panic_total %d\n", e.stats.panicCount())

	// #13 slow_lookup_total{kind}（B-6.11-3）
	writeCacheCounter(w, "otpmask_cache_slow_lookup_total",
		"查询耗时超观测阈值的次数（仅观测，不中断；B-6.11-3）",
		e.stats.slowLookupSnapshot(), []string{"kind"})

	// #24 estimated_bytes / #25 readonly（§6.9）
	fmt.Fprintf(w, "# HELP otpmask_cache_estimated_bytes 估算内存占用（字节；§5.6）\n# TYPE otpmask_cache_estimated_bytes gauge\n")
	fmt.Fprintf(w, "otpmask_cache_estimated_bytes %d\n", e.estBytes.Load())
	ro := 0
	if e.readOnly.Load() {
		ro = 1
	}
	fmt.Fprintf(w, "# HELP otpmask_cache_readonly 只读态 0/1（高水位；§6.9.2）\n# TYPE otpmask_cache_readonly gauge\n")
	fmt.Fprintf(w, "otpmask_cache_readonly %d\n", ro)

	// #26 disabled_total{reason} / #27 clock_skew_total（§6.9）
	writeCacheCounter(w, "otpmask_cache_disabled_total",
		"缓存写入被整体拒绝的次数（按原因；§6.9）",
		e.stats.disabledSnapshot(), []string{"reason"})
	fmt.Fprintf(w, "# HELP otpmask_cache_clock_skew_total 时钟回拨检测次数（§6.9.1）\n# TYPE otpmask_cache_clock_skew_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_clock_skew_total %d\n", e.stats.clockSkewCount())

	// #8 读时快审阻断计数
	fmt.Fprintf(w, "# HELP otpmask_cache_read_fast_check_block_total 读时快审阻断次数（命中但被 L1 快审拦下）\n# TYPE otpmask_cache_read_fast_check_block_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_read_fast_check_block_total %d\n", s.FastCheckBlocks)

	// #7 语义误命中反馈计数（二期）
	fmt.Fprintf(w, "# HELP otpmask_cache_semantic_false_positive_total 语义缓存误命中反馈次数（二期）\n# TYPE otpmask_cache_semantic_false_positive_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_semantic_false_positive_total %d\n", s.SemanticFP)

	// #14 节省 token 数（估算，观测口径，非计费依据）
	fmt.Fprintf(w, "# HELP otpmask_cache_saved_tokens_total 缓存命中节省的上游输入 token 数（估算，命中即节省）\n# TYPE otpmask_cache_saved_tokens_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_saved_tokens_total %d\n", s.SavedTokens)

	// 运行模式（本地观测 gauge）
	if s.Mode != "" {
		fmt.Fprintf(w, "# HELP otpmask_cache_mode 当前缓存运行模式（1=当前模式；off|exact|semantic|full）\n# TYPE otpmask_cache_mode gauge\n")
		fmt.Fprintf(w, "otpmask_cache_mode{mode=%q} 1\n", s.Mode)
	}
}

// renderLookupDuration 输出按 kind 分组的查询耗时直方图。
func (e *engine) renderLookupDuration(w io.Writer) {
	type hsnap struct {
		buckets []float64
		counts  []uint64
		sum     float64
		total   uint64
	}

	e.stats.durMu.Lock()
	snaps := make(map[string]hsnap, len(e.stats.durs))
	for k, h := range e.stats.durs {
		h.mu.Lock()
		b := make([]float64, len(h.buckets))
		copy(b, h.buckets)
		c := make([]uint64, len(h.counts))
		copy(c, h.counts)
		snaps[k] = hsnap{buckets: b, counts: c, sum: h.sum, total: h.total}
		h.mu.Unlock()
	}
	e.stats.durMu.Unlock()

	if len(snaps) == 0 {
		return
	}

	fmt.Fprintf(w, "# HELP otpmask_cache_lookup_duration_seconds 缓存查询耗时（秒，按 kind）\n# TYPE otpmask_cache_lookup_duration_seconds histogram\n")
	kinds := make([]string, 0, len(snaps))
	for k := range snaps {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	for _, k := range kinds {
		s := snaps[k]
		for i, b := range s.buckets {
			fmt.Fprintf(w, "otpmask_cache_lookup_duration_seconds_bucket{kind=%q,le=%q} %d\n",
				k, strconv.FormatFloat(b, 'g', -1, 64), s.counts[i])
		}
		fmt.Fprintf(w, "otpmask_cache_lookup_duration_seconds_bucket{kind=%q,le=\"+Inf\"} %d\n", k, s.total)
		fmt.Fprintf(w, "otpmask_cache_lookup_duration_seconds_sum{kind=%q} %g\n", k, s.sum)
		fmt.Fprintf(w, "otpmask_cache_lookup_duration_seconds_count{kind=%q} %d\n", k, s.total)
	}
}

// renderJitter 输出抖动注入量直方图（§9.1 #11，按 path 分组：hit|miss）。
func (e *engine) renderJitter(w io.Writer) {
	type hsnap struct {
		buckets []float64
		counts  []uint64
		sum     float64
		total   uint64
	}

	snaps := make(map[string]hsnap, 2)
	for k, h := range e.stats.jitterSnapshot() {
		h.mu.Lock()
		b := make([]float64, len(h.buckets))
		copy(b, h.buckets)
		c := make([]uint64, len(h.counts))
		copy(c, h.counts)
		snaps[k] = hsnap{buckets: b, counts: c, sum: h.sum, total: h.total}
		h.mu.Unlock()
	}
	if len(snaps) == 0 {
		return
	}

	fmt.Fprintf(w, "# HELP otpmask_cache_jitter_seconds 抖动注入量（秒，按 path=hit|miss）\n# TYPE otpmask_cache_jitter_seconds histogram\n")
	paths := make([]string, 0, len(snaps))
	for k := range snaps {
		paths = append(paths, k)
	}
	sort.Strings(paths)
	for _, k := range paths {
		s := snaps[k]
		for i, b := range s.buckets {
			fmt.Fprintf(w, "otpmask_cache_jitter_seconds_bucket{path=%q,le=%q} %d\n",
				k, strconv.FormatFloat(b, 'g', -1, 64), s.counts[i])
		}
		fmt.Fprintf(w, "otpmask_cache_jitter_seconds_bucket{path=%q,le=\"+Inf\"} %d\n", k, s.total)
		fmt.Fprintf(w, "otpmask_cache_jitter_seconds_sum{path=%q} %g\n", k, s.sum)
		fmt.Fprintf(w, "otpmask_cache_jitter_seconds_count{path=%q} %d\n", k, s.total)
	}
}

// renderExtraDuration 渲染附加耗时直方图（§9.1 #10 快审 / #39 embed）；无样本时不输出。
func (e *engine) renderExtraDuration(w io.Writer, key, metric, help string) {
	h := e.stats.extraDurSnapshot()[key]
	if h == nil {
		return
	}
	h.mu.Lock()
	b := append([]float64(nil), h.buckets...)
	c := append([]uint64(nil), h.counts...)
	sum, total := h.sum, h.total
	h.mu.Unlock()

	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s histogram\n", metric, help, metric)
	for i, bv := range b {
		fmt.Fprintf(w, "%s_bucket{le=%q} %d\n", metric, strconv.FormatFloat(bv, 'g', -1, 64), c[i])
	}
	fmt.Fprintf(w, "%s_bucket{le=\"+Inf\"} %d\n", metric, total)
	fmt.Fprintf(w, "%s_sum %g\n", metric, sum)
	fmt.Fprintf(w, "%s_count %d\n", metric, total)
}

// writeCacheCounter 输出 counter 类型指标（仿 metrics.go writeCounter 风格）。
// data 的 key = label1|label2|...，按标签字典序排序输出。
func writeCacheCounter(w io.Writer, name, help string, data map[string]uint64, labelNames []string) {
	if len(data) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s counter\n", name, help, name)

	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for _, k := range keys {
		labels := strings.Split(k, ":") // Lookups 的 key 是 kind:result
		labelStr := ""
		for i, ln := range labelNames {
			if i < len(labels) {
				if i > 0 {
					labelStr += ","
				}
				labelStr += fmt.Sprintf("%s=%q", ln, labels[i])
			}
		}
		if labelStr != "" {
			fmt.Fprintf(w, "%s{%s} %d\n", name, labelStr, data[k])
		} else {
			fmt.Fprintf(w, "%s %d\n", name, data[k])
		}
	}
}
