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
