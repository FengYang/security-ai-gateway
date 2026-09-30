package cacheengine

import (
	"fmt"
	"io"
	"sort"
	"strings"
)

// RenderPrometheus 以 Prometheus 文本格式输出缓存指标。
// 指标命名前缀：otpmask_cache_
// 对应设计文档 §9.1 的核心指标集。
func (e *engine) RenderPrometheus(w io.Writer) {
	s := e.Stats()

	// 1. lookups_total（查询计数，按 kind 和 result）
	writeCacheCounter(w, "otpmask_cache_lookups_total",
		"缓存查询计数（按层级 kind 与结果 result；kind=precheck|exact|negative|semantic；result=hit|miss|fastcheck_miss|disabled|not_cacheable|canary_skip|canary_write_only）",
		s.Lookups, []string{"kind", "result"})

	// 2. 精确缓存条目数（gauge）
	fmt.Fprintf(w, "# HELP otpmask_cache_exact_entries 当前精确缓存条目数\n# TYPE otpmask_cache_exact_entries gauge\n")
	fmt.Fprintf(w, "otpmask_cache_exact_entries %d\n", s.ExactEntries)

	// 3. 负向缓存条目数（gauge）
	fmt.Fprintf(w, "# HELP otpmask_cache_negative_entries 当前负向缓存条目数\n# TYPE otpmask_cache_negative_entries gauge\n")
	fmt.Fprintf(w, "otpmask_cache_negative_entries %d\n", s.NegativeEntries)

	// 4. 向量缓存条目数（gauge，二期）
	fmt.Fprintf(w, "# HELP otpmask_cache_vector_entries 当前向量索引条目数（语义缓存二期）\n# TYPE otpmask_cache_vector_entries gauge\n")
	fmt.Fprintf(w, "otpmask_cache_vector_entries %d\n", s.VectorEntries)

	// 5. LRU 淘汰计数
	fmt.Fprintf(w, "# HELP otpmask_cache_evictions_total 精确缓存 LRU 淘汰总次数\n# TYPE otpmask_cache_evictions_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_evictions_total %d\n", s.Evictions)

	// 6. 读时快审阻断计数
	fmt.Fprintf(w, "# HELP otpmask_cache_read_fast_check_block_total 读时快审阻断次数（命中但被 L1 快审拦下）\n# TYPE otpmask_cache_read_fast_check_block_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_read_fast_check_block_total %d\n", s.FastCheckBlocks)

	// 7. 语义误命中反馈计数（二期）
	fmt.Fprintf(w, "# HELP otpmask_cache_semantic_false_positive_total 语义缓存误命中反馈次数（二期）\n# TYPE otpmask_cache_semantic_false_positive_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_semantic_false_positive_total %d\n", s.SemanticFP)

	// 8. 节省 token 数（估算）
	fmt.Fprintf(w, "# HELP otpmask_cache_saved_tokens_total 缓存命中节省的上游输入 token 数（估算，命中即节省）\n# TYPE otpmask_cache_saved_tokens_total counter\n")
	fmt.Fprintf(w, "otpmask_cache_saved_tokens_total %d\n", s.SavedTokens)

	// 9. 缓存运行模式（gauge）
	if s.Mode != "" {
		fmt.Fprintf(w, "# HELP otpmask_cache_mode 当前缓存运行模式（1=当前模式；off|exact|semantic|full）\n# TYPE otpmask_cache_mode gauge\n")
		fmt.Fprintf(w, "otpmask_cache_mode{mode=%q} 1\n", s.Mode)
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
