package a2aregistry

// P2-2 T-5 可观测：A2A 注册中心控制面指标（§6.5）。
//
// 与 gateway-core / tee-infer 同构：标准库手写 Prometheus 文本格式（零外部依赖）。
//
// 指标族：
//
//	a2a_agent_registry_size{status}      注册 Agent 数（按生命周期状态：active/deleted）
//	a2a_registry_revision                注册表全局 revision（Gauge，始终输出）
//	a2a_signature_failures_total{reason} 验签失败计数（按原因）
//
// 大小与 revision 为**抓取时从存储实时统计**（避免进程内计数漂移/重启丢值）；
// 验签失败为事件计数，进程内累计（与既有 counter 语义一致）。

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// SignatureFailureReason 是验签失败原因（a2a_signature_failures_total.reason）。
const (
	SigFailSignatureInvalid = "signature_invalid"
	SigFailNoKey            = "no_key"
	SigFailParseError       = "parse_error"
	SigFailUnknownKey       = "unknown_key"
	SigFailMalformedCard    = "malformed_card"
)

// Metrics 保存注册中心的**事件类**指标（线程安全）。
// 大小类指标在抓取时由 RenderMetrics 从存储统计。
type Metrics struct {
	mu      sync.Mutex
	sigFail map[string]int64 // reason → count
}

func newMetrics() *Metrics {
	return &Metrics{sigFail: map[string]int64{}}
}

// ObserveSignatureFailure 递增验签失败计数（reason 见 SigFail* 常量）。
func (m *Metrics) ObserveSignatureFailure(reason string) {
	if reason == "" {
		reason = SigFailSignatureInvalid
	}
	m.mu.Lock()
	m.sigFail[reason]++
	m.mu.Unlock()
}

// Metrics 返回该注册中心的指标集合（始终非 nil）。
func (r *Registry) Metrics() *Metrics {
	return r.metrics
}

// RenderMetrics 输出 Prometheus 文本格式。
//
// 存储不可用时大小/revision 输出 0（观测降级），事件计数照常输出——
// 观测降级不得使拉取失败。
func (r *Registry) RenderMetrics(w io.Writer) {
	size, rev := map[string]int64{}, int64(0)
	if s, v, ok := r.countRegistry(); ok {
		size, rev = s, v
	}

	fmt.Fprintf(w, "# HELP a2a_agent_registry_size 注册 Agent 数（按生命周期状态）\n# TYPE a2a_agent_registry_size gauge\n")
	for _, k := range sortedMetricKeys(size) {
		fmt.Fprintf(w, "a2a_agent_registry_size{status=%q} %d\n", k, size[k])
	}

	fmt.Fprintf(w, "# HELP a2a_registry_revision 注册表全局 revision\n# TYPE a2a_registry_revision gauge\n")
	fmt.Fprintf(w, "a2a_registry_revision %d\n", rev)

	r.metrics.mu.Lock()
	defer r.metrics.mu.Unlock()
	fmt.Fprintf(w, "# HELP a2a_signature_failures_total AgentCard 验签失败计数（按原因）\n# TYPE a2a_signature_failures_total counter\n")
	for _, k := range sortedMetricKeys(r.metrics.sigFail) {
		fmt.Fprintf(w, "a2a_signature_failures_total{reason=%q} %d\n", k, r.metrics.sigFail[k])
	}
}

// countRegistry 统计 Agent 生命周期分布与全局 revision，返回是否统计成功。
func (r *Registry) countRegistry() (map[string]int64, int64, bool) {
	if r == nil || r.store == nil || r.degraded {
		return nil, 0, false
	}
	out := map[string]int64{}
	rows, err := r.store.db.Query(`SELECT status, COUNT(*) FROM a2a_agents GROUP BY status`)
	if err != nil {
		return nil, 0, false
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var st string
		var n int64
		if err := rows.Scan(&st, &n); err != nil {
			return nil, 0, false
		}
		out[st] = n
	}
	if err := rows.Err(); err != nil {
		return nil, 0, false
	}
	var rev int64
	// 全局 revision：取表内最大值；空表则为 0（不伪造 >0 的「已初始化」）。
	if err := r.store.db.QueryRow(`SELECT COALESCE(MAX(registry_revision), 0) FROM a2a_agents`).Scan(&rev); err != nil {
		return nil, 0, false
	}
	return out, rev, true
}

// sortedKeys 返回 map 键的稳定升序切片（Prometheus 输出需确定序）。
func sortedMetricKeys(m map[string]int64) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
