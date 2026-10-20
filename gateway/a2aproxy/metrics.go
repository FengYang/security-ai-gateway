package a2aproxy

// P2-2 T-5 可观测：A2A 数据面指标（§6.5）。
//
// 采用与 gateway-core / tee-infer 同构的写法：标准库手写 Prometheus 文本格式（零外部依赖），
// 指标名与标签与生产 prometheus/client_golang 方案保持一致，后续替换时无需改动仪表板
// （见 gateway/gateway-core/internal/api/metrics.go 首部说明）。
//
// 契约口径：
//
//	a2a_tasks_total{tenant,agent,skill,state}              观测到的 Task 状态事件计数
//	a2a_task_duration_seconds{agent}                       终态耗时直方图（秒）
//	a2a_authz_denies_total{agent,reason}                   ACL 拒绝计数（含未知 skill）
//	a2a_rate_limit_decisions_total{scope,decision}         限流决策计数
//
// 约束：不新增采集组件（T-5）；仅在本进程内聚合并由 /metrics 暴露给既有抓取链路。
// 实施约束（R-2）：所有标签均为**元数据**，不含任何正文/密钥材料。

import (
	"fmt"
	"io"
	"math"
	"sort"
	"sync"
	"time"
)

// taskDurationBuckets 是耗时直方图上界（秒）；与 Gatewaycore 侧手写直方图保持同族取值。
var taskDurationBuckets = []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120}

// RateLimitScope 是限流命中的键范围（供 a2a_rate_limit_decisions_total.scope）。
const (
	// RateLimitScopeExact 命中 tenant|agent|skill 精确键。
	RateLimitScopeExact = "tenant_agent_skill"
	// RateLimitScopeWildcard 未命中精确键，回退 tenant|agent|* 通配键。
	RateLimitScopeWildcard = "tenant_agent"
	// RateLimitScopeNone 无匹配规则（缺省不限流）。
	RateLimitScopeNone = "none"
	// RateLimitScopeUnknown 限流器未上报作用域（未实现 RateLimitScopeObserver）。
	RateLimitScopeUnknown = "unknown"
)

// RateLimitScopeObserver 是**可选**接口：由限流器提供本次决策命中的键范围（T-5）。
//
// 采用可选接口而非扩展 Governance 签名的理由：限流程式触达面广，改动既有签名会波及
// 全部实现者；未实现的 Governance 按 RateLimitScopeUnknown 计，不阻断也不误报。
type RateLimitScopeObserver interface {
	// LastRateLimitScope 返回最近一次 Allow 调用命中的键范围。
	LastRateLimitScope() string
}

// A2AMetrics 是 A2A 数据面指标集合（线程安全）。
//
// 语义说明：
//   - a2a_tasks_total 按「观测到的状态事件」计数（含同一 Task 的多次 working 观测），
//     与去重后的审计记录数不等价——此处统计的是**数据面观测行为**，去重语义由
//     TaskAuditStore 负责（T-3b）。
//   - a2a_task_duration_seconds 仅在**终态且起点已知**时落样本（F-6 D-F6-5/SM-9/SM-10：
//     起点未知则留空，不伪造耗时）。
type A2AMetrics struct {
	mu        sync.Mutex
	tasks     map[string]int64 // tenant|agent|skill|state
	authz     map[string]int64 // agent|reason
	rlDec     map[string]int64 // scope|decision
	histCount map[string]int64 // agent → count
	histSum   map[string]float64
	histBuck  map[string][]int64   // agent → 按 bucket 下标累计
	starts    map[string]time.Time // tenant|agent|task_id → 首次观测时间（终态后清除）
}

// NewA2AMetrics 构造空的指标集合。
func NewA2AMetrics() *A2AMetrics {
	return &A2AMetrics{
		tasks:     map[string]int64{},
		authz:     map[string]int64{},
		rlDec:     map[string]int64{},
		histCount: map[string]int64{},
		histSum:   map[string]float64{},
		histBuck:  map[string][]int64{},
		starts:    map[string]time.Time{},
	}
}

// ObserveTaskState 递增 Task 状态观测计数。
func (m *A2AMetrics) ObserveTaskState(tenant, agent, skill, state string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tasks[tenant+"|"+agent+"|"+skill+"|"+state]++
}

// ObserveAuthzDeny 递增 ACL 拒绝计数。
func (m *A2AMetrics) ObserveAuthzDeny(agent, reason string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.authz[agent+"|"+reason]++
}

// ObserveRateLimit 递增限流决策计数。
func (m *A2AMetrics) ObserveRateLimit(scope, decision string) {
	if scope == "" {
		scope = RateLimitScopeUnknown
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rlDec[scope+"|"+decision]++
}

// TrackTaskStart 标记一个任务的观测起点（首次观测时调用，重复调用不覆盖）。
func (m *A2AMetrics) TrackTaskStart(tenant, agent, taskID string, at time.Time) {
	if taskID == "" {
		return
	}
	key := tenant + "|" + agent + "|" + taskID
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.starts[key]; ok {
		return
	}
	m.starts[key] = at
}

// ObserveTerminalTask 在终态时结算耗时：起点已知则落一个直方图样本并返回
// (durationMs, true)；起点未知（如网关重启后首见即终态）返回 (0, false)，不伪造耗时
// （F-6 D-F6-5/SM-9/SM-10）。
func (m *A2AMetrics) ObserveTerminalTask(tenant, agent, taskID string, at time.Time) (int64, bool) {
	if taskID == "" {
		return 0, false
	}
	key := tenant + "|" + agent + "|" + taskID
	m.mu.Lock()
	defer m.mu.Unlock()
	start, ok := m.starts[key]
	if !ok {
		return 0, false
	}
	delete(m.starts, key)
	sec := at.Sub(start).Seconds()
	if sec < 0 || math.IsNaN(sec) || math.IsInf(sec, 0) {
		return 0, false
	}
	m.histCount[agent]++
	m.histSum[agent] += sec
	buckets := m.histBuck[agent]
	if buckets == nil {
		buckets = make([]int64, len(taskDurationBuckets))
		m.histBuck[agent] = buckets
	}
	for i, le := range taskDurationBuckets {
		if sec <= le {
			buckets[i]++
		}
	}
	return int64(sec * 1000), true
}

// monotonicity note：starts 在终态时删除；若任务永不见终态，条目随进程存活。
// MVP 以任务数有界为假设，逐出门禁需补 evict 策略（见交付评审「后续建议」）。

// Render 输出 Prometheus 文本格式到 w。
func (m *A2AMetrics) Render(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	writeA2ACounter(w, "a2a_tasks_total", "观测到的 A2A Task 状态事件计数（含重复状态观测）",
		m.tasks, []string{"tenant", "agent", "skill", "state"}, "counter")
	writeA2ACounter(w, "a2a_authz_denies_total", "A2A 授权拒绝计数（含未知 skill）",
		m.authz, []string{"agent", "reason"}, "counter")
	writeA2ACounter(w, "a2a_rate_limit_decisions_total", "A2A 限流决策计数",
		m.rlDec, []string{"scope", "decision"}, "counter")
	m.renderDuration(w)
}

// renderDuration 输出耗时直方图三件套（_bucket / _sum / _count）。
func (m *A2AMetrics) renderDuration(w io.Writer) {
	if len(m.histCount) == 0 {
		return
	}
	name := "a2a_task_duration_seconds"
	fmt.Fprintf(w, "# HELP %s A2A Task 终态耗时（秒；仅起点已知时落样本）\n# TYPE %s histogram\n", name, name)
	agents := make([]string, 0, len(m.histCount))
	for a := range m.histCount {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	for _, a := range agents {
		buckets := m.histBuck[a]
		cum := int64(0)
		for i, le := range taskDurationBuckets {
			cum += buckets[i]
			fmt.Fprintf(w, "%s_bucket{agent=%q,le=%q} %d\n", name, a, fmtLe(le), cum)
		}
		fmt.Fprintf(w, "%s_bucket{agent=%q,le=\"+Inf\"} %d\n", name, a, m.histCount[a])
		fmt.Fprintf(w, "%s_sum{agent=%q} %s\n", name, a, fmtFloat(m.histSum[a]))
		fmt.Fprintf(w, "%s_count{agent=%q} %d\n", name, a, m.histCount[a])
	}
}

// fmtLe 输出 le 标签值（避免科学计数法；与 Prometheus 文本约定一致）。
func fmtLe(v float64) string {
	return fmtFloat(v)
}

// fmtFloat 输出浮点，去掉无意义尾零（Go %v 对 1 输出 1，对 0.05 输出 0.05）。
func fmtFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%g", v)
}

// writeA2ACounter 输出一个计数/计量族（labels 决定维度，键以 | 分隔）。
func writeA2ACounter(w io.Writer, name, help string, data map[string]int64, labels []string, typ string) {
	if len(data) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(w, "%s{%s} %d\n", name, a2aLabelPairs(labels, splitA2AKey(k)), data[k])
	}
}

// splitA2AKey "a|b|c" → [a b c]。
func splitA2AKey(k string) []string {
	out := []string{}
	cur := ""
	for i := 0; i < len(k); i++ {
		if k[i] == '|' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(k[i])
	}
	return append(out, cur)
}

// a2aLabelPairs 生成 `l1="v1",l2="v2"` 片段。
func a2aLabelPairs(labels, values []string) string {
	if len(labels) != len(values) {
		return ""
	}
	out := ""
	for i, l := range labels {
		if i > 0 {
			out += ","
		}
		out += fmt.Sprintf("%s=%q", l, values[i])
	}
	return out
}
