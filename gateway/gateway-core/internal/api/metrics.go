// metrics.go — gateway-core 指标（Phase 1 门禁 #7/#9 控制面部分）。
//
// 与 tee-infer 同构：标准库手写 Prometheus 文本格式（零外部依赖），
// 指标名与生产 prometheus/client_golang 方案保持一致，后续替换时无需改动仪表板。
//
// 指标族：
//
//	gateway_core_ratelimit_table_version              当前生效限流表版本（gauge，始终输出）
//	gateway_core_ratelimit_rules_total{kind,scope,action}  当前表规则数（按维度，表为空则无样本）
//	gateway_core_ratelimit_change_total{result}       策略变更结果计数（applied/rolled_back/rejected）
//	gateway_core_ratelimit_tee_applied_total{result}   TEE 侧配额下发结果（ok/failed/skipped）
//	gateway_core_ratelimit_pull_reject_total{reason}   拉取被拒计数（unauthorized/no_table）
//	gateway_core_policy_audit_events                  策略变更审计链长度（gauge，始终输出）
package api

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
)

// coreMetrics 控制面指标集合（线程安全）。
type coreMetrics struct {
	mu           sync.Mutex
	tableVer     int64
	rules        map[string]int64 // kind|scope|action
	changes      map[string]int64 // result
	teeApplied   map[string]int64 // result
	pullReject   map[string]int64 // reason
	auditEvents  int64
	reportResult map[string]int64 // P1-6 M3.4：TTFT 上报处理结果（ok/reject/duplicate；渲染见 M3.8）
	ttftResets   int64            // P1-6 M3.6：TTFT 统计重置次数（渲染见 M3.8）
}

func newCoreMetrics() *coreMetrics {
	return &coreMetrics{
		rules:        make(map[string]int64),
		changes:      make(map[string]int64),
		teeApplied:   make(map[string]int64),
		pullReject:   make(map[string]int64),
		reportResult: make(map[string]int64),
	}
}

// setTable 记录生效表版本与规则维度分布（每次成功变更后调用）。
func (m *coreMetrics) setTable(version int, rules map[string]int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tableVer = int64(version)
	m.rules = make(map[string]int64, len(rules))
	for k, v := range rules {
		m.rules[k] = int64(v)
	}
}

// incChange 记录变更结果（applied / rolled_back / rejected）。
func (m *coreMetrics) incChange(result string) {
	m.mu.Lock()
	m.changes[result]++
	m.mu.Unlock()
}

// incTeeApplied 记录 TEE 侧配额下发结果（ok / failed / skipped）。
func (m *coreMetrics) incTeeApplied(result string) {
	m.mu.Lock()
	m.teeApplied[result]++
	m.mu.Unlock()
}

// incPullReject 记录拉取被拒（unauthorized / no_table）。
func (m *coreMetrics) incPullReject(reason string) {
	m.mu.Lock()
	m.pullReject[reason]++
	m.mu.Unlock()
}

// incReportResult 记录 TTFT 上报处理结果（ok / reject / duplicate，§6.5）。
func (m *coreMetrics) incReportResult(result string) {
	m.mu.Lock()
	m.reportResult[result]++
	m.mu.Unlock()
}

// incTTFTReset 记录 TTFT 统计重置次数（§6.5 gateway_core_route_ttft_reset_total；渲染见 M3.8）。
func (m *coreMetrics) incTTFTReset() {
	m.mu.Lock()
	m.ttftResets++
	m.mu.Unlock()
}

// setAuditEvents 记录策略变更审计链长度。
func (m *coreMetrics) setAuditEvents(n int) {
	m.mu.Lock()
	m.auditEvents = int64(n)
	m.mu.Unlock()
}

// render 输出 Prometheus 文本格式。
func (m *coreMetrics) render(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(w, "# HELP gateway_core_ratelimit_table_version 当前生效限流表版本\n# TYPE gateway_core_ratelimit_table_version gauge\n")
	fmt.Fprintf(w, "gateway_core_ratelimit_table_version %d\n", m.tableVer)
	writeCoreCounter(w, "gateway_core_ratelimit_rules_total", "当前限流表规则数（按 kind/scope/action）", m.rules, []string{"kind", "scope", "action"}, "gauge")
	writeCoreCounter(w, "gateway_core_ratelimit_change_total", "策略变更结果计数", m.changes, []string{"result"}, "counter")
	writeCoreCounter(w, "gateway_core_ratelimit_tee_applied_total", "TEE 侧配额下发结果计数", m.teeApplied, []string{"result"}, "counter")
	writeCoreCounter(w, "gateway_core_ratelimit_pull_reject_total", "限流表拉取被拒计数", m.pullReject, []string{"reason"}, "counter")
	fmt.Fprintf(w, "# HELP gateway_core_policy_audit_events 策略变更审计链长度\n# TYPE gateway_core_policy_audit_events gauge\n")
	fmt.Fprintf(w, "gateway_core_policy_audit_events %d\n", m.auditEvents)
}

// writeCoreCounter 输出一个指标族（labels 决定标签维度）。
func writeCoreCounter(w io.Writer, name, help string, data map[string]int64, labels []string, typ string) {
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
		fmt.Fprintf(w, "%s{%s} %d\n", name, coreLabelPairs(labels, coreSplitKey(k)), data[k])
	}
}

// coreSplitKey "a|b|c" → [a b c]。
func coreSplitKey(k string) []string {
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

// coreLabelPairs 生成 `label1="v1",label2="v2"` 片段。
func coreLabelPairs(labels, values []string) string {
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

// handleMetrics 暴露控制面指标（内网 token 鉴权，与其余端点一致）。
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	s.metrics.setAuditEvents(s.audit.Len())
	s.metrics.render(w)
}
