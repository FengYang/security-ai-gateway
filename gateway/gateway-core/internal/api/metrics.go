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
//	gateway_core_route_ttft_report_total{result}      TTFT 上报处理结果（ok/reject/duplicate；M3.8）
//	gateway_core_route_ttft_samples_total{tenant,model,endpoint,cache}  累计落片样本数（M3.8）
//	gateway_core_route_ttft_reset_total               TTFT 统计重置次数（M3.8，始终输出）
//	gateway_core_route_ttft_last_update_seconds{...}  TTFT 条目最近落片时间（gauge，抓取时计算；M3.8）
//	gateway_core_route_ttft_p50_ms{...} / _p95_ms{...}  TTFT 窗口分位（gauge，抓取时计算；M3.8）
package api

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"

	"security-ai-gateway/gateway/gateway-core/internal/route"
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
	reportResult map[string]int64 // P1-6 M3.4：TTFT 上报处理结果（ok/reject/duplicate；渲染 M3.8）
	ttftResets   int64            // P1-6 M3.6：TTFT 统计重置次数（渲染 M3.8）
	ttftSamples  map[string]int64 // P1-6 M3.8：tenant|model|endpoint|cache → 累计落片样本数
}

func newCoreMetrics() *coreMetrics {
	return &coreMetrics{
		rules:        make(map[string]int64),
		changes:      make(map[string]int64),
		teeApplied:   make(map[string]int64),
		pullReject:   make(map[string]int64),
		reportResult: make(map[string]int64),
		ttftSamples:  make(map[string]int64),
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

// incTTFTReset 记录 TTFT 统计重置次数（§6.5 gateway_core_route_ttft_reset_total）。
func (m *coreMetrics) incTTFTReset() {
	m.mu.Lock()
	m.ttftResets++
	m.mu.Unlock()
}

// incTTFTSamples 累计落片样本数（§6.5 gateway_core_route_ttft_samples_total；仅 TTFTIngestOK 落片调用）。
func (m *coreMetrics) incTTFTSamples(tenant, model, endpoint, cache string, n uint64) {
	if n == 0 {
		return
	}
	key := tenant + "|" + model + "|" + endpoint + "|" + cache
	m.mu.Lock()
	m.ttftSamples[key] += int64(n)
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
	// ---- P1-6 M3.8：TTFT 控制面指标（§6.5；环形刻盘三族见 Server.renderTTFTGauges）----
	writeCoreCounter(w, "gateway_core_route_ttft_report_total", "TTFT 上报处理结果计数（ok/reject/duplicate）", m.reportResult, []string{"result"}, "counter")
	writeCoreCounter(w, "gateway_core_route_ttft_samples_total", "TTFT 累计落片样本数", m.ttftSamples, []string{"tenant", "model", "endpoint", "cache"}, "counter")
	fmt.Fprintf(w, "# HELP gateway_core_route_ttft_reset_total TTFT 统计重置次数\n# TYPE gateway_core_route_ttft_reset_total counter\n")
	fmt.Fprintf(w, "gateway_core_route_ttft_reset_total %d\n", m.ttftResets)
	fmt.Fprintf(w, "# HELP gateway_core_policy_audit_events 策略变更审计链长度\n# TYPE gateway_core_policy_audit_events gauge\n")
	fmt.Fprintf(w, "gateway_core_policy_audit_events %d\n", m.auditEvents)
}

// renderTTFTGauges 渲染 TTFT 环形刻盘指标（§6.5；抓取时从聚合环实时计算）。
// 三族 Gauge：last_update_seconds / p50_ms / p95_ms；键空间 = 环内全部聚合键（稳定序）。
// 注：last_update/p50/p95 为「当前窗口」视图（Gauge 语义）；累计样本数走 Counter（samples_total）。
func (s *Server) renderTTFTGauges(w io.Writer) {
	keys := s.ttftRing.Keys("", "")
	if len(keys) == 0 {
		return
	}
	type ttftSnap struct {
		k      route.TTFTKey
		p50    int64
		p95    int64
		update int64
	}
	snaps := make([]ttftSnap, 0, len(keys))
	for _, k := range keys {
		wnd, ok := s.ttftRing.Merge(k)
		if !ok {
			continue
		}
		p50, _ := wnd.Quantile(0.5)
		p95, _ := wnd.Quantile(0.95)
		snaps = append(snaps, ttftSnap{k: k, p50: p50, p95: p95, update: wnd.UpdatedAt})
	}
	if len(snaps) == 0 {
		return
	}
	fmt.Fprintf(w, "# HELP gateway_core_route_ttft_last_update_seconds TTFT 聚合条目最近落片时间（Unix 秒）\n# TYPE gateway_core_route_ttft_last_update_seconds gauge\n")
	for _, sn := range snaps {
		fmt.Fprintf(w, "gateway_core_route_ttft_last_update_seconds{%s} %d\n", ttftLabelPairs(sn.k), sn.update)
	}
	fmt.Fprintf(w, "# HELP gateway_core_route_ttft_p50_ms TTFT 窗口分位 p50（毫秒）\n# TYPE gateway_core_route_ttft_p50_ms gauge\n")
	for _, sn := range snaps {
		fmt.Fprintf(w, "gateway_core_route_ttft_p50_ms{%s} %d\n", ttftLabelPairs(sn.k), sn.p50)
	}
	fmt.Fprintf(w, "# HELP gateway_core_route_ttft_p95_ms TTFT 窗口分位 p95（毫秒）\n# TYPE gateway_core_route_ttft_p95_ms gauge\n")
	for _, sn := range snaps {
		fmt.Fprintf(w, "gateway_core_route_ttft_p95_ms{%s} %d\n", ttftLabelPairs(sn.k), sn.p95)
	}
}

// ttftLabelPairs 生成 TTFT 键标签片段（固定序 tenant/model/endpoint/cache）。
func ttftLabelPairs(k route.TTFTKey) string {
	return fmt.Sprintf("tenant=%q,model=%q,endpoint=%q,cache=%q", k.Tenant, k.Model, k.Endpoint, k.Cache)
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
	// P1-6 M3.8：TTFT 环形刻盘（抓取时实时计算；不经 coreMetrics 存储）
	s.renderTTFTGauges(w)
}
