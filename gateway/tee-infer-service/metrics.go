// Package main — 可观测性指标。
//
// 用标准库手写 Prometheus 文本格式暴露 /metrics（零外部依赖），
// 指标名与标签与生产 prometheus/client_golang 方案保持一致，
// 后续替换 client_golang 时无需改动仪表板。
//
// 指标族：
// otpmask_inference_requests_total{tenant,result}  推理请求计数（ok/deny 结果）
// otpmask_tokens_in_total{tenant}                  输入 token（向量数）计数
// otpmask_tokens_out_total{tenant}                 输出 token 计数
// otpmask_denies_total{tenant,reason}              拒绝计数（bad_signature/replay/guardrail_* 等）
// otpmask_quota_denies_total{tenant,window}        配额拒绝计数（按触发维度归因：minute|day|total，B 项）
// otpmask_shadow_reports_total{result}             数据面明文影子窗口级上报计数（accepted/deduped/rejected，A 项）
// otpmask_guard_classifier_total{backend,result}   语义分类器调用（ok=侧车判定可用 / degraded=不可用已回退）
// otpmask_key_issue_total{tenant}                  密钥签发计数
// otpmask_reconcile_mismatch_total{reason}         审计-计量对账不一致次数（按差异分类，S5）
// otpmask_shadow_would_reject_total{tenant,rule}   影子命中计数（只计数不拒绝，S5 判据 4）
// otpmask_reconcile_diff_tokens{reason}            对账偏差 token 量级累计（按差异分类，S5）
// otpmask_billing_blocked_total{reason}            对外出账阻断置位次数（按差异分类，S5）
// otpmask_billing_suppressed_total{reason}         被阻断抑制的计费推送事件数（S5）
// otpmask_billing_blocked                          对外出账是否被阻断（gauge 0/1，S5）
// otpmask_reconcile_last_run_timestamp_seconds     最近一次对账时刻（gauge，S5）
// otpmask_audit_events                             审计链当前长度（gauge）
package main

import (
	"fmt"
	"io"
	"sort"
	"sync"
)

// otpmaskMetrics 指标集合（按标签维度 map 累加，线程安全）。
type otpmaskMetrics struct {
	mu              sync.Mutex
	requests        map[string]int64 // tenant|result
	tokensIn        map[string]int64 // tenant
	tokensOut       map[string]int64 // tenant
	denies          map[string]int64 // tenant|reason
	keyIssues       map[string]int64 // tenant
	reconcile       map[string]int64 // reason（对账不一致次数，S5 起按差异分类）
	tokenTraffic    map[string]int64 // tenant
	recomputeOps    map[string]int64 // op（补算调用计数）
	recomputeDur    map[string]int64 // op（补算耗时累计，毫秒）
	guardClassifier map[string]int64 // backend|result（语义分类器调用）
	// S5（判据 6）对账/出账阻断可观测
	reconcileDiff     map[string]int64 // reason（偏差 token 量级累计）
	reconcileLastRun  int64            // gauge：上次对账时刻（UTC 秒）
	billingBlocked    int64            // gauge 0/1：对外出账是否被阻断
	billingBlockCount map[string]int64 // reason（阻断置位次数）
	billingSuppressed map[string]int64 // reason（被阻断抑制的推送事件数）
	// S5（判据 4）：影子 would_reject 计数（tenant|rule）
	shadowWouldReject map[string]int64
	// B 项：配额拒绝按触发维度归因（tenant|window，window=minute|day|total）
	quotaDenies map[string]int64
	// A 项：数据面明文影子窗口级上报计数（result=accepted|deduped|rejected）
	shadowReports map[string]int64
}

func newMetrics() *otpmaskMetrics {
	return &otpmaskMetrics{
		requests:          make(map[string]int64),
		tokensIn:          make(map[string]int64),
		tokensOut:         make(map[string]int64),
		denies:            make(map[string]int64),
		keyIssues:         make(map[string]int64),
		reconcile:         make(map[string]int64),
		tokenTraffic:      make(map[string]int64),
		recomputeOps:      make(map[string]int64),
		recomputeDur:      make(map[string]int64),
		guardClassifier:   make(map[string]int64),
		reconcileDiff:     make(map[string]int64),
		billingBlockCount: make(map[string]int64),
		billingSuppressed: make(map[string]int64),
		shadowWouldReject: make(map[string]int64),
		quotaDenies:       make(map[string]int64),
		shadowReports:     make(map[string]int64),
	}
}

// incShadowWouldReject 记录影子命中（判据 4：只计数不拒绝；rule = rpm|tpm|daily_budget）。
func (m *otpmaskMetrics) incShadowWouldReject(tenant, rule string) {
	m.mu.Lock()
	m.shadowWouldReject[tenant+"|"+rule]++
	m.mu.Unlock()
}

// incGuardClassifier 记录语义分类器调用结果（GF.4.3）。
// result=ok：侧车判定可用；result=degraded：侧车不可用并已回退关键词规则
// （此时语义检出能力回落到关键词水位，须可观测、可告警）。
func (m *otpmaskMetrics) incGuardClassifier(backend, result string) {
	m.mu.Lock()
	m.guardClassifier[backend+"|"+result]++
	m.mu.Unlock()
}

// incReconcileMismatch 记录一次对账不一致（reason = 差异分类）及其偏差量级（token）。
// S5 起该计数器语义为"对账不一致次数"（此前为偏差累加，标签值固定 "mismatch"）。
func (m *otpmaskMetrics) incReconcileMismatch(reason string, diffTokens int64) {
	m.mu.Lock()
	m.reconcile[reason]++
	m.reconcileDiff[reason] += diffTokens
	m.mu.Unlock()
}

// setReconcileRun 记录最近一次对账时刻（UTC 纳秒 → 秒）与出账阻断状态。
func (m *otpmaskMetrics) setReconcileRun(runAtUnixNano int64, blocked bool) {
	m.mu.Lock()
	m.reconcileLastRun = runAtUnixNano / 1e9
	if blocked {
		m.billingBlocked = 1
	} else {
		m.billingBlocked = 0
	}
	m.mu.Unlock()
}

// setBillingBlocked 记录对外出账阻断状态翻转（blocked=true 时按 reason 计数）。
func (m *otpmaskMetrics) setBillingBlocked(reason string, blocked bool) {
	m.mu.Lock()
	if blocked {
		m.billingBlockCount[reason]++
		m.billingBlocked = 1
	} else {
		m.billingBlocked = 0
	}
	m.mu.Unlock()
}

// incBillingSuppressed 记录因对账不一致被抑制的计费推送事件数（按差异分类）。
func (m *otpmaskMetrics) incBillingSuppressed(reason string) {
	m.mu.Lock()
	m.billingSuppressed[reason]++
	m.mu.Unlock()
}

// incAttestTokenTraffic 记录 token 模式流量。
func (m *otpmaskMetrics) incAttestTokenTraffic(tenant string) {
	m.mu.Lock()
	m.tokenTraffic[tenant]++
	m.mu.Unlock()
}

// incRecompute 记录补算调用计数与耗时（毫秒累计）。
func (m *otpmaskMetrics) incRecompute(op string, durationMs int64) {
	m.mu.Lock()
	m.recomputeOps[op]++
	m.recomputeDur[op] += durationMs
	m.mu.Unlock()
}

func (m *otpmaskMetrics) incRequest(tenant, result string) {
	m.mu.Lock()
	m.requests[tenant+"|"+result]++
	m.mu.Unlock()
}

func (m *otpmaskMetrics) addTokens(tenant string, in, out int64) {
	m.mu.Lock()
	m.tokensIn[tenant] += in
	m.tokensOut[tenant] += out
	m.mu.Unlock()
}

func (m *otpmaskMetrics) incDeny(tenant, reason string) {
	m.mu.Lock()
	m.denies[tenant+"|"+reason]++
	m.mu.Unlock()
}

// incQuotaDeny 记录一次配额拒绝并归因到触发维度（B 项：window = minute|day，"" 归一为 total
// ＝累计维度，避免空标签值在面板/告警里不可读）。
func (m *otpmaskMetrics) incQuotaDeny(tenant, window string) {
	if window == "" {
		window = "total"
	}
	m.mu.Lock()
	m.quotaDenies[tenant+"|"+window]++
	m.mu.Unlock()
}

// incShadowReport 记录窗口级影子上报的处理结果（A 项：result = accepted|deduped|rejected）。
// n<=0 不计数（避免无意义样本）。
func (m *otpmaskMetrics) incShadowReport(result string, n int64) {
	if n <= 0 {
		return
	}
	m.mu.Lock()
	m.shadowReports[result] += n
	m.mu.Unlock()
}

func (m *otpmaskMetrics) incKeyIssue(tenant string) {
	m.mu.Lock()
	m.keyIssues[tenant]++
	m.mu.Unlock()
}

// render 输出完整 Prometheus 文本（审计链长度由调用方经 auditEvents 注入）。
func (m *otpmaskMetrics) render(w io.Writer, auditEvents int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	writeCounter(w, "otpmask_inference_requests_total", "推理请求计数（按租户与结果）", m.requests, []string{"tenant", "result"})
	writeCounter(w, "otpmask_tokens_in_total", "输入 token 计数（按租户）", m.tokensIn, []string{"tenant"})
	writeCounter(w, "otpmask_tokens_out_total", "输出 token 计数（按租户）", m.tokensOut, []string{"tenant"})
	writeCounter(w, "otpmask_denies_total", "拒绝计数（按租户与原因）", m.denies, []string{"tenant", "reason"})
	writeCounter(w, "otpmask_quota_denies_total", "配额拒绝计数（按租户与触发维度：minute|day|total）", m.quotaDenies, []string{"tenant", "window"})
	writeCounter(w, "otpmask_shadow_reports_total", "数据面明文影子窗口级上报计数（accepted/deduped/rejected）", m.shadowReports, []string{"result"})
	writeCounter(w, "otpmask_guard_classifier_total", "语义分类器调用（ok=侧车判定可用 / degraded=不可用已回退关键词规则）", m.guardClassifier, []string{"backend", "result"})
	writeCounter(w, "otpmask_key_issue_total", "密钥签发计数（按租户）", m.keyIssues, []string{"tenant"})
	writeCounter(w, "otpmask_reconcile_mismatch_total", "审计-计量对账不一致次数（按差异分类）", m.reconcile, []string{"reason"})
	writeCounter(w, "otpmask_shadow_would_reject_total", "影子命中计数（只计数不拒绝；按租户与维度）", m.shadowWouldReject, []string{"tenant", "rule"})
	writeCounter(w, "otpmask_reconcile_diff_tokens", "审计-计量对账偏差 token 量级累计（按差异分类）", m.reconcileDiff, []string{"reason"})
	writeCounter(w, "otpmask_billing_blocked_total", "对外出账阻断置位次数（按差异分类）", m.billingBlockCount, []string{"reason"})
	writeCounter(w, "otpmask_billing_suppressed_total", "因对账不一致被抑制的计费推送事件数（按差异分类）", m.billingSuppressed, []string{"reason"})
	writeCounter(w, "otpmask_attest_token_traffic_total", "token 证明模式流量", m.tokenTraffic, []string{"tenant"})
	writeCounter(w, "otpmask_recompute_ops_total", "补算调用计数（按算子）", m.recomputeOps, []string{"op"})
	writeCounter(w, "otpmask_recompute_duration_ms_total", "补算耗时累计（按算子，毫秒）", m.recomputeDur, []string{"op"})
	fmt.Fprintf(w, "# HELP otpmask_billing_blocked 对外出账是否被对账结果阻断（1=阻断）\n# TYPE otpmask_billing_blocked gauge\n")
	fmt.Fprintf(w, "otpmask_billing_blocked %d\n", m.billingBlocked)
	if m.reconcileLastRun > 0 {
		fmt.Fprintf(w, "# HELP otpmask_reconcile_last_run_timestamp_seconds 最近一次审计-计量对账时刻（UTC 秒）\n# TYPE otpmask_reconcile_last_run_timestamp_seconds gauge\n")
		fmt.Fprintf(w, "otpmask_reconcile_last_run_timestamp_seconds %d\n", m.reconcileLastRun)
	}
	if auditEvents > 0 {
		fmt.Fprintf(w, "# HELP otpmask_audit_events 审计哈希链当前长度\n# TYPE otpmask_audit_events gauge\n")
		fmt.Fprintf(w, "otpmask_audit_events %d\n", auditEvents)
	}
}

// writeCounter 输出一个 counter 指标族（labels 决定标签维度）。
func writeCounter(w io.Writer, name, help string, data map[string]int64, labels []string) {
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
		fmt.Fprintf(w, "%s{%s} %d\n", name, labelPairs(labels, splitKey(k)), data[k])
	}
}

// splitKey "a|b" → [a b]（无分隔符 → [k]）。
func splitKey(k string) []string {
	for i := 0; i < len(k); i++ {
		if k[i] == '|' {
			return []string{k[:i], k[i+1:]}
		}
	}
	return []string{k}
}

// labelPairs 生成 `label1="v1",label2="v2"` 片段。
func labelPairs(labels, values []string) string {
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
