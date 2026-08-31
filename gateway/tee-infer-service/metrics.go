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
// otpmask_key_issue_total{tenant}                  密钥签发计数
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
	mu        sync.Mutex
	requests  map[string]int64 // tenant|result
	tokensIn  map[string]int64 // tenant
	tokensOut map[string]int64 // tenant
	denies    map[string]int64 // tenant|reason
	keyIssues map[string]int64 // tenant
	reconcile map[string]int64 // reason（审计-计费对账偏差，）
	tokenTraffic map[string]int64 // tenant
}

func newMetrics() *otpmaskMetrics {
	return &otpmaskMetrics{
		requests:  make(map[string]int64),
		tokensIn:  make(map[string]int64),
		tokensOut: make(map[string]int64),
		denies:    make(map[string]int64),
		keyIssues: make(map[string]int64),
		reconcile: make(map[string]int64),
		tokenTraffic: make(map[string]int64),
	}
}

// incReconcileMismatch 记录审计-计费对账偏差。
func (m *otpmaskMetrics) incReconcileMismatch(diff int64) {
	m.mu.Lock()
	m.reconcile["mismatch"] += diff
	m.mu.Unlock()
}

// incAttestTokenTraffic 记录 token 模式流量。
func (m *otpmaskMetrics) incAttestTokenTraffic(tenant string) {
	m.mu.Lock()
	m.tokenTraffic[tenant]++
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
	writeCounter(w, "otpmask_key_issue_total", "密钥签发计数（按租户）", m.keyIssues, []string{"tenant"})
	writeCounter(w, "otpmask_reconcile_mismatch_total", "审计-计费对账偏差累计", m.reconcile, []string{"reason"})
	writeCounter(w, "otpmask_attest_token_traffic_total", "token 证明模式流量", m.tokenTraffic, []string{"tenant"})
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
