// Package main — 可观测性指标。
//
// 标准库手写 Prometheus 文本格式（零外部依赖，项目规范）。
// 指标族：
// gateway_admin_requests_total                   经鉴权放行的请求计数
// gateway_admin_auth_rejected_total              鉴权/授权拒绝计数（缺/坏令牌、未知角色、越权 403）
// gateway_admin_broker_requests_total            broker 中转请求计数{provider,code,reason}
//
//	（reason ∈ ok/upstream_error/path_denied/provider_unknown）
//
// gateway_admin_broker_config_reload_failed_total 凭据目录热加载失败计数（M2 A-1；失败保留旧配置）
package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

type adminMetrics struct {
	mu           sync.Mutex
	requests     int64
	authRejected int64
	broker       map[string]int64 // key = provider|code|reason
	reloadFailed int64
}

var metrics = newAdminMetrics()

func newAdminMetrics() *adminMetrics { return &adminMetrics{broker: map[string]int64{}} }

func (m *adminMetrics) request() {
	m.mu.Lock()
	m.requests++
	m.mu.Unlock()
}

func (m *adminMetrics) incAuthRejected() {
	m.mu.Lock()
	m.authRejected++
	m.mu.Unlock()
}

// incBrokerReloadFailed 记录一次凭据配置重载失败（失败即保留旧配置，服务不中断）。
func (m *adminMetrics) incBrokerReloadFailed() {
	m.mu.Lock()
	m.reloadFailed++
	m.mu.Unlock()
}

// brokerRequest broker 中转计数。provider 仅接受配置内名称或常量 "_unknown"
// （外部输入不得直接作 label，防基数爆炸）。
func (m *adminMetrics) brokerRequest(provider, code, reason string) {
	m.mu.Lock()
	m.broker[provider+"|"+code+"|"+reason]++
	m.mu.Unlock()
}

func (m *adminMetrics) render(w io.Writer) {
	m.mu.Lock()
	defer m.mu.Unlock()
	fmt.Fprintf(w, "# HELP gateway_admin_requests_total 经鉴权放行的管理面请求计数\n# TYPE gateway_admin_requests_total counter\n")
	fmt.Fprintf(w, "gateway_admin_requests_total %d\n", m.requests)
	fmt.Fprintf(w, "# HELP gateway_admin_auth_rejected_total 鉴权/授权拒绝计数（缺/坏令牌、未知角色、越权 403）\n# TYPE gateway_admin_auth_rejected_total counter\n")
	fmt.Fprintf(w, "gateway_admin_auth_rejected_total %d\n", m.authRejected)
	fmt.Fprintf(w, "# HELP gateway_admin_broker_config_reload_failed_total 凭据目录热加载失败计数（失败保留旧配置）\n# TYPE gateway_admin_broker_config_reload_failed_total counter\n")
	fmt.Fprintf(w, "gateway_admin_broker_config_reload_failed_total %d\n", m.reloadFailed)

	fmt.Fprintf(w, "# HELP gateway_admin_broker_requests_total broker 中转请求计数（按 provider/code/reason）\n# TYPE gateway_admin_broker_requests_total counter\n")
	keys := make([]string, 0, len(m.broker))
	for k := range m.broker {
		keys = append(keys, k)
	}
	sort.Strings(keys) // 确定性输出，便于 diff/测试断言
	for _, k := range keys {
		parts := strings.SplitN(k, "|", 3)
		// %q 转义 \、" 与换行，满足 Prometheus label 值转义要求
		fmt.Fprintf(w, "gateway_admin_broker_requests_total{provider=%q,code=%q,reason=%q} %d\n",
			parts[0], parts[1], parts[2], m.broker[k])
	}
}
