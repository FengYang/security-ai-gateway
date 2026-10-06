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
// gateway_admin_audit_events                        审计链当前事件数（G1）
// gateway_admin_broker_audit_write_failed_total     审计链写入失败计数（G1；fail-closed 拒绝变更）
// gateway_cryptop_profile_switch_total{from,to}    密码 profile/mask_prg 切换计数（P0-4 §4.3.10，#12）
//
// 跨源指标（P0-4 §10.1 双读计数）：
// cryptop_dualread_total{artifact}  用非主 profile 算法成功解算 wire/hash/signature 次数
//   artifact ∈ {audit, billing}（本进程发射）；enclave 由 tee-infer 发射
package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
)

type adminMetrics struct {
	mu              sync.Mutex
	requests        int64
	authRejected    int64
	broker          map[string]int64 // key = provider|code|reason
	reloadFailed    int64
	auditEvents     int64 // gauge：审计链当前事件数（G1）
	auditWriteFails int64
	profileSwitch   map[string]int64 // #12：key = from|to（P0-4 §4.3.10）
	dualRead        map[string]int64 // 跨源：artifact（audit/billing）
}

var metrics = newAdminMetrics()

func newAdminMetrics() *adminMetrics {
	return &adminMetrics{broker: map[string]int64{}, profileSwitch: map[string]int64{}, dualRead: map[string]int64{}}
}

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

// setAuditEvents 更新审计链当前事件数（gauge，G1）。
func (m *adminMetrics) setAuditEvents(n int) {
	m.mu.Lock()
	m.auditEvents = int64(n)
	m.mu.Unlock()
}

// incBrokerAuditWriteFailed 记录一次审计链写入失败（G1 fail-closed：对应业务变更被拒绝）。
func (m *adminMetrics) incBrokerAuditWriteFailed() {
	m.mu.Lock()
	m.auditWriteFails++
	m.mu.Unlock()
}

// brokerRequest broker 中转计数。provider 仅接受配置内名称或常量 "_unknown"
// （外部输入不得直接作 label，防基数爆炸）。
func (m *adminMetrics) brokerRequest(provider, code, reason string) {
	m.mu.Lock()
	m.broker[provider+"|"+code+"|"+reason]++
	m.mu.Unlock()
}

// incProfileSwitch 记录一次 profile/mask_prg 切换（#12 唯一生产者）。
// from/to 均为枚举值（handler 已校验），无基数爆炸风险。
func (m *adminMetrics) incProfileSwitch(from, to string) {
	m.mu.Lock()
	m.profileSwitch[from+"|"+to]++
	m.mu.Unlock()
}

// incDualRead 记录一次双读（用非主 profile 算法成功解算）。
// artifact ∈ {audit, billing}（本进程），由调用方保证为有限枚举。
func (m *adminMetrics) incDualRead(artifact string) {
	m.mu.Lock()
	m.dualRead[artifact]++
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
	fmt.Fprintf(w, "# HELP gateway_admin_audit_events 审计链当前事件数\n# TYPE gateway_admin_audit_events gauge\n")
	fmt.Fprintf(w, "gateway_admin_audit_events %d\n", m.auditEvents)
	fmt.Fprintf(w, "# HELP gateway_admin_broker_audit_write_failed_total 审计链写入失败计数（fail-closed 拒绝变更）\n# TYPE gateway_admin_broker_audit_write_failed_total counter\n")
	fmt.Fprintf(w, "gateway_admin_broker_audit_write_failed_total %d\n", m.auditWriteFails)

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

	fmt.Fprintf(w, "# HELP gateway_cryptop_profile_switch_total 密码 profile/mask_prg 切换计数（§4.3.10）\n# TYPE gateway_cryptop_profile_switch_total counter\n")
	swKeys := make([]string, 0, len(m.profileSwitch))
	for k := range m.profileSwitch {
		swKeys = append(swKeys, k)
	}
	sort.Strings(swKeys) // 确定性输出，便于 diff/测试断言
	for _, k := range swKeys {
		parts := strings.SplitN(k, "|", 2)
		fmt.Fprintf(w, "gateway_cryptop_profile_switch_total{from=%q,to=%q} %d\n",
			parts[0], parts[1], m.profileSwitch[k])
	}

	// 跨源：cryptop_dualread_total{artifact}（audit/billing 由本进程发射）
	if len(m.dualRead) > 0 {
		fmt.Fprintf(w, "# HELP cryptop_dualread_total 双读计数（用非主 profile 算法成功解算 wire/hash/signature）\n# TYPE cryptop_dualread_total counter\n")
		drKeys := make([]string, 0, len(m.dualRead))
		for k := range m.dualRead {
			drKeys = append(drKeys, k)
		}
		sort.Strings(drKeys)
		for _, k := range drKeys {
			fmt.Fprintf(w, "cryptop_dualread_total{artifact=%q} %d\n", k, m.dualRead[k])
		}
	}
}
