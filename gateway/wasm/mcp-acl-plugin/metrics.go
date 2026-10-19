package main

// metrics.go —— mcp-acl 插件最小指标集（T-4）。proxy-wasm Counter 无标签能力
// （见 otpmask metrics.go 注释），本体 §6.6 的 {tenant,tool} 维度由结构化日志承接。
//
//	mcpacl_requests_total          进入头阶段的请求数
//	mcpacl_allows_total            tools/call 授权放行数
//	mcpacl_denies_total            拒绝数（原因/租户/工具维度见结构化日志）
//	mcpacl_fetch_cb_total          拉取回调被执行次数（恒 0 ⇒ 回调被丢弃）
//	mcpacl_fetch_ok_total          单源验签通过并写入缓存次数（两源合计）
//	mcpacl_fetch_reject_total      单源被拒/拉取失败次数（非 200/解析/验签/回滚/超限/下限）
//	mcpacl_crypto_call_total       cryptop sidecar 调用次数
//	mcpacl_crypto_failclosed_total sidecar 调用失败（fail-closed）次数
//
// hostcall 仅在 wasm 运行时可用（go:wasmimport 在宿主单测进程不可调用）：
// pwCounter 懒初始化（Define 同名幂等，复用同一 stat），metricsHostGuard 由
// 单测置位跳过——与 otpmask 纯逻辑测试策略一致。

import "github.com/higress-group/proxy-wasm-go-sdk/proxywasm"

// metricsHostGuard 单测环境守卫：true 时 incr 为 no-op（防 hostcall panic）。
var metricsHostGuard = false

// pwCounter 懒初始化的 proxy-wasm 计数器（MetricCounter 为值类型，以 bool 标记已 Define）。
type pwCounter struct {
	name    string
	c       proxywasm.MetricCounter
	defined bool
}

// incr 计数 +1；首次调用时 Define（同名指标幂等，返回同一 stat）。
func (m *pwCounter) incr() {
	m.add(1)
}

// add 计数 +offset；首次调用时 Define（同名指标幂等，返回同一 stat）。
func (m *pwCounter) add(offset uint64) {
	if metricsHostGuard {
		return
	}
	if !m.defined {
		m.c = proxywasm.DefineCounterMetric(m.name)
		m.defined = true
	}
	m.c.Increment(offset)
}

var (
	metricRequests         = &pwCounter{name: "mcpacl_requests_total"}
	metricAllows           = &pwCounter{name: "mcpacl_allows_total"}
	metricDenies           = &pwCounter{name: "mcpacl_denies_total"}
	metricFetchCb          = &pwCounter{name: "mcpacl_fetch_cb_total"}
	metricFetchOK          = &pwCounter{name: "mcpacl_fetch_ok_total"}
	metricFetchReject      = &pwCounter{name: "mcpacl_fetch_reject_total"}
	metricCryptoCall       = &pwCounter{name: "mcpacl_crypto_call_total"}
	metricCryptoFailClosed = &pwCounter{name: "mcpacl_crypto_failclosed_total"}
)
