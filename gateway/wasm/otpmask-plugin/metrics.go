package main

// metrics.go — 插件最小指标集（W-1 评审项）。
//
// 指标经 proxy-wasm hostcall 注册到 Envoy stats（higress 标准通道，stat 前缀挂 plugin）：
//
//	otpmask_request_total         请求进入数（onHttpRequestHeaders）
//	otpmask_fail_closed_total     fail-closed 拒绝数（503）
//	otpmask_decrypt_error_total   解密/流校验失败数（整流拒绝）
//	otpmask_keys_issued_total     请求密钥签发数（入库即计）
//	otpmask_keys_deleted_total    请求密钥删除数（存量 = issued - deleted）
//	otpmask_route_degraded_total  路由降级数（§6：L1 处方缺失/失效 → 走 L2 默认路由表）
//	otpmask_route_fetch_cb_total  路由表拉取**回调被执行**次数（异步响应到达回调的次数；
//	                              恒为 0 说明回调从未执行，例如响应已随 fail-closed 发出后
//	                              流上下文结束导致挂起回调被丢弃）
//	otpmask_route_fetch_ok_total  路由表验签通过并写入缓存次数
//	otpmask_route_fetch_reject_total 路由表被拒次数（验签失败 / 版本回滚 / 路由未启用 / 非 200）
//
// hostcall 仅在 wasm 运行时可用（go:wasmimport 在宿主单测进程不可调用）：
// pwCounter 懒初始化（Define 同名幂等，复用同一 stat），metricsHostGuard 由
// TestMain 置位跳过——与 streamdone_test 的纯逻辑测试策略一致。

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
	if metricsHostGuard {
		return
	}
	if !m.defined {
		m.c = proxywasm.DefineCounterMetric(m.name)
		m.defined = true
	}
	m.c.Increment(1)
}

// 插件计数器（W-1 最小集 + §6 降级/拉取可观测）。
var (
	metricRequests         = &pwCounter{name: "otpmask_request_total"}
	metricFailClosed       = &pwCounter{name: "otpmask_fail_closed_total"}
	metricDecryptError     = &pwCounter{name: "otpmask_decrypt_error_total"}
	metricKeysIssued       = &pwCounter{name: "otpmask_keys_issued_total"}
	metricKeysDeleted      = &pwCounter{name: "otpmask_keys_deleted_total"}
	metricRouteDegraded    = &pwCounter{name: "otpmask_route_degraded_total"}
	metricRouteFetchCb     = &pwCounter{name: "otpmask_route_fetch_cb_total"}
	metricRouteFetchOK     = &pwCounter{name: "otpmask_route_fetch_ok_total"}
	metricRouteFetchReject = &pwCounter{name: "otpmask_route_fetch_reject_total"}
)
