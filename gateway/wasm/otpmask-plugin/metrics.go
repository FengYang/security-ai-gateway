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
//	otpmask_cred_fetch_cb_total   段① 凭据拉取**回调被执行**次数（恒 0 ⇒ 回调被丢弃）
//	otpmask_cred_fetch_ok_total   段① 凭据校验通过并写入运行态次数
//	otpmask_cred_fetch_reject_total 段① 凭据被拒次数（非 200 / 解析失败 / 载荷非法；插件保留旧值）
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
	// 段① 凭据运行态拉取（门禁 #8）：cb 恒为 0 ⇒ 回调从未执行（异步回调被丢弃）；
	// reject 持续增长 ⇒ 端点不可用/令牌错误/载荷非法（插件保留旧值继续服务）。
	metricCredFetchCb     = &pwCounter{name: "otpmask_cred_fetch_cb_total"}
	metricCredFetchOK     = &pwCounter{name: "otpmask_cred_fetch_ok_total"}
	metricCredFetchReject = &pwCounter{name: "otpmask_cred_fetch_reject_total"}
	// 限流表拉取（门禁 #7 / 判据 5）：reject 持续增长 ⇒ 策略源不可用/验签失败/版本回退
	// （插件保留旧表）；degraded ⇒ **从未拉到**任何可用表（按设计 §6 放行 + 告警）。
	metricRateLimitFetchCb     = &pwCounter{name: "otpmask_ratelimit_fetch_cb_total"}
	metricRateLimitFetchOK     = &pwCounter{name: "otpmask_ratelimit_fetch_ok_total"}
	metricRateLimitFetchReject = &pwCounter{name: "otpmask_ratelimit_fetch_reject_total"}
	metricRateLimitDegraded    = &pwCounter{name: "otpmask_ratelimit_degraded_total"}
	// C 项（门禁 #7 边界 C）：gateway-core 通道令牌集拉取（每集合独立读令牌；失败保留旧令牌）。
	metricChannelFetchCb     = &pwCounter{name: "otpmask_core_channel_fetch_cb_total"}
	metricChannelFetchOK     = &pwCounter{name: "otpmask_core_channel_fetch_ok_total"}
	metricChannelFetchReject = &pwCounter{name: "otpmask_core_channel_fetch_reject_total"}
)

// 说明（如实）：**不暴露**"当前生效限流表版本"仪表。proxy-wasm 的 MetricGauge 在多 worker
// 下由 Envoy 按**累加**聚合（各 worker 独立实例、共享进程级统计），"当前值"语义不成立（实测
// 版本 4 被累加为 17×4=68）。版本可观测改由：插件日志（"验签通过并已入缓存 version=N"）与
// gateway-core `GET /ratelimits` 的 version 字段承担。
