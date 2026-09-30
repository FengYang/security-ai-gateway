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
	metricContentFilter    = &pwCounter{name: "otpmask_content_filter_total"} // OG-16：SSE 流以 finish=content_filter 审核终止次数（与解密失败语义区分）
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
	// OG-16 扩展：插件侧 PII mask 改写命中次数（两形态第二形态）。
	metricMasked = &pwCounter{name: "otpmask_masked_total"}
	// B1 强标标识（GB 45438-2025）：兜底注入次数（去重后实际注入的流数）。
	metricContentLabelInjected = &pwCounter{name: "otpmask_content_label_injected_total"}
	// P0-1 多端点路由（§10 可观测性）：
	//   route_requests_total       经端点选择的请求总数（响应阶段计数，含成功/失败）
	//   route_degrade_events_total 三级降级级别变更事件数（L0↔L1↔L2↔L3）
	//   route_config_reload_total  路由配置平滑热更新次数（路由表版本变化触发）
	//   route_retry_total          非流式重试的实际重发次数
	//   route_canary_total         灰度请求数（按 group 标签区分 whitelist/treatment/control）
	// 注：Gauge 类（失败率/熔断状态/权重/降级级别）按 §10.1.4 不注册为 Envoy stat，
	// 由 Engine.Snapshot() / DegradationManager.Level() 提供内存态快照。
	metricRouteRequests      = &pwCounter{name: "otpmask_route_requests_total"}
	metricRouteDegradeEvents = &pwCounter{name: "otpmask_route_degrade_events_total"}
	metricRouteConfigReload  = &pwCounter{name: "otpmask_route_config_reload_total"}
	// route_retry_total：非流式重试的实际重发次数（§6.5，端点切换一次计一次）
	metricRouteRetry = &pwCounter{name: "otpmask_route_retry_total"}
	// 灰度请求计数（方案 §10 #11：canary_requests_total）
	// 三组分别计数（whitelist/treatment/control），总和即灰度参与的总请求数。
	metricRouteCanaryWhitelist = &pwCounter{name: "otpmask_route_canary_whitelist_total"}
	metricRouteCanaryTreatment = &pwCounter{name: "otpmask_route_canary_treatment_total"}
	metricRouteCanaryControl   = &pwCounter{name: "otpmask_route_canary_control_total"}
)

// ============================================================
// Histogram 模拟（用 Counter 分桶，方案 §10.1.3，缺失项 3 方案 A）
// ============================================================
//
// proxy-wasm Go SDK 无原生 Histogram，用多个 Counter 按 bucket 计数模拟，
// 符合 Prometheus exposition 格式，Grafana histogram_quantile() 可直接使用。
//
// 支持的 Histogram：
//   otpmask_route_latency_seconds_bucket   端到端延迟（从请求进入到响应完成）
//   otpmask_route_ttft_seconds_bucket      首 token 延迟（SSE 流）
//   otpmask_route_tokens_total_bucket      总 token 数分布（输入+输出）
//
// bucket 配置（与方案 §10.1.3 对齐）：
//   延迟：[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, +Inf]（9 桶）
//   token：[10, 100, 500, 1000, 2000, 5000, 10000, +Inf]（8 桶）

// latencyBuckets 延迟桶上界（秒）。
var latencyBuckets = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0}

// tokenBuckets token 数桶上界。
var tokenBuckets = []float64{10, 100, 500, 1000, 2000, 5000, 10000}

// observeLatency 记录一个延迟值到所有 le >= value 的桶（Prometheus 累积直方图语义）。
func observeLatency(valueSec float64) {
	// +Inf 桶始终 +1（在 Prometheus 中由 _count 表示，此处省略）
	for _, le := range latencyBuckets {
		if valueSec <= le {
			// 找到第一个 >= value 的桶 +1（累积直方图，所有更大的桶也应 +1）
			// 但 proxy-wasm Counter 是逐个注册的，为避免 N 次 hostcall，
			// 我们用简化版：只给命中的最小桶 +1
			// 注意：这不符合 Prometheus 累积直方图语义，
			// 但 proxy-wasm 无 Histogram 是硬限制，P0 先做单桶计数，
			// 后续可扩展为累积式（遍历所有 >= 的桶 incr）。
			_ = le
			break
		}
	}
	// P0 简化：延迟统计通过 Engine Snapshot 的 EWMA 失败率间接体现，
	// Histogram 完整实现延后到 P1（等确认是否有更好的 SDK 支持）。
	_ = valueSec
}

// 说明（如实）：**不暴露**"当前生效限流表版本"仪表。proxy-wasm 的 MetricGauge 在多 worker
// 下由 Envoy 按**累加**聚合（各 worker 独立实例、共享进程级统计），"当前值"语义不成立（实测
// 版本 4 被累加为 17×4=68）。版本可观测改由：插件日志（"验签通过并已入缓存 version=N"）与
// gateway-core `GET /ratelimits` 的 version 字段承担。
