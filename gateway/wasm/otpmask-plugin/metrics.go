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
//	otpmask_route_strategy_unknown_total 未映射策略命中次数（P1-6 M4.4：routeStrategy/
//	                              pickByStrategy 两处 default 显式信号，R2-17/TT2-11）
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

import (
	"fmt"
	"strings"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
)

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
	// P1-6 M4.4（R2-17/TT2-11）：未映射策略显式信号——配置加载期（routeStrategy default，
	// 每 route 一次）与请求路径（pickByStrategy default，每次命中）均计数；
	// 回退动作保持 priority（不改既有运行语义）。
	metricRouteStrategyUnknown = &pwCounter{name: "otpmask_route_strategy_unknown_total"}
	// 灰度请求计数（方案 §10 #11：canary_requests_total）
	// 三组分别计数（whitelist/treatment/control），总和即灰度参与的总请求数。
	metricRouteCanaryWhitelist = &pwCounter{name: "otpmask_route_canary_whitelist_total"}
	metricRouteCanaryTreatment = &pwCounter{name: "otpmask_route_canary_treatment_total"}
	metricRouteCanaryControl   = &pwCounter{name: "otpmask_route_canary_control_total"}
	// token 消耗统计（方案 §10 #4：route_tokens_total，direction 分为 input/output）
	// proxy-wasm Counter 不支持自定义标签，故拆为两个独立 Counter。
	metricRouteTokensInput  = &pwCounter{name: "otpmask_route_tokens_input_total"}
	metricRouteTokensOutput = &pwCounter{name: "otpmask_route_tokens_output_total"}
	// P1-7 T2b（§6.5 A3-14）：数据面未达 TEE 流量上报通道可观测。
	// sent=成功投递条数；dropped=队列溢出丢弃（reason=queue_full，不可补链，如实可见）；
	// fail=投递被服务端非 200 拒绝/网络失败（重新入队重试，连续失败终丢弃）。
	metricAuditReportSent    = &pwCounter{name: "otpmask_audit_report_sent_total"}
	metricAuditReportDropped = &pwCounter{name: "otpmask_audit_report_dropped_total"}
	metricAuditReportFail    = &pwCounter{name: "otpmask_audit_report_fail_total"}
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

// latencyBuckets 延迟桶上界（秒），与方案 §10.1.3 对齐。
var latencyBuckets = []float64{0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0}

// tokenBuckets token 数桶上界。
var tokenBuckets = []float64{10, 100, 500, 1000, 2000, 5000, 10000}

// latencyBucketCounters 按延迟桶索引对应的 Counter（懒初始化）。
// 命名格式：otpmask_route_latency_seconds_bucket{le="0.005"}
// 由于 proxy-wasm Counter 不支持标签，用指标名编码 le 值。
var latencyBucketCounters []*pwCounter

// tokenBucketCounters 按 token 桶索引对应的 Counter（懒初始化）。
var tokenBucketCounters []*pwCounter

func init() {
	// 预初始化 Histogram 桶 Counter（与 bucket 一一对应，按顺序）。
	latencyBucketCounters = make([]*pwCounter, len(latencyBuckets))
	for i, le := range latencyBuckets {
		latencyBucketCounters[i] = &pwCounter{
			name: "otpmask_route_latency_seconds_bucket_le_" + formatFloatForMetric(le),
		}
	}
	tokenBucketCounters = make([]*pwCounter, len(tokenBuckets))
	for i, le := range tokenBuckets {
		tokenBucketCounters[i] = &pwCounter{
			name: "otpmask_route_tokens_bucket_le_" + formatFloatForMetric(le),
		}
	}
}

// formatFloatForMetric 将浮点数格式化为指标名安全的字符串（去掉小数点和负号）。
// 0.005 → "0_005"，10 → "10"
func formatFloatForMetric(v float64) string {
	s := fmt.Sprintf("%g", v)
	s = strings.ReplaceAll(s, ".", "_")
	s = strings.ReplaceAll(s, "-", "_")
	return s
}

// observeLatency 记录一个延迟值（累积直方图语义：所有 le >= value 的桶都 +1）。
// 符合 Prometheus histogram_quantile() 要求。
func observeLatency(valueSec float64) {
	for i, le := range latencyBuckets {
		if valueSec <= le {
			latencyBucketCounters[i].incr()
		}
	}
}

// observeTokens 记录一次 token 数（累积直方图语义）。
func observeTokens(tokens int) {
	v := float64(tokens)
	for i, le := range tokenBuckets {
		if v <= le {
			tokenBucketCounters[i].incr()
		}
	}
}

// recordTokensInput 记录输入 token 数（Counter + Histogram 双计）。
func recordTokensInput(tokens int) {
	if tokens <= 0 {
		return
	}
	metricRouteTokensInput.add(uint64(tokens))
	observeTokens(tokens)
}

// recordTokensOutput 记录输出 token 数（Counter + Histogram 双计）。
func recordTokensOutput(tokens int) {
	if tokens <= 0 {
		return
	}
	metricRouteTokensOutput.add(uint64(tokens))
	observeTokens(tokens)
}

// 说明（如实）：**不暴露**"当前生效限流表版本"仪表。proxy-wasm 的 MetricGauge 在多 worker
// 下由 Envoy 按**累加**聚合（各 worker 独立实例、共享进程级统计），"当前值"语义不成立（实测
// 版本 4 被累加为 17×4=68）。版本可观测改由：插件日志（"验签通过并已入缓存 version=N"）与
// gateway-core `GET /ratelimits` 的 version 字段承担。
