package main

// metrics.go — 插件指标（proxy-wasm hostcall → Envoy stats，前缀 wasmcustom）。
//
// 指标（**无标签**：proxy-wasm MetricCounter 无标签语义，若把标签值编入 stat 名会带来
// 无界基数；维度明细由**窗口级上报**落 tee-infer 审计链与 `/metrics` 承担，见设计 §7）：
//
//	otpmask_shadow_would_reject_total    影子命中累计（只计数不拒绝）
//	otpmask_shadow_report_sent_total     成功上报的窗口级汇总条数
//	otpmask_shadow_report_dropped_total  队列溢出丢弃条数（审计可能缺报，须告警）
//	otpmask_shadow_report_fail_total     上报失败条数（失败已重新入队重试）
//	otpmask_shadow_head_missing_total    缺维度头（x-tenant-id / x-mse-consumer）而跳过的计数
//	otpmask_shadow_cred_fetch_ok_total   通道令牌运行态拉取成功次数
//	otpmask_shadow_cred_fetch_reject_total 通道令牌拉取被拒次数（非 200 / 载荷非法；保留旧令牌）
//	otpmask_shadow_cred_fetch_cb_total   通道令牌拉取**回调被执行**次数（恒 0 ⇒ 回调被丢弃）
//	otpmask_shadow_table_fetch_ok_total  限流表验签通过并入缓存次数
//	otpmask_shadow_table_fetch_reject_total 限流表被拒次数（非 200 / 验签失败 / 版本回退；保留旧表）
//
// hostcall 仅在 wasm 运行时可用（go:wasmimport 在宿主单测进程不可调用）：
// pwCounter 懒初始化（Define 同名幂等），hostGuard 由单测置位跳过计数与日志。

import "github.com/higress-group/proxy-wasm-go-sdk/proxywasm"

// hostGuard 宿主单测守卫：true 时**所有 proxy-wasm hostcall**（计数与日志）为 no-op，防 panic。
// 由单测 TestMain 置位；运行时恒为 false。
var hostGuard = false

// logInfof 经守卫的信息日志（hostcall：宿主单测不可调用）。
func logInfof(format string, args ...interface{}) {
	if hostGuard {
		return
	}
	proxywasm.LogInfof(format, args...)
}

// logWarnf 经守卫的告警日志（hostcall：宿主单测不可调用）。
func logWarnf(format string, args ...interface{}) {
	if hostGuard {
		return
	}
	proxywasm.LogWarnf(format, args...)
}

// pwCounter 懒初始化的 proxy-wasm 计数器（MetricCounter 为值类型，以 bool 标记已 Define）。
type pwCounter struct {
	name    string
	c       proxywasm.MetricCounter
	defined bool
}

// incr 计数 +1。
func (m *pwCounter) incr() { m.add(1) }

// add 计数 +n（n<=0 不计数）。
func (m *pwCounter) add(n int64) {
	if hostGuard || n <= 0 {
		return
	}
	if !m.defined {
		m.c = proxywasm.DefineCounterMetric(m.name)
		m.defined = true
	}
	m.c.Increment(uint64(n))
}

var (
	metricWouldReject   = &pwCounter{name: "otpmask_shadow_would_reject_total"}
	metricReportSent    = &pwCounter{name: "otpmask_shadow_report_sent_total"}
	metricReportDropped = &pwCounter{name: "otpmask_shadow_report_dropped_total"}
	metricReportFail    = &pwCounter{name: "otpmask_shadow_report_fail_total"}
	metricHeadMissing   = &pwCounter{name: "otpmask_shadow_head_missing_total"}
	metricCredFetchOK   = &pwCounter{name: "otpmask_shadow_cred_fetch_ok_total"}
	metricCredFetchRej  = &pwCounter{name: "otpmask_shadow_cred_fetch_reject_total"}
	// cb 恒为 0 ⇒ 回调从未执行（异步回调被丢弃/集群不可达），与 otpmask 的同名诊断手法一致。
	metricCredFetchCb   = &pwCounter{name: "otpmask_shadow_cred_fetch_cb_total"}
	metricCredDisabled  = &pwCounter{name: "otpmask_shadow_cred_disabled_total"}
	metricTableFetchOK  = &pwCounter{name: "otpmask_shadow_table_fetch_ok_total"}
	metricTableFetchRej = &pwCounter{name: "otpmask_shadow_table_fetch_reject_total"}
)
