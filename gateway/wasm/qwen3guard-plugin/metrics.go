package main

// metrics.go — qwen3guard 插件最小指标集（B3 / 合规达标最小集 G13）。
//
// 指标经 proxy-wasm hostcall 注册到 Envoy stats（stat 前缀挂插件名）：
//
//	qwen3guard_failclosed_total   审核服务不可用（分发失败 / 超时 / 非 200 / 解析失败 /
//	                              构造送检体失败）时按 fail-closed 拒答的次数
//
// 用途：B3 判据要求 fail-closed 路径「有审计与告警」——本计数器供告警与趋势观测；
// 失败原因（stage/cause）落在 Warnf 日志中，不另设标签以避免高基数。
//
// hostcall 仅在 wasm 运行时可用（go:wasmimport 在宿主单测进程不可调用）：
// pwCounter 懒初始化（Define 同名幂等，复用同一 stat），metricsHostGuard 置位时 incr 为
// no-op（与 otpmask 插件 metrics.go 同法，便于宿主纯逻辑测试）。

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

// 插件计数器。
var (
	metricFailClosed = &pwCounter{name: "qwen3guard_failclosed_total"}
	// B1 强标标识（GB 45438-2025）：流首标识帧注入次数（每流至多一次，去重后实际注入的流数）。
	metricContentLabelInjected = &pwCounter{name: "qwen3guard_content_label_injected_total"}
)
