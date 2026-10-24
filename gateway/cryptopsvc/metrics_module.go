// metrics_module.go —— S3 模块指标接线上层（P1-5 M5，设计文档附录 B 新增 cryptop_module_*）。
//
// 数据源（全部经可选接口从 ModuleBackend 探测，module 包零侵入）：
//   - cryptop_module_rand_health{slot}         ← PKCS11Backend.RandHealth()（R-S3-12/GM2-03）
//   - cryptop_module_health{slot,peer}         ← FailoverManager.Snapshot()（有主备）或 backend.Health()（单后端）
//   - cryptop_module_failover_total{from_slot,to_slot,reason} ← FailoverSnapshot.FailoverCounts（累计）
//   - cryptop_module_sessions_active{slot}     ← backend.PoolStats().InUse
//   - cryptop_module_latency_seconds{op,slot}  ← ModuleOpObserver 注入（moduleProvider 方法计时）
//
// 口径（务必如实，避免误导）：
//   - 仅 sm-module 档装配后端后发射；intl/sm-software 档无模块语义，不发射（档位条件指标，
//     门禁清单按 conditional 登记，防 intl 档误判 FAIL）；
//   - failover_total 的 from_slot/to_slot 标签值承载 peer 角色（primary/backup）——附录 B
//     标签命名沿用 MetricsSink.RecordFailover 契约；槽位身份由 cryptop_module_health 的
//     slot 标签表达（每 peer 一条）；
//   - 探活类 gauge 为 pull 语义：/metrics 抓取时刻轮询实时值，非事件推送；
//   - 锁序：metrics.mu → moduleMetrics.mu（render 持 m.mu 调用本文件渲染；ObserveModuleOp
//     只持 mod.mu，反向序不存在）。

package cryptopsvc

import (
	"fmt"
	"io"
	"sort"
	"sync"

	cryptopmodule "security-ai-gateway/gateway/cryptop/module"
)

// moduleLatencyBuckets 模块运算延迟桶（秒）。较 cryptop_op_duration_seconds 放宽上界：
// 网络密码机形态（D-5）单次调用可达百毫秒级，最宽至 5s。
var moduleLatencyBuckets = []float64{0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5}

// ---- 可选接口（module 包具体类型实现；经 ModuleBackend 值断言探测）----

type randHealthProvider interface{ RandHealth() cryptopmodule.RandHealthStatus }
type poolStatsProvider interface{ PoolStats() cryptopmodule.PoolStats }
type slotLabelProvider interface{ SlotLabel() string }
type failoverSnapProvider interface{ Snapshot() cryptopmodule.FailoverSnapshot }

// moduleMetrics S3 模块指标集合（M5）。
type moduleMetrics struct {
	mu      sync.Mutex
	latency map[string]*histogram // op → cryptop_module_latency_seconds

	src cryptopmodule.ModuleBackend // 装配期绑定（bindModule；nil = 无模块，不发射）
}

func newModuleMetrics() *moduleMetrics {
	return &moduleMetrics{latency: map[string]*histogram{}}
}

// bindModule 绑定模块后端（NewServer 装配期调用一次；之后 renderModule 轮询其状态）。
func (mm *moduleMetrics) bindModule(b cryptopmodule.ModuleBackend) {
	mm.mu.Lock()
	mm.src = b
	mm.mu.Unlock()
}

// ObserveModuleOp 实现 cryptop.ModuleOpObserver：模块运算耗时入直方图。
func (mm *moduleMetrics) ObserveModuleOp(op string, sec float64) {
	mm.mu.Lock()
	defer mm.mu.Unlock()
	if mm.latency == nil {
		mm.latency = map[string]*histogram{}
	}
	h := mm.latency[op]
	if h == nil {
		h = newHistogram(moduleLatencyBuckets)
		mm.latency[op] = h
	}
	h.observe(sec)
}

// moduleSlotLabel 取后端槽位标签（不支持时 "unknown"）。
func moduleSlotLabel(b cryptopmodule.ModuleBackend) string {
	if sl, ok := b.(slotLabelProvider); ok {
		if s := sl.SlotLabel(); s != "" {
			return s
		}
	}
	return "unknown"
}

// renderModule 输出 S3 模块指标段（由 metrics.render 在锁内调用；锁序见文件头）。
func (mm *moduleMetrics) renderModule(w io.Writer) {
	if mm == nil {
		return
	}
	mm.mu.Lock()
	src := mm.src
	mm.mu.Unlock()
	if src == nil {
		return // 非 sm-module 档：无模块语义，不发射
	}
	slot := moduleSlotLabel(src)

	// cryptop_module_rand_health{slot}（附录 B required；R-S3-12 随机数启动自检）。
	if rh, ok := src.(randHealthProvider); ok {
		writeGaugeF64Labels(w, "cryptop_module_rand_health",
			"模块随机数启动自检健康状态（1=通过/0=失败，R-S3-12/GM2-03）",
			map[string]string{"slot": slot}, float64(rh.RandHealth().Int()))
	}

	// cryptop_module_health{slot,peer}（附录 B required；1=ok/0.5=degraded/0=down）。
	// 有主备装配时每 peer 一条（各带自身槽位）；单后端仅 primary。
	if snap, ok := src.(failoverSnapProvider); ok {
		s := snap.Snapshot()
		writeGaugeF64Labels(w, "cryptop_module_health",
			"模块健康状态（1=ok/0.5=degraded/0=down，按 peer）",
			map[string]string{"slot": s.PrimarySlot, "peer": "primary"}, s.PrimaryLevel.Float64())
		if s.HasBackup {
			writeGaugeF64Labels(w, "cryptop_module_health",
				"模块健康状态（1=ok/0.5=degraded/0=down，按 peer）",
				map[string]string{"slot": s.BackupSlot, "peer": "backup"}, s.BackupLevel.Float64())
		}
		// cryptop_module_failover_total{from_slot,to_slot,reason}（累计计数器）。
		writeCounter(w, "cryptop_module_failover_total",
			"主备切换计数（from_slot/to_slot 标签值承载 peer 角色 primary/backup；reason=primary_down/switchback）",
			s.FailoverCounts, []string{"from_slot", "to_slot", "reason"})
	} else {
		writeGaugeF64Labels(w, "cryptop_module_health",
			"模块健康状态（1=ok/0.5=degraded/0=down，按 peer）",
			map[string]string{"slot": slot, "peer": "primary"}, src.Health().Float64())
	}

	// cryptop_module_sessions_active{slot}（会话池活跃数；池使用率观测）。
	if ps, ok := src.(poolStatsProvider); ok {
		st := ps.PoolStats()
		writeGaugeF64Labels(w, "cryptop_module_sessions_active",
			"模块会话池活跃（在借）会话数（池使用率观测）",
			map[string]string{"slot": slot}, float64(st.InUse))
	}

	// cryptop_module_latency_seconds{op,slot}（直方图；ModuleOpObserver 注入数据）。
	mm.mu.Lock()
	ops := make([]string, 0, len(mm.latency))
	for op := range mm.latency {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	for _, op := range ops {
		writeHistogram(w, "cryptop_module_latency_seconds",
			"模块运算延迟（秒，按 op）", mm.latency[op],
			fmt.Sprintf("op=%q,slot=%q", op, slot))
	}
	mm.mu.Unlock()
}

// ---- 渲染辅助 ----

// writeGaugeF64Labels 输出带标签 gauge（float 值；标签按 key 排序保证确定性）。
func writeGaugeF64Labels(w io.Writer, name, help string, labels map[string]string, v float64) {
	fmt.Fprintf(w, "# HELP %s %s\n# TYPE %s gauge\n", name, help, name)
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Fprintf(w, "%s{%s} %g\n", name, labelPairs(keys, labelVals(keys, labels)), v)
}

func labelVals(keys []string, m map[string]string) []string {
	vals := make([]string, len(keys))
	for i, k := range keys {
		vals[i] = m[k]
	}
	return vals
}
