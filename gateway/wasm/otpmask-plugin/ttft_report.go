package main

// ttft_report.go — P1-6 M2：数据面 TTFT 采集与上报（固定桶计数 + 首 token 采样 + 上报体/待确认队列）。
//
// 范围（如实，随 M2 原子滚动补全）：
//   - M2.2：固定 11 桶计数（§3.4；逐边界对齐 tee-infer-service/metrics.go ttftBuckets）；
//   - M2.3：标识解析（node/VM ID，R2-03/G-3）+ 上报体构造 + batch_id + 超限拆分（TT2-08）；
//   - M2.1（待）：首 token 采样钩子（解密回调 + delta.content 判定，R2-04/R2-05）；
//   - M2.4（待）：待确认队列（冻结/确认清零/上限丢弃，R2-06）；
//   - M2.5（待）：周期上报 tick（复用 wrapper.RegisterTickFunc 范式）。
//
// 本文件不含路由决策/权函数（TT2-19 解耦）；指标注册见 metrics.go（M5）。

import (
	"fmt"
	"hash/fnv"
	"strconv"
)

// TTFTBucketCount TTFT 上报桶数（§3.4：11 桶；+Inf 为隐式兜底桶，不计入上报数组）。
const TTFTBucketCount = 11

// ttftBucketUpperBoundsMs 桶上界（毫秒，严格升序；§3.4）。
//
// 口径对齐（M2.2 验收）：逐边界等于 gateway/tee-infer-service/metrics.go 的 ttftBuckets
// （秒制 {0.01,0.025,0.05,0.1,0.25,0.5,1,2,5,10,30} × 1000）。两侧共同锁定同一字面量基线
// （ttft_report_test.go 断言），任一侧改动必须双侧同改，保证桶边界一致、口径可比。
var ttftBucketUpperBoundsMs = [TTFTBucketCount]int64{
	10, 25, 50, 100, 250, 500, 1000, 2000, 5000, 10000, 30000,
}

// ttftBucketCounts 固定桶计数（O(端点数×桶数)；观测零分配）。
type ttftBucketCounts struct {
	counts [TTFTBucketCount]uint64
}

// observe 计入一次 TTFT 样本（毫秒；负值防御归 0；超末桶上界归末桶，§3.4）。
func (c *ttftBucketCounts) observe(ms int64) {
	c.counts[ttftBucketIndex(ms)]++
}

// total 返回桶计数总和（当前周期样本数）。
func (c *ttftBucketCounts) total() uint64 {
	var n uint64
	for _, v := range c.counts {
		n += v
	}
	return n
}

// ttftBucketIndex 返回毫秒值所属桶（首个上界 ≥ ms 的桶；> 30000ms 归末桶，§3.4）。
func ttftBucketIndex(ms int64) int {
	if ms < 0 {
		ms = 0
	}
	for i, ub := range ttftBucketUpperBoundsMs {
		if ms <= ub {
			return i
		}
	}
	return TTFTBucketCount - 1
}

// ============================================================
// M2.3：标识解析 + 上报体构造 + batch_id + 超限拆分（§6.2 / R2-03 / TT2-08）
// ============================================================

// TTFTReportMaxSamples 单 batch 样本条目上限（§6.2 TT2-08，与下发侧单次上限对称）。
const TTFTReportMaxSamples = 1000

// ttftIdentity 上报标识（每 VM 初始化时解析一次，之后稳定复用；batch_id 由它派生）。
type ttftIdentity struct {
	node string
	vmID string
}

// Envoy 属性路径（R2-03/G-3）：
//   - node 取标准子路径 node.id（节点名；单一 ["node"] 路径返回节点整包不适用）；
//   - vm_id 取 wasm 属性 plugin_vm_id——host 为每个 VM 分配的唯一 ID，**强于**本体 R2-03
//     预设的「随机/哈希生成」口径（同节点多 worker 加载独立 VM，无碰撞风险）。
var (
	ttftNodeIDProp = []string{"node", "id"}
	ttftVMIDProp   = []string{"plugin_vm_id"}
)

// ttftResolveNodeName 节点名解析（双通道兼容，G-3）：配置 node_name 优先（部署显式收口），
// 其次 Envoy 属性 node.id；均缺省 → "unknown-node"（如实兜底；batch_id 仍逐实例稳定）。
func ttftResolveNodeName(cfgName string, getProp func([]string) (string, error)) string {
	if cfgName != "" {
		return cfgName
	}
	if getProp != nil {
		if v, err := getProp(ttftNodeIDProp); err == nil && v != "" {
			return v
		}
	}
	return "unknown-node"
}

// ttftResolveVMID VM 实例 ID 解析（R2-03）：Envoy 属性 plugin_vm_id 优先（host 唯一分配）；
// 属性不可得（旧 host/非 Envoy 宿主）→ 生成 8 hex 短 ID（FNV-1a 混合节点名 + 时间种子；
// 非密码用途，仅需「同实例稳定、跨实例不撞」——同节点多 worker 同一毫秒初始化的碰撞概率
// 已通过「各 VM 独立相对初始化顺序 + host 属性优先」降至可忽略，属如实兜底）。
func ttftResolveVMID(getProp func([]string) (string, error), node string, nowUnixNano int64) string {
	if getProp != nil {
		if v, err := getProp(ttftVMIDProp); err == nil && v != "" {
			return v
		}
	}
	return ttftGeneratedVMID(node, nowUnixNano)
}

// ttftGeneratedVMID 生成 8 hex 位 VM 短 ID（确定性：同 (node, nano) → 同 ID，便于测试）。
func ttftGeneratedVMID(node string, nowUnixNano int64) string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(node))
	_, _ = h.Write([]byte(strconv.FormatInt(nowUnixNano, 10)))
	return fmt.Sprintf("%08x", h.Sum32())
}

// ttftBatchID 构造 batch_id（§6.2：node|vm_id|周期起始秒；拆分分片追加 |分片序号）。
func ttftBatchID(node, vmID string, cycleStartSec int64) string {
	return node + "|" + vmID + "|" + strconv.FormatInt(cycleStartSec, 10)
}

// ttftSample 单端点上报样本（§6.2；buckets 为 11 桶**桶内计数**——非累积，+Inf 隐式兜底不入数组）。
type ttftSample struct {
	Tenant   string                  `json:"tenant"`
	Model    string                  `json:"model"`
	Endpoint string                  `json:"endpoint"`
	Cache    string                  `json:"cache"`
	Buckets  [TTFTBucketCount]uint64 `json:"buckets"`
}

// ttftReport 上报体（§6.2）。Worker 字段语义为 **VM 实例 ID**（R2-03；字段名保留兼容命名）。
type ttftReport struct {
	Node       string       `json:"node"`
	Worker     string       `json:"worker"`
	BatchID    string       `json:"batch_id"`
	ReportedAt int64        `json:"reported_at"` // 毫秒（周期起始秒 ×1000；控制面时间窗/去重按此）
	Samples    []ttftSample `json:"samples"`
}

// ttftBuildReports 构造本周期上报批次（TT2-08）：样本 ≤ maxPerBatch → 单 batch（无序号后缀）；
// 超限按输入顺序拆分为多个 batch（同周期内**顺序**上报；batch_id 追加 |1..k，1 起）。
// maxPerBatch ≤ 0 → 取 TTFTReportMaxSamples；样本为空 → nil（本周期无上报）。
func ttftBuildReports(id ttftIdentity, cycleStartSec int64, samples []ttftSample, maxPerBatch int) []ttftReport {
	if len(samples) == 0 {
		return nil
	}
	if maxPerBatch <= 0 {
		maxPerBatch = TTFTReportMaxSamples
	}
	chunks := (len(samples) + maxPerBatch - 1) / maxPerBatch
	reports := make([]ttftReport, 0, chunks)
	for i := 0; i < chunks; i++ {
		lo := i * maxPerBatch
		hi := lo + maxPerBatch
		if hi > len(samples) {
			hi = len(samples)
		}
		batchID := ttftBatchID(id.node, id.vmID, cycleStartSec)
		if chunks > 1 {
			batchID += "|" + strconv.Itoa(i+1)
		}
		reports = append(reports, ttftReport{
			Node:       id.node,
			Worker:     id.vmID,
			BatchID:    batchID,
			ReportedAt: cycleStartSec * 1000,
			Samples:    samples[lo:hi],
		})
	}
	return reports
}
