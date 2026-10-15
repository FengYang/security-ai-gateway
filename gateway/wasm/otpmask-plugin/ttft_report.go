package main

// ttft_report.go — P1-6 M2：数据面 TTFT 采集与上报（固定桶计数 + 首 token 采样 + 上报体/待确认队列）。
//
// 范围（如实，随 M2 原子滚动补全）：
//   - M2.2：固定 11 桶计数（§3.4；逐边界对齐 tee-infer-service/metrics.go ttftBuckets）；
//   - M2.3：标识解析（node/VM ID，R2-03/G-3）+ 上报体构造 + batch_id + 超限拆分（TT2-08）；
//   - M2.1：首 token 采样钩子（解密回调 + delta.content 判定，R2-04/R2-05/C-3）；
//   - M2.4（待）：待确认队列（冻结/确认清零/上限丢弃，R2-06）；
//   - M2.5（待）：周期上报 tick（复用 wrapper.RegisterTickFunc 范式）。
//
// 本文件不含路由决策/权函数（TT2-19 解耦）；指标注册见 metrics.go（M5）。

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"sync"
	"time"

	"github.com/higress-group/wasm-go/pkg/wrapper"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/streamparser"
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

// ============================================================
// M2.1：首 token 采样钩子（解密回调接线，§3.4 / R2-04 / R2-05 / C-3）
// ============================================================

// ttftCacheMiss cache 维度缺省值（D-10/§3.2 第 9 步）：TEE 侧命中标识回传契约（M2.7）
// 未落地前恒记 miss（cache_partition=true 时等价不分层，不影响 miss 画像正确性）。
const ttftCacheMiss = "miss"

// ttftKey TTFT 聚合键（§3.4/§6.2：(tenant, model, endpoint, cache)）。
type ttftKey struct {
	tenant   string
	model    string
	endpoint string
	cache    string
}

// ttftRespSample 单响应采样状态（挂 respStreamState，随响应回收）。
//
// 并发与资源口径（R2-05/C-3，如实）：解析器实例随响应级状态创建（多响应流交错下不可
// 全局共享）；缓冲定长封顶（maxSSELineBytes）、判定在解密后 chunk 上 O(1) 完成、
// 首 token 后 fired 短路不再喂入——无随 chunk 数增长的累积。
type ttftRespSample struct {
	parser *streamparser.SSEParser // 内容判定（R2-04：delta.content 非空）
	fired  bool                    // 已捕获候选（不再喂入）
	ready  bool                    // 候选有效待提交（流完整结束才提交）
	key    ttftKey
	ms     int64
}

// ttftCounters 单 VM 端点桶计数存储（C-4：O(端点数×桶数)，不随请求增长）。
// 冻结快照/清零由 M2.4/M2.5 周期管线消费；此处仅提供累计与查询原语。
type ttftCounters struct {
	mu sync.Mutex
	m  map[ttftKey]*ttftBucketCounts
}

func newTTFTCounters() *ttftCounters {
	return &ttftCounters{m: make(map[ttftKey]*ttftBucketCounts)}
}

// observe 将一次 TTFT 样本（毫秒）累计到键对应桶。
func (c *ttftCounters) observe(k ttftKey, ms int64) {
	c.mu.Lock()
	b := c.m[k]
	if b == nil {
		b = &ttftBucketCounts{}
		c.m[k] = b
	}
	b.observe(ms)
	c.mu.Unlock()
}

// lookup 返回键当前桶计数副本（无该键 → ok=false）。
func (c *ttftCounters) lookup(k ttftKey) (ttftBucketCounts, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.m[k]
	if !ok {
		return ttftBucketCounts{}, false
	}
	return *b, true
}

// ttftStore 插件 VM 级存储实例（§6.2：每个 Envoy worker 加载独立 Wasm VM、各自持桶独立上报）。
var ttftStore = newTTFTCounters()

// ttftCapture 计算候选样本（纯函数；无路由上下文/起点缺失 → 不采样）。
// endpoint 取请求级路由决策上下文（P0-1）；无端点归属（未走多端点路由）时如实跳过。
func ttftCapture(ep, tenant, model string, startNs, nowNs int64) (ttftKey, int64, bool) {
	if ep == "" || startNs <= 0 || nowNs <= 0 {
		return ttftKey{}, 0, false
	}
	ms := (nowNs - startNs) / int64(time.Millisecond)
	if ms < 0 {
		ms = 0 // 时钟异常防御（如发生，如实归 0 桶）
	}
	return ttftKey{tenant: tenant, model: model, endpoint: ep, cache: ttftCacheMiss}, ms, true
}

// ttftOnDecryptedOut 解密回调接线（M2.1）：把解密后重建的明文 SSE 喂入内容判定解析器
// （须在 label 注入之前调用——仅模型内容参与判定，插件注入帧不触发）；首个
// delta.content 非空 token 到达 → now - RouteStart 记候选。
// 非流式/整包路径不接线（§3.4：非流式/失败请求不计入）；候选提交唯一发生在
// 流完整结束处（ttftCommitOnComplete），解密失败/截断流的候选自然丢弃。
func ttftOnDecryptedOut(ctx wrapper.HttpContext, config PluginConfig, st *respStreamState, out []byte) {
	if st == nil || len(out) == 0 {
		return
	}
	if st.ttft == nil {
		st.ttft = &ttftRespSample{}
	}
	ep, _ := ctx.GetContext(ctxKeyRouteEndpoint).(string)
	tenant, _ := ctx.GetContext(ctxKeyTenantID).(string)
	startNs, _ := ctx.GetContext(ctxKeyRouteStart).(int64)
	st.ttft.onOut(out, ep, tenant, config.Model, startNs, time.Now().UnixNano())
}

// onOut 判定 + 捕获核心（无 ctx，可单测）：首内容 token 到达时按已解析的路由上下文记候选。
// 首 token 后（fired）不再喂入；无路由上下文（endpoint 空/起点缺失）→ 如实不记候选。
func (s *ttftRespSample) onOut(out []byte, ep, tenant, model string, startNs, nowNs int64) {
	if len(out) == 0 || s.fired {
		return
	}
	if s.parser == nil {
		s.parser = streamparser.NewContentDeltaSSEParser()
	}
	s.parser.Feed(out)
	if !s.parser.FirstTokenSent() {
		return
	}
	s.fired = true
	key, ms, ok := ttftCapture(ep, tenant, model, startNs, nowNs)
	if !ok {
		return
	}
	s.key, s.ms, s.ready = key, ms, true
}

// ttftCommitOnComplete 流完整结束时提交候选（唯一提交点；幂等——ready 置空后不再提交）。
func ttftCommitOnComplete(st *respStreamState) {
	if st == nil || st.ttft == nil || !st.ttft.ready {
		return
	}
	s := st.ttft
	s.ready = false
	ttftStore.observe(s.key, s.ms)
}
