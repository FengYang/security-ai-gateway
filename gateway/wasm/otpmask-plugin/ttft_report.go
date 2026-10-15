package main

// ttft_report.go — P1-6 M2：数据面 TTFT 采集与上报（固定桶计数 + 首 token 采样 + 上报体/待确认队列）。
//
// 范围（如实，随 M2 原子滚动补全）：
//   - M2.2：固定 11 桶计数（§3.4；逐边界对齐 tee-infer-service/metrics.go ttftBuckets）；
//   - M2.3：标识解析（node/VM ID，R2-03/G-3）+ 上报体构造 + batch_id + 超限拆分（TT2-08）；
//   - M2.1：首 token 采样钩子（解密回调 + delta.content 判定，R2-04/R2-05/C-3）；
//   - M2.4：待确认队列（冻结/确认移除/上限丢弃，R2-06/R2-18）；
//   - M2.5：周期上报 tick（ttft_poll_interval_seconds 缺省 10s ≤ T=25s；cb/ok/reject/drop 指标）；
//   - M2.7：cache 维度输入接缝（TEE 响应头命中标识；契约未落地恒 miss，D-10/P0-2）。
//
// 本文件不含路由决策/权函数（TT2-19 解耦）；指标注册见 metrics.go（M5）。

import (
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/higress-group/proxy-wasm-go-sdk/proxywasm"
	logs "github.com/higress-group/wasm-go/pkg/log"
	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"

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

// ttftCacheMiss cache 维度缺省值（D-10/§3.2 第 9 步）。
const ttftCacheMiss = "miss"

// ttftCacheHit cache 维度命中标识（D-10：hit 样本仅观测/控制面聚合，不参与路由权；R-11）。
const ttftCacheHit = "hit"

// ttftCacheHeaderName TEE 侧缓存命中标识响应头名（M2.7 输入接缝；P0-2 契约）。
//
// ⚠️ 跨文档依赖（§8「P0-2 语义缓存」）：命中判定在 tee-infer 进程内、数据面不可见，
// 须由 TEE 响应头回传；契约未落地 → **空串 = 不读取响应头、cache 恒记 miss**
// （cache_partition=true 时等价不分层，不影响 miss 画像正确性）。
// 契约定稿后仅需填写实际头名（如 "X-Otpmask-Cache"）——上报/待确认队列/下发写回
// 全链路已按任意 cache 值工作，数据面即自动 hit/miss 归维（M2.7 验收后半句）。
var ttftCacheHeaderName = ""

// ttftCacheDimFromValue 解析命中标识取值 → 维度名：仅显式 "hit"（忽略大小写/首尾空白）归 hit；
// 其余（"miss"/空/未知值）一律 miss——路由权只用 miss（D-10/R-11：本期不启用 hit 样本路由）。
func ttftCacheDimFromValue(v string) string {
	if strings.EqualFold(strings.TrimSpace(v), ttftCacheHit) {
		return ttftCacheHit
	}
	return ttftCacheMiss
}

// ttftCacheDimFromHeaders 从 TEE 响应头读取缓存维度（M2.7 输入接缝）：
// 契约未落地（ttftCacheHeaderName 为空）→ 不发起读取、恒 miss（零行为变化）。
func ttftCacheDimFromHeaders(getHeader func(string) (string, error)) string {
	if ttftCacheHeaderName == "" {
		return ttftCacheMiss
	}
	v, err := getHeader(ttftCacheHeaderName)
	if err != nil {
		v = ""
	}
	return ttftCacheDimFromValue(v)
}

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

// freeze 原子快照当前周期全部键计数并清零（周期边界冻结，M2.4）：
// 返回快照副本；清零即开新周期——冻结之后到达的新样本计入下一周期，不受影响。
// 无样本 → nil。
func (c *ttftCounters) freeze() map[ttftKey]ttftBucketCounts {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.m) == 0 {
		return nil
	}
	out := make(map[ttftKey]ttftBucketCounts, len(c.m))
	for k, b := range c.m {
		out[k] = *b
	}
	c.m = make(map[ttftKey]*ttftBucketCounts) // 新周期独立 map（在飞观测无共享）
	return out
}

// ttftStore 插件 VM 级存储实例（§6.2：每个 Envoy worker 加载独立 Wasm VM、各自持桶独立上报）。
var ttftStore = newTTFTCounters()

// ttftCapture 计算候选样本（纯函数；无路由上下文/起点缺失 → 不采样）。
// endpoint 取请求级路由决策上下文（P0-1）；无端点归属（未走多端点路由）时如实跳过。
// cache 为 M2.7 输入接缝解析出的维度（空 → 缺省 miss）。
func ttftCapture(ep, tenant, model, cache string, startNs, nowNs int64) (ttftKey, int64, bool) {
	if ep == "" || startNs <= 0 || nowNs <= 0 {
		return ttftKey{}, 0, false
	}
	if cache == "" {
		cache = ttftCacheMiss
	}
	ms := (nowNs - startNs) / int64(time.Millisecond)
	if ms < 0 {
		ms = 0 // 时钟异常防御（如发生，如实归 0 桶）
	}
	return ttftKey{tenant: tenant, model: model, endpoint: ep, cache: cache}, ms, true
}

// ttftOnDecryptedOut 解密回调接线（M2.1）：把解密后重建的明文 SSE 喂入内容判定解析器
// （须在 label 注入之前调用——仅模型内容参与判定，插件注入帧不触发）；首个
// delta.content 非空 token 到达 → now - RouteStart 记候选。
// 非流式/整包路径不接线（§3.4：非流式/失败请求不计入）；候选提交唯一发生在
// 流完整结束处（ttftCommitOnComplete），解密失败/截断流的候选自然丢弃。
// cache 维度（M2.7）：取响应头阶段缓存的命中标识（契约未落地 → 恒 miss）。
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
	cache, _ := ctx.GetContext(ctxKeyTTFTCache).(string)
	if cache == "" {
		cache = ttftCacheMiss
	}
	st.ttft.onOut(out, ep, tenant, config.Model, cache, startNs, time.Now().UnixNano())
}

// onOut 判定 + 捕获核心（无 ctx，可单测）：首内容 token 到达时按已解析的路由上下文记候选。
// 首 token 后（fired）不再喂入；无路由上下文（endpoint 空/起点缺失）→ 如实不记候选。
func (s *ttftRespSample) onOut(out []byte, ep, tenant, model, cache string, startNs, nowNs int64) {
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
	key, ms, ok := ttftCapture(ep, tenant, model, cache, startNs, nowNs)
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

// ============================================================
// M2.4：待确认队列（冻结快照 / 确认移除 / 未确认原样重发 / 超限丢最旧，§6.2 / R2-06 / R2-18）
// ============================================================

// TTFTReportQueueCap 待确认队列上限（批次数；§6.2/R2-06「如 4 批」）。
// 超限时丢最旧未确认批次并计入 drop 计数（R2-18）——保新弃旧，防止控制面长期不可达时
// 无界积压（C-4：内存不随请求/时间增长）。
const TTFTReportQueueCap = 4

// ttftSamplesFromSnapshot 把冻结快照转为上报样本序列（确定性顺序：
// endpoint → tenant → model → cache 字典序）。顺序仅用于同周期批次构成可复现、可测；
// 控制面不依赖样本顺序。零样本键（计数总和为 0）不上报。
func ttftSamplesFromSnapshot(snap map[ttftKey]ttftBucketCounts) []ttftSample {
	if len(snap) == 0 {
		return nil
	}
	keys := make([]ttftKey, 0, len(snap))
	for k := range snap {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.endpoint != b.endpoint {
			return a.endpoint < b.endpoint
		}
		if a.tenant != b.tenant {
			return a.tenant < b.tenant
		}
		if a.model != b.model {
			return a.model < b.model
		}
		return a.cache < b.cache
	})
	samples := make([]ttftSample, 0, len(keys))
	for _, k := range keys {
		b := snap[k]
		if b.total() == 0 {
			continue // 零样本键不上报
		}
		samples = append(samples, ttftSample{
			Tenant:   k.tenant,
			Model:    k.model,
			Endpoint: k.endpoint,
			Cache:    k.cache,
			Buckets:  b.counts,
		})
	}
	return samples
}

// ttftReportQueue VM 级待确认队列（M2.4，§6.2）：
//   - 周期边界冻结快照 → 构造批次（TT2-08 拆分）→ 尾部入队（同周期批次保序）；
//   - 仅当控制面**成功响应**（M3 契约：result=ok/dropped/duplicate 均为确认成功，见台账 G-6）
//     才 ack 出队；
//   - 未确认批次在下个 tick **原样重发**（batch_id 不变——控制面按 batch_id 去重不双计）；
//   - 上限 TTFTReportQueueCap 批，超限丢最旧 + drop 计数（R2-06/R2-18）。
type ttftReportQueue struct {
	mu      sync.Mutex
	q       []ttftReport
	dropped uint64 // 超限丢弃批次数（report_drop_total 数据源，M5 指标注册）
}

func newTTFTReportQueue() *ttftReportQueue {
	return &ttftReportQueue{q: make([]ttftReport, 0, TTFTReportQueueCap)}
}

// freezeCycle 周期边界冻结（M2.4/M2.5 共用）：快照并清零存储 → 构造本周期批次 → 入队。
// 返回本次入队批次数与本次因超限丢弃批次数；无样本 → 0,0（不产生空批次）。
func (q *ttftReportQueue) freezeCycle(id ttftIdentity, cycleStartSec int64, store *ttftCounters) (enqueued, dropped int) {
	samples := ttftSamplesFromSnapshot(store.freeze())
	if len(samples) == 0 {
		return 0, 0
	}
	return q.appendAll(ttftBuildReports(id, cycleStartSec, samples, TTFTReportMaxSamples))
}

// appendAll 尾部批量入队（保序）；超上限丢最旧并计数（返回本次丢弃数）。
func (q *ttftReportQueue) appendAll(reports []ttftReport) (enqueued, dropped int) {
	if len(reports) == 0 {
		return 0, 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.q = append(q.q, reports...)
	for len(q.q) > TTFTReportQueueCap {
		q.q = q.q[1:] // 丢最旧未确认批次
		q.dropped++
		dropped++
	}
	return len(reports), dropped
}

// head 取队头批次（发送轮次调用；**不移除**——收到成功响应后由 ack 移除）。
func (q *ttftReportQueue) head() (ttftReport, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.q) == 0 {
		return ttftReport{}, false
	}
	return q.q[0], true
}

// ack 移除队头批次（仅控制面成功响应后调用）。未确认时不得调用 → 下个 tick 原样重发。
func (q *ttftReportQueue) ack() {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.q) == 0 {
		return
	}
	q.q = q.q[1:]
}

// ackByID 按 batch_id 移除已确认批次（M2.5 传输回调使用；防「超限丢最旧」竞态下
// 误删新队头——按身份匹配而非盲弹队头；批次已被丢弃时 no-op）。
func (q *ttftReportQueue) ackByID(batchID string) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for i := range q.q {
		if q.q[i].BatchID == batchID {
			q.q = append(q.q[:i], q.q[i+1:]...)
			return
		}
	}
}

// len 当前待确认批次数。
func (q *ttftReportQueue) len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.q)
}

// droppedTotal 累计超限丢弃批次数（report_drop_total，R2-18）。
func (q *ttftReportQueue) droppedTotal() uint64 {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

// ============================================================
// M2.5：周期上报 tick（冻结→发送→确认/重发；§6.2 / §6.4 / §6.5）
// ============================================================

// TTFT 上报/拉取周期边界（§6.4）：缺省 10s；必须 ≤ 分片窗口 T=25s（防滑窗覆盖不足/过期误判）。
const (
	TTFTReportIntervalDefaultSec = 10
	TTFTReportIntervalMaxSec     = 25
)

// ttftGetProperty proxy-wasm 属性读取入口（单测注入；wasm 运行态为 proxywasm.GetProperty）。
var ttftGetProperty = func(path []string) (string, error) {
	v, err := proxywasm.GetProperty(path)
	return string(v), err
}

// ttftLogWarnf 上报链路告警（单测环境 no-op；hostcall 仅在 wasm 运行时可用——同 metricsHostGuard 纪律）。
func ttftLogWarnf(format string, args ...interface{}) {
	if metricsHostGuard {
		return
	}
	proxywasm.LogWarnf(format, args...)
}

// ttftTruncate 日志截断（防异常响应体刷日志）。
func ttftTruncate(b []byte) string {
	if len(b) > 120 {
		b = b[:120]
	}
	return string(b)
}

// ttftRuntimeState TTFT 上报运行态（VM 级；parseConfig 时初始化/刷新）。
type ttftRuntimeState struct {
	enabled    bool // 控制面通道（service/port）配置齐备才注册 tick
	service    string
	port       int64
	token      string // 静态通道令牌（运行态凭据端点拉取优先，回退至此）
	intervalMs int64

	nodeName      string       // 配置 node_name（优先于 Envoy node.id，G-3 双通道）
	identity      ttftIdentity // VM 实例标识（懒解析一次后稳定复用）
	identityReady bool
	lastFreezeSec int64 // 上一周期起始秒（batch_id 周期起始；0 = 尚未冻结）
	inflight      bool  // 单飞：同 VM 同一时刻至多一个在飞上报

	// —— M2.6 统计拉取态（§6.3：round-robin 分片 + 单飞）——
	fetchCursor   int   // round-robin 游标（对字典序租户列表取模）
	fetchInflight int   // 在飞拉取请求数（回调被丢弃时由 tick 陈旧自愈复位）
	fetchStartSec int64 // 本批拉取发起秒（陈旧自愈判定：>2×周期视为回调丢失）
}

// ttftRuntime 上报运行态单例（VM 级）；ttftQueue 待确认队列单例（§6.2：每 VM 独立上报）。
var (
	ttftRuntime ttftRuntimeState
	ttftQueue   = newTTFTReportQueue()
)

// initTTFTRuntime 按配置初始化/刷新 TTFT 上报运行态并注册 tick。
// 未配置控制面通道（service/port）→ 置空不注册（零行为变化；采集仍本地累计，M5 指标可见）。
// ⚠️ 每次插件启动/热更新都重新注册（wasm-go 会清空全局 tick 注册表；同 routefetch.go 范式）。
func initTTFTRuntime(config PluginConfig, log logs.Log) {
	rt := &ttftRuntime
	rt.enabled = false
	rt.identityReady = false
	rt.lastFreezeSec = 0
	rt.inflight = false
	rt.fetchCursor = 0
	rt.fetchInflight = 0
	rt.fetchStartSec = 0
	rt.nodeName = config.NodeName

	intervalMs := config.TTFTPollIntervalSeconds * 1000
	if intervalMs <= 0 {
		intervalMs = TTFTReportIntervalDefaultSec * 1000
	}
	if intervalMs > TTFTReportIntervalMaxSec*1000 {
		// 防御性收口（parseConfig 已告警收口；此处兜底直接调用方）。
		intervalMs = TTFTReportIntervalMaxSec * 1000
	}
	if intervalMs < 100 {
		intervalMs = 100
	}
	rt.intervalMs = intervalMs

	rt.service = config.GatewayCoreService
	rt.port = config.GatewayCorePort
	rt.token = config.GatewayCoreToken

	if rt.service == "" || rt.port <= 0 {
		log.Infof("otpmask-plugin: TTFT 上报未启用（未配置 gateway_core_service/port；采集仍本地累计、无网络行为）")
		return
	}
	rt.enabled = true
	wrapper.RegisterTickFunc(rt.intervalMs, ttftReportTick)
	log.Infof("otpmask-plugin: TTFT 上报 tick 已注册 period_ms=%d（每次插件启动/热更新重新注册）", rt.intervalMs)
	// M2.6：统计拉取 tick（同周期；无已建引擎租户集时零网络）。
	wrapper.RegisterTickFunc(rt.intervalMs, ttftFetchTick)
	log.Infof("otpmask-plugin: TTFT 统计拉取 tick 已注册 period_ms=%d（round-robin 分片 ≤%d 租户/tick）",
		rt.intervalMs, TTFTStatsMaxTenantsPerTick)
}

// ensureIdentity 解析并缓存上报标识（每 VM 一次；属性通道不可得时如实兜底）。
func (rt *ttftRuntimeState) ensureIdentity() ttftIdentity {
	if !rt.identityReady {
		node := ttftResolveNodeName(rt.nodeName, ttftGetProperty)
		rt.identity = ttftIdentity{
			node: node,
			vmID: ttftResolveVMID(ttftGetProperty, node, time.Now().UnixNano()),
		}
		rt.identityReady = true
	}
	return rt.identity
}

// nextCycleStart 计算本次冻结的周期起始秒并推进周期指针（首 tick 以 now-interval 为起点）。
// 返回值即 batch_id 的周期起始秒：冻结后不变（重发同 batch_id），逐周期单调递增。
func (rt *ttftRuntimeState) nextCycleStart(nowSec int64) int64 {
	start := rt.lastFreezeSec
	if start <= 0 {
		start = nowSec - rt.intervalMs/1000
	}
	rt.lastFreezeSec = nowSec
	return start
}

// ttftReportTick 周期上报任务（wrapper.RegisterTickFunc 回调）。
func ttftReportTick() {
	ttftReportTickAt(time.Now().Unix())
}

// ttftReportTickAt tick 主流程（nowSec 注入可测）：
// 周期边界冻结快照入待确认队列 → 尝试发送队头（成功确认出队；未确认下个 tick 原样重发）。
func ttftReportTickAt(nowSec int64) {
	rt := &ttftRuntime
	if !rt.enabled {
		return
	}
	cycleStart := rt.nextCycleStart(nowSec)
	if _, dropped := ttftQueue.freezeCycle(rt.ensureIdentity(), cycleStart, ttftStore); dropped > 0 {
		metricTTFTReportDrop.add(uint64(dropped)) // 队列超限丢最旧（R2-06/R2-18）
	}
	rt.sendHead()
}

// sendHead 发送队头批次（单飞；发送不改队列——成功响应经 ttftOnReportResponse ack 出队）。
func (rt *ttftRuntimeState) sendHead() {
	if rt.inflight {
		return // 上一批在飞（回调未归）→ 本 tick 跳过（无并发在飞、不重排）
	}
	batch, ok := ttftQueue.head()
	if !ok {
		return
	}
	body, err := json.Marshal(batch)
	if err != nil {
		// 防御：ttftReport 全静态字段恒可序列化；如发生按未确认处理（保留重发）
		metricTTFTReportReject.incr()
		ttftLogWarnf("otpmask-plugin: TTFT 上报编码失败（保留待确认队列）: %v", err)
		return
	}
	headers := [][2]string{{"Content-Type", "application/json"}}
	token := rt.token
	if v := runtimeCoreChannelToken(); v != "" { // 运行态通道令牌优先（C 项；回退静态配置）
		token = v
	}
	if token != "" {
		headers = append(headers, [2]string{"Authorization", "Bearer " + token})
	}
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: rt.service, Port: rt.port})
	rt.inflight = true
	err = cli.Post("/routes/ttft/report", headers, body,
		func(statusCode int, _ http.Header, respBody []byte) {
			rt.inflight = false
			ttftOnReportResponse(statusCode, respBody, batch.BatchID)
		})
	if err != nil {
		rt.inflight = false
		metricTTFTReportReject.incr()
		ttftLogWarnf("otpmask-plugin: TTFT 上报触发失败（保留待确认队列，下个 tick 原样重发）: %v", err)
	}
}

// ttftOnReportResponse 上报响应处理（M3 契约，台账 G-6）：
//
//	200 且 result ∈ {ok, dropped, duplicate} ⇒ 确认成功（ack 出队；ok=落片、dropped=旧世代
//	批次弃发、duplicate=控制面按 batch_id 去重）；其余（400/404/503/网络错/非契约载荷）
//	一律视为**未确认** ⇒ 保留批次下个 tick 原样重发（至少一次；队列上限丢最旧兜底防积压）。
func ttftOnReportResponse(statusCode int, respBody []byte, batchID string) {
	metricTTFTReportCb.incr()
	if statusCode == http.StatusOK {
		switch ttftParseReportResult(respBody) {
		case "ok", "dropped", "duplicate":
			ttftQueue.ackByID(batchID)
			metricTTFTReportOK.incr()
			return
		}
		ttftLogWarnf("otpmask-plugin: TTFT 上报返回 200 但载荷非确认结构（保留重发）body=%s", ttftTruncate(respBody))
	} else {
		ttftLogWarnf("otpmask-plugin: TTFT 上报返回 %d（保留待确认队列，下个 tick 原样重发）body=%s",
			statusCode, ttftTruncate(respBody))
	}
	metricTTFTReportReject.incr()
}

// ttftParseReportResult 解析上报响应 result 字段（缺失/非法 → ""）。
func ttftParseReportResult(respBody []byte) string {
	return gjson.GetBytes(respBody, "result").String()
}
