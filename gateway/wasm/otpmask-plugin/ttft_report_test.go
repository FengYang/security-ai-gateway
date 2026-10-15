package main

// ttft_report_test.go — P1-6 M2.2/M2.3：固定桶计数结构 + 标识解析/上报体构造与拆分。

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
	"time"
)

// TestTTFTBucketBoundsAlignTeeInfer：桶边界与 tee-infer-service/metrics.go ttftBuckets 逐字段一致。
// （两侧共同锁定同一字面量基线——同 CanonicalBytes 基线手法；任一改动必须双侧同改。）
func TestTTFTBucketBoundsAlignTeeInfer(t *testing.T) {
	// gateway/tee-infer-service/metrics.go: ttftBuckets（秒制）
	teeInferSeconds := []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 5, 10, 30}
	if len(teeInferSeconds) != TTFTBucketCount {
		t.Fatalf("桶数不一致：tee-infer=%d 插件=%d", len(teeInferSeconds), TTFTBucketCount)
	}
	for i, s := range teeInferSeconds {
		if want, got := int64(s*1000), ttftBucketUpperBoundsMs[i]; want != got {
			t.Fatalf("桶 %d 边界不一致：tee-infer=%dms 插件=%dms", i, want, got)
		}
	}
	// 升序 + 末桶 = 30000ms（§6.1 max_ttft_ms 缺省）
	for i := 1; i < TTFTBucketCount; i++ {
		if ttftBucketUpperBoundsMs[i] <= ttftBucketUpperBoundsMs[i-1] {
			t.Fatalf("桶上界须严格升序：idx %d", i)
		}
	}
	if ttftBucketUpperBoundsMs[TTFTBucketCount-1] != 30000 {
		t.Fatalf("末桶上界应为 30000ms（§6.1 max_ttft_ms 缺省）")
	}
}

// TestTTFTBucketIndex：边界值落桶语义（≤ 上界归该桶）与超限兜底。
func TestTTFTBucketIndex(t *testing.T) {
	cases := []struct {
		ms   int64
		want int
	}{
		{0, 0}, {1, 0}, {10, 0},
		{11, 1}, {25, 1},
		{26, 2}, {50, 2},
		{51, 3}, {100, 3},
		{101, 4}, {250, 4},
		{251, 5}, {500, 5},
		{501, 6}, {1000, 6},
		{1001, 7}, {2000, 7},
		{2001, 8}, {5000, 8},
		{5001, 9}, {10000, 9},
		{10001, 10}, {30000, 10},
		{30001, 10}, {1 << 40, 10}, // 超最后一桶归末桶（§3.4）
		{-5, 0}, // 负值防御归 0
	}
	for _, c := range cases {
		if got := ttftBucketIndex(c.ms); got != c.want {
			t.Errorf("ttftBucketIndex(%d)=%d，want %d", c.ms, got, c.want)
		}
	}
}

// TestTTFTBucketCountsObserve：观测累计与总数。
func TestTTFTBucketCountsObserve(t *testing.T) {
	var c ttftBucketCounts
	for _, ms := range []int64{5, 10, 11, 25, 30000, 99999, 7} {
		c.observe(ms)
	}
	if c.total() != 7 {
		t.Fatalf("total 应=7，got %d", c.total())
	}
	if c.counts[0] != 3 { // 5, 10, 7
		t.Fatalf("桶0应=3，got %d", c.counts[0])
	}
	if c.counts[1] != 2 { // 11, 25
		t.Fatalf("桶1应=2，got %d", c.counts[1])
	}
	if c.counts[10] != 2 { // 30000, 99999
		t.Fatalf("桶10应=2，got %d", c.counts[10])
	}
}

// ---- M2.3：标识解析 / batch_id / 上报体构造与拆分 ----

func propFunc(v string, err error) func([]string) (string, error) {
	return func([]string) (string, error) { return v, err }
}

// TestTTFTResolveNodeName：双通道（配置优先 → Envoy 属性 node.id → 兜底）。
func TestTTFTResolveNodeName(t *testing.T) {
	if got := ttftResolveNodeName("my-node", propFunc("envoy-0", nil)); got != "my-node" {
		t.Errorf("配置应优先：got %q", got)
	}
	if got := ttftResolveNodeName("", propFunc("envoy-0", nil)); got != "envoy-0" {
		t.Errorf("属性兜底应生效：got %q", got)
	}
	if got := ttftResolveNodeName("", propFunc("", errors.New("no property"))); got != "unknown-node" {
		t.Errorf("属性失败应兜底 unknown-node：got %q", got)
	}
	if got := ttftResolveNodeName("", nil); got != "unknown-node" {
		t.Errorf("nil 取值器应兜底 unknown-node：got %q", got)
	}
}

// TestTTFTResolveVMID：plugin_vm_id 优先；不可得 → 8 hex 确定性生成。
func TestTTFTResolveVMID(t *testing.T) {
	if got := ttftResolveVMID(propFunc("vm-abc", nil), "envoy-0", 1); got != "vm-abc" {
		t.Errorf("属性应优先：got %q", got)
	}
	g1 := ttftResolveVMID(propFunc("", errors.New("no property")), "envoy-0", 1760000000000000000)
	g2 := ttftResolveVMID(nil, "envoy-0", 1760000000000000000)
	if g1 != g2 {
		t.Fatalf("同种子应确定性生成：%q vs %q", g1, g2)
	}
	if len(g1) != 8 {
		t.Fatalf("生成 ID 应为 8 hex：%q", g1)
	}
	if _, err := strconv.ParseUint(g1, 16, 32); err != nil {
		t.Fatalf("生成 ID 应为 hex：%q（%v）", g1, err)
	}
	if g3 := ttftResolveVMID(nil, "envoy-0", 1760000000000000001); g3 == g1 {
		t.Fatalf("不同种子不应相同（FNV 确定值断言）：%q", g3)
	}
}

// TestTTFTBatchIDAndBuildReports：batch_id 稳定/不撞 + 超限拆分顺序与后缀。
func TestTTFTBatchIDAndBuildReports(t *testing.T) {
	id := ttftIdentity{node: "envoy-0", vmID: "2f3a"}
	want := "envoy-0|2f3a|1760000000"
	if got := ttftBatchID(id.node, id.vmID, 1760000000); got != want {
		t.Fatalf("batch_id 格式：got %q want %q", got, want)
	}
	if got := ttftBatchID(id.node, id.vmID, 1760000000); got != want {
		t.Fatalf("同输入应稳定：%q", got)
	}
	if got := ttftBatchID(id.node, id.vmID, 1760000001); got == want {
		t.Fatalf("跨周期不应相同：%q", got)
	}
	if got := ttftBatchID(id.node, "9fff", 1760000000); got == want {
		t.Fatalf("跨实例不应相同：%q", got)
	}

	// 单块（≤ 上限）：无序号后缀；reported_at = 周期起始秒 ×1000
	samples := make([]ttftSample, 5)
	for i := range samples {
		samples[i].Endpoint = fmt.Sprintf("ep-%d", i)
	}
	reports := ttftBuildReports(id, 1760000000, samples, 0)
	if len(reports) != 1 || reports[0].BatchID != want || reports[0].ReportedAt != 1760000000000 {
		t.Fatalf("单块构造不符：%+v", reports)
	}
	if reports[0].Node != "envoy-0" || reports[0].Worker != "2f3a" {
		t.Fatalf("node/worker 不符：%+v", reports[0])
	}

	// 超限拆分：7 条 / 上限 3 → 3 批（3/3/1），后缀 1..3 顺序且样本顺序保持
	samples = make([]ttftSample, 7)
	for i := range samples {
		samples[i].Endpoint = fmt.Sprintf("ep-%d", i)
	}
	reports = ttftBuildReports(id, 100, samples, 3)
	if len(reports) != 3 {
		t.Fatalf("应 3 批，got %d", len(reports))
	}
	sizes := []int{3, 3, 1}
	for i, rep := range reports {
		if len(rep.Samples) != sizes[i] {
			t.Errorf("批 %d 大小应 %d，got %d", i, sizes[i], len(rep.Samples))
		}
		if wantID := fmt.Sprintf("envoy-0|2f3a|100|%d", i+1); rep.BatchID != wantID {
			t.Errorf("批 %d batch_id 应 %q，got %q", i, wantID, rep.BatchID)
		}
		if rep.ReportedAt != 100000 {
			t.Errorf("批 %d reported_at 应 100000，got %d", i, rep.ReportedAt)
		}
	}
	if reports[0].Samples[0].Endpoint != "ep-0" || reports[1].Samples[0].Endpoint != "ep-3" || reports[2].Samples[0].Endpoint != "ep-6" {
		t.Fatalf("样本顺序应保持：%q %q %q",
			reports[0].Samples[0].Endpoint, reports[1].Samples[0].Endpoint, reports[2].Samples[0].Endpoint)
	}

	// 缺省上限：2505 条 → 1000/1000/505
	big := make([]ttftSample, 2505)
	reports = ttftBuildReports(id, 1, big, 0)
	if len(reports) != 3 || len(reports[0].Samples) != 1000 || len(reports[1].Samples) != 1000 || len(reports[2].Samples) != 505 {
		t.Fatalf("缺省上限拆分不符：%d 批", len(reports))
	}

	// 空样本 → nil
	if got := ttftBuildReports(id, 1, nil, 0); got != nil {
		t.Fatalf("空样本应 nil，got %+v", got)
	}
}

// TestTTFTReportJSONShape：上报体逐字段对齐 §6.2（含 11 桶数组）。
func TestTTFTReportJSONShape(t *testing.T) {
	id := ttftIdentity{node: "envoy-0", vmID: "abc123"}
	var s ttftSample
	s.Tenant, s.Model, s.Endpoint, s.Cache = "t-001", "qwen-max", "tee-gpu-a", "miss"
	s.Buckets[0], s.Buckets[1] = 12, 30
	rep := ttftBuildReports(id, 1760000000, []ttftSample{s}, 0)[0]
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if m["node"] != "envoy-0" || m["worker"] != "abc123" ||
		m["batch_id"] != "envoy-0|abc123|1760000000" || m["reported_at"] != float64(1760000000000) {
		t.Fatalf("上报体标量字段不符：%s", raw)
	}
	samples, ok := m["samples"].([]any)
	if !ok || len(samples) != 1 {
		t.Fatalf("samples 结构不符：%s", raw)
	}
	first := samples[0].(map[string]any)
	if first["tenant"] != "t-001" || first["model"] != "qwen-max" ||
		first["endpoint"] != "tee-gpu-a" || first["cache"] != "miss" {
		t.Fatalf("样本维度字段不符：%s", raw)
	}
	buckets, ok := first["buckets"].([]any)
	if !ok || len(buckets) != TTFTBucketCount {
		t.Fatalf("buckets 应 %d 项：%s", TTFTBucketCount, raw)
	}
	if buckets[0] != float64(12) || buckets[1] != float64(30) {
		t.Fatalf("buckets 取值不符：%s", raw)
	}
}

// ---- M2.1：首 token 采样钩子（R2-04/R2-05/C-3）----

// TestTTFTCapture：纯函数捕获语义（毫秒换算/缺失上下文不采样/负值钳制）。
func TestTTFTCapture(t *testing.T) {
	const start = int64(1_000_000_000) // 纳秒基准
	key, ms, ok := ttftCapture("tee-gpu-a", "t-001", "qwen-max", start, start+120*int64(time.Millisecond))
	if !ok || ms != 120 || key != (ttftKey{tenant: "t-001", model: "qwen-max", endpoint: "tee-gpu-a", cache: ttftCacheMiss}) {
		t.Fatalf("正常捕获不符：key=%+v ms=%d ok=%v", key, ms, ok)
	}
	if _, _, ok := ttftCapture("", "t-001", "qwen-max", start, start+1); ok {
		t.Fatal("无端点不应采样")
	}
	if _, _, ok := ttftCapture("ep", "t-001", "m", 0, start+1); ok {
		t.Fatal("无起点不应采样")
	}
	if _, ms, ok := ttftCapture("ep", "t", "m", start+10, start+1); !ok || ms != 0 {
		t.Fatalf("负值应钳制为 0：ms=%d ok=%v", ms, ok)
	}
}

// TestTTFTSamplerRoleFrameThenContent：role 帧不触发；内容帧触发并记候选（R2-04 验收）。
func TestTTFTSamplerRoleFrameThenContent(t *testing.T) {
	const start = int64(2_000_000_000)
	s := &ttftRespSample{}
	// role 帧（无 delta.content）——不触发、无候选
	s.onOut([]byte("data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n"),
		"tee-gpu-a", "t-001", "qwen-max", start, start+50*int64(time.Millisecond))
	if s.fired || s.ready {
		t.Fatal("role 帧不应触发")
	}
	// 内容帧 → 触发并记候选（50ms）
	s.onOut([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"Hi\"}}]}\n\n"),
		"tee-gpu-a", "t-001", "qwen-max", start, start+50*int64(time.Millisecond))
	if !s.fired || !s.ready {
		t.Fatal("内容帧应触发并记候选")
	}
	if s.ms != 50 || s.key.endpoint != "tee-gpu-a" || s.key.cache != "miss" {
		t.Fatalf("候选不符：ms=%d key=%+v", s.ms, s.key)
	}
	// 首 token 后停止喂入：候选不被改写
	s.onOut([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"more\"}}]}\n\n"),
		"tee-gpu-a", "t-001", "qwen-max", start, start+999*int64(time.Millisecond))
	if s.ms != 50 {
		t.Fatalf("首 token 后不应改写候选：ms=%d", s.ms)
	}
}

// TestTTFTSamplerNoRouteContext：无路由上下文（endpoint 空）→ 触发但不记候选（如实不采样）。
func TestTTFTSamplerNoRouteContext(t *testing.T) {
	const start = int64(3_000_000_000)
	s := &ttftRespSample{}
	s.onOut([]byte("data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n"),
		"", "t-001", "qwen-max", start, start+10*int64(time.Millisecond))
	if !s.fired || s.ready {
		t.Fatalf("无端点应触发但不记候选：fired=%v ready=%v", s.fired, s.ready)
	}
}

// TestTTFTCommitOnlyOnComplete：唯一提交点 + 幂等；未就绪/无状态时 no-op（失败流候选丢弃）。
func TestTTFTCommitOnlyOnComplete(t *testing.T) {
	old := ttftStore
	ttftStore = newTTFTCounters()
	defer func() { ttftStore = old }()

	key := ttftKey{tenant: "t-001", model: "qwen-max", endpoint: "tee-gpu-a", cache: "miss"}
	st := &respStreamState{ttft: &ttftRespSample{ready: true, key: key, ms: 150}}
	ttftCommitOnComplete(st)
	b, ok := ttftStore.lookup(key)
	if !ok || b.total() != 1 || b.counts[4] != 1 { // 150ms ∈ (100,250] → idx4
		t.Fatalf("提交应落桶 idx4：%+v ok=%v", b, ok)
	}
	// 幂等：重复提交不双计
	ttftCommitOnComplete(st)
	if b2, _ := ttftStore.lookup(key); b2.total() != 1 {
		t.Fatalf("重复提交应幂等：%+v", b2)
	}
	// 未就绪（fired 但无候选）与无状态 → no-op（不 panic）
	ttftCommitOnComplete(&respStreamState{ttft: &ttftRespSample{fired: true}})
	ttftCommitOnComplete(&respStreamState{})
	ttftCommitOnComplete(nil)
	if b3, _ := ttftStore.lookup(key); b3.total() != 1 {
		t.Fatalf("no-op 路径不应改变计数：%+v", b3)
	}
}

// TestTTFTCountersObserveIsolation：键隔离与 lookup 副本语义。
func TestTTFTCountersObserveIsolation(t *testing.T) {
	c := newTTFTCounters()
	k1 := ttftKey{tenant: "t1", model: "m", endpoint: "e1", cache: "miss"}
	k2 := ttftKey{tenant: "t1", model: "m", endpoint: "e2", cache: "miss"}
	c.observe(k1, 5)  // 桶0
	c.observe(k1, 15) // 桶1
	c.observe(k2, 30) // 桶2
	b1, ok := c.lookup(k1)
	if !ok || b1.counts[0] != 1 || b1.counts[1] != 1 || b1.total() != 2 {
		t.Fatalf("k1 计数不符：%+v", b1)
	}
	b2, ok := c.lookup(k2)
	if !ok || b2.counts[2] != 1 || b2.total() != 1 {
		t.Fatalf("k2 计数不符：%+v", b2)
	}
	b1.counts[0] = 99 // lookup 为副本：改写不影响内部
	if again, _ := c.lookup(k1); again.counts[0] != 1 {
		t.Fatalf("lookup 应为副本：%+v", again)
	}
	if _, ok := c.lookup(ttftKey{endpoint: "nope"}); ok {
		t.Fatal("未观测键应 ok=false")
	}
}

// ---- M2.4：待确认队列（冻结/确认移除/原样重发/超限丢最旧）----

// TestTTFTCountersFreezeResets：冻结原子性——快照含全部计数、清零开新周期、空存储冻结为 nil。
func TestTTFTCountersFreezeResets(t *testing.T) {
	c := newTTFTCounters()
	k1 := ttftKey{tenant: "t1", model: "m", endpoint: "e1", cache: "miss"}
	k2 := ttftKey{tenant: "t1", model: "m", endpoint: "e2", cache: "miss"}
	c.observe(k1, 5)   // k1 桶0（≤10）
	c.observe(k1, 12)  // k1 桶1（(10,25]）
	c.observe(k2, 300) // k2 桶5（(250,500]）

	snap := c.freeze()
	if len(snap) != 2 || snap[k1].counts[0] != 1 || snap[k1].counts[1] != 1 || snap[k2].counts[5] != 1 {
		t.Fatalf("冻结快照不符：%+v", snap)
	}
	if _, ok := c.lookup(k1); ok {
		t.Fatal("冻结后应清零")
	}
	c.observe(k1, 800) // 新周期样本（(500,1000] → 桶6）
	snap2 := c.freeze()
	if len(snap2) != 1 || snap2[k1].counts[6] != 1 {
		t.Fatalf("新周期快照不符：%+v", snap2)
	}
	if snap := c.freeze(); snap != nil {
		t.Fatalf("空存储冻结应为 nil：%+v", snap)
	}
}

// TestTTFTSamplesFromSnapshotOrder：快照转样本——确定性顺序（endpoint→tenant→model→cache）+ 零样本键跳过。
func TestTTFTSamplesFromSnapshotOrder(t *testing.T) {
	var a, b, zero ttftBucketCounts
	a.counts[0] = 3
	b.counts[1] = 1
	kA := ttftKey{tenant: "t2", model: "m", endpoint: "e1", cache: "miss"}
	kB := ttftKey{tenant: "t1", model: "m", endpoint: "e1", cache: "miss"}
	kZ := ttftKey{tenant: "t3", model: "m", endpoint: "e1", cache: "miss"}
	samples := ttftSamplesFromSnapshot(map[ttftKey]ttftBucketCounts{kB: b, kZ: zero, kA: a})
	if len(samples) != 2 {
		t.Fatalf("零样本键应跳过：%+v", samples)
	}
	if samples[0].Tenant != "t1" || samples[1].Tenant != "t2" {
		t.Fatalf("顺序应按 tenant 字典序：%+v", samples)
	}
	if samples[1].Buckets[0] != 3 || samples[0].Buckets[1] != 1 {
		t.Fatalf("桶计数未映射：%+v", samples)
	}
	if got := ttftSamplesFromSnapshot(nil); got != nil {
		t.Fatalf("nil 快照应为 nil：%+v", got)
	}
}

// TestTTFTQueueFreezeResendAck：冻结入队→发送不改队列（失败原样重发同一 batch_id）→成功 ack 出队。
func TestTTFTQueueFreezeResendAck(t *testing.T) {
	store := newTTFTCounters()
	store.observe(ttftKey{tenant: "t-001", model: "qwen-max", endpoint: "tee-gpu-a", cache: "miss"}, 120)
	store.observe(ttftKey{tenant: "t-001", model: "qwen-max", endpoint: "tee-gpu-b", cache: "miss"}, 45)
	q := newTTFTReportQueue()
	id := ttftIdentity{node: "envoy-0", vmID: "abc123"}
	enq, drp := q.freezeCycle(id, 1760000000, store)
	if enq != 1 || drp != 0 || q.len() != 1 {
		t.Fatalf("冻结入队不符：enq=%d drp=%d len=%d", enq, drp, q.len())
	}
	h1, ok := q.head()
	if !ok || h1.BatchID != "envoy-0|abc123|1760000000" || h1.ReportedAt != 1760000000000 || len(h1.Samples) != 2 {
		t.Fatalf("队头批次不符：%+v", h1)
	}
	if h1.Samples[0].Endpoint != "tee-gpu-a" || h1.Samples[1].Endpoint != "tee-gpu-b" {
		t.Fatalf("样本顺序不符：%+v", h1.Samples)
	}
	if h1.Samples[0].Buckets[4] != 1 { // 120ms ∈ (100,250]
		t.Fatalf("样本桶计数不符：%+v", h1.Samples[0])
	}
	// 发送失败（无 ack）：下个 tick 原样重发——同一 batch_id、同一内容（控制面按 batch_id 去重不双计）
	h2, _ := q.head()
	if h2.BatchID != h1.BatchID || h2.ReportedAt != h1.ReportedAt ||
		len(h2.Samples) != len(h1.Samples) || h2.Samples[0] != h1.Samples[0] {
		t.Fatalf("失败重发应原样：h1=%+v h2=%+v", h1, h2)
	}
	// 控制面成功响应 → 出队
	q.ack()
	if q.len() != 0 {
		t.Fatalf("ack 后应出队：len=%d", q.len())
	}
	if _, ok := q.head(); ok {
		t.Fatal("空队列 head 应 ok=false")
	}
	q.ack() // 空队列 ack 幂等（不 panic）
}

// TestTTFTQueueFreezeEmpty：无样本周期不产生批次（0,0，队列不变）。
func TestTTFTQueueFreezeEmpty(t *testing.T) {
	q := newTTFTReportQueue()
	enq, drp := q.freezeCycle(ttftIdentity{node: "n", vmID: "v"}, 100, newTTFTCounters())
	if enq != 0 || drp != 0 || q.len() != 0 {
		t.Fatalf("空周期不应入队：enq=%d drp=%d len=%d", enq, drp, q.len())
	}
}

// TestTTFTQueueOverflowDropsOldest：超上限丢最旧并计数（R2-06/R2-18）；腾位后恢复入队。
func TestTTFTQueueOverflowDropsOldest(t *testing.T) {
	q := newTTFTReportQueue()
	id := ttftIdentity{node: "n", vmID: "v"}
	key := ttftKey{tenant: "t", model: "m", endpoint: "e", cache: "miss"}
	for c := int64(1); c <= 5; c++ { // cap=4 → 第 5 次冻结丢最旧（cycle=1）
		s := newTTFTCounters()
		s.observe(key, 10)
		q.freezeCycle(id, c, s)
	}
	if q.len() != TTFTReportQueueCap || q.droppedTotal() != 1 {
		t.Fatalf("超限应丢最旧：len=%d dropped=%d", q.len(), q.droppedTotal())
	}
	h, _ := q.head()
	if h.ReportedAt != 2*1000 { // cycle=1 批次已丢，队头应为 cycle=2
		t.Fatalf("丢最旧后队头不符：%+v", h)
	}
	// ack 腾位 → 再冻结不再丢
	q.ack()
	s := newTTFTCounters()
	s.observe(key, 10)
	if _, drp := q.freezeCycle(id, 6, s); drp != 0 || q.droppedTotal() != 1 {
		t.Fatalf("腾位后不应再丢：dropped=%d", q.droppedTotal())
	}
	if q.len() != TTFTReportQueueCap {
		t.Fatalf("腾位后长度不符：len=%d", q.len())
	}
}

// TestTTFTQueueSplitOrderPreserved：同周期拆分批次按序入队、按序确认（TT2-08）。
func TestTTFTQueueSplitOrderPreserved(t *testing.T) {
	id := ttftIdentity{node: "n", vmID: "v"}
	samples := make([]ttftSample, 7)
	for i := range samples {
		samples[i] = ttftSample{Tenant: "t", Model: "m", Endpoint: fmt.Sprintf("e%d", i), Cache: "miss"}
		samples[i].Buckets[0] = 1
	}
	reps := ttftBuildReports(id, 100, samples, 3) // 3 批：|1 |2 |3
	q := newTTFTReportQueue()
	if enq, drp := q.appendAll(reps); enq != 3 || drp != 0 {
		t.Fatalf("入队数不符：enq=%d drp=%d", enq, drp)
	}
	for _, want := range []string{"n|v|100|1", "n|v|100|2", "n|v|100|3"} {
		h, ok := q.head()
		if !ok || h.BatchID != want {
			t.Fatalf("确认顺序不符：got=%+v want=%s", h, want)
		}
		q.ack()
	}
	if q.len() != 0 {
		t.Fatalf("全部确认后应为空：len=%d", q.len())
	}
}

// ---- M2.5：周期上报 tick ----

// ttftTestLog logs.Log 测试桩（仅计数 Warnf，其余 no-op）。
type ttftTestLog struct{ warns int }

func (l *ttftTestLog) Trace(string)                     {}
func (l *ttftTestLog) Tracef(string, ...interface{})    {}
func (l *ttftTestLog) Debug(string)                     {}
func (l *ttftTestLog) Debugf(string, ...interface{})    {}
func (l *ttftTestLog) Info(string)                      {}
func (l *ttftTestLog) Infof(string, ...interface{})     {}
func (l *ttftTestLog) Warn(string)                      { l.warns++ }
func (l *ttftTestLog) Warnf(string, ...interface{})     { l.warns++ }
func (l *ttftTestLog) Error(string)                     {}
func (l *ttftTestLog) Errorf(string, ...interface{})    {}
func (l *ttftTestLog) Critical(string)                  {}
func (l *ttftTestLog) Criticalf(string, ...interface{}) {}
func (l *ttftTestLog) ResetID(string)                   {}

// TestTTFTInitRuntimeGatingAndInterval：配置门（未配置服务 → 不启用）+ 周期缺省/收口（≤25s）。
func TestTTFTInitRuntimeGatingAndInterval(t *testing.T) {
	old := ttftRuntime
	defer func() { ttftRuntime = old }()
	lg := &ttftTestLog{}

	initTTFTRuntime(PluginConfig{}, lg)
	if ttftRuntime.enabled {
		t.Fatal("未配置控制面通道不应启用")
	}
	if ttftRuntime.intervalMs != 10000 {
		t.Fatalf("缺省周期应为 10s：%d", ttftRuntime.intervalMs)
	}
	initTTFTRuntime(PluginConfig{GatewayCoreService: "core.svc", GatewayCorePort: 19090, TTFTPollIntervalSeconds: 60}, lg)
	if !ttftRuntime.enabled || ttftRuntime.intervalMs != 25000 {
		t.Fatalf("启用/收口不符：enabled=%v interval=%d", ttftRuntime.enabled, ttftRuntime.intervalMs)
	}
	initTTFTRuntime(PluginConfig{GatewayCoreService: "core.svc", GatewayCorePort: 19090, TTFTPollIntervalSeconds: 5}, lg)
	if !ttftRuntime.enabled || ttftRuntime.intervalMs != 5000 {
		t.Fatalf("合法周期应保留：enabled=%v interval=%d", ttftRuntime.enabled, ttftRuntime.intervalMs)
	}
}

// TestTTFTEnsureIdentityCachedOnce：标识懒解析一次并缓存；node_name 配置优先（G-3 双通道）。
func TestTTFTEnsureIdentityCachedOnce(t *testing.T) {
	oldGet := ttftGetProperty
	defer func() { ttftGetProperty = oldGet }()
	calls := 0
	ttftGetProperty = func(path []string) (string, error) {
		calls++
		if path[0] == "node" {
			return "envoy-9", nil
		}
		return "vm-9", nil
	}
	rt := &ttftRuntimeState{}
	id := rt.ensureIdentity()
	if id.node != "envoy-9" || id.vmID != "vm-9" {
		t.Fatalf("标识解析不符：%+v", id)
	}
	if calls != 2 {
		t.Fatalf("node/vm_id 属性应各读一次：calls=%d", calls)
	}
	_ = rt.ensureIdentity()
	if calls != 2 {
		t.Fatalf("缓存后不应再读属性：calls=%d", calls)
	}
	rt2 := &ttftRuntimeState{nodeName: "cfg-node"}
	if id2 := rt2.ensureIdentity(); id2.node != "cfg-node" || id2.vmID != "vm-9" {
		t.Fatalf("配置 node_name 应优先：%+v", id2)
	}
}

// TestTTFTNextCycleStart：周期起点推进（首 tick = now-interval；其后取上次冻结时刻）。
func TestTTFTNextCycleStart(t *testing.T) {
	rt := &ttftRuntimeState{intervalMs: 10000}
	if s := rt.nextCycleStart(1000); s != 990 {
		t.Fatalf("首 tick 起点应为 now-10s：%d", s)
	}
	if s := rt.nextCycleStart(1010); s != 1000 {
		t.Fatalf("次 tick 起点应为上次冻结时刻：%d", s)
	}
	if s := rt.nextCycleStart(1020); s != 1010 {
		t.Fatalf("周期起点应单调推进：%d", s)
	}
}

// TestTTFTReportTickFreezeSendOrchestration：冻结入队/清零/空周期不入队/FIFO 保序/超限丢最旧。
// inflight 置位跳过网络发送（传输回调语义另测）。
func TestTTFTReportTickFreezeSendOrchestration(t *testing.T) {
	oldRT, oldQ, oldStore := ttftRuntime, ttftQueue, ttftStore
	defer func() { ttftRuntime, ttftQueue, ttftStore = oldRT, oldQ, oldStore }()
	ttftStore = newTTFTCounters()
	ttftQueue = newTTFTReportQueue()
	ttftRuntime = ttftRuntimeState{
		enabled: true, intervalMs: 10000,
		identityReady: true, identity: ttftIdentity{node: "envoy-0", vmID: "abc"},
		inflight: true, // 跳过网络发送（聚焦冻结/队列编排）
	}
	key := ttftKey{tenant: "t-001", model: "qwen-max", endpoint: "tee-gpu-a", cache: "miss"}

	ttftStore.observe(key, 120)
	ttftReportTickAt(1000)
	h, ok := ttftQueue.head()
	if !ok || h.BatchID != "envoy-0|abc|990" || len(h.Samples) != 1 {
		t.Fatalf("冻结入队不符：%+v ok=%v", h, ok)
	}
	if _, ok := ttftStore.lookup(key); ok {
		t.Fatal("冻结后存储应清零（开新周期）")
	}
	// 空周期：不产生新批次
	ttftReportTickAt(1010)
	if ttftQueue.len() != 1 {
		t.Fatalf("空周期不应入队：len=%d", ttftQueue.len())
	}
	// 第二周期入队：FIFO 保序（队头仍为第一批）
	ttftStore.observe(key, 30)
	ttftReportTickAt(1020)
	if ttftQueue.len() != 2 {
		t.Fatalf("第二周期应入队：len=%d", ttftQueue.len())
	}
	if h2, _ := ttftQueue.head(); h2.BatchID != "envoy-0|abc|990" {
		t.Fatalf("FIFO 保序被破坏：head=%s", h2.BatchID)
	}
	// 超限丢最旧（cap=4）：再入 3 批 → 共 5 批 → 丢 1（cycle=990）
	for i := int64(0); i < 3; i++ {
		ttftStore.observe(key, 10)
		ttftReportTickAt(1030 + i*10)
	}
	if ttftQueue.len() != TTFTReportQueueCap || ttftQueue.droppedTotal() != 1 {
		t.Fatalf("超限丢最旧不符：len=%d dropped=%d", ttftQueue.len(), ttftQueue.droppedTotal())
	}
	if h3, _ := ttftQueue.head(); h3.BatchID != "envoy-0|abc|1010" {
		t.Fatalf("丢最旧后队头应为第二周期批次：%s", h3.BatchID)
	}
}

// TestTTFTOnReportResponseContract：200+ok/dropped/duplicate → 确认出队；
// 其余（400/404/503/非契约载荷）→ 保留重发（至少一次）；ackByID 按身份精确匹配。
func TestTTFTOnReportResponseContract(t *testing.T) {
	old := ttftQueue
	defer func() { ttftQueue = old }()
	id := ttftIdentity{node: "n", vmID: "v"}

	seed := func() string {
		ttftQueue = newTTFTReportQueue()
		var s ttftSample
		s.Tenant, s.Model, s.Endpoint, s.Cache = "t", "m", "e", "miss"
		s.Buckets[0] = 1
		reps := ttftBuildReports(id, 100, []ttftSample{s}, 0)
		ttftQueue.appendAll(reps)
		return reps[0].BatchID
	}

	for _, c := range []struct {
		body string
	}{
		{`{"result":"ok"}`},
		{`{"result":"ok","dropped":3}`},
		{`{"result":"dropped"}`},
		{`{"result":"duplicate"}`},
	} {
		batchID := seed()
		ttftOnReportResponse(200, []byte(c.body), batchID)
		if ttftQueue.len() != 0 {
			t.Fatalf("确认成功应出队：body=%s len=%d", c.body, ttftQueue.len())
		}
	}
	for _, c := range []struct {
		status int
		body   string
	}{
		{400, `{"error":"invalid_request"}`},
		{404, `{"error":"not_found"}`},
		{503, `{"error":"source_unavailable"}`},
		{200, `{"foo":"bar"}`},
		{200, `not-json`},
		{500, ``},
	} {
		batchID := seed()
		ttftOnReportResponse(c.status, []byte(c.body), batchID)
		if ttftQueue.len() != 1 {
			t.Fatalf("未确认应保留重发：status=%d body=%s len=%d", c.status, c.body, ttftQueue.len())
		}
	}

	// ackByID：不匹配 no-op、精确移除（防误删新队头）
	ttftQueue = newTTFTReportQueue()
	samples := []ttftSample{
		{Tenant: "t", Model: "m", Endpoint: "e1", Cache: "miss"},
		{Tenant: "t", Model: "m", Endpoint: "e2", Cache: "miss"},
	}
	samples[0].Buckets[0], samples[1].Buckets[0] = 1, 1
	reps := ttftBuildReports(id, 100, samples, 1) // 2 批：|1 |2
	ttftQueue.appendAll(reps)
	ttftQueue.ackByID("no-such-batch")
	if ttftQueue.len() != 2 {
		t.Fatalf("不匹配 ack 不应改动：len=%d", ttftQueue.len())
	}
	ttftQueue.ackByID(reps[0].BatchID)
	if ttftQueue.len() != 1 {
		t.Fatalf("精确移除后应为 1：len=%d", ttftQueue.len())
	}
	if h, _ := ttftQueue.head(); h.BatchID != reps[1].BatchID {
		t.Fatalf("应仅移除匹配批次：head=%s want=%s", h.BatchID, reps[1].BatchID)
	}
}
