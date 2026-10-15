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
