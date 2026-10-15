package main

// ttft_report_test.go — P1-6 M2.2/M2.3：固定桶计数结构 + 标识解析/上报体构造与拆分。

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"testing"
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
