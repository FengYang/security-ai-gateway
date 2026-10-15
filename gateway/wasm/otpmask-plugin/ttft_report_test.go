package main

// ttft_report_test.go — P1-6 M2.2：固定桶计数结构（§3.4；桶边界逐字段对齐 tee-infer）。

import "testing"

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
