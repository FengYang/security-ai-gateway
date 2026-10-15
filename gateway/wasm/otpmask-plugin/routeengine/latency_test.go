package routeengine

import (
	"encoding/json"
	"testing"
)

// ============================================================
// M1.1 验收（本体 v1.5 §4.1 M1.1 / §6.1 / §6.3）：
//   - 结构存在性与类型（编译期断言）
//   - JSON 标签与 §6.1 latency 字段表、§6.3 stats 条目逐字段一致
//   - normalized() 仅越界钳制：非法范围回缺省，合法显式 0 值保留
// ============================================================

// 编译期结构断言：字段名与类型逐一固定（改动字段会在此处编译失败）。
var (
	_ = TTFTStat{
		P50Ms:     int64(0),
		P95Ms:     int64(0),
		Samples:   int64(0),
		Valid:     false,
		UpdatedAt: int64(0),
		Cache:     "miss",
	}
	_ = LatencyConfig{
		WindowSec:      int(0),
		Quantile:       "",
		Gamma:          float64(0),
		MinWeight:      float64(0),
		ExploreRatio:   float64(0),
		MinSamples:     int(0),
		StaleSec:       int(0),
		CachePartition: false,
		MaxTTFTMs:      int64(0),
	}
)

// TestLatencyConfig_JSONFieldsMatchSchema：§6.1 字段表 9 字段逐一核对。
func TestLatencyConfig_JSONFieldsMatchSchema(t *testing.T) {
	raw, err := json.Marshal(LatencyConfig{
		WindowSec:      300,
		Quantile:       "p95",
		Gamma:          1.0,
		MinWeight:      0.05,
		ExploreRatio:   0.05,
		MinSamples:     20,
		StaleSec:       75,
		CachePartition: true,
		MaxTTFTMs:      30000,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{
		"window_sec", "quantile", "gamma", "min_weight", "explore_ratio",
		"min_samples", "stale_sec", "cache_partition", "max_ttft_ms",
	}
	if len(got) != len(want) {
		t.Fatalf("JSON 字段数=%d，期望 %d：%v", len(got), len(want), raw)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("缺少字段 %q（JSON 标签须与 §6.1 字段表一致）", k)
		}
	}
}

// TestTTFTStat_JSONFieldsMatchStatsContract：§6.3 stats 条目 6 字段逐一核对。
func TestTTFTStat_JSONFieldsMatchStatsContract(t *testing.T) {
	raw, err := json.Marshal(TTFTStat{
		P50Ms: 210, P95Ms: 480, Samples: 1200, Valid: true, UpdatedAt: 1760000000, Cache: "miss",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := []string{"p50_ms", "p95_ms", "samples", "valid", "updated_at", "cache"}
	if len(got) != len(want) {
		t.Fatalf("JSON 字段数=%d，期望 %d：%v", len(got), len(want), raw)
	}
	for _, k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("缺少字段 %q（JSON 标签须与 §6.3 stats 条目一致）", k)
		}
	}
}

// TestLatencyConfig_Normalized：越界钳制与合法显式 0 值保留。
func TestLatencyConfig_Normalized(t *testing.T) {
	// 全零值：越界字段（window/quantile/min_samples/stale/max_ttft）回缺省；
	// gamma=0 / min_weight=0 / explore_ratio=0 为合法显式值，须保留。
	z := (LatencyConfig{}).normalized()
	if z.WindowSec != defaultLatencyWindowSec {
		t.Errorf("零值 window_sec 应为缺省 %d，got %d", defaultLatencyWindowSec, z.WindowSec)
	}
	if z.Quantile != defaultLatencyQuantile {
		t.Errorf("空 quantile 应为缺省 %q，got %q", defaultLatencyQuantile, z.Quantile)
	}
	if z.Gamma != 0 {
		t.Errorf("gamma=0 为合法显式值，不应被改写，got %v", z.Gamma)
	}
	if z.MinWeight != 0 {
		t.Errorf("min_weight=0 为合法显式值（范围 0–0.5），不应被改写，got %v", z.MinWeight)
	}
	if z.ExploreRatio != 0 {
		t.Errorf("explore_ratio=0 为合法显式值，不应被改写，got %v", z.ExploreRatio)
	}
	if z.MinSamples != defaultLatencyMinSamples {
		t.Errorf("min_samples=0 应回缺省 %d，got %d", defaultLatencyMinSamples, z.MinSamples)
	}
	if z.StaleSec != defaultLatencyStaleSec {
		t.Errorf("stale_sec=0 应回缺省 %d，got %d", defaultLatencyStaleSec, z.StaleSec)
	}
	if z.MaxTTFTMs != defaultLatencyMaxTTFTMs {
		t.Errorf("max_ttft_ms=0 应回缺省 %d，got %d", defaultLatencyMaxTTFTMs, z.MaxTTFTMs)
	}

	cases := []struct {
		name string
		in   LatencyConfig
		chk  func(LatencyConfig) bool
		desc string
	}{
		{"window-too-small", LatencyConfig{WindowSec: 10, Quantile: "p95", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.WindowSec == 300 }, "window_sec<60 → 300"},
		{"window-too-large", LatencyConfig{WindowSec: 4000, Quantile: "p95", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.WindowSec == 300 }, "window_sec>3600 → 300"},
		{"quantile-p99", LatencyConfig{WindowSec: 300, Quantile: "p99", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Quantile == "p95" }, "quantile 非 p50/p95 → p95"},
		{"gamma-negative", LatencyConfig{WindowSec: 300, Quantile: "p95", Gamma: -0.1, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Gamma == 1.0 }, "gamma<0 → 1.0"},
		{"gamma-too-large", LatencyConfig{WindowSec: 300, Quantile: "p95", Gamma: 6, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Gamma == 1.0 }, "gamma>5 → 1.0"},
		{"minweight-too-large", LatencyConfig{WindowSec: 300, Quantile: "p95", MinWeight: 0.6, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.MinWeight == 0.05 }, "min_weight>0.5 → 0.05"},
		{"explore-too-large", LatencyConfig{WindowSec: 300, Quantile: "p95", ExploreRatio: 1.5, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.ExploreRatio == 0.05 }, "explore_ratio>1 → 0.05"},
		{"stale-too-small", LatencyConfig{WindowSec: 300, Quantile: "p95", MinSamples: 20, StaleSec: 24, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.StaleSec == 75 }, "stale_sec<25 → 75"},
		{"maxttft-too-small", LatencyConfig{WindowSec: 300, Quantile: "p95", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 999},
			func(c LatencyConfig) bool { return c.MaxTTFTMs == 30000 }, "max_ttft_ms<1000 → 30000"},
		// 合法边界值原样保留
		{"legal-gamma-5", LatencyConfig{WindowSec: 300, Quantile: "p95", Gamma: 5, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Gamma == 5 }, "gamma=5 合法边界保留"},
		{"legal-explore-1", LatencyConfig{WindowSec: 300, Quantile: "p95", ExploreRatio: 1, MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.ExploreRatio == 1 }, "explore_ratio=1 合法边界保留"},
		{"legal-quantile-p50", LatencyConfig{WindowSec: 300, Quantile: "p50", MinSamples: 20, StaleSec: 75, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.Quantile == "p50" }, "quantile=p50 保留"},
		{"legal-stale-25", LatencyConfig{WindowSec: 300, Quantile: "p95", MinSamples: 20, StaleSec: 25, MaxTTFTMs: 30000},
			func(c LatencyConfig) bool { return c.StaleSec == 25 }, "stale_sec=25 合法边界保留"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.in.normalized(); !tc.chk(got) {
				t.Errorf("%s：断言失败，got %+v", tc.desc, got)
			}
		})
	}
}
