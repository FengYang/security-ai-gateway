package main

// compat_test.go — P1-6 M6.6：插件侧兼容测试（§9.1「兼容测试」）。
//
// 逐条对齐 §9.1：
//   - 旧路由表（无 latency、无 strategy）→ 引擎配置与 P0-1 一致（策略缺省、latency 全缺省、
//     端点原样保留、灰度不启用），行为不变量（C-8/V-7）；
//   - `/metrics` 既有输出不变：P1-6 之前的全部 Counter 名称逐一冻结，P1-6 增量**仅新增**
//     （无改名/无删除/无重名）；既有 Histogram 桶命名（latency/tokens）保持不变。
//
// 逐字节口径（CanonicalBytes/验签）由 internal/route 与 routecache 的基线单测覆盖，
// 本文件只补「配置映射 + 指标命名」的兼容面。

import (
	"testing"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routecache"
	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
)

// TestCompat_LegacyRouteBuildsDefaultConfig 旧路由表（P1-6 之前形态）→ 引擎配置与 P0-1 一致。
func TestCompat_LegacyRouteBuildsDefaultConfig(t *testing.T) {
	legacy := &routecache.TableRoute{
		Tenant: "t-legacy", Model: "qwen-max", DefaultEngine: "cmaas",
		Endpoints: []routecache.TableEndpoint{
			{Name: "e1", URL: "https://e1.internal/v1", Weight: 1, Priority: 1, Enabled: true},
			{Name: "e2", URL: "https://e2.internal/v1", Weight: 0, Priority: 2, Enabled: true},
		},
	}
	cfg := buildEngineConfig(legacy)
	if cfg.Strategy != routeengine.StrategyPriority {
		t.Fatalf("旧表缺省策略应 priority（与 P0-1 一致），got %q", cfg.Strategy)
	}
	if cfg.Latency != routeengine.DefaultLatencyConfig() {
		t.Fatalf("旧表 latency 应全缺省：%+v", cfg.Latency)
	}
	if len(cfg.Endpoints) != 2 || cfg.Endpoints[0].Name != "e1" || cfg.Endpoints[1].Name != "e2" {
		t.Fatalf("旧表端点应原样保留：%+v", cfg.Endpoints)
	}
	if cfg.Canary.Enabled {
		t.Fatalf("旧表不应启用灰度：%+v", cfg.Canary)
	}
}

// legacyCounterNames P1-6 之前的既有 Counter 名称冻结基线（§9.1「/metrics 既有输出不变」）。
// 键 = 指标名；值 = 对应的包级 Counter（比对 name 字段逐字一致）。
func legacyCounterNames() map[string]*pwCounter {
	return map[string]*pwCounter{
		"otpmask_request_total":                   metricRequests,
		"otpmask_fail_closed_total":               metricFailClosed,
		"otpmask_decrypt_error_total":             metricDecryptError,
		"otpmask_content_filter_total":            metricContentFilter,
		"otpmask_keys_issued_total":               metricKeysIssued,
		"otpmask_keys_deleted_total":              metricKeysDeleted,
		"otpmask_route_degraded_total":            metricRouteDegraded,
		"otpmask_route_fetch_cb_total":            metricRouteFetchCb,
		"otpmask_route_fetch_ok_total":            metricRouteFetchOK,
		"otpmask_route_fetch_reject_total":        metricRouteFetchReject,
		"otpmask_cred_fetch_cb_total":             metricCredFetchCb,
		"otpmask_cred_fetch_ok_total":             metricCredFetchOK,
		"otpmask_cred_fetch_reject_total":         metricCredFetchReject,
		"otpmask_ratelimit_fetch_cb_total":        metricRateLimitFetchCb,
		"otpmask_ratelimit_fetch_ok_total":        metricRateLimitFetchOK,
		"otpmask_ratelimit_fetch_reject_total":    metricRateLimitFetchReject,
		"otpmask_ratelimit_degraded_total":        metricRateLimitDegraded,
		"otpmask_core_channel_fetch_cb_total":     metricChannelFetchCb,
		"otpmask_core_channel_fetch_ok_total":     metricChannelFetchOK,
		"otpmask_core_channel_fetch_reject_total": metricChannelFetchReject,
		"otpmask_masked_total":                    metricMasked,
		"otpmask_content_label_injected_total":    metricContentLabelInjected,
		"otpmask_route_requests_total":            metricRouteRequests,
		"otpmask_route_degrade_events_total":      metricRouteDegradeEvents,
		"otpmask_route_config_reload_total":       metricRouteConfigReload,
		"otpmask_route_retry_total":               metricRouteRetry,
		"otpmask_route_canary_whitelist_total":    metricRouteCanaryWhitelist,
		"otpmask_route_canary_treatment_total":    metricRouteCanaryTreatment,
		"otpmask_route_canary_control_total":      metricRouteCanaryControl,
		"otpmask_route_tokens_input_total":        metricRouteTokensInput,
		"otpmask_route_tokens_output_total":       metricRouteTokensOutput,
		"otpmask_audit_report_sent_total":         metricAuditReportSent,
		"otpmask_audit_report_dropped_total":      metricAuditReportDropped,
		"otpmask_audit_report_fail_total":         metricAuditReportFail,
	}
}

// p16AddedCounterNames P1-6 新增 Counter（仅新增，不得与既有名冲突）。
func p16AddedCounterNames() map[string]*pwCounter {
	return map[string]*pwCounter{
		"otpmask_route_ttft_report_cb_total":            metricTTFTReportCb,
		"otpmask_route_ttft_report_ok_total":            metricTTFTReportOK,
		"otpmask_route_ttft_report_reject_total":        metricTTFTReportReject,
		"otpmask_route_ttft_report_drop_total":          metricTTFTReportDrop,
		"otpmask_route_ttft_stats_fetch_cb_total":       metricTTFTStatsFetchCb,
		"otpmask_route_ttft_stats_fetch_ok_total":       metricTTFTStatsFetchOK,
		"otpmask_route_ttft_stats_fetch_reject_total":   metricTTFTStatsFetchReject,
		"otpmask_route_latency_pick_weighted_total":     metricRouteLatencyPickWeighted,
		"otpmask_route_latency_pick_fastest_total":      metricRouteLatencyPickFastest,
		"otpmask_route_latency_pick_hybrid_total":       metricRouteLatencyPickHybrid,
		"otpmask_route_ttft_fallback_unreachable_total": metricRouteTTFTFallbackUnreachable,
		"otpmask_route_ttft_fallback_stale_total":       metricRouteTTFTFallbackStale,
		"otpmask_route_ttft_fallback_low_samples_total": metricRouteTTFTFallbackLowSamples,
		"otpmask_route_ttft_fallback_no_samples_total":  metricRouteTTFTFallbackNoSamples,
		"otpmask_route_ttft_fallback_no_rand_total":     metricRouteTTFTFallbackNoRand,
		"otpmask_route_strategy_unknown_total":          metricRouteStrategyUnknown,
	}
}

// TestCompat_MetricsLegacyNamesUnchanged 既有 Counter 名称逐字冻结（改名/删除即失败）。
func TestCompat_MetricsLegacyNamesUnchanged(t *testing.T) {
	for want, c := range legacyCounterNames() {
		if c == nil {
			t.Fatalf("既有 Counter %q 未定义（被删除）", want)
		}
		if c.name != want {
			t.Fatalf("既有 Counter 改名：want %q got %q", want, c.name)
		}
	}
}

// TestCompat_MetricsAdditiveOnly P1-6 指标仅新增：新增名存在、且与既有名无重名。
func TestCompat_MetricsAdditiveOnly(t *testing.T) {
	legacy := legacyCounterNames()
	added := p16AddedCounterNames()
	for want, c := range added {
		if c == nil {
			t.Fatalf("P1-6 新增 Counter %q 未定义", want)
		}
		if c.name != want {
			t.Fatalf("P1-6 新增 Counter 命名不符：want %q got %q", want, c.name)
		}
		if _, dup := legacy[want]; dup {
			t.Fatalf("P1-6 新增 Counter 与既有名冲突：%q", want)
		}
	}
	// 全套名称唯一（无重名/无覆盖）。
	seen := map[string]bool{}
	for n := range legacy {
		seen[n] = true
	}
	for n := range added {
		if seen[n] {
			t.Fatalf("指标名重复：%q", n)
		}
		seen[n] = true
	}
}

// TestCompat_LegacyHistogramBucketsUnchanged 既有 Histogram 桶命名（latency/tokens）不变；
// P1-6 新增 TTFT 桶为独立命名空间（不覆盖既有）。
func TestCompat_LegacyHistogramBucketsUnchanged(t *testing.T) {
	if len(latencyBucketCounters) == 0 || len(tokenBucketCounters) == 0 {
		t.Fatal("既有 Histogram 桶 Counter 未初始化")
	}
	for i, le := range latencyBuckets {
		want := "otpmask_route_latency_seconds_bucket_le_" + formatFloatForMetric(le)
		if latencyBucketCounters[i].name != want {
			t.Fatalf("latency 桶 %d 命名漂移：got %q want %q", i, latencyBucketCounters[i].name, want)
		}
	}
	for i, le := range tokenBuckets {
		want := "otpmask_route_tokens_bucket_le_" + formatFloatForMetric(le)
		if tokenBucketCounters[i].name != want {
			t.Fatalf("tokens 桶 %d 命名漂移：got %q want %q", i, tokenBucketCounters[i].name, want)
		}
	}
	// P1-6 TTFT 桶独立命名空间（前缀不与既有冲突）。
	for i := range ttftBucketCounters {
		if len(ttftBucketCounters[i].name) < len("otpmask_route_ttft_seconds_bucket_le_") ||
			ttftBucketCounters[i].name[:len("otpmask_route_ttft_seconds_bucket_le_")] != "otpmask_route_ttft_seconds_bucket_le_" {
			t.Fatalf("TTFT 桶 %d 命名不符：%q", i, ttftBucketCounters[i].name)
		}
	}
}
