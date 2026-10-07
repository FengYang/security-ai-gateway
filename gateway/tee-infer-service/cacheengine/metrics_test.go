package cacheengine

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// TestRenderPrometheus 测试 Prometheus 指标渲染。
func TestRenderPrometheus(t *testing.T) {
	cfg := testConfig()
	cfg.Mode = ModeExact
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)
	e := eng.(*engine)

	// 做一些查询和写入产生数据
	ctx := LookupContext{
		TenantID:     "t1",
		EngineType:   "cmaas",
		Model:        "m1",
		MaxNewTokens: 100,
		TransformedHash: "abc123",
		PromptText:   "test prompt long enough",
		PolicyVer:    "1",
		GuardVer:     "v1",
	}

	// 3 次 miss
	for i := 0; i < 3; i++ {
		eng.Lookup(ctx)
	}

	// 写入
	eng.Store(StoreContext{LookupContext: ctx, Writable: true}, InferResult{
		Text:      "answer text",
		TokensOut: 10,
		Finish:    "stop",
	})

	// 1 次 hit
	eng.Lookup(ctx)

	// 渲染
	var buf bytes.Buffer
	e.RenderPrometheus(&buf)
	output := buf.String()

	// 验证关键指标存在
	checks := []string{
		"otpmask_cache_lookups_total",
		"otpmask_cache_lookup_duration_seconds",
		"otpmask_cache_entries",
		"otpmask_cache_evictions_total",
		"otpmask_cache_panic_total",
		"otpmask_cache_read_fast_check_block_total",
		"otpmask_cache_saved_tokens_total",
		"otpmask_cache_mode",
	}

	for _, name := range checks {
		if !strings.Contains(output, name) {
			t.Errorf("output missing metric: %s", name)
		}
	}

	// 验证 exact:miss 和 exact:hit 的值
	if !strings.Contains(output, `kind="exact",result="miss"`) {
		t.Error("output missing exact:miss label")
	}
	if !strings.Contains(output, `kind="exact",result="hit"`) {
		t.Error("output missing exact:hit label")
	}

	// 验证 mode 标签
	if !strings.Contains(output, `mode="exact"`) {
		t.Error("output missing mode=exact label")
	}

	// 条目数按 store 标签输出（详设 §9.1 #3）
	if !strings.Contains(output, `otpmask_cache_entries{store="exact"}`) {
		t.Error("output missing otpmask_cache_entries{store=\"exact\"}")
	}
	// 查询耗时直方图存在 _count/_sum/_bucket（详设 §9.1 #2）
	if !strings.Contains(output, "otpmask_cache_lookup_duration_seconds_count") ||
		!strings.Contains(output, "otpmask_cache_lookup_duration_seconds_sum") ||
		!strings.Contains(output, "otpmask_cache_lookup_duration_seconds_bucket") {
		t.Error("output missing lookup duration histogram series")
	}
}

// TestRenderPrometheus_Jitter 抖动注入量直方图渲染（§9.1 #11；path=hit|miss）。
func TestRenderPrometheus_Jitter(t *testing.T) {
	cfg := testConfig()
	eng := NewCacheEngine(cfg).(*engine)
	eng.RecordJitter("hit", 3*time.Millisecond)
	eng.RecordJitter("miss", 1*time.Millisecond)

	var buf bytes.Buffer
	eng.RenderPrometheus(&buf)
	out := buf.String()
	for _, want := range []string{
		"otpmask_cache_jitter_seconds_bucket",
		"otpmask_cache_jitter_seconds_sum",
		`otpmask_cache_jitter_seconds_count{path="hit"} 1`,
		`otpmask_cache_jitter_seconds_count{path="miss"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("jitter 指标渲染缺失：%s\n%s", want, out)
		}
	}
}

// TestRenderPrometheus_WriteRejectedAndFastCheck R3（§9.1 #5 写入被拒 / #9 快审错误 / #10 快审耗时）。
func TestRenderPrometheus_WriteRejectedAndFastCheck(t *testing.T) {
	cfg := testConfig()
	cfg.Guard.ReadFastCheck = true
	eng := NewCacheEngine(cfg)
	e := eng.(*engine)

	// #5：TokensOut < MinTokens → too_short
	ctx := LookupContext{TenantID: "t1", EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
		TransformedHash: "h1", PromptText: "long enough prompt", PolicyVer: "1", GuardVer: "v1"}
	eng.Store(StoreContext{LookupContext: ctx, Writable: true},
		InferResult{Text: "x", TokensOut: 0, Finish: "stop"})

	// #9/#10：分类器不可用 → error + 耗时观测
	e.scanner = &mockScanner{avail: false}
	_, _, _ = e.readFastCheck(&Entry{Text: "cached text", GuardVer: "v1", Kind: KindExact}, "v1")

	var buf bytes.Buffer
	eng.RenderPrometheus(&buf)
	out := buf.String()
	for _, want := range []string{
		`otpmask_cache_write_rejected_total{reason="too_short"} 1`,
		"otpmask_cache_read_fast_check_error_total 1",
		"otpmask_cache_read_fast_check_duration_seconds_count 1",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("缺指标：%s\n%s", want, out)
		}
	}
}

// TestObserveLookup_InvalidKindPanics 非法 kind 标签必须 panic（§9.1 硬约束）。
func TestObserveLookup_InvalidKindPanics(t *testing.T) {
	s := newStatsCollector()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on invalid lookup kind")
		}
	}()
	s.observeLookup("bogus", "hit")
}

// TestObserveLookup_InvalidResultPanics 非法 result 标签必须 panic（§9.1 硬约束）。
func TestObserveLookup_InvalidResultPanics(t *testing.T) {
	s := newStatsCollector()
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on invalid lookup result")
		}
	}()
	s.observeLookup("exact", "bogus")
}

// TestObserveLookup_ValidEnums 合法枚举不 panic 且计数正确。
func TestObserveLookup_ValidEnums(t *testing.T) {
	s := newStatsCollector()
	for _, kind := range []string{"precheck", "exact", "negative", "semantic"} {
		for _, result := range []string{"hit", "miss", "disabled", "not_cacheable", "fastcheck_miss"} {
			s.observeLookup(kind, result)
		}
	}
	var snap StatsSnapshot
	s.fillSnapshot(&snap)
	if len(snap.Lookups) != 20 {
		t.Fatalf("expected 20 lookup series, got %d", len(snap.Lookups))
	}
}
