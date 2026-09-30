package cacheengine

import (
	"bytes"
	"strings"
	"testing"
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
		"otpmask_cache_exact_entries",
		"otpmask_cache_negative_entries",
		"otpmask_cache_vector_entries",
		"otpmask_cache_evictions_total",
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
}
