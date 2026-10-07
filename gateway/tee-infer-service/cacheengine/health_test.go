package cacheengine

import (
	"bytes"
	"strings"
	"testing"
)

// TestHealth_ReadOnlyWatermark §6.9.2：高水位只读（停写可读），回落恢复写。
func TestHealth_ReadOnlyWatermark(t *testing.T) {
	eng := NewCacheEngine(runtimeCfg(false)) // watermark_high=0.9 / low=0.8
	e := eng.(*engine)
	sc := l1StoreCtx()

	if out := eng.Store(sc, InferResult{Text: "a", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store: %+v", out)
	}

	// 高水位 → 只读
	e.UpdateReadOnly(0.95)
	if !e.IsReadOnly() {
		t.Fatal("expected read-only at high watermark")
	}
	out := eng.Store(sc, InferResult{Text: "b", TokensOut: 20, Finish: "stop"})
	if out.Stored || out.Skipped != "readonly" {
		t.Fatalf("expected readonly skip, got %+v", out)
	}
	if got := e.stats.disabledSnapshot()["readonly"]; got != 1 {
		t.Fatalf("disabled_total{readonly} = %d, want 1", got)
	}
	// 只读期间读仍可用
	if r := eng.Lookup(sc.LookupContext); !r.Hit {
		t.Fatalf("read must still work in read-only mode, reason=%s", r.RejectReason)
	}

	// 回落 → 恢复写
	e.UpdateReadOnly(0.7)
	if e.IsReadOnly() {
		t.Fatal("expected writable after watermark low")
	}
	if out := eng.Store(sc, InferResult{Text: "c", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store after recovery: %+v", out)
	}
}

// TestHealth_ClockSkew §6.9.1：时钟回拨计数，前进不计数。
func TestHealth_ClockSkew(t *testing.T) {
	e := NewCacheEngine(runtimeCfg(false)).(*engine)

	if e.CheckClockSkew(1000) {
		t.Fatal("first observation must not be skew")
	}
	if !e.CheckClockSkew(900) {
		t.Fatal("expected skew on backward clock")
	}
	if e.stats.clockSkewCount() != 1 {
		t.Fatalf("clock_skew = %d, want 1", e.stats.clockSkewCount())
	}
	if e.CheckClockSkew(1100) {
		t.Fatal("forward clock must not count as skew")
	}
}

// TestHealth_MetricsRendered §9.1 #24/#25/#27：新增指标可渲染。
func TestHealth_MetricsRendered(t *testing.T) {
	e := NewCacheEngine(runtimeCfg(false)).(*engine)
	e.SetEstimatedBytes(12345)
	e.UpdateReadOnly(0.95)

	var buf bytes.Buffer
	e.RenderPrometheus(&buf)
	out := buf.String()
	for _, want := range []string{
		"otpmask_cache_estimated_bytes 12345",
		"otpmask_cache_readonly 1",
		"otpmask_cache_clock_skew_total",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("metrics output missing %q", want)
		}
	}
}
