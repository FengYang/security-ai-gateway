package cacheengine

import (
	"testing"
	"time"
)

// TestReplay_SingleBlock 非流式 → 单分片。
func TestReplay_SingleBlock(t *testing.T) {
	cfg := DefaultConfig()
	r := NewReplayer(&cfg)

	entry := &Entry{
		Kind: KindExact,
		Text: "hello world",
	}

	segs := r.Replay(entry, false)
	if len(segs) != 1 {
		t.Fatalf("expected 1 segment, got %d", len(segs))
	}
	if segs[0].Text != "hello world" {
		t.Fatalf("unexpected text: %s", segs[0].Text)
	}
	if segs[0].At != 0 {
		t.Fatalf("expected At=0, got %v", segs[0].At)
	}
}

// TestReplay_StreamWithPacedGaps 流式回放 + gap 钳制。
func TestReplay_StreamWithPacedGaps(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Stream.Enabled = true
	cfg.Stream.MinGap = Duration(5 * time.Millisecond)
	cfg.Stream.MaxGap = Duration(100 * time.Millisecond)

	r := NewReplayer(&cfg)

	entry := &Entry{
		Kind: KindExact,
		Text: "abcdef",
		Segments: []Segment{
			{Text: "ab", At: 0},
			{Text: "cd", At: 2 * time.Millisecond},     // 太小，会被提到 MinGap
			{Text: "ef", At: 200 * time.Millisecond},   // 太大，会被降到 MaxGap
		},
	}

	segs := r.Replay(entry, true)
	if len(segs) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(segs))
	}

	// 第 0 个：At=0
	if segs[0].At != 0 {
		t.Fatalf("seg0 At: expected 0, got %v", segs[0].At)
	}

	// 第 1 个：gap 从 2ms 被提到 5ms → At=5ms
	if segs[1].At != 5*time.Millisecond {
		t.Fatalf("seg1 At: expected 5ms, got %v", segs[1].At)
	}

	// 第 2 个：gap 从 198ms 被降到 100ms → At=5+100=105ms
	if segs[2].At != 105*time.Millisecond {
		t.Fatalf("seg2 At: expected 105ms, got %v", segs[2].At)
	}
}

// TestReplay_NilEntry nil 条目返回 nil。
func TestReplay_NilEntry(t *testing.T) {
	cfg := DefaultConfig()
	r := NewReplayer(&cfg)

	segs := r.Replay(nil, false)
	if segs != nil {
		t.Fatal("expected nil for nil entry")
	}
}

// TestReplay_StreamNoSegments 流式但无分片 → 降级单块。
func TestReplay_StreamNoSegments(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Stream.Enabled = true
	r := NewReplayer(&cfg)

	entry := &Entry{Kind: KindExact, Text: "full text"}
	segs := r.Replay(entry, true)

	if len(segs) != 1 {
		t.Fatalf("expected 1 segment (fallback), got %d", len(segs))
	}
	if segs[0].Text != "full text" {
		t.Fatalf("unexpected text: %s", segs[0].Text)
	}
}

// TestSegmentsFor_Valid 合法分片 → 保留。
func TestSegmentsFor_Valid(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Stream.Enabled = true

	ctx := StoreContext{LookupContext: LookupContext{Stream: true}}
	res := InferResult{
		Finish: "stop",
		Segments: []Segment{
			{Text: "a", At: 0},
			{Text: "b", At: 10 * time.Millisecond},
		},
	}

	segs := segmentsFor(ctx, res, &cfg)
	if len(segs) != 2 {
		t.Fatalf("expected 2 segments, got %d", len(segs))
	}
}

// TestSegmentsFor_TooMany 分片数超限 → 降级。
func TestSegmentsFor_TooMany(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Stream.Enabled = true
	cfg.Stream.MaxSegments = 2

	ctx := StoreContext{LookupContext: LookupContext{Stream: true}}
	segs := make([]Segment, 5)
	for i := 0; i < 5; i++ {
		segs[i] = Segment{Text: "x", At: time.Duration(i) * time.Millisecond}
	}
	res := InferResult{Finish: "stop", Segments: segs}

	result := segmentsFor(ctx, res, &cfg)
	if result != nil {
		t.Fatal("expected nil when exceeding MaxSegments")
	}
}

// TestSegmentsFor_NotStream 非流式 → nil。
func TestSegmentsFor_NotStream(t *testing.T) {
	cfg := DefaultConfig()
	ctx := StoreContext{LookupContext: LookupContext{Stream: false}}
	res := InferResult{
		Finish:   "stop",
		Segments: []Segment{{Text: "x", At: 0}},
	}

	if segmentsFor(ctx, res, &cfg) != nil {
		t.Fatal("expected nil for non-stream")
	}
}
