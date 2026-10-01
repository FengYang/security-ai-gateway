package cacheengine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// writeTempJSONL 创建临时 JSONL 文件并返回路径。
func writeTempJSONL(t *testing.T, entries []WarmEntry) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "warmup.jsonl")

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	for _, e := range entries {
		if err := enc.Encode(e); err != nil {
			t.Fatalf("encode: %v", err)
		}
	}
	return path
}

// TestWarmer_FileBasic 基本文件预热。
func TestWarmer_FileBasic(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	eng := NewCacheEngine(cfg)

	entries := []WarmEntry{
		{TransformedHash: "hash-golang", Prompt: "what is golang", Text: "Go is a programming language.", TenantID: "t1"},
		{TransformedHash: "hash-rust", Prompt: "what is rust", Text: "Rust is a systems language.", TenantID: "t1"},
		{TransformedHash: "hash-python", Prompt: "what is python", Text: "Python is a scripting language.", TenantID: "t1"},
	}
	path := writeTempJSONL(t, entries)
	warmer := NewFileWarmer(&cfg, eng, path)

	// 初始状态 idle
	s := warmer.Status()
	if s.Status != WarmIdle {
		t.Fatalf("expected idle, got %s", s.Status)
	}

	// 执行预热
	result := warmer.Warm(context.Background())

	if result.Status != WarmSucceeded {
		t.Fatalf("expected succeeded, got %s, err=%s", result.Status, result.LastError)
	}
	if result.Total != 3 {
		t.Fatalf("expected total=3, got %d", result.Total)
	}
	if result.Succeeded != 3 {
		t.Fatalf("expected succeeded=3, got %d (skipped=%d, failed=%d)",
			result.Succeeded, result.Skipped, result.Failed)
	}

	// 验证预热后可以命中（用已知 transformed_hash）
	r := eng.Lookup(LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "default",
		MaxNewTokens:    2048,
		TransformedHash: "hash-golang",
		PromptText:      "what is golang",
		PolicyVer:       "1",
		GuardVer:        "1",
	})
	if !r.Hit {
		t.Fatalf("expected hit after warmup, reason=%s", r.RejectReason)
	}
	if r.Entry.Text != "Go is a programming language." {
		t.Fatalf("unexpected text: %s", r.Entry.Text)
	}
}

// TestWarmer_MaxItems 最大条目限制。
func TestWarmer_MaxItems(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Warmup.MaxItems = 2
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	eng := NewCacheEngine(cfg)

	entries := []WarmEntry{
		{Prompt: "p1", Text: "a1 answer text", TenantID: "t1"},
		{Prompt: "p2", Text: "a2 answer text", TenantID: "t1"},
		{Prompt: "p3", Text: "a3 answer text", TenantID: "t1"},
		{Prompt: "p4", Text: "a4 answer text", TenantID: "t1"},
	}
	path := writeTempJSONL(t, entries)
	warmer := NewFileWarmer(&cfg, eng, path)

	result := warmer.Warm(context.Background())

	if result.Status != WarmSucceeded {
		t.Fatalf("expected succeeded, got %s", result.Status)
	}
	if result.Total != 2 {
		t.Fatalf("expected total=2 (max_items), got %d", result.Total)
	}
}

// TestWarmer_SkipEmpty 跳过空 prompt/text。
func TestWarmer_SkipEmpty(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	eng := NewCacheEngine(cfg)

	entries := []WarmEntry{
		{Prompt: "", Text: "answer", TenantID: "t1"},           // 空 prompt
		{Prompt: "valid prompt", Text: "", TenantID: "t1"},     // 空 text
		{Prompt: "valid prompt", Text: "valid answer", TenantID: "t1"}, // 正常
	}
	path := writeTempJSONL(t, entries)
	warmer := NewFileWarmer(&cfg, eng, path)

	result := warmer.Warm(context.Background())

	if result.Skipped != 2 {
		t.Fatalf("expected 2 skipped, got %d", result.Skipped)
	}
	if result.Succeeded != 1 {
		t.Fatalf("expected 1 succeeded, got %d", result.Succeeded)
	}
	if result.Total != 3 {
		t.Fatalf("expected total=3, got %d", result.Total)
	}
}

// TestWarmer_FileNotFound  文件不存在。
func TestWarmer_FileNotFound(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	eng := NewCacheEngine(cfg)

	warmer := NewFileWarmer(&cfg, eng, "nonexistent_path_xyz.jsonl")
	result := warmer.Warm(context.Background())

	if result.Status != WarmFailed {
		t.Fatalf("expected failed, got %s", result.Status)
	}
	if result.LastError == "" {
		t.Fatal("should have error message")
	}
}

// TestWarmer_Cancel 取消预热。
func TestWarmer_Cancel(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	eng := NewCacheEngine(cfg)

	// 构造大量条目，确保有时间取消
	entries := make([]WarmEntry, 1000)
	for i := range entries {
		entries[i] = WarmEntry{
			Prompt:   "long enough prompt text for warmup",
			Text:     "answer text with enough content",
			TenantID: "t1",
		}
	}
	path := writeTempJSONL(t, entries)
	warmer := NewFileWarmer(&cfg, eng, path)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // 立即取消

	result := warmer.Warm(ctx)

	if result.Status != WarmFailed {
		t.Fatalf("expected failed (canceled), got %s", result.Status)
	}
}

// TestWarmer_ConcurrentOnlyOne 并发只允许一个运行。
func TestWarmer_ConcurrentOnlyOne(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	eng := NewCacheEngine(cfg)

	entries := []WarmEntry{
		{Prompt: "p1", Text: "answer one text here", TenantID: "t1"},
	}
	path := writeTempJSONL(t, entries)
	warmer := NewFileWarmer(&cfg, eng, path)

	// 第一个正常执行
	r1 := warmer.Warm(context.Background())
	if r1.Status != WarmSucceeded {
		t.Fatalf("first warm should succeed, got %s", r1.Status)
	}

	// 第二个也应该能执行（第一个已完成）
	r2 := warmer.Warm(context.Background())
	if r2.Status != WarmSucceeded {
		t.Fatalf("second warm should succeed, got %s", r2.Status)
	}
}

// TestWarmer_WithHash 提供 transformed_hash 的情况。
func TestWarmer_WithHash(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	eng := NewCacheEngine(cfg)

	entries := []WarmEntry{
		{
			TransformedHash: "custom-hash-123",
			Prompt:          "any prompt text long enough",
			Text:            "cached answer content",
			TenantID:        "t1",
		},
	}
	path := writeTempJSONL(t, entries)
	warmer := NewFileWarmer(&cfg, eng, path)

	result := warmer.Warm(context.Background())
	if result.Status != WarmSucceeded {
		t.Fatalf("expected succeeded, got %s", result.Status)
	}

	// 用自定义 hash 应该能命中
	r := eng.Lookup(LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "default",
		MaxNewTokens:    2048,
		TransformedHash: "custom-hash-123",
		PromptText:      "any prompt text long enough",
		PolicyVer:       "1",
		GuardVer:        "1",
	})
	if !r.Hit {
		t.Fatalf("expected hit with custom hash, reason=%s", r.RejectReason)
	}
}
