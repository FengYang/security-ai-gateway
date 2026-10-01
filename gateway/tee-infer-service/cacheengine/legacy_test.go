package cacheengine

import (
	"testing"
)

// TestLegacyAdapter_GetPut 旧接口 Get/Put 基本功能。
func TestLegacyAdapter_GetPut(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)
	adapter := NewLegacyAdapter(eng)

	// 空 → miss
	if _, ok := adapter.Get("key1"); ok {
		t.Fatal("expected miss on empty cache")
	}

	// 写入
	adapter.Put("key1", "value1")

	// 命中
	val, ok := adapter.Get("key1")
	if !ok {
		t.Fatal("expected hit")
	}
	if val != "value1" {
		t.Fatalf("expected 'value1', got '%s'", val)
	}
}

// TestLegacyAdapter_KeyIsolation 不同 key 互不干扰。
func TestLegacyAdapter_KeyIsolation(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeExact
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false

	eng := NewCacheEngine(cfg)
	adapter := NewLegacyAdapter(eng)

	adapter.Put("k1", "v1")
	adapter.Put("k2", "v2")

	v1, ok1 := adapter.Get("k1")
	v2, ok2 := adapter.Get("k2")
	_, ok3 := adapter.Get("k3")

	if !ok1 || v1 != "v1" {
		t.Fatal("k1 mismatch")
	}
	if !ok2 || v2 != "v2" {
		t.Fatal("k2 mismatch")
	}
	if ok3 {
		t.Fatal("k3 should miss")
	}
}

// TestLegacyAdapter_ModeOff mode=off 时永不命中。
func TestLegacyAdapter_ModeOff(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Mode = ModeOff

	eng := NewCacheEngine(cfg)
	adapter := NewLegacyAdapter(eng)

	adapter.Put("k1", "v1")

	if _, ok := adapter.Get("k1"); ok {
		t.Fatal("expected miss when mode=off")
	}
}
