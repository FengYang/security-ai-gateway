package cacheengine

import (
	"testing"
	"time"
)

// ===== Duration / ByteSize 解析 =====

func TestDuration_Unmarshal(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{`"5s"`, 5 * time.Second},
		{`"200ms"`, 200 * time.Millisecond},
		{`"1h"`, time.Hour},
		{`5000000000`, 5 * time.Second}, // 整数 = 纳秒
		{`null`, 0},
		{`""`, 0},
	}
	for _, c := range cases {
		var d Duration
		if err := d.UnmarshalJSON([]byte(c.in)); err != nil {
			t.Fatalf("unmarshal %s: %v", c.in, err)
		}
		if d.D() != c.want {
			t.Fatalf("unmarshal %s: got %v, want %v", c.in, d.D(), c.want)
		}
	}
}

func TestDuration_UnmarshalInvalid(t *testing.T) {
	var d Duration
	if err := d.UnmarshalJSON([]byte(`"abc"`)); err == nil {
		t.Fatal("expected error for invalid duration string")
	}
}

func TestByteSize_Unmarshal(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{`"256MB"`, 256 * 1024 * 1024},
		{`"64KB"`, 64 * 1024},
		{`"1GB"`, 1024 * 1024 * 1024},
		{`"512B"`, 512},
		{`"1024"`, 1024},
		{`65536`, 65536},
		{`null`, 0},
	}
	for _, c := range cases {
		var b ByteSize
		if err := b.UnmarshalJSON([]byte(c.in)); err != nil {
			t.Fatalf("unmarshal %s: %v", c.in, err)
		}
		if b.Bytes() != c.want {
			t.Fatalf("unmarshal %s: got %d, want %d", c.in, b.Bytes(), c.want)
		}
	}
}

func TestByteSize_UnmarshalInvalid(t *testing.T) {
	var b ByteSize
	if err := b.UnmarshalJSON([]byte(`"12XB"`)); err == nil {
		t.Fatal("expected error for invalid byte size")
	}
}

// ===== 配置加载 =====

func TestLoadConfigBytes_Defaults(t *testing.T) {
	cfg, err := LoadConfigBytes([]byte(`{}`))
	if err != nil {
		t.Fatalf("load defaults: %v", err)
	}
	if cfg.Mode != ModeOff {
		t.Fatalf("empty config must keep default mode=off, got %s", cfg.Mode)
	}
	if cfg.Exact.TTL.D() != 3600*time.Second {
		t.Fatalf("default exact.ttl mismatch: %v", cfg.Exact.TTL.D())
	}
}

func TestLoadConfigBytes_DurationAndSize(t *testing.T) {
	cfg, err := LoadConfigBytes([]byte(`{
		"mode": "exact",
		"cache_memory_budget": "1GB",
		"exact": {"ttl": "1800s", "max_entry_bytes": "64KB"}
	}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Exact.TTL.D() != 1800*time.Second {
		t.Fatalf("exact.ttl: got %v", cfg.Exact.TTL.D())
	}
	if cfg.Exact.MaxEntryBytes.Bytes() != 64*1024 {
		t.Fatalf("max_entry_bytes: got %d", cfg.Exact.MaxEntryBytes.Bytes())
	}
	if cfg.CacheMemoryBudget.Bytes() != 1024*1024*1024 {
		t.Fatalf("cache_memory_budget: got %d", cfg.CacheMemoryBudget.Bytes())
	}
}

// TestLoadConfigBytes_CodeMathTags 验证 code/math 标签不再错位（P0 缺陷回归锚）。
func TestLoadConfigBytes_CodeMathTags(t *testing.T) {
	cfg, err := LoadConfigBytes([]byte(`{
		"mode": "semantic",
		"semantic": {
			"enabled": true,
			"threshold": {"factual": 0.93, "general": 0.87, "code": 0.97, "math": 0.95}
		}
	}`))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Semantic.Threshold.Code != 0.97 {
		t.Fatalf("threshold.code: got %v, want 0.97", cfg.Semantic.Threshold.Code)
	}
	if cfg.Semantic.Threshold.Math != 0.95 {
		t.Fatalf("threshold.math: got %v, want 0.95", cfg.Semantic.Threshold.Math)
	}
}

func TestLoadConfigBytes_WrapperForm(t *testing.T) {
	cfg, err := LoadConfigBytes([]byte(`{"cache": {"mode": "exact"}}`))
	if err != nil {
		t.Fatalf("load wrapper: %v", err)
	}
	if cfg.Mode != ModeExact {
		t.Fatalf("mode: got %s, want exact", cfg.Mode)
	}
}

func TestLoadConfigBytes_UnknownField(t *testing.T) {
	if _, err := LoadConfigBytes([]byte(`{"nope": 1}`)); err == nil {
		t.Fatal("expected error for unknown field")
	}
}

func TestLoadConfigBytes_InvalidRule(t *testing.T) {
	// rule 5：exact.ttl < 1s
	if _, err := LoadConfigBytes([]byte(`{"exact": {"ttl": "0s"}}`)); err == nil {
		t.Fatal("expected validation error for exact.ttl < 1s")
	}
}

// ===== 环境变量覆盖 =====

func TestApplyEnv_Overrides(t *testing.T) {
	t.Setenv("CACHE_MODE", "exact")
	t.Setenv("CACHE_REDIS_ENABLED", "true")
	t.Setenv("CACHE_REDIS_ADDR", "redis.internal:6380")
	t.Setenv("CACHE_EMBEDDER_DIM", "1024")

	cfg := DefaultConfig()
	if err := ApplyEnv(&cfg); err != nil {
		t.Fatalf("apply env: %v", err)
	}
	if cfg.Mode != ModeExact {
		t.Fatalf("mode: got %s", cfg.Mode)
	}
	if !cfg.Redis.Enabled || cfg.Redis.Addr != "redis.internal:6380" {
		t.Fatalf("redis override failed: %+v", cfg.Redis)
	}
	if cfg.Semantic.Embedder.Dim != 1024 {
		t.Fatalf("embedder dim: got %d", cfg.Semantic.Embedder.Dim)
	}
}

func TestApplyEnv_InvalidBool(t *testing.T) {
	t.Setenv("CACHE_REDIS_ENABLED", "maybe")
	cfg := DefaultConfig()
	if err := ApplyEnv(&cfg); err == nil {
		t.Fatal("expected error for invalid boolean env")
	}
}

func TestApplyEnv_InvalidCombination(t *testing.T) {
	// mode=semantic 但 semantic.enabled=false → 校验失败
	t.Setenv("CACHE_MODE", "semantic")
	cfg := DefaultConfig()
	if err := ApplyEnv(&cfg); err == nil {
		t.Fatal("expected validation error for mode=semantic without semantic.enabled")
	}
}
