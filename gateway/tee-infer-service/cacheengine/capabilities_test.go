package cacheengine

import (
	"context"
	"errors"
	"testing"
)

func TestHostTrusted(t *testing.T) {
	cases := []struct {
		addr  string
		cidrs []string
		want  bool
	}{
		{"10.0.0.5:6379", []string{"10.0.0.0/8"}, true},
		{"10.0.0.5:6379", []string{"192.168.0.0/16"}, false},
		{"127.0.0.1:6379", []string{"127.0.0.0/8"}, true},
		{"10.0.0.5:6379", nil, false},                         // 无 CIDR → fail-closed
		{"10.0.0.5", []string{"10.0.0.0/8"}, true},            // 无端口
		{"10.9.0.5:6379", []string{"192.168.0.0/16", "10.0.0.0/8"}, true},
	}
	for _, c := range cases {
		got, err := HostTrusted(c.addr, c.cidrs)
		if err != nil {
			t.Fatalf("HostTrusted(%q, %v): %v", c.addr, c.cidrs, err)
		}
		if got != c.want {
			t.Errorf("HostTrusted(%q, %v) = %v, want %v", c.addr, c.cidrs, got, c.want)
		}
	}
}

func TestHostTrusted_InvalidCIDR(t *testing.T) {
	if _, err := HostTrusted("10.0.0.5:6379", []string{"not-a-cidr"}); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestDetectRediSearch(t *testing.T) {
	ctx := context.Background()

	// COMMAND INFO FT.SEARCH 返回非空条目 → 可用
	ops := newFakeOps()
	ops.doFn = func(args ...any) (any, error) {
		if args[0] == "COMMAND" {
			return []any{map[string]any{"name": "ft.search"}}, nil
		}
		return nil, errors.New("nope")
	}
	if !DetectRediSearch(ctx, ops) {
		t.Fatal("expected RediSearch detected via COMMAND INFO")
	}

	// 条目为 nil → 不可用（回退 MODULE LIST 也失败）
	ops.doFn = func(args ...any) (any, error) { return []any{nil}, nil }
	if DetectRediSearch(ctx, ops) {
		t.Fatal("expected not detected when COMMAND INFO empty")
	}

	// 回退 MODULE LIST 命中 search
	ops.doFn = func(args ...any) (any, error) {
		if args[0] == "COMMAND" {
			return nil, errors.New("unsupported")
		}
		return "name\nsearch\nver\n20000", nil
	}
	if !DetectRediSearch(ctx, ops) {
		t.Fatal("expected RediSearch detected via MODULE LIST fallback")
	}

	// 全部探测失败 → fail-safe false
	ops.doFn = func(args ...any) (any, error) { return nil, errors.New("down") }
	if DetectRediSearch(ctx, ops) {
		t.Fatal("expected false when probing fails")
	}
}

func TestCapabilities_CanVSS(t *testing.T) {
	cases := []struct {
		caps Capabilities
		want bool
	}{
		{Capabilities{true, true}, true},
		{Capabilities{true, false}, false},
		{Capabilities{false, true}, false},
		{Capabilities{false, false}, false},
	}
	for _, c := range cases {
		if got := c.caps.CanVSS(); got != c.want {
			t.Errorf("CanVSS(%+v) = %v, want %v", c.caps, got, c.want)
		}
	}
}

func TestResolveVectorBackend(t *testing.T) {
	cfg := DefaultConfig()

	// 非 redis-vss：原样返回
	cfg.Semantic.Vector.Backend = "flat"
	if bk, err := ResolveVectorBackend(&cfg, Capabilities{}); err != nil || bk != "flat" {
		t.Fatalf("flat passthrough = (%q, %v)", bk, err)
	}

	// redis-vss 但不同时满足双条件 → fail-closed
	cfg.Semantic.Vector.Backend = "redis-vss"
	if _, err := ResolveVectorBackend(&cfg, Capabilities{RediSearch: true, Trusted: false}); err == nil {
		t.Fatal("expected fail-closed when Redis not in trusted CIDR")
	}
	if _, err := ResolveVectorBackend(&cfg, Capabilities{RediSearch: false, Trusted: true}); err == nil {
		t.Fatal("expected fail-closed when RediSearch unavailable")
	}

	// 双条件满足 → 启用 VSS
	if bk, err := ResolveVectorBackend(&cfg, Capabilities{RediSearch: true, Trusted: true}); err != nil || bk != "redis-vss" {
		t.Fatalf("vss enable = (%q, %v)", bk, err)
	}
}

func TestProbeCapabilities(t *testing.T) {
	ops := newFakeOps()
	ops.doFn = func(args ...any) (any, error) {
		return []any{map[string]any{"name": "ft.search"}}, nil
	}
	cfg := RedisConfig{Addr: "127.0.0.1:6379", TrustedCIDR: []string{"127.0.0.0/8"}}
	caps := ProbeCapabilities(context.Background(), ops, cfg)
	if !caps.CanVSS() {
		t.Fatalf("expected CanVSS=true, got %+v", caps)
	}
}
