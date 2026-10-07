package cacheengine

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Capabilities Redis 能力探测结果（形态 B/C 决策输入，§3.1.2）。
type Capabilities struct {
	RediSearch bool // RediSearch / 向量检索模块可用
	Trusted    bool // Redis 地址落在 trusted_cidr 内（可信域）
}

// CanVSS VSS（形态 C）仅在 RediSearch 可用且处于可信域时启用（详设 §3.1.2 裁决）。
func (c Capabilities) CanVSS() bool { return c.RediSearch && c.Trusted }

// DetectRediSearch 探测 RediSearch 是否可用。
// 探测失败 / 无法判定 → 返回 false（fail-safe：不启用 VSS）。
func DetectRediSearch(ctx context.Context, ops redisOps) bool {
	if res, err := ops.Do(ctx, "COMMAND", "INFO", "FT.SEARCH"); err == nil {
		if arr, ok := res.([]any); ok && len(arr) > 0 && arr[0] != nil {
			return true
		}
	}
	if res, err := ops.Do(ctx, "MODULE", "LIST"); err == nil {
		return strings.Contains(strings.ToLower(fmt.Sprintf("%v", res)), "search")
	}
	return false
}

// HostTrusted 判断 addr 的主机是否落在任一 CIDR 内。
// addr 形如 host:port；cidrs 为空 → false（fail-closed）。
func HostTrusted(addr string, cidrs []string) (bool, error) {
	if len(cidrs) == 0 {
		return false, nil
	}
	host := addr
	if h, _, err := net.SplitHostPort(addr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		ips, err := net.LookupIP(host)
		if err != nil || len(ips) == 0 {
			return false, fmt.Errorf("cache: resolve %q failed: %v", host, err)
		}
		ip = ips[0]
	}
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(strings.TrimSpace(c))
		if err != nil {
			return false, fmt.Errorf("cache: invalid cidr %q: %w", c, err)
		}
		if n.Contains(ip) {
			return true, nil
		}
	}
	return false, nil
}

// ProbeCapabilities 探测 RediSearch 与可信域（可信域解析异常按不可信处理）。
func ProbeCapabilities(ctx context.Context, ops redisOps, cfg RedisConfig) Capabilities {
	trusted, _ := HostTrusted(cfg.Addr, cfg.TrustedCIDR)
	return Capabilities{RediSearch: DetectRediSearch(ctx, ops), Trusted: trusted}
}

// ResolveVectorBackend 解析最终向量后端。
// 默认（flat/hnsw 等）原样返回；配置为 redis-vss 但不同时满足
// "RediSearch 可用 且 处于可信域" 时返回错误，由调用方拒绝启动（fail-closed，§3.1.2 / §7.7）。
func ResolveVectorBackend(cfg *CacheConfig, caps Capabilities) (string, error) {
	backend := cfg.Semantic.Vector.Backend
	if backend == "" {
		backend = "flat"
	}
	if backend != "redis-vss" {
		return backend, nil
	}
	if !caps.CanVSS() {
		return "", fmt.Errorf(
			"cache: vector.backend=redis-vss rejected (fail-closed): requires RediSearch available AND Redis in trusted_cidr (redisearch=%v trusted=%v)",
			caps.RediSearch, caps.Trusted)
	}
	return "redis-vss", nil
}
