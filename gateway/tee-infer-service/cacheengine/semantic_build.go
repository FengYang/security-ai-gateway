package cacheengine

import (
	"context"
	"fmt"
)

// BuildSemanticStoreFromConfig 按配置组装语义存储（embedder + 向量索引 + SemanticStore）。
//
// 仅当 semantic.enabled 时返回非 nil。向量后端由 ResolveVectorBackend 决定：
// 配置 redis-vss 但（未探测到 RediSearch 或 Redis 不在可信域）→ 返回错误（fail-closed，§3.1.2/§7.7）。
// 组装前后执行启动期维度探针（§6.9 / B-7.6-1），失败即返回错误，由调用方降级为精确缓存。
func BuildSemanticStoreFromConfig(ctx context.Context, cfg *CacheConfig) (SemanticStore, error) {
	if cfg == nil || !cfg.Semantic.Enabled {
		return nil, nil
	}
	var ops redisOps
	var caps Capabilities
	if cfg.Redis.Enabled {
		ops = NewGoRedisOps(cfg.Redis)
		caps = ProbeCapabilities(ctx, ops, cfg.Redis)
	}
	return buildSemanticStore(ctx, cfg, ops, caps)
}

// buildSemanticStore 组装实现（ops 仅 redis-vss 后端需要）。
func buildSemanticStore(ctx context.Context, cfg *CacheConfig, ops redisOps, caps Capabilities) (SemanticStore, error) {
	backend, err := ResolveVectorBackend(cfg, caps)
	if err != nil {
		return nil, err
	}
	emb, err := NewSidecarEmbedderFromConfig(cfg.Semantic.Embedder)
	if err != nil {
		return nil, err
	}
	if err := VerifyEmbedderDim(ctx, emb, cfg.Semantic.Embedder.Dim); err != nil {
		return nil, fmt.Errorf("cache: semantic embedder probe: %w", err)
	}

	var idx VectorIndex
	switch backend {
	case "redis-vss":
		if ops == nil {
			return nil, fmt.Errorf("cache: vector.backend=redis-vss requires redis enabled")
		}
		idx, err = NewRedisVectorIndex(ctx, cfg, ops)
		if err != nil {
			return nil, err
		}
	case "hnsw":
		h := cfg.Semantic.Vector.HNSW
		idx = NewHNSWVectorIndex(cfg.Semantic.Embedder.Dim, h.MaxEntries, h.M, h.EfConstruction, h.EfSearch)
	case "flat":
		idx = NewFlatVectorIndex(cfg.Semantic.Embedder.Dim, cfg.Semantic.Vector.FlatMaxEntries)
	default:
		// 显式拒绝未知后端（修正历史"静默降级为 flat"隐患）
		return nil, fmt.Errorf("cache: unsupported vector backend %q (allowed: flat|hnsw|redis-vss)", backend)
	}
	return NewSemanticStore(cfg, emb, idx)
}
