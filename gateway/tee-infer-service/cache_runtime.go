package main

// §6.10 缓存配置热更新：运行时单一原子快照 + 启动期装配。
//
// 设计依据：本体 §6.10 / B-6.10-1（单次 reload 原子切换）、B-6.10-2（结构性维度变更需重启）。
// 快照经 atomic.Pointer 发布：单请求内只 Load 一次，保证同一请求看到同一版本配置与引擎。

import (
	"context"
	"log"
	"os"
	"time"

	"security-ai-gateway/gateway/tee-infer-service/cacheengine"
)

// cacheState 缓存运行时快照（§6.10 热更新：单次 reload 原子切换，保证请求内一致）。
type cacheState struct {
	engine  cacheengine.CacheEngine
	config  *cacheengine.CacheConfig
	enabled bool
	mode    string
	replay  cacheReplayConfig
}

// newCacheState 由当前配置与新引擎构造快照。
func newCacheState(cfg *cacheengine.CacheConfig, eng cacheengine.CacheEngine) *cacheState {
	if cfg == nil {
		return nil
	}
	return &cacheState{
		engine:  eng,
		config:  cfg,
		enabled: cfg.Mode != cacheengine.ModeOff,
		mode:    string(cfg.Mode),
		replay:  cacheReplayConfig{minGap: cfg.Stream.MinGap.D(), maxGap: cfg.Stream.MaxGap.D()},
	}
}

// cacheState 取当前运行时快照（nil = 未装配）。
func (s *teeServer) cacheState() *cacheState { return s.cacheRT.Load() }

// buildCacheState 启动期缓存装配（§6.10）：加载/校验/维度探针降级/语义装配 → 运行时快照。
// 逻辑与既有启动期装配逐字一致（含日志文案与降级语义）。
func buildCacheState() *cacheState {
	// P0-2 语义缓存：默认 mode=off（与现网逐字节一致）；经 legacyAdapter 复用既有 Get/Put 接线点。
	cacheCfg := cacheengine.DefaultConfig()
	if p := os.Getenv("CACHE_CONFIG_PATH"); p != "" {
		if c, err := cacheengine.LoadConfig(p); err != nil {
			log.Printf("[tee] 缓存配置加载失败，回退默认（mode=off）：%v", err)
		} else {
			cacheCfg = c
		}
	}
	if err := cacheengine.ApplyEnv(&cacheCfg); err != nil {
		log.Printf("[tee] 缓存环境变量覆盖失败，回退默认（mode=off）：%v", err)
		cacheCfg = cacheengine.DefaultConfig()
	}
	// 启动期维度探针：语义启用时校验 sidecar 维度；失败按 §6.9/B-7.6-1 降级为精确缓存。
	if cacheCfg.Semantic.Enabled && (cacheCfg.Mode == cacheengine.ModeSemantic || cacheCfg.Mode == cacheengine.ModeFull) {
		probeCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		emb, err := cacheengine.NewSidecarEmbedderFromConfig(cacheCfg.Semantic.Embedder)
		if err == nil {
			err = cacheengine.VerifyEmbedderDim(probeCtx, emb, cacheCfg.Semantic.Embedder.Dim)
		}
		cancel()
		if err != nil {
			log.Printf("[tee] 语义缓存探针失败，降级为精确缓存（mode=exact）：%v", err)
			cacheCfg.Mode = cacheengine.ModeExact
			cacheCfg.Semantic.Enabled = false
		}
	}
	// P5：语义装配（embedder + 向量索引 + SemanticStore）。失败即按 §6.9/B-7.6-1 降级为精确缓存。
	var cacheOpts []cacheengine.EngineOption
	if store, err := cacheengine.BuildSemanticStoreFromConfig(context.Background(), &cacheCfg); err != nil {
		log.Printf("[tee] 语义存储装配失败，禁用语义缓存：%v", err)
		cacheCfg.Semantic.Enabled = false
	} else if store != nil {
		cacheOpts = append(cacheOpts, cacheengine.WithSemanticStore(store))
	}
	cacheEng := cacheengine.NewCacheEngine(cacheCfg, cacheOpts...)
	return newCacheState(&cacheCfg, cacheEng)
}
