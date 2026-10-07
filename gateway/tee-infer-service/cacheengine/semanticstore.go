package cacheengine

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// SemanticStore 语义缓存存储层（§4.1.3 / §5.3）。
// 职责：
//   - 编排 Embedder + VectorIndex（向量索引只存元数据，正文在 ExactStore）
//   - 语义查询：embed → topK 候选 → 阈值过滤 → 实体指纹校验 → 返回最佳 entry_id
//   - 写入：embed response → upsert 向量索引（通过 entry_id 关联 ExactStore 正文）
//   - 版本校验、租户隔离、TTL 过期过滤
//
// 注意：SemanticStore 不持有 ExactStore（正文存取由 engine 编排），
// 两者通过 entry_id 关联（VectorMeta.EntryID == ExactStore key）。
type SemanticStore interface {
	// Lookup 语义查询。返回命中的 entry_id 和相似度；未命中返回 reason。
	// 注意：返回的 entryID 是 ExactStore 的 key，可直接用于 exactStore.Get(entryID)。
	Lookup(ctx LookupContext) (hit bool, entryID string, sim float64, scene string, threshold float64, reason string)

	// Store 写入向量索引。内部计算 response embedding。
	Store(entryID string, text string, meta VectorMeta) error

	// Delete 删除指定 entry 的向量索引。
	Delete(entryID string) error

	// Invalidate 按选择器失效（返回删除的向量条目数）。
	Invalidate(sel InvalidateSelector) int

	// Size 当前向量条目数。
	Size() int

	// Close 关闭。
	Close() error

	// Enabled 语义缓存是否启用（mode + 租户策略）。
	Enabled(tenantID string) bool
}

// semanticStore 语义缓存实现。
type semanticStore struct {
	cfg            *CacheConfig
	embedder       Embedder // 明文域 embedder
	secureEmbedder Embedder // 密态域 embedder（可选，nil 表示密态降级用明文）
	index          VectorIndex
	nowFn          nowFunc
	stats          *statsCollector // §9.1 指标发射（由 engine 在注入后接线；nil = 不发射）
}

// classifyEmbedError 按哨兵把 embed 错误归类到 §9.1 #17/#28/#29/#30。
func (s *semanticStore) classifyEmbedError(err error) {
	if s.stats == nil || err == nil {
		return
	}
	switch {
	case errors.Is(err, ErrEmbedTimeout):
		s.stats.observeEmbedTimeout()          // #29
		s.stats.observeEmbedderError("timeout") // #28
	case errors.Is(err, ErrEmbedDimMismatch):
		s.stats.observeEmbedDimMismatch() // #30
	case errors.Is(err, ErrEmbedUnavailable):
		s.stats.observeEmbedderError("unreachable") // #28
	case errors.Is(err, ErrEmbedInvalid):
		s.stats.observeEmbedderError("bad_response") // #28
		if strings.Contains(err.Error(), "empty") {
			s.stats.observeEmbedInvalid("empty") // #17
		} else {
			s.stats.observeEmbedInvalid("bad_response") // #17
		}
	default:
		s.stats.observeEmbedderError("unreachable")
	}
}

// embedOnce 调用 embedder 并记录耗时（§9.1 #39）与错误分类（#17/#28/#29/#30）。
func (s *semanticStore) embedOnce(ctx context.Context, emb Embedder, text string) ([]float32, error) {
	start := time.Now()
	vec, err := emb.Embed(ctx, text)
	if s.stats != nil {
		s.stats.observeExtraDuration("embed", time.Since(start)) // #39
	}
	if err != nil {
		s.classifyEmbedError(err)
	}
	return vec, err
}

// NewSemanticStore 构造语义缓存存储。
// embedder 不可为 nil（即使是 stub，也由调用方决定）。
// index 不可为 nil。
func NewSemanticStore(cfg *CacheConfig, embedder Embedder, index VectorIndex) (SemanticStore, error) {
	if cfg == nil {
		return nil, fmt.Errorf("semantic store: cfg is nil")
	}
	if embedder == nil {
		return nil, fmt.Errorf("semantic store: embedder is nil")
	}
	if index == nil {
		return nil, fmt.Errorf("semantic store: index is nil")
	}
	return &semanticStore{
		cfg:      cfg,
		embedder: embedder,
		index:    index,
		nowFn:    defaultNow,
	}, nil
}

// NewSemanticStoreDual 构造带密态 embedder 的双路语义缓存存储。
func NewSemanticStoreDual(cfg *CacheConfig, plain Embedder, secure Embedder, index VectorIndex) (SemanticStore, error) {
	ss, err := NewSemanticStore(cfg, plain, index)
	if err != nil {
		return nil, err
	}
	ss.(*semanticStore).secureEmbedder = secure
	return ss, nil
}

// Enabled 语义缓存是否启用。
func (s *semanticStore) Enabled(tenantID string) bool {
	if s.cfg.Mode != ModeSemantic && s.cfg.Mode != ModeFull {
		return false
	}
	if !s.cfg.Semantic.Enabled {
		return false
	}
	if !s.embedder.Available() {
		return false
	}
	// 租户策略
	return tenantPolicy(s.cfg, tenantID) != PolicyOff
}

// Lookup 语义查询（§6.5）。
// 流程：取场景化阈值 → embed query → 向量检索 → 阈值过滤 → 返回最佳 entry_id
func (s *semanticStore) Lookup(ctx LookupContext) (bool, string, float64, string, float64, string) {
	scene := string(ctx.Scene)
	if scene == "" {
		scene = "general"
	}

	// 获取场景化阈值
	th := s.sceneThreshold(scene)

	// 计算 query 向量（按安全域选择 embedder）
	ctx2, cancel := context.WithTimeout(context.Background(), s.cfg.Semantic.Embedder.Timeout.D())
	defer cancel()

	emb := s.embedderForLevel(ctx.SecurityLevel)
	vec, err := s.embedOnce(ctx2, emb, ctx.PromptText)
	if err != nil {
		return false, "", 0, scene, th, "embed_error"
	}

	// 向量检索（topK + 硬过滤）
	filter := VectorFilter{
		TenantID:      ctx.TenantID,
		EngineType:    ctx.EngineType,
		Model:         ctx.Model,
		PolicyVer:     ctx.PolicyVer,
		GuardVer:      ctx.GuardVer,
		SecurityLevel: ctx.SecurityLevel,
	}

	hits, err := s.index.Search(vec, s.cfg.Semantic.Vector.TopK, filter)
	if err != nil {
		if s.stats != nil {
			s.stats.observeVectorError("search") // §9.1 #31
		}
		return false, "", 0, scene, th, "no_candidates"
	}
	if len(hits) == 0 {
		return false, "", 0, scene, th, "no_candidates"
	}

	// 取第一个超过阈值的候选（已按相似度降序）
	best := hits[0]
	if best.Similarity < th {
		if s.stats != nil {
			s.stats.observeSemanticReject("threshold") // §9.1 #37
		}
		return false, best.EntryID, best.Similarity, scene, th, "below_threshold"
	}

	return true, best.EntryID, best.Similarity, scene, th, ""
}

// Store 写入向量索引。
// 计算 response embedding → upsert 向量索引。
// 如果 embed 失败，返回错误（由 engine 决定是否回滚 ExactStore）。
func (s *semanticStore) Store(entryID string, text string, meta VectorMeta) error {
	// 按安全域选择 embedder
	emb := s.embedderForLevel(meta.SecurityLevel)
	if !emb.Available() {
		return fmt.Errorf("embedder unavailable for level=%s", meta.SecurityLevel)
	}
	if text == "" {
		return fmt.Errorf("empty text")
	}

	ctx, cancel := context.WithTimeout(context.Background(), s.cfg.Semantic.Embedder.Timeout.D())
	defer cancel()

	vec, err := s.embedOnce(ctx, emb, text)
	if err != nil {
		return fmt.Errorf("embed response: %w", err)
	}

	if err := s.index.Upsert(entryID, vec, meta); err != nil {
		if s.stats != nil {
			s.stats.observeVectorError("upsert") // §9.1 #31
		}
		return err
	}
	return nil
}

// embedderForLevel 根据安全等级返回对应的 embedder。
func (s *semanticStore) embedderForLevel(level SecurityLevel) Embedder {
	if (level == SecLevelSecure || level == SecLevelHSM) && s.secureEmbedder != nil {
		return s.secureEmbedder
	}
	return s.embedder
}

// Delete 删除指定 entry 的向量索引。
func (s *semanticStore) Delete(entryID string) error {
	err := s.index.Delete(entryID)
	if err != nil && s.stats != nil {
		s.stats.observeVectorError("delete") // §9.1 #31
	}
	return err
}

// Invalidate 失效语义缓存。
// FLAT 索引不支持按标签批量删除，仅支持 key 精确删除和全量失效。
// 生产环境 Redis VSS 才支持高效标签删除。
func (s *semanticStore) Invalidate(sel InvalidateSelector) int {
	// 注：FLAT 索引的批量删除代价为 O(N)，在条目多时不适合同步调用。
	// 一期先返回 0，后续接入 Redis VSS 后再实现。
	return 0
}

// Size 当前向量索引条目数。
func (s *semanticStore) Size() int {
	return s.index.Size()
}

// Close 关闭。
func (s *semanticStore) Close() error {
	return nil
}

// sceneThreshold 获取场景化阈值。
// 场景名与 ThresholdConfig 字段映射：factual → Factual, general → General, code → Code, math → Math。
func (s *semanticStore) sceneThreshold(scene string) float64 {
	tc := s.cfg.Semantic.Threshold
	switch scene {
	case "factual":
		if tc.Factual > 0 {
			return tc.Factual
		}
	case "general":
		if tc.General > 0 {
			return tc.General
		}
	case "code":
		if tc.Code > 0 {
			return tc.Code
		}
	case "math":
		if tc.Math > 0 {
			return tc.Math
		}
	}
	// 默认为 general 阈值（如果有），否则 0.85 兜底
	if tc.General > 0 {
		return tc.General
	}
	return 0.85
}
