package cacheengine

import "fmt"

// StructuralDiff 比对两份配置中**不可热更**（需重启）的结构性维度（本体 §6.10.1 / B-6.10-2）。
// 返回差异描述列表（顺序稳定）；空 = 可热更。判定口径：
//   - embedder（kind/model_id/dim）：维度或模型错配会让新查询与既有向量语义不一致 → 必须重启（B-6.10-2）
//   - vector.backend：后端形态切换需重建索引 → 重启
//   - 容量类（exact/negative.max_entries、flat/hnsw.max_entries）：容量是构造期参数 → 重启
//   - redis.*：连接与键空间属构造期参数（L1 后端实例复用）→ 重启
//   - key_format / scope：键语义 → 重启
//   - semantic.enabled 由 false → true：需在装配期构建 embedder+向量索引 → 重启
//
// 其余维度（mode / policy_version / threshold / ttl_policy / gray / write_limit / jitter /
// guard / tenant_policy / stream / warmup / singleflight / memory）均可热更。
func StructuralDiff(old, new *CacheConfig) []string {
	if old == nil || new == nil {
		return []string{"config: nil"}
	}
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	// embedder（B-6.10-2：模型/维度变更必须拒绝）
	if old.Semantic.Embedder.Kind != new.Semantic.Embedder.Kind {
		add("semantic.embedder.kind: %s → %s", old.Semantic.Embedder.Kind, new.Semantic.Embedder.Kind)
	}
	if old.Semantic.Embedder.ModelID != new.Semantic.Embedder.ModelID {
		add("semantic.embedder.model_id: %s → %s", old.Semantic.Embedder.ModelID, new.Semantic.Embedder.ModelID)
	}
	if old.Semantic.Embedder.Dim != new.Semantic.Embedder.Dim {
		add("semantic.embedder.dim: %d → %d", old.Semantic.Embedder.Dim, new.Semantic.Embedder.Dim)
	}

	// 语义启用开关：关闭 → 开启需装配期构建索引
	if !old.Semantic.Enabled && new.Semantic.Enabled {
		add("semantic.enabled: false → true（需装配期构建语义存储）")
	}

	// 向量后端与容量
	if old.Semantic.Vector.Backend != new.Semantic.Vector.Backend {
		add("semantic.vector.backend: %s → %s", old.Semantic.Vector.Backend, new.Semantic.Vector.Backend)
	}
	if old.Semantic.Vector.FlatMaxEntries != new.Semantic.Vector.FlatMaxEntries {
		add("semantic.vector.flat_max_entries: %d → %d", old.Semantic.Vector.FlatMaxEntries, new.Semantic.Vector.FlatMaxEntries)
	}
	if old.Semantic.Vector.HNSW.MaxEntries != new.Semantic.Vector.HNSW.MaxEntries {
		add("semantic.vector.hnsw.max_entries: %d → %d", old.Semantic.Vector.HNSW.MaxEntries, new.Semantic.Vector.HNSW.MaxEntries)
	}
	if old.Exact.MaxEntries != new.Exact.MaxEntries {
		add("exact.max_entries: %d → %d", old.Exact.MaxEntries, new.Exact.MaxEntries)
	}
	if old.Negative.MaxEntries != new.Negative.MaxEntries {
		add("negative.max_entries: %d → %d", old.Negative.MaxEntries, new.Negative.MaxEntries)
	}

	// Redis（连接与键空间）
	if redisStructuralDiff(old.Redis) != redisStructuralDiff(new.Redis) {
		add("redis.*: 连接/键空间参数变更需重启")
	}

	// 键语义
	if old.KeyFormat != new.KeyFormat {
		add("key_format: %s → %s", old.KeyFormat, new.KeyFormat)
	}
	if old.Scope != new.Scope {
		add("scope: %s → %s", old.Scope, new.Scope)
	}
	return out
}

// redisStructuralDiff 生成 Redis 连接/键空间维度的可比较指纹（结构维度）。
func redisStructuralDiff(r RedisConfig) string {
	return fmt.Sprintf("en=%t|addr=%s|db=%d|pref=%s|cidr=%v|ref=%s",
		r.Enabled, r.Addr, r.DB, r.KeyPrefix, r.TrustedCIDR, r.PasswordRef)
}
