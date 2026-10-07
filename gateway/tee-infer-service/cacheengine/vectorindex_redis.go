package cacheengine

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// redisVectorIndex 基于 Redis VSS 的向量索引（形态 C，§5.4）。
// 仅在能力探测通过（RediSearch 可用 + Redis 处于可信域）后由调用方构造；
// 启用门禁见 ResolveVectorBackend（配置 redis-vss 但双条件不满足 → 拒绝启动）。
type redisVectorIndex struct {
	ops    redisOps
	dim    int
	index  string // FT 索引名
	prefix string // 向量 HASH 键前缀（og:c:1:v:）
	nowFn  nowFunc
}

// NewRedisVectorIndex 构造 VSS 向量索引并幂等创建 FT 索引（FT.CREATE）。
func NewRedisVectorIndex(ctx context.Context, cfg *CacheConfig, ops redisOps) (VectorIndex, error) {
	if cfg == nil {
		return nil, fmt.Errorf("cache: vss: cfg is nil")
	}
	if ops == nil {
		return nil, fmt.Errorf("cache: vss: ops is nil")
	}
	if cfg.Semantic.Embedder.Dim <= 0 {
		return nil, fmt.Errorf("cache: vss: embedder dim must be positive")
	}
	prefix := cfg.Redis.KeyPrefix
	if prefix == "" {
		prefix = "og:c:1:"
	}
	v := &redisVectorIndex{
		ops:    ops,
		dim:    cfg.Semantic.Embedder.Dim,
		index:  prefix + "idx",
		prefix: prefix + "v:",
		nowFn:  defaultNow,
	}
	if err := v.ensureIndex(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

// Backend 返回后端名。
func (v *redisVectorIndex) Backend() string { return "redis-vss" }

// ensureIndex 幂等创建 FT 索引；"index already exists" 视为成功。
func (v *redisVectorIndex) ensureIndex(ctx context.Context) error {
	_, err := v.ops.Do(ctx, "FT.CREATE", v.index,
		"ON", "HASH",
		"PREFIX", "1", v.prefix,
		"SCHEMA",
		"vec", "VECTOR", "FLAT", "6",
		"TYPE", "FLOAT32", "DIM", strconv.Itoa(v.dim), "DISTANCE_METRIC", "COSINE",
		"tenant", "TAG",
		"engine", "TAG",
		"model", "TAG",
		"pver", "TAG",
		"gver", "TAG",
		"expire", "NUMERIC",
	)
	if err != nil && !strings.Contains(strings.ToLower(err.Error()), "index already exists") {
		return fmt.Errorf("cache: vss FT.CREATE: %w", err)
	}
	return nil
}

// Upsert 写入向量 HASH（§5.3.1：字段与 FT schema 对齐；载荷仍在 og:c:1:e:*，向量只存元数据）。
func (v *redisVectorIndex) Upsert(id string, vec []float32, meta VectorMeta) error {
	if len(vec) != v.dim {
		return fmt.Errorf("vss: vector dim mismatch: got %d, want %d", len(vec), v.dim)
	}
	_, err := v.ops.Do(context.Background(), "HSET", v.prefix+id,
		"vec", vec32bytes(vec),
		"tenant", meta.TenantID,
		"engine", meta.EngineType,
		"model", meta.Model,
		"pver", meta.PolicyVer,
		"gver", meta.GuardVer,
		"expire", strconv.FormatInt(meta.ExpireAt, 10),
	)
	return err
}

// Delete 删除向量 HASH。
func (v *redisVectorIndex) Delete(id string) error {
	_, err := v.ops.Del(context.Background(), v.prefix+id)
	return err
}

// Size 通过 FT.INFO 读取索引实时条目数（num_docs）；失败回退 0（不影响主链）。
func (v *redisVectorIndex) Size() int {
	res, err := v.ops.Do(context.Background(), "FT.INFO", v.index)
	if err != nil {
		return 0
	}
	return parseVSSNumDocs(res)
}

// parseVSSNumDocs 从 FT.INFO 返回序列（[name, value, name, value, ...]）解析 num_docs（纯函数，便于单测）。
func parseVSSNumDocs(res any) int {
	arr, ok := res.([]any)
	if !ok {
		return 0
	}
	for i := 0; i+1 < len(arr); i += 2 {
		name, _ := arr[i].(string)
		if name != "num_docs" {
			continue
		}
		switch n := arr[i+1].(type) {
		case int64:
			return int(n)
		case int:
			return n
		case string:
			if v, err := strconv.Atoi(n); err == nil {
				return v
			}
		}
	}
	return 0
}

// Search FT.SEARCH KNN + TAG 硬过滤（§5.4）。
// 硬过滤（租户/引擎/模型/版本/过期）绝不交给相似度决定。
func (v *redisVectorIndex) Search(vec []float32, topK int, f VectorFilter) ([]VectorHit, error) {
	if len(vec) != v.dim {
		return nil, fmt.Errorf("vss: query dim mismatch: got %d, want %d", len(vec), v.dim)
	}
	if topK <= 0 {
		topK = 5
	}
	q := buildVSSQuery(f, topK, v.nowFn().UnixMilli())
	res, err := v.ops.Do(context.Background(),
		"FT.SEARCH", v.index, q,
		"PARAMS", "2", "q", vec32bytes(vec),
		"SORTBY", "__vec_score",
		"RETURN", "3", "__vec_score", "tenant", "model",
		"LIMIT", "0", strconv.Itoa(topK),
		"DIALECT", "2",
	)
	if err != nil {
		return nil, err
	}
	return parseVSSHits(res, v.prefix)
}

// buildVSSQuery 构造 KNN 查询串（纯函数，便于单测）：
//
//	(@tenant:{t} @engine:{e} @model:{m} @pver:{pv} @gver:{gv} @expire:[now +inf])=>[KNN K @vec $q AS __vec_score]
func buildVSSQuery(f VectorFilter, topK int, nowMs int64) string {
	var b strings.Builder
	b.WriteString("(")
	if f.TenantID != "" {
		fmt.Fprintf(&b, "@tenant:{%s} ", f.TenantID)
	}
	if f.EngineType != "" {
		fmt.Fprintf(&b, "@engine:{%s} ", f.EngineType)
	}
	if f.Model != "" {
		fmt.Fprintf(&b, "@model:{%s} ", f.Model)
	}
	if f.PolicyVer != "" {
		fmt.Fprintf(&b, "@pver:{%s} ", f.PolicyVer)
	}
	if f.GuardVer != "" {
		fmt.Fprintf(&b, "@gver:{%s} ", f.GuardVer)
	}
	fmt.Fprintf(&b, "@expire:[%d +inf]", nowMs)
	b.WriteString(")")
	fmt.Fprintf(&b, "=>[KNN %d @vec $q AS __vec_score]", topK)
	return b.String()
}

// parseVSSHits 解析 FT.SEARCH 返回（[total, key, [field,value,...], ...]）；
// 相似度 = 1 - COSINE 距离（距离 ∈ [0,2]）→ 与进程内 FLAT 的口径一致（§5.4）。
func parseVSSHits(res any, keyPrefix string) ([]VectorHit, error) {
	arr, ok := res.([]any)
	if !ok || len(arr) == 0 {
		return []VectorHit{}, nil
	}
	out := make([]VectorHit, 0, (len(arr)-1)/2)
	for i := 1; i+1 < len(arr); i += 2 {
		key, _ := arr[i].(string)
		fields, _ := arr[i+1].([]any)
		hit := VectorHit{EntryID: strings.TrimPrefix(key, keyPrefix)}
		for j := 0; j+1 < len(fields); j += 2 {
			name := fmt.Sprintf("%v", fields[j])
			val := fmt.Sprintf("%v", fields[j+1])
			switch name {
			case "__vec_score":
				if d, err := strconv.ParseFloat(val, 64); err == nil {
					hit.Similarity = 1 - d
				}
			case "tenant":
				hit.Meta.TenantID = val
			case "model":
				hit.Meta.Model = val
			}
		}
		out = append(out, hit)
	}
	return out, nil
}

// vec32bytes 将 float32 向量编码为小端字节串（VSS FLOAT32 要求）。
func vec32bytes(vec []float32) string {
	buf := make([]byte, 4*len(vec))
	for i, f := range vec {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(f))
	}
	return string(buf)
}
