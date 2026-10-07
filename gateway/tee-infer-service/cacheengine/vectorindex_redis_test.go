package cacheengine

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newTestVSSCfg() *CacheConfig {
	cfg := DefaultConfig()
	cfg.Redis.KeyPrefix = "og:c:1:"
	cfg.Semantic.Embedder.Dim = 4
	return &cfg
}

// ===== 纯函数 =====

func TestBuildVSSQuery(t *testing.T) {
	got := buildVSSQuery(VectorFilter{
		TenantID: "t1", EngineType: "cmaas", Model: "m1", PolicyVer: "p1", GuardVer: "g1",
	}, 5, 1700000000000)
	want := "(@tenant:{t1} @engine:{cmaas} @model:{m1} @pver:{p1} @gver:{g1} @expire:[1700000000000 +inf])=>[KNN 5 @vec $q AS __vec_score]"
	if got != want {
		t.Fatalf("buildVSSQuery mismatch:\n got=%s\nwant=%s", got, want)
	}

	// 仅租户 + 过期（其余过滤为空则不出现）
	got2 := buildVSSQuery(VectorFilter{TenantID: "t9"}, 3, 42)
	want2 := "(@tenant:{t9} @expire:[42 +inf])=>[KNN 3 @vec $q AS __vec_score]"
	if got2 != want2 {
		t.Fatalf("partial query mismatch:\n got=%s\nwant=%s", got2, want2)
	}
}

func TestParseVSSHits(t *testing.T) {
	res := []any{
		int64(2),
		"og:c:1:v:kh1", []any{"__vec_score", "0.10", "tenant", "t1", "model", "m1"},
		"og:c:1:v:kh2", []any{"__vec_score", "0.30", "tenant", "t1", "model", "m1"},
	}
	hits, err := parseVSSHits(res, "og:c:1:v:")
	if err != nil {
		t.Fatalf("parseVSSHits: %v", err)
	}
	if len(hits) != 2 {
		t.Fatalf("len=%d, want 2", len(hits))
	}
	if hits[0].EntryID != "kh1" {
		t.Fatalf("entryID=%q, want kh1 (prefix trimmed)", hits[0].EntryID)
	}
	if diff := hits[0].Similarity - 0.9; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("similarity=%v, want 0.9 (1 - cosine distance)", hits[0].Similarity)
	}
	if hits[0].Meta.TenantID != "t1" || hits[0].Meta.Model != "m1" {
		t.Fatalf("meta=%+v", hits[0].Meta)
	}

	// 空结果
	if hs, err := parseVSSHits([]any{int64(0)}, "og:c:1:v:"); err != nil || len(hs) != 0 {
		t.Fatalf("empty result = (%v, %v)", hs, err)
	}
}

func TestVec32Bytes(t *testing.T) {
	a := vec32bytes([]float32{1, -1, 0.5, 0})
	b := vec32bytes([]float32{1, -1, 0.5, 0})
	if len(a) != 16 {
		t.Fatalf("len=%d, want 16 (4 floats x 4 bytes)", len(a))
	}
	if a != b {
		t.Fatal("encoding must be deterministic")
	}
	if vec32bytes([]float32{1, 0, 0, 0}) == vec32bytes([]float32{0, 1, 0, 0}) {
		t.Fatal("distinct vectors must encode differently")
	}
}

// ===== 构造与校验 =====

func TestNewRedisVectorIndex_Validation(t *testing.T) {
	ops := newFakeOps()
	ops.doFn = func(args ...any) (any, error) { return "OK", nil }

	if _, err := NewRedisVectorIndex(context.Background(), nil, ops); err == nil {
		t.Fatal("expected error for nil cfg")
	}
	if _, err := NewRedisVectorIndex(context.Background(), newTestVSSCfg(), nil); err == nil {
		t.Fatal("expected error for nil ops")
	}
	bad := newTestVSSCfg()
	bad.Semantic.Embedder.Dim = 0
	if _, err := NewRedisVectorIndex(context.Background(), bad, ops); err == nil {
		t.Fatal("expected error for dim<=0")
	}
}

func TestRedisVectorIndex_EnsureIndex_ToleratesExisting(t *testing.T) {
	ops := newFakeOps()
	ops.doFn = func(args ...any) (any, error) {
		return nil, errors.New("Index already exists")
	}
	if _, err := NewRedisVectorIndex(context.Background(), newTestVSSCfg(), ops); err != nil {
		t.Fatalf("existing index must be tolerated, got %v", err)
	}
}

func TestRedisVectorIndex_EnsureIndex_PropagatesError(t *testing.T) {
	ops := newFakeOps()
	ops.doFn = func(args ...any) (any, error) { return nil, errors.New("boom") }
	if _, err := NewRedisVectorIndex(context.Background(), newTestVSSCfg(), ops); err == nil {
		t.Fatal("expected FT.CREATE error to propagate")
	}
}

// ===== Upsert / Search =====

func newVSSWithFake(t *testing.T, searchResult any) (VectorIndex, *fakeOps) {
	t.Helper()
	ops := newFakeOps()
	ops.doFn = func(args ...any) (any, error) {
		switch args[0] {
		case "FT.CREATE":
			return "OK", nil
		case "FT.SEARCH":
			return searchResult, nil
		case "HSET":
			return int64(1), nil
		default:
			return nil, errors.New("unexpected command")
		}
	}
	v, err := NewRedisVectorIndex(context.Background(), newTestVSSCfg(), ops)
	if err != nil {
		t.Fatalf("NewRedisVectorIndex: %v", err)
	}
	return v, ops
}

func TestRedisVectorIndex_UpsertDimMismatch(t *testing.T) {
	v, _ := newVSSWithFake(t, []any{int64(0)})
	if err := v.Upsert("kh1", []float32{1, 2}, VectorMeta{}); err == nil {
		t.Fatal("expected dim mismatch error")
	}
}

func TestRedisVectorIndex_UpsertAndDelete(t *testing.T) {
	v, ops := newVSSWithFake(t, []any{int64(0)})
	vec := []float32{1, 0, 0, 0}
	if err := v.Upsert("kh1", vec, VectorMeta{TenantID: "t1", Model: "m1", PolicyVer: "p1", GuardVer: "g1", ExpireAt: 123}); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	if _, ok := ops.data["og:c:1:v:kh1"]; ok {
		// fakeOps.Do 不走 Set，故此处不落 data；仅在集成测试校验真实 HASH。
		t.Log("note: fakeOps records Do only via doFn")
	}
	if err := v.Delete("kh1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if v.Backend() != "redis-vss" {
		t.Fatalf("backend=%s", v.Backend())
	}
}

func TestRedisVectorIndex_Search(t *testing.T) {
	canned := []any{
		int64(2),
		"og:c:1:v:kh1", []any{"__vec_score", "0.05", "tenant", "t1", "model", "m1"},
		"og:c:1:v:kh2", []any{"__vec_score", "0.40", "tenant", "t1", "model", "m1"},
	}
	v, _ := newVSSWithFake(t, canned)

	hits, err := v.Search([]float32{1, 0, 0, 0}, 2, VectorFilter{TenantID: "t1", Model: "m1"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) != 2 || hits[0].EntryID != "kh1" {
		t.Fatalf("hits=%+v", hits)
	}
	if diff := hits[0].Similarity - 0.95; diff > 1e-9 || diff < -1e-9 {
		t.Fatalf("similarity=%v, want 0.95", hits[0].Similarity)
	}
}

func TestRedisVectorIndex_SearchDimMismatch(t *testing.T) {
	v, _ := newVSSWithFake(t, []any{int64(0)})
	if _, err := v.Search([]float32{1, 2}, 2, VectorFilter{}); err == nil {
		t.Fatal("expected query dim mismatch error")
	}
}

// ===== 集成（真实 Redis Stack；未配置或未探测到 RediSearch 时跳过） =====

func TestRedisVectorIndex_Integration(t *testing.T) {
	addr := os.Getenv("CACHE_REDIS_TEST_ADDR")
	if addr == "" {
		t.Skip("CACHE_REDIS_TEST_ADDR not set; skipping VSS integration test")
	}
	db := 15
	if v := os.Getenv("CACHE_REDIS_TEST_DB"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			db = n
		}
	}
	ops := NewGoRedisOps(RedisConfig{Addr: addr, DB: db,
		DialTimeout: Duration(time.Second), ReadTimeout: Duration(time.Second),
		WriteTimeout: Duration(time.Second), MaxRetries: 0})
	defer func() { _ = ops.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if !DetectRediSearch(ctx, ops) {
		t.Skip("RediSearch not available on target Redis; skipping VSS integration test")
	}

	cfg := newTestVSSCfg()
	cfg.Redis.Addr = addr
	cfg.Redis.DB = db
	cfg.Redis.KeyPrefix = "og:c:test:"

	v, err := NewRedisVectorIndex(ctx, cfg, ops)
	if err != nil {
		t.Fatalf("NewRedisVectorIndex: %v", err)
	}

	const id = "kh-vss-int"
	_, _ = ops.Del(ctx, cfg.Redis.KeyPrefix+"v:"+id)
	meta := VectorMeta{TenantID: "t-int", EngineType: "cmaas", Model: "m-int",
		PolicyVer: "p1", GuardVer: "g1", ExpireAt: time.Now().Add(time.Hour).UnixMilli()}
	if err := v.Upsert(id, []float32{1, 0, 0, 0}, meta); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	hits, err := v.Search([]float32{1, 0, 0, 0}, 1,
		VectorFilter{TenantID: "t-int", EngineType: "cmaas", Model: "m-int", PolicyVer: "p1", GuardVer: "g1"})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) == 0 || hits[0].EntryID != id {
		t.Fatalf("expected self-hit, got %+v", hits)
	}
	if !strings.HasPrefix(hits[0].EntryID, "kh") {
		t.Fatalf("entryID not trimmed: %q", hits[0].EntryID)
	}
	if err := v.Delete(id); err != nil {
		t.Fatalf("Delete: %v", err)
	}
}
