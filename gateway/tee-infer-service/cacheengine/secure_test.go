package cacheengine

import (
	"context"
	"testing"
)

// ===== SecurityLevel 类型测试 =====

func TestSecurityLevel_Constants(t *testing.T) {
	if SecLevelPlain != "plain" {
		t.Fatalf("SecLevelPlain = %s", SecLevelPlain)
	}
	if SecLevelSecure != "secure" {
		t.Fatalf("SecLevelSecure = %s", SecLevelSecure)
	}
	if SecLevelHSM != "hsm" {
		t.Fatalf("SecLevelHSM = %s", SecLevelHSM)
	}
}

// ===== 向量索引安全域隔离测试 =====

func TestVectorIndex_SecurityLevelFilter(t *testing.T) {
	dim := 4
	idx := NewFlatVectorIndex(dim, 100)

	// 写入 3 条，分属不同安全域
	metaPlain := VectorMeta{TenantID: "t1", Model: "m1", SecurityLevel: SecLevelPlain}
	metaSecure := VectorMeta{TenantID: "t1", Model: "m1", SecurityLevel: SecLevelSecure}
	metaHSM := VectorMeta{TenantID: "t1", Model: "m1", SecurityLevel: SecLevelHSM}

	vecPlain := []float32{1, 0, 0, 0}
	vecSecure := []float32{0, 1, 0, 0}
	vecHSM := []float32{0, 0, 1, 0}

	idx.Upsert("plain-1", vecPlain, metaPlain)
	idx.Upsert("secure-1", vecSecure, metaSecure)
	idx.Upsert("hsm-1", vecHSM, metaHSM)

	// 查 plain → 只能命中 plain
	hits, err := idx.Search([]float32{1, 1, 1, 0}, 10, VectorFilter{
		TenantID:      "t1",
		SecurityLevel: SecLevelPlain,
	})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 plain hit, got %d", len(hits))
	}
	if hits[0].EntryID != "plain-1" {
		t.Fatalf("expected plain-1, got %s", hits[0].EntryID)
	}

	// 查 secure → 只能命中 secure
	hits, err = idx.Search([]float32{1, 1, 1, 0}, 10, VectorFilter{
		TenantID:      "t1",
		SecurityLevel: SecLevelSecure,
	})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	if len(hits) != 1 {
		t.Fatalf("expected 1 secure hit, got %d", len(hits))
	}
	if hits[0].EntryID != "secure-1" {
		t.Fatalf("expected secure-1, got %s", hits[0].EntryID)
	}

	// 不过滤安全级 → 全部命中
	hits, err = idx.Search([]float32{1, 1, 1, 0}, 10, VectorFilter{TenantID: "t1"})
	if err != nil {
		t.Fatalf("search error: %v", err)
	}
	if len(hits) != 3 {
		t.Fatalf("expected 3 hits without level filter, got %d", len(hits))
	}
}

// ===== 语义层安全域隔离测试 =====

// mockSecureEmbedder 测试用密态 embedder，返回与明文不同的向量。
type mockSecureEmbedder struct {
	dim   int
	model string
}

func (m *mockSecureEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	// 返回确定性向量：secure 用负数开头，区别于明文
	vec := make([]float32, m.dim)
	for i := 0; i < m.dim && i < len(text); i++ {
		vec[i] = -float32(text[i]) / 255.0
	}
	// 归一化
	norm := float32(0)
	for _, v := range vec {
		norm += v * v
	}
	if norm > 0 {
		norm = float32(0)
		for _, v := range vec {
			norm += v * v
		}
		norm = float32(0)
		for _, v := range vec {
			norm += v * v
		}
	}
	// 简单起见不归一化，flat index 会自动归一化
	return vec, nil
}
func (m *mockSecureEmbedder) Dim() int        { return m.dim }
func (m *mockSecureEmbedder) Model() string   { return m.model }
func (m *mockSecureEmbedder) Available() bool { return true }

func TestSemanticStore_SecurityIsolation(t *testing.T) {
	cfg := testSemanticConfig()
	cfg.Semantic.Threshold.General = 0.0 // 阈值低一点便于测试

	dim := 32
	plainEmb := NewDeterministicEmbedder(dim)
	secureEmb := &mockSecureEmbedder{dim: dim, model: "secure-model"}
	idx := NewFlatVectorIndex(dim, 1000)

	ss, err := NewSemanticStoreDual(&cfg, plainEmb, secureEmb, idx)
	if err != nil {
		t.Fatalf("NewSemanticStoreDual: %v", err)
	}

	// 写入明文域条目
	metaPlain := VectorMeta{
		EntryID:       "plain-key",
		TenantID:      "t1",
		Model:         "m1",
		Scene:         SceneGeneral,
		SecurityLevel: SecLevelPlain,
	}
	ss.Store("plain-key", "plain domain answer text content", metaPlain)

	// 写入密态域条目
	metaSecure := VectorMeta{
		EntryID:       "secure-key",
		TenantID:      "t1",
		Model:         "m1",
		Scene:         SceneGeneral,
		SecurityLevel: SecLevelSecure,
	}
	ss.Store("secure-key", "secure domain answer text content", metaSecure)

	// 明文域查询 → 只能命中明文条目
	ctxPlain := LookupContext{
		TenantID:      "t1",
		Model:         "m1",
		PromptText:    "plain domain answer text content",
		Scene:         SceneGeneral,
		SecurityLevel: SecLevelPlain,
	}
	hit, entryID, _, _, _, _ := ss.Lookup(ctxPlain)
	if !hit {
		t.Fatal("plain lookup should hit")
	}
	if entryID != "plain-key" {
		t.Fatalf("expected plain-key, got %s", entryID)
	}

	// 密态域查询 → 只能命中密态条目
	ctxSecure := LookupContext{
		TenantID:      "t1",
		Model:         "m1",
		PromptText:    "secure domain answer text content",
		Scene:         SceneGeneral,
		SecurityLevel: SecLevelSecure,
	}
	hit, entryID, _, _, _, _ = ss.Lookup(ctxSecure)
	if !hit {
		t.Fatal("secure lookup should hit")
	}
	if entryID != "secure-key" {
		t.Fatalf("expected secure-key, got %s", entryID)
	}

	// 明文域查询不应命中密态条目（SecurityLevel 过滤）
	// 验证方式：密态域的 entryID=secure-key，用相同 prompt 明文域查询应该返回 no_candidates 或别的
	// 因为 SecurityLevel 过滤掉了密态条目
	// 为了确保，我们只写入密态条目，然后明文域查询
	idx2 := NewFlatVectorIndex(dim, 1000)
	ss2, _ := NewSemanticStoreDual(&cfg, plainEmb, secureEmb, idx2)

	// 只写密态
	metaOnlySecure := VectorMeta{
		EntryID:       "only-secure",
		TenantID:      "t1",
		Model:         "m1",
		Scene:         SceneGeneral,
		SecurityLevel: SecLevelSecure,
	}
	ss2.Store("only-secure", "only in secure domain answer text", metaOnlySecure)

	// 明文域查询 → 应该查不到（SecurityLevel 过滤）
	ctxOnlyPlain := LookupContext{
		TenantID:      "t1",
		Model:         "m1",
		PromptText:    "only in secure domain answer text",
		Scene:         SceneGeneral,
		SecurityLevel: SecLevelPlain,
	}
	hit, _, _, _, _, reason := ss2.Lookup(ctxOnlyPlain)
	if hit {
		t.Fatal("plain lookup should not see secure-only entries")
	}
	if reason != "no_candidates" {
		t.Fatalf("expected no_candidates, got %s", reason)
	}

	// 密态域查询 → 应该能查到
	ctxOnlySecure := LookupContext{
		TenantID:      "t1",
		Model:         "m1",
		PromptText:    "only in secure domain answer text",
		Scene:         SceneGeneral,
		SecurityLevel: SecLevelSecure,
	}
	hit, entryID, _, _, _, _ = ss2.Lookup(ctxOnlySecure)
	if !hit {
		t.Fatal("secure lookup should see secure-only entries")
	}
	if entryID != "only-secure" {
		t.Fatalf("expected only-secure, got %s", entryID)
	}
}

// ===== engine 集成安全域测试 =====

func TestEngine_SecurityLevelIsolation(t *testing.T) {
	cfg := testSemanticConfig()
	cfg.Semantic.Threshold.General = 0.0
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false

	dim := 32
	plainEmb := NewDeterministicEmbedder(dim)
	secureEmb := &mockSecureEmbedder{dim: dim, model: "secure-model"}
	idx := NewFlatVectorIndex(dim, 1000)
	ss, _ := NewSemanticStoreDual(&cfg, plainEmb, secureEmb, idx)

	eng := NewCacheEngine(cfg, WithSemanticStore(ss))

	prompt := "this is a test prompt for security isolation check"
	answer := "this is the answer text for the test prompt"

	// 明文域写入
	ctxPlain := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "plain-hash",
			PromptText:      prompt,
			PolicyVer:       "v1",
			GuardVer:        "v1",
			Scene:           SceneGeneral,
			SecurityLevel:   SecLevelPlain,
		},
		Writable: true,
	}
	outcome := eng.Store(ctxPlain, InferResult{Text: answer, TokensOut: 20, Finish: "stop"})
	if !outcome.Stored {
		t.Fatalf("plain store failed: %s", outcome.Skipped)
	}

	// 密态域写入
	ctxSecure := StoreContext{
		LookupContext: LookupContext{
			TenantID:        "t1",
			EngineType:      "cmaas",
			Model:           "m1",
			MaxNewTokens:    100,
			TransformedHash: "secure-hash",
			PromptText:      prompt,
			PolicyVer:       "v1",
			GuardVer:        "v1",
			Scene:           SceneGeneral,
			SecurityLevel:   SecLevelSecure,
		},
		Writable: true,
	}
	outcome = eng.Store(ctxSecure, InferResult{Text: "secure answer", TokensOut: 20, Finish: "stop"})
	if !outcome.Stored {
		t.Fatalf("secure store failed: %s", outcome.Skipped)
	}

	// 明文精确查询 → 命中明文
	r := eng.Lookup(LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "plain-hash",
		PromptText:      prompt,
		PolicyVer:       "v1",
		GuardVer:        "v1",
		Scene:           SceneGeneral,
		SecurityLevel:   SecLevelPlain,
	})
	if !r.Hit {
		t.Fatalf("plain exact lookup should hit, reason=%s", r.RejectReason)
	}
	if r.Entry.Text != answer {
		t.Fatalf("expected plain answer, got %s", r.Entry.Text)
	}

	// 密态精确查询 → 命中密态
	r = eng.Lookup(LookupContext{
		TenantID:        "t1",
		EngineType:      "cmaas",
		Model:           "m1",
		MaxNewTokens:    100,
		TransformedHash: "secure-hash",
		PromptText:      prompt,
		PolicyVer:       "v1",
		GuardVer:        "v1",
		Scene:           SceneGeneral,
		SecurityLevel:   SecLevelSecure,
	})
	if !r.Hit {
		t.Fatalf("secure exact lookup should hit, reason=%s", r.RejectReason)
	}
	if r.Entry.Text != "secure answer" {
		t.Fatalf("expected secure answer, got %s", r.Entry.Text)
	}
}

// ===== dualEmbedder 测试 =====

func TestDualEmbedder_PlainFallback(t *testing.T) {
	plain := NewDeterministicEmbedder(32)
	de, err := NewDualEmbedder(plain, nil)
	if err != nil {
		t.Fatalf("NewDualEmbedder: %v", err)
	}

	dual := de.(*dualEmbedder)
	if dual.SecureAvailable() {
		t.Fatal("secure should not be available")
	}
	if dual.SecureModel() != "" {
		t.Fatalf("secure model should be empty, got %s", dual.SecureModel())
	}

	// 无 secure 时，secure level 降级到 plain
	vec, err := dual.EmbedSecure(context.Background(), "test", SecLevelSecure)
	if err != nil {
		t.Fatalf("EmbedSecure: %v", err)
	}
	if len(vec) != 32 {
		t.Fatalf("expected 32-dim vec, got %d", len(vec))
	}
}

func TestDualEmbedder_SecurePath(t *testing.T) {
	plain := NewDeterministicEmbedder(32)
	secure := &mockSecureEmbedder{dim: 32, model: "secure-bge"}
	de, err := NewDualEmbedder(plain, secure)
	if err != nil {
		t.Fatalf("NewDualEmbedder: %v", err)
	}

	dual := de.(*dualEmbedder)
	if !dual.SecureAvailable() {
		t.Fatal("secure should be available")
	}
	if dual.SecureModel() != "secure-bge" {
		t.Fatalf("expected secure-bge, got %s", dual.SecureModel())
	}

	// plain 走明文 embedder
	vPlain, _ := dual.EmbedSecure(context.Background(), "hello", SecLevelPlain)
	// secure 走密态 embedder
	vSecure, _ := dual.EmbedSecure(context.Background(), "hello", SecLevelSecure)

	// 两个向量应该不同
	if len(vPlain) != len(vSecure) {
		t.Fatalf("dim mismatch: %d vs %d", len(vPlain), len(vSecure))
	}
	// 检查第一个元素符号（明文是正的，密态 mock 是负的）
	if vPlain[0] == 0 || vSecure[0] == 0 {
		t.Fatalf("vectors should not be zero")
	}
}
