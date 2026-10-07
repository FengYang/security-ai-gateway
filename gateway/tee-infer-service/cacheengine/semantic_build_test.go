package cacheengine

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// fakeSidecar 返回固定向量的 embedding sidecar（用于打通语义链路：不同文本 → 相同向量 → 命中）。
func fakeSidecar(t *testing.T, dim int) *httptest.Server {
	t.Helper()
	vec := make([]float32, dim)
	for i := range vec {
		vec[i] = 0.125
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/embed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": []any{map[string]any{"embedding": vec, "index": 0}},
		})
	})
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	return httptest.NewServer(mux)
}

func semanticTestCfg(t *testing.T, sidecarURL string, dim int) CacheConfig {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Mode = ModeSemantic
	cfg.Semantic.Enabled = true
	cfg.Semantic.Embedder.Endpoint = sidecarURL + "/embed"
	cfg.Semantic.Embedder.HealthEndpoint = sidecarURL + "/health"
	cfg.Semantic.Embedder.Dim = dim
	cfg.Exact.MinPromptTokens = 2
	cfg.Exact.MinTokens = 2
	cfg.Guard.ReadFastCheck = false
	cfg.Guard.WriteRequiresOutGuard = false
	return cfg
}

// TestBuildSemanticStoreFromConfig_DisabledSemantic 语义关闭 → 不组装、无错误。
func TestBuildSemanticStoreFromConfig_DisabledSemantic(t *testing.T) {
	cfg := DefaultConfig() // Semantic.Enabled=false
	store, err := BuildSemanticStoreFromConfig(context.Background(), &cfg)
	if err != nil || store != nil {
		t.Fatalf("store=%v err=%v, want (nil, nil)", store, err)
	}
}

// TestBuildSemanticStoreFromConfig_ProbeFailsFailClosed sidecar 不可用 → 组装失败（fail-closed）。
func TestBuildSemanticStoreFromConfig_ProbeFailsFailClosed(t *testing.T) {
	cfg := semanticTestCfg(t, "http://127.0.0.1:1", 8) // 不可达
	if _, err := BuildSemanticStoreFromConfig(context.Background(), &cfg); err == nil {
		t.Fatal("expected fail-closed when embedder unreachable")
	}
}

// TestBuildSemanticStoreFromConfig_VSSFailClosed 配置 redis-vss 但未满足双条件 → 拒绝。
func TestBuildSemanticStoreFromConfig_VSSFailClosed(t *testing.T) {
	ts := fakeSidecar(t, 8)
	defer ts.Close()
	cfg := semanticTestCfg(t, ts.URL, 8)
	cfg.Semantic.Vector.Backend = "redis-vss" // 无 RediSearch / 未配置可信域
	if _, err := BuildSemanticStoreFromConfig(context.Background(), &cfg); err == nil {
		t.Fatal("expected fail-closed for redis-vss without capabilities")
	}
}

// TestSemantic_EndToEnd_Hit 语义链路端到端：写入后，近义文本（不同精确键）经语义命中。
func TestSemantic_EndToEnd_Hit(t *testing.T) {
	dim := 8
	ts := fakeSidecar(t, dim)
	defer ts.Close()

	cfg := semanticTestCfg(t, ts.URL, dim)
	store, err := BuildSemanticStoreFromConfig(context.Background(), &cfg)
	if err != nil {
		t.Fatalf("build semantic store: %v", err)
	}
	if store == nil {
		t.Fatal("expected non-nil semantic store")
	}

	eng := NewCacheEngine(cfg, WithSemanticStore(store))
	sc := StoreContext{
		LookupContext: LookupContext{
			TenantID: "t1", EngineType: "cmaas", Model: "m1", MaxNewTokens: 100,
			TransformedHash: "h1", PromptText: "原始问题内容", PolicyVer: "1", GuardVer: "v1",
			Scene: SceneGeneral,
		},
		Writable: true,
	}
	if out := eng.Store(sc, InferResult{Text: "缓存的答案文本", TokensOut: 20, Finish: "stop"}); !out.Stored {
		t.Fatalf("store: %+v", out)
	}

	// 近义查询：精确键不同（h2）→ 精确不命中，应经语义命中
	lc := sc.LookupContext
	lc.TransformedHash = "h2"
	lc.PromptText = "近义问法内容"
	r := eng.Lookup(lc)
	if !r.Hit {
		t.Fatalf("expected semantic hit, got reason=%s", r.RejectReason)
	}
	if r.Kind != KindSemantic {
		t.Fatalf("expected KindSemantic, got %s", r.Kind)
	}
	if r.Entry == nil || r.Entry.Text != "缓存的答案文本" {
		t.Fatalf("unexpected replayed entry: %+v", r.Entry)
	}
}
