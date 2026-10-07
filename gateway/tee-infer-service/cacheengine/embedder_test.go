package cacheengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestDeriveHealthURL 健康端点推导（回归锚：不再把 /health 拼到 /embed 之后）。
func TestDeriveHealthURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{"http://127.0.0.1:18081/embed", "http://127.0.0.1:18081/health"},
		{"https://sidecar.internal:8443/embed", "https://sidecar.internal:8443/health"},
		{"http://h:9/api/v1/embed", "http://h:9/health"},
		{"", ""},
		{"127.0.0.1:18081/embed", ""}, // 缺 scheme
		{"/embed", ""},                // 缺 host
	}
	for _, c := range cases {
		if got := deriveHealthURL(c.in); got != c.want {
			t.Errorf("deriveHealthURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSidecarEmbedder_Available_UsesRootHealthPath 探活命中 /health（而非 /embed/health）。
func TestSidecarEmbedder_Available_UsesRootHealthPath(t *testing.T) {
	var gotPath string
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNotFound)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	emb, err := NewSidecarEmbedder(SidecarEmbedderConfig{URL: ts.URL + "/embed", Model: "m", Dim: 4})
	if err != nil {
		t.Fatalf("NewSidecarEmbedder: %v", err)
	}
	if !emb.Available() {
		t.Fatal("expected Available()=true when /health returns 200")
	}
	if gotPath != "/health" {
		t.Fatalf("health probe path = %q, want /health", gotPath)
	}
}

// TestSidecarEmbedder_Available_Non200 健康端点非 200 → 不可用。
func TestSidecarEmbedder_Available_Non200(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	emb, err := NewSidecarEmbedder(SidecarEmbedderConfig{URL: ts.URL + "/embed", Model: "m", Dim: 4})
	if err != nil {
		t.Fatalf("NewSidecarEmbedder: %v", err)
	}
	if emb.Available() {
		t.Fatal("expected Available()=false on non-200 health")
	}
}

// TestSidecarEmbedder_Available_UnparsableURL 无法推导健康端点 → fail-closed 不可用。
func TestSidecarEmbedder_Available_UnparsableURL(t *testing.T) {
	emb, err := NewSidecarEmbedder(SidecarEmbedderConfig{URL: "127.0.0.1:18081/embed", Model: "m", Dim: 4})
	if err != nil {
		t.Fatalf("NewSidecarEmbedder: %v", err)
	}
	if emb.Available() {
		t.Fatal("expected Available()=false when health URL cannot be derived")
	}
}

// TestSidecarEmbedder_Embed_OK 正常 embed（含维度校验）。
func TestSidecarEmbedder_Embed_OK(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/embed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"embedding":[0.1,0.2,0.3,0.4],"index":0}]}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	emb, err := NewSidecarEmbedder(SidecarEmbedderConfig{URL: ts.URL + "/embed", Model: "m", Dim: 4, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewSidecarEmbedder: %v", err)
	}
	vec, err := emb.Embed(context.Background(), "hello")
	if err != nil {
		t.Fatalf("Embed: %v", err)
	}
	if len(vec) != 4 {
		t.Fatalf("embedding dim = %d, want 4", len(vec))
	}
}

// TestSidecarEmbedder_Embed_DimMismatch 维度不一致 → 报错（不静默接受）。
func TestSidecarEmbedder_Embed_DimMismatch(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/embed", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"embedding":[0.1,0.2],"index":0}]}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	emb, err := NewSidecarEmbedder(SidecarEmbedderConfig{URL: ts.URL + "/embed", Model: "m", Dim: 8, Timeout: time.Second})
	if err != nil {
		t.Fatalf("NewSidecarEmbedder: %v", err)
	}
	if _, err := emb.Embed(context.Background(), "hello"); err == nil {
		t.Fatal("expected dim mismatch error")
	} else if !strings.Contains(err.Error(), "dim mismatch") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestDefaultSidecarConfig_SingleSource 默认值单一来源：完全派生自 DefaultConfig 的 embedder 段。
func TestDefaultSidecarConfig_SingleSource(t *testing.T) {
	e := DefaultConfig().Semantic.Embedder
	sc := DefaultSidecarConfig()
	if sc.URL != e.Endpoint {
		t.Errorf("URL = %q, want %q", sc.URL, e.Endpoint)
	}
	if sc.HealthURL != e.HealthEndpoint {
		t.Errorf("HealthURL = %q, want %q", sc.HealthURL, e.HealthEndpoint)
	}
	if sc.Model != e.ModelID {
		t.Errorf("Model = %q, want %q", sc.Model, e.ModelID)
	}
	if sc.Dim != e.Dim {
		t.Errorf("Dim = %d, want %d", sc.Dim, e.Dim)
	}
	if sc.Timeout != e.Timeout.D() {
		t.Errorf("Timeout = %v, want %v", sc.Timeout, e.Timeout.D())
	}
}

// TestVerifyEmbedderDim 启动期维度探针：一致通过；不一致 / nil / 不可用均失败。
func TestVerifyEmbedderDim(t *testing.T) {
	emb := NewDeterministicEmbedder(8)
	if err := VerifyEmbedderDim(context.Background(), emb, 8); err != nil {
		t.Fatalf("expected pass, got %v", err)
	}
	if err := VerifyEmbedderDim(context.Background(), emb, 16); err == nil {
		t.Fatal("expected dim mismatch error")
	}
	if err := VerifyEmbedderDim(context.Background(), nil, 8); err == nil {
		t.Fatal("expected error for nil embedder")
	}
	if err := VerifyEmbedderDim(context.Background(), NewStubEmbedder(8), 8); err == nil {
		t.Fatal("expected error for unavailable (stub) embedder")
	}
}
