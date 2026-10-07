package cacheengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Embedder 向量编码器接口（§3.4）。
// 实现：sidecar（HTTP 调用 TEE 内 embedding sidecar）/ stub（测试用）。
type Embedder interface {
	// Embed 对输入文本生成 embedding 向量。
	// 输入文本通常是经过规范化后的 query 或 response。
	Embed(ctx context.Context, text string) ([]float32, error)
	// Dim 返回向量维度。
	Dim() int
	// Model 返回使用的模型名称（用于标识与版本校验）。
	Model() string
	// Available 检查编码器是否可用（sidecar 存活探针）。
	Available() bool
}

// ===== sidecar HTTP 实现（TEE 内明文域调用） =====

// SidecarEmbedderConfig sidecar 编码器配置。
type SidecarEmbedderConfig struct {
	URL            string        // sidecar embed endpoint，如 http://127.0.0.1:18081/embed
	HealthURL      string        // 健康检查端点；留空则由 URL 推导为 scheme://host/health
	Model          string        // 请求的模型名，如 bge-large-zh-v1.5
	Dim            int           // 预期维度
	Timeout        time.Duration // 请求超时
	MaxConns       int           // 连接池大小
	MaxBatchTokens int           // 单请求最大 token（预留，当前单条）
}

// DefaultSidecarConfig 返回默认 sidecar 配置。
func DefaultSidecarConfig() SidecarEmbedderConfig {
	return SidecarEmbedderConfig{
		URL:      "http://127.0.0.1:8088/embed",
		Model:    "bge-large-zh-v1.5",
		Dim:      1024,
		Timeout:  500 * time.Millisecond,
		MaxConns: 32,
	}
}

// sidecarEmbedder HTTP 调用 TEE 内 embedding sidecar。
type sidecarEmbedder struct {
	cfg    SidecarEmbedderConfig
	client *http.Client
}

// NewSidecarEmbedder 构造 sidecar 编码器。
func NewSidecarEmbedder(cfg SidecarEmbedderConfig) (Embedder, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("embedder url is required")
	}
	if cfg.Dim <= 0 {
		return nil, fmt.Errorf("embedder dim must be positive")
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 500 * time.Millisecond
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 32
	}
	// HealthURL 留空时由 embed endpoint 推导（scheme://host/health），
	// 避免把健康检查拼到 /embed 之后（历史上的 /embed/health 缺陷）。
	if cfg.HealthURL == "" {
		cfg.HealthURL = deriveHealthURL(cfg.URL)
	}
	return &sidecarEmbedder{
		cfg: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        cfg.MaxConns,
				MaxIdleConnsPerHost: cfg.MaxConns,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}, nil
}

// embedRequest sidecar 请求体。
type embedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

// embedResponse sidecar 响应体。
type embedResponse struct {
	Data []struct {
		Embedding []float32 `json:"embedding"`
		Index     int       `json:"index"`
	} `json:"data"`
	Model string `json:"model,omitempty"`
	Error string `json:"error,omitempty"`
}

// Embed 调用 sidecar 生成向量。
func (s *sidecarEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	if text == "" {
		return nil, fmt.Errorf("embedder: empty text")
	}

	reqBody := embedRequest{
		Model: s.cfg.Model,
		Input: []string{text},
	}
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("embedder: marshal: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(buf))
	if err != nil {
		return nil, fmt.Errorf("embedder: new request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := s.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("embedder: request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, fmt.Errorf("embedder: status %d: %s", resp.StatusCode, string(body))
	}

	var out embedResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("embedder: decode: %w", err)
	}
	if out.Error != "" {
		return nil, fmt.Errorf("embedder: %s", out.Error)
	}
	if len(out.Data) == 0 || len(out.Data[0].Embedding) == 0 {
		return nil, fmt.Errorf("embedder: empty embedding")
	}
	if len(out.Data[0].Embedding) != s.cfg.Dim {
		return nil, fmt.Errorf("embedder: dim mismatch: got %d, expected %d",
			len(out.Data[0].Embedding), s.cfg.Dim)
	}
	return out.Data[0].Embedding, nil
}

func (s *sidecarEmbedder) Dim() int      { return s.cfg.Dim }
func (s *sidecarEmbedder) Model() string { return s.cfg.Model }

// Available 通过轻量 GET 请求检查 sidecar 是否存活。
// 使用独立推导/配置的 HealthURL（不再把 "/health" 拼到 embed 端点之后）。
func (s *sidecarEmbedder) Available() bool {
	if s.cfg.HealthURL == "" {
		return false // 无法推导健康端点 → 视为不可用（fail-closed 到语义 miss）
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.HealthURL, nil)
	if err != nil {
		return false
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// deriveHealthURL 从 embed endpoint 推导健康检查地址（scheme://host/health）。
// 例：http://127.0.0.1:18081/embed → http://127.0.0.1:18081/health
// 无法解析（缺 scheme/host）时返回空串，由调用方按不可用处理。
func deriveHealthURL(embedURL string) string {
	u, err := url.Parse(embedURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host + "/health"
}

// ===== stub 实现（测试/默认关闭） =====

// stubEmbedder 空实现，返回不可用。用于 mode=off 或 exact 时的占位。
type stubEmbedder struct {
	dim int
}

// NewStubEmbedder 构造 stub 编码器（不可用）。
func NewStubEmbedder(dim int) Embedder {
	if dim <= 0 {
		dim = 1024
	}
	return &stubEmbedder{dim: dim}
}

func (s *stubEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	return nil, fmt.Errorf("embedder: stub not available")
}
func (s *stubEmbedder) Dim() int       { return s.dim }
func (s *stubEmbedder) Model() string  { return "stub" }
func (s *stubEmbedder) Available() bool { return false }

// deterministicEmbedder 确定性向量生成（测试专用）。
// 基于文本哈希生成稳定的伪随机向量，便于单测验证索引逻辑。
type deterministicEmbedder struct {
	dim int
}

// NewDeterministicEmbedder 构造确定性测试编码器。
func NewDeterministicEmbedder(dim int) Embedder {
	if dim <= 0 {
		dim = 32
	}
	return &deterministicEmbedder{dim: dim}
}

func (d *deterministicEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	vec := make([]float32, d.dim)
	// 简单确定性：用字节和 + 位置生成有区分度的伪向量
	sum := float32(0)
	for _, c := range text {
		sum += float32(c)
	}
	for i := 0; i < d.dim; i++ {
		v := float32(i+1)*0.1 + sum*0.001
		// 让不同文本的向量方向有差异
		if i%2 == 0 {
			v = -v
		}
		vec[i] = v
	}
	return vec, nil
}
func (d *deterministicEmbedder) Dim() int       { return d.dim }
func (d *deterministicEmbedder) Model() string  { return "deterministic-test" }
func (d *deterministicEmbedder) Available() bool { return true }
