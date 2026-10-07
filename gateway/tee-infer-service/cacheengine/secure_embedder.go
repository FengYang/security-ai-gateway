package cacheengine

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// ===== 密态路径 embedder =====

// SecureSidecarEmbedderConfig 密态路径 sidecar embedder 配置（§7.4）。
// 密态 embedder 与明文 embedder 隔离：使用独立的 sidecar 端点/模型。
// 安全域内的请求走密态 embedder，向量只在对应安全域内可见。
type SecureSidecarEmbedderConfig struct {
	Enabled bool   // 是否启用密态 embedder
	URL     string // 密态 sidecar endpoint
	Model   string // 密态模型名（可以与明文不同）
	Dim     int    // 向量维度（必须与明文一致，否则不能共用向量索引）
	TimeoutMs int  // 超时毫秒
}

// DefaultSecureEmbedderConfig 返回密态 embedder 默认配置。
// 单一来源：维度/超时与明文 embedder 保持一致（维度不一致则无法共用向量索引）；
// 端点与模型按部署约定由明文默认值派生（端口 +1、模型后缀 "-secure"），
// 上线时应由部署配置显式覆盖。
func DefaultSecureEmbedderConfig() SecureSidecarEmbedderConfig {
	plain := DefaultConfig().Semantic.Embedder
	return SecureSidecarEmbedderConfig{
		Enabled:   false,
		URL:       shiftPort(plain.Endpoint, 1),
		Model:     plain.ModelID + "-secure",
		Dim:       plain.Dim,
		TimeoutMs: int(plain.Timeout.D().Milliseconds()),
	}
}

// shiftPort 将 URL 的端口号加 delta；无端口或不可解析时原样返回。
func shiftPort(rawURL string, delta int) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	port := u.Port()
	if port == "" {
		return rawURL
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return rawURL
	}
	u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(n+delta))
	return u.String()
}

// dualEmbedder 双路 embedder：根据 SecurityLevel 选择明文或密态 embedder。
// plain → plainEmbedder
// secure/hsm → secureEmbedder（若未启用则降级到 plain，调用方需感知降级风险）
type dualEmbedder struct {
	plain  Embedder
	secure Embedder
}

// NewDualEmbedder 构造双路 embedder。
// plain 为明文域 embedder，secure 为密态域 embedder（可为 nil，此时 secure 降级到 plain）。
func NewDualEmbedder(plain, secure Embedder) (Embedder, error) {
	if plain == nil {
		return nil, fmt.Errorf("plain embedder is required")
	}
	return &dualEmbedder{plain: plain, secure: secure}, nil
}

// Embed 根据 SecurityLevel 选择 embedder。
// 注意：此方法签名与 Embedder 接口不匹配（需要 SecurityLevel）。
// 实际使用通过 EmbedSecure 方法。
func (d *dualEmbedder) Embed(ctx context.Context, text string) ([]float32, error) {
	// 默认走明文
	return d.plain.Embed(ctx, text)
}

// EmbedSecure 按安全级别选择 embedder。
func (d *dualEmbedder) EmbedSecure(ctx context.Context, text string, level SecurityLevel) ([]float32, error) {
	if level == SecLevelSecure || level == SecLevelHSM {
		if d.secure != nil {
			return d.secure.Embed(ctx, text)
		}
		// 密态 embedder 未配置 → 降级到明文
		// 调用方（语义层）应通过 SecurityLevel 过滤保证不跨域混存
		return d.plain.Embed(ctx, text)
	}
	return d.plain.Embed(ctx, text)
}

// Dim 返回向量维度（以明文 embedder 为准）。
func (d *dualEmbedder) Dim() int {
	return d.plain.Dim()
}

// Model 返回明文模型名。
func (d *dualEmbedder) Model() string {
	return d.plain.Model()
}

// Available 检查明文 embedder 是否可用。
func (d *dualEmbedder) Available() bool {
	return d.plain.Available()
}

// SecureAvailable 检查密态 embedder 是否可用。
func (d *dualEmbedder) SecureAvailable() bool {
	return d.secure != nil && d.secure.Available()
}

// SecureModel 返回密态模型名（如未配置则返回空）。
func (d *dualEmbedder) SecureModel() string {
	if d.secure == nil {
		return ""
	}
	return d.secure.Model()
}
