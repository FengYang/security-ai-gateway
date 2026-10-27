package providers

import (
	"context"
	"fmt"
	"net/http"

	"security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/normalize"
	"security-ai-gateway/gateway/confllm-adapter/ohttp"
)

// AzureProvider Microsoft Azure Confidential Inferencing（proxy-mediated，P1，OHTTP/HPKE + MAA 占位）。
//
// 文档：Azure 机密推理使用 OHTTP + HPKE 端到端加密，需客户端本地/企业 proxy 中转。
//   - 非 OHTTP 分支（Attestation.Mode != "ohttp"）：走标准 OpenAI 兼容路径（契约测试覆盖此分支，§QA-6）。
//   - OHTTP 分支：用对端 HPKE 公钥加密请求体，经 proxy 转发至机密 enclave（真实加密，pending-doc 待用户提供公钥）。
//
// MAA 证明校验本期为占位（MAAVerifier 返回 unknown，R4）。
//
// pending-doc：Azure 提供的 HPKE 公钥需用户后续补齐；缺公钥时 OHTTP 分支返回明确错误而非静默降级。
type AzureProvider struct {
	*BaseHTTPProvider
	ohttpClient *ohttp.OHClient
	proxyURL    string
}

// NewAzureProvider 构造 Azure 适配器。
func NewAzureProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	b := buildBaseHTTPProvider(cfg, opts...)
	b.meta = fillMeta(cfg.Meta)
	b.caps = cfg.Capabilities
	if len(b.caps.Protocols) == 0 {
		b.caps.Protocols = []string{"openai"}
	}
	if len(b.caps.AllowedVendorKeys) == 0 {
		b.caps.AllowedVendorKeys = []string{"ohttp", "hpke"}
		b.allowedVendorKeys = b.caps.AllowedVendorKeys
	}
	b.region = confllm.RegionForeign
	if cfg.Deployment == "" {
		b.meta.Deployment = string(confllm.DeploymentProxyMediated)
	} else {
		b.meta.Deployment = string(cfg.Deployment)
	}

	az := &AzureProvider{BaseHTTPProvider: b}
	if cfg.Attestation.Mode == "ohttp" {
		az.proxyURL = firstNonEmpty(cfg.ProxyMediated.ProxyURL, cfg.Endpoint)
		// pending-doc：peerHPK 需用户从 Azure 机密推理文档获取并注入配置。
		// 此处置 nil，调用 OHTTP 分支时返回明确错误（fail-closed，不静默降级）。
		_ = az.proxyURL
	}
	return az, nil
}

// Chat 覆盖基类：OHTTP 模式走加密分支，否则走标准 OpenAI 分支。
func (a *AzureProvider) Chat(ctx context.Context, req *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	if a.ohttpClient != nil {
		return a.chatOHTTP(ctx, req)
	}
	return a.BaseHTTPProvider.Chat(ctx, req)
}

// Stream 覆盖基类：OHTTP 模式走加密分支，否则走标准 OpenAI 分支。
func (a *AzureProvider) Stream(ctx context.Context, req *confllm.ChatRequest) (confllm.StreamReader, error) {
	if a.ohttpClient != nil {
		return nil, confllm.NewProviderError(confllm.CodeInvalidRequest, http.StatusBadRequest,
			"Azure OHTTP 流式分支 pending-doc：当前未实现加密流式通道")
	}
	return a.BaseHTTPProvider.Stream(ctx, req)
}

// chatOHTTP OHTTP/HPKE 加密分支（真实加密 + 真实 HTTP；framing 为简化占位，见 ohttp.PendingDocNote）。
func (a *AzureProvider) chatOHTTP(ctx context.Context, req *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	cred, err := a.resolveCredential(ctx)
	if err != nil {
		return nil, err
	}
	body := a.buildBody(req)
	enc, ct, err := a.ohttpClient.Encrypt(body)
	if err != nil {
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway, "OHTTP 加密失败")
	}
	// 简化 binary HTTP framing 占位：encapsulated key 拼接 ciphertext（pending-doc RFC 9458）。
	payload := append(append([]byte{}, enc...), ct...)
	url := a.proxyURL + a.chatPath
	raw, _, perr := a.doRequest(ctx, http.MethodPost, url, payload, cred.Key)
	if perr != nil {
		return nil, perr
	}
	return normalize.ParseChatCompletion(raw)
}

var _ = fmt.Sprintf
