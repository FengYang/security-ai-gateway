package providers

import "security-ai-gateway/gateway/confllm-adapter"

// TencentProvider 腾讯云 TC-AICC / TokenHub（managed，P0，OpenAI 兼容路径）。
//
// 文档：TokenHub OpenAI 兼容 /v1/chat/completions；L2 透传 reasoning_content（§P1-2 / §7.4）。
// 本期仅出向 OpenAI 路径（Anthropic 路径标记 known-but-unsupported，Q6）。
func NewTencentProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	b := buildBaseHTTPProvider(cfg, opts...)
	b.meta = fillMeta(cfg.Meta)
	b.caps = cfg.Capabilities
	if len(b.caps.Protocols) == 0 {
		b.caps.Protocols = []string{"openai"}
	}
	if len(b.caps.AllowedVendorKeys) == 0 {
		b.caps.AllowedVendorKeys = []string{"reasoning_content"}
		b.allowedVendorKeys = b.caps.AllowedVendorKeys
	}
	b.region = confllm.RegionDomestic
	if cfg.Deployment != "" {
		b.meta.Deployment = string(cfg.Deployment)
	}
	return b, nil
}

func init() {
	confllm.GlobalRegistry.RegisterType("tencent", NewTencentProvider)
}
