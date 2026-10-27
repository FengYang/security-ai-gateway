package providers

import "security-ai-gateway/gateway/confllm-adapter"

// VolcengineProvider 火山引擎方舟（managed，P0，OpenAI 兼容）。
//
// 文档：方舟 OpenAI 兼容 /api/v3/chat/completions；L2 透传 thinking（§P1-2 / §7.4）。
func NewVolcengineProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	b := buildBaseHTTPProvider(cfg, opts...)
	b.meta = fillMeta(cfg.Meta)
	b.chatPath = "/api/v3/chat/completions"
	b.caps = cfg.Capabilities
	if len(b.caps.Protocols) == 0 {
		b.caps.Protocols = []string{"openai"}
	}
	if len(b.caps.AllowedVendorKeys) == 0 {
		b.caps.AllowedVendorKeys = []string{"thinking"}
		b.allowedVendorKeys = b.caps.AllowedVendorKeys
	}
	b.region = confllm.RegionDomestic
	if cfg.Deployment != "" {
		b.meta.Deployment = string(cfg.Deployment)
	}
	return b, nil
}

func init() {
	confllm.GlobalRegistry.RegisterType("volcengine", NewVolcengineProvider)
}
