package providers

import "security-ai-gateway/gateway/confllm-adapter"

// AWSProvider AWS Nitro Enclaves（self-hosted / Enclave，P1）。
//
// 文档：Nitro Enclaves 无 GPU 直通，宜作密态前置处理 / 网关 / 小量化模型。
// 形态为在 Enclave 内自建 OpenAI 兼容服务，经 vsock 通信；endpoint 由客户配置。
func NewAWSProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	b := buildBaseHTTPProvider(cfg, opts...)
	b.meta = fillMeta(cfg.Meta)
	b.caps = cfg.Capabilities
	if len(b.caps.Protocols) == 0 {
		b.caps.Protocols = []string{"openai"}
	}
	b.region = confllm.RegionForeign
	if cfg.Deployment == "" {
		b.meta.Deployment = string(confllm.DeploymentSelfHostedCVM)
	} else {
		b.meta.Deployment = string(cfg.Deployment)
	}
	// Nitro Enclaves 宜作密态前置/小模型，标记 thinking 不一定支持。
	b.caps.SupportsTools = false
	return b, nil
}

func init() {
	confllm.GlobalRegistry.RegisterType("aws", NewAWSProvider)
}
