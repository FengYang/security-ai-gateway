package providers

import "security-ai-gateway/gateway/confllm-adapter"

// GCPProvider Google Cloud Confidential GKE Nodes（self-hosted，P1）。
//
// 文档：机密推理 = 在 Confidential GKE 节点上自建 vLLM / TensorRT-LLM / SGLang，
// 暴露 OpenAI 兼容 endpoint（客户自有机密 endpoint，非托管 LLM API）。
// endpoint 由客户配置（如 https://<customer-confidential-gke>/v1）。
func NewGCPProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
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
	return b, nil
}

func init() {
	confllm.GlobalRegistry.RegisterType("gcp", NewGCPProvider)
}
