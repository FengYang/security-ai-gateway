package providers

import "security-ai-gateway/gateway/confllm-adapter"

// NEARAIProvider NEAR AI Cloud Confidential Inference（managed，P0，OpenAI 兼容）。
//
// 文档：https://cloud-api.near.ai/v1/chat/completions；每响应携带硬件签名 quote
// （X-Attestation 头），本期仅记录不校验（NearQuoteVerifier 返回 unknown，R4）。
// 模型目录含 deepseek/GLM/Kimi/Qwen，与国内语义对齐。
func NewNEARAIProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	b := buildBaseHTTPProvider(cfg, opts...)
	b.meta = fillMeta(cfg.Meta)
	b.caps = cfg.Capabilities
	if len(b.caps.Protocols) == 0 {
		b.caps.Protocols = []string{"openai"}
	}
	// NEAR 真实模型列表路径为 /v1/model/list（非 OpenAI 惯例 /v1/models），
	// 由 golden request 锁定（§7.4 QA2-13/14），避免 mock 双路径掩盖真实 404。
	b.modelsPath = "/v1/model/list"
	b.region = confllm.RegionForeign
	if cfg.Deployment != "" {
		b.meta.Deployment = string(cfg.Deployment)
	}
	return b, nil
}

func init() {
	confllm.GlobalRegistry.RegisterType("nearai", NewNEARAIProvider)
}
