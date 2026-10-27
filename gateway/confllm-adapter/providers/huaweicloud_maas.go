package providers

import "security-ai-gateway/gateway/confllm-adapter"

// HuaweiMaaSProvider 华为云 ModelArts Studio（MaaS）OpenAI 兼容变体。
//
// 形态：managed + http，非密态 / 低保障（pending-doc，§7.1 R1）。
// MaaS 公有 API 是否运行在机密域内，公开文档未明确（与阿里百炼同款风险），故密态等级默认 unknown，
// 不声称 A 类。与 HuaweiProvider（专用密态服务 = A 类）是同一厂商的两种形态（§7 R1）。
func NewHuaweiMaaSProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	b := buildBaseHTTPProvider(cfg, opts...)
	b.meta = fillMeta(cfg.Meta)
	b.region = confllm.RegionDomestic
	b.caps = cfg.Capabilities
	if len(b.caps.Protocols) == 0 {
		b.caps.Protocols = []string{"openai"}
	}
	// MaaS OpenAI 兼容 endpoint（如 https://api.modelarts-maas.com/openai/v1）。
	// 非密态变体：密态等级保持 unknown（不冒充 A 类，§7.5）。
	return b, nil
}

func init() {
	confllm.GlobalRegistry.RegisterType("huawei-maas", NewHuaweiMaaSProvider)
}
