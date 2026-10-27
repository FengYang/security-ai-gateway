package providers

import "security-ai-gateway/gateway/confllm-adapter"

// AliyunBailianProvider 阿里云百炼 DashScope（managed + http，OpenAI 兼容 compatible-mode/v1）。
//
// 形态：非密态 / 低保障（K1 双服务裁决：与 aliyun-confidential（CAI 机密 AI，SDK 密态·可验证）是同一厂商
// 的**两种不同服务**，无回退通道）。百炼公有 API 是否运行在机密域内，公开文档未明确，故密态等级默认
// unknown，不声称 A 类（§7 R1）。本期按文档化 OpenAI 兼容 endpoint 实现真实调用路径（BaseHTTPProvider），
// pending-doc 验证其密态等级。
//
// 注册类型键：aliyun-bailian（与 aliyun-confidential 并列，K1 终裁）。
func NewAliyunBailianProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	b := buildBaseHTTPProvider(cfg, opts...)
	b.meta = fillMeta(cfg.Meta)
	b.region = confllm.RegionDomestic
	b.caps = cfg.Capabilities
	if len(b.caps.Protocols) == 0 {
		b.caps.Protocols = []string{"openai"}
	}
	// 非密态变体：密态等级保持 unknown（不冒充 A 类，§7.5 K7）。
	return b, nil
}

func init() {
	confllm.GlobalRegistry.RegisterType("aliyun-bailian", NewAliyunBailianProvider)
}
