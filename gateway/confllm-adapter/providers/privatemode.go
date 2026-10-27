package providers

import "security-ai-gateway/gateway/confllm-adapter"

// PrivatemodeProvider Edgeless Systems Privatemode（proxy-mediated，P0，OpenAI 兼容）。
//
// 文档：客户端须先部署本地 proxy（ghcr.io/edgelesssys/privatemode/privatemode-proxy），
// endpoint 指向本地 proxy（如 http://localhost:8787）。proxy 在 prompt 离开本机前
// 校验远程证明。本期 proxy 由运维侧部署，适配器走标准 OpenAI 兼容路径。
func NewPrivatemodeProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	b := buildBaseHTTPProvider(cfg, opts...)
	b.meta = fillMeta(cfg.Meta)
	b.caps = cfg.Capabilities
	if len(b.caps.Protocols) == 0 {
		b.caps.Protocols = []string{"openai"}
	}
	b.region = confllm.RegionForeign
	if cfg.Deployment == "" {
		b.meta.Deployment = string(confllm.DeploymentProxyMediated)
	} else {
		b.meta.Deployment = string(cfg.Deployment)
	}
	return b, nil
}

func init() {
	confllm.GlobalRegistry.RegisterType("privatemode", NewPrivatemodeProvider)
}
