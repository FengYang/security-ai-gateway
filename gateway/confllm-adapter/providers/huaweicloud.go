package providers

import (
	"context"

	"security-ai-gateway/gateway/confllm-adapter"
)

// HuaweiConfidentialClient 华为云专用密态 SDK 客户端抽象（真实实现见 huaweicloud_client.go）。
type HuaweiConfidentialClient = confllm.VendorSDKClient

// HuaweiProvider 华为云（managed + vendor-sdk，专用密态服务 = A+K 双信任根机密计算）。
//
// 华为机密推理 = 用户私有 HYOK 密钥端到端加密的机密服务（PRD §1.1 #3）。本期按文档化密态 endpoint
// 实现真实调用路径（huaweicloud_client.go）+ attestation hook。MaaS OpenAI 兼容网关作为非密态/低保障
// pending-doc 变体，见 huaweicloud_maas.go（§7.1 R1）。
type HuaweiProvider struct {
	id     string
	region confllm.Region
	meta   confllm.ConfidentialityMeta
	caps   confllm.Capabilities
	client confllm.VendorSDKClient
}

// NewHuaweiProvider 构造华为云适配器：注入 *Fake 则用于离线验证，否则构造真实客户端。
func NewHuaweiProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	o := confllm.ApplyOptions(opts...)
	var client confllm.VendorSDKClient
	if o.SDKClient() != nil {
		client = o.SDKClient()
	} else {
		c, err := newHuaweiConfidentialClient(cfg, opts...)
		if err != nil {
			return nil, err
		}
		client = c
	}
	return &HuaweiProvider{
		id:     cfg.ID,
		region: confllm.RegionDomestic,
		meta:   fillMeta(cfg.Meta),
		caps:   cfg.Capabilities,
		client: client,
	}, nil
}

func (p *HuaweiProvider) ID() string                            { return p.id }
func (p *HuaweiProvider) Region() confllm.Region                { return p.region }
func (p *HuaweiProvider) Metadata() confllm.ConfidentialityMeta { return p.meta }
func (p *HuaweiProvider) Capabilities() confllm.Capabilities    { return p.caps }

func (p *HuaweiProvider) Chat(ctx context.Context, req *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	return p.client.Chat(ctx, req)
}
func (p *HuaweiProvider) Stream(ctx context.Context, req *confllm.ChatRequest) (confllm.StreamReader, error) {
	return p.client.Stream(ctx, req)
}
func (p *HuaweiProvider) ListModels(ctx context.Context) ([]confllm.ModelInfo, error) {
	return p.client.ListModels(ctx)
}
func (p *HuaweiProvider) Health(ctx context.Context) confllm.HealthStatus {
	return p.client.Health(ctx)
}

func init() {
	confllm.GlobalRegistry.RegisterType("huawei-confidential", NewHuaweiProvider)
}
