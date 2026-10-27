package providers

import (
	"context"

	"security-ai-gateway/gateway/confllm-adapter"
)

// AliyunConfidentialClient 阿里云专用密态 SDK 客户端抽象（真实实现见 aliyun_client.go）。
type AliyunConfidentialClient = confllm.VendorSDKClient

// AliyunProvider 阿里云百炼机密推理（managed + vendor-sdk，可验证密态服务，K1 必须支持）。
//
// 真实形态 = TEE + TNG 可信网关 + Trustee 远程证明，厂商交付物为 pai-cc 工具链（无官方 Go SDK），
// 真实调用路径见 aliyun_client.go（pai-cc 子进程 + attest-then-infer fail-closed）。
// 与「百炼 DashScope 公有 API」（aliyun-bailian，http 非密态）是两个不同服务/不同 provider，
// 无回退通道。对接方案：docs/详细设计/confllm/百炼机密推理-技术对接方案.md。
type AliyunProvider struct {
	id     string
	region confllm.Region
	meta   confllm.ConfidentialityMeta
	caps   confllm.Capabilities
	client confllm.VendorSDKClient
}

// NewAliyunProvider 构造阿里云适配器：注入 *Fake 则用于离线验证，否则构造真实客户端。
func NewAliyunProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	o := confllm.ApplyOptions(opts...)
	var client confllm.VendorSDKClient
	if o.SDKClient() != nil {
		client = o.SDKClient()
	} else {
		c, err := newAliyunConfidentialClient(cfg, opts...)
		if err != nil {
			return nil, err
		}
		client = c
	}
	return &AliyunProvider{
		id:     cfg.ID,
		region: confllm.RegionDomestic,
		meta:   fillMeta(cfg.Meta),
		caps:   cfg.Capabilities,
		client: client,
	}, nil
}

func (p *AliyunProvider) ID() string                            { return p.id }
func (p *AliyunProvider) Region() confllm.Region                { return p.region }
func (p *AliyunProvider) Metadata() confllm.ConfidentialityMeta { return p.meta }
func (p *AliyunProvider) Capabilities() confllm.Capabilities    { return p.caps }

func (p *AliyunProvider) Chat(ctx context.Context, req *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	return p.client.Chat(ctx, req)
}
func (p *AliyunProvider) Stream(ctx context.Context, req *confllm.ChatRequest) (confllm.StreamReader, error) {
	return p.client.Stream(ctx, req)
}
func (p *AliyunProvider) ListModels(ctx context.Context) ([]confllm.ModelInfo, error) {
	return p.client.ListModels(ctx)
}
func (p *AliyunProvider) Health(ctx context.Context) confllm.HealthStatus {
	return p.client.Health(ctx)
}

func init() {
	confllm.GlobalRegistry.RegisterType("aliyun-confidential", NewAliyunProvider)
}
