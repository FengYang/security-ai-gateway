package providers

import (
	"context"

	"security-ai-gateway/gateway/confllm-adapter"
)

// HuaweiConfidentialClient 华为云专用密态 SDK 客户端抽象（真实实现见 huaweicloud_client.go）。
type HuaweiConfidentialClient = confllm.VendorSDKClient

// HuaweiProvider 华为云密态服务（K1：`huawei-confidential` = `managed` + `vendor-sdk` 传输抽象）。
//
// 华为密态推理技术脉络：TEE（Kunpeng/昇腾）+ xEnclave 远程证明 + HYOK 自持密钥（A+K 双信任根）。
// **2026-10-27 调研结论**：华为密态推理 = 在 ModelArts 托管推理 endpoint 开启 confidential_inference
// 配置开关，经标准 RESTful + IAM Token 头 `X-Auth-Token` 调用；官方仅 Python SDK，**无 Go SDK、无类
// pai-cc 的 CLI**。故 K1 的 `vendor-sdk` 传输抽象在华为侧**落地为 HTTP/REST 真实调用**（见
// huaweicloud_client.go 的 huaweiClientImpl，已含 `X-Auth-Token` 鉴权 + attestation hook），属诚实
// realization，非"待 SDK 替换的占位"。
// MaaS OpenAI 兼容网关作为非密态/低保障变体，见 huaweicloud_maas.go（§7.1 R1）。
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
