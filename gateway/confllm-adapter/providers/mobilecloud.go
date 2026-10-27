package providers

import (
	"context"
	"fmt"

	"security-ai-gateway/gateway/confllm-adapter"
)

// MobileCloudRequiredCredentials 移动云 MoMA 接入所需的凭据清单（候补骨架，pending-credential）。
//
// 移动云公开 API 文档不足（仅产品能力页，无 curl/SDK 示例），本期实现接口 + 状态反馈，
// 真实协议接入待用户补齐凭据与文档（pending-credential + pending-doc，不在 10 家内）。
var MobileCloudRequiredCredentials = []string{
	"MOBILECLOUD_API_KEY",
	"MOBILECLOUD_ENDPOINT",
	"MOBILECLOUD_ACCOUNT_ID",
	"MOBILECLOUD_TENANT_TOKEN",
}

// MobileCloudProvider 移动云 MoMA 候补骨架（pending-credential）。
// 实现 ConfidentialLLMProvider 仅在未配置凭据时返回明确 pending 错误 + 所需凭据清单。
type MobileCloudProvider struct {
	id   string
	meta confllm.ConfidentialityMeta
}

// NewMobileCloudProvider 构造移动云骨架（不参与 10 家真实调用）。
func NewMobileCloudProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (confllm.ConfidentialLLMProvider, error) {
	return &MobileCloudProvider{id: cfg.ID, meta: fillMeta(cfg.Meta)}, nil
}

func (m *MobileCloudProvider) ID() string                            { return m.id }
func (m *MobileCloudProvider) Region() confllm.Region                { return confllm.RegionDomestic }
func (m *MobileCloudProvider) Metadata() confllm.ConfidentialityMeta { return m.meta }
func (m *MobileCloudProvider) Capabilities() confllm.Capabilities    { return confllm.Capabilities{} }

// Chat 返回 pending-credential 错误 + 所需凭据清单（绝不降级为无凭据直连，§7.3 R5）。
func (m *MobileCloudProvider) Chat(ctx context.Context, req *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	return nil, confllm.NewProviderError(confllm.CodePendingCredential, 503,
		fmt.Sprintf("移动云 MoMA 骨架未接入：缺少凭据 %v（pending-credential）", MobileCloudRequiredCredentials))
}

// Stream 同 Chat（pending-credential）。
func (m *MobileCloudProvider) Stream(ctx context.Context, req *confllm.ChatRequest) (confllm.StreamReader, error) {
	return nil, confllm.NewProviderError(confllm.CodePendingCredential, 503,
		fmt.Sprintf("移动云 MoMA 骨架未接入：缺少凭据 %v（pending-credential）", MobileCloudRequiredCredentials))
}

// ListModels 同 Chat（pending-credential）。
func (m *MobileCloudProvider) ListModels(ctx context.Context) ([]confllm.ModelInfo, error) {
	return nil, confllm.NewProviderError(confllm.CodePendingCredential, 503,
		fmt.Sprintf("移动云 MoMA 骨架未接入：缺少凭据 %v（pending-credential）", MobileCloudRequiredCredentials))
}

// Health 标记 pending-credential。
func (m *MobileCloudProvider) Health(ctx context.Context) confllm.HealthStatus {
	return confllm.HealthStatus{Ready: false, PendingCredential: true, Detail: "pending-credential", MinConfidentialityClass: m.meta.ConfidentialityClass}
}

func init() {
	confllm.GlobalRegistry.RegisterType("mobilecloud", NewMobileCloudProvider)
}
