package confllm

import "context"

// VendorSDKClient SDK 型厂商传输抽象（阿里/华为专用密态 SDK 实现；测试用 *Fake）。
//
// 与 ConfidentialLLMProvider 对齐：SDK 密态信道细节封装在 client 内部，
// 返回/接收的已是 L1 归一类型（见 §1.3 / §1.5）。
type VendorSDKClient interface {
	Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
	Stream(ctx context.Context, req *ChatRequest) (StreamReader, error)
	ListModels(ctx context.Context) ([]ModelInfo, error)
	Health(ctx context.Context) HealthStatus
}

// ProviderFactory 从 ProviderConfig 构造 ConfidentialLLMProvider 的工厂（编译期注册，init 约定）。
type ProviderFactory func(cfg ProviderConfig, opts ...ProviderOption) (ConfidentialLLMProvider, error)
