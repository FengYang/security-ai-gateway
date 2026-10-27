package providers

import (
	"context"

	"security-ai-gateway/gateway/confllm-adapter"
)

// huaweiClientImpl 华为云密态客户端真实实现（按文档化密态 endpoint 调用，A+K 双信任根）。
//
// 华为机密推理 = 用户私有 HYOK 密钥端到端加密（PRD §1.1 #3），endpoint 由用户提供于 cfg.Endpoint。
// 调用前执行 attestation hook（占位，Verdict=unknown，R4）。
// pending-doc：若用户提供专用密态 SDK（gated），在此替换内部 HTTP 调用为 SDK 调用，适配层不变。
type huaweiClientImpl struct {
	*BaseHTTPProvider
}

func newHuaweiConfidentialClient(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) (*huaweiClientImpl, error) {
	b := buildBaseHTTPProvider(cfg, opts...)
	b.meta = fillMeta(cfg.Meta)
	b.region = confllm.RegionDomestic
	b.caps = cfg.Capabilities
	if len(b.caps.Protocols) == 0 {
		b.caps.Protocols = []string{"openai"}
	}
	return &huaweiClientImpl{BaseHTTPProvider: b}, nil
}

// HuaweiConfidentialClientFake 华为云客户端离线验证用 Fake。
type HuaweiConfidentialClientFake struct {
	lastChat *confllm.ChatRequest
	fixed    *confllm.ChatResponse
	fail     bool
}

// NewHuaweiConfidentialClientFake 构造离线验证 Fake。
func NewHuaweiConfidentialClientFake() *HuaweiConfidentialClientFake {
	return &HuaweiConfidentialClientFake{}
}

// SetFail 设置是否强制失败。
func (f *HuaweiConfidentialClientFake) SetFail(v bool) { f.fail = v }

// LastChat 返回最近一次 Chat 请求（断言用）。
func (f *HuaweiConfidentialClientFake) LastChat() *confllm.ChatRequest { return f.lastChat }

func (f *HuaweiConfidentialClientFake) Chat(ctx context.Context, req *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	if f.fail {
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, 502, "fake forced failure")
	}
	f.lastChat = req
	if f.fixed != nil {
		return f.fixed, nil
	}
	return &confllm.ChatResponse{
		ID:      "fake-huawei",
		Object:  "chat.completion",
		Model:   req.Model,
		Choices: []confllm.Choice{{Index: 0, Message: confllm.Message{Role: "assistant", Content: "huawei confidential mock"}, FinishReason: "stop"}},
		Usage:   confllm.Usage{PromptTokens: 1, CompletionTokens: 3, TotalTokens: 4},
	}, nil
}

func (f *HuaweiConfidentialClientFake) Stream(ctx context.Context, req *confllm.ChatRequest) (confllm.StreamReader, error) {
	return &memStreamReader{chunks: []*confllm.StreamChunk{
		{ID: "fake-huawei", Object: "chat.completion.chunk", Model: req.Model, Choices: []confllm.StreamChoice{{Index: 0, Delta: confllm.Message{Role: "assistant", Content: "huawei "}}}},
		{ID: "fake-huawei", Object: "chat.completion.chunk", Model: req.Model, Choices: []confllm.StreamChoice{{Index: 0, Delta: confllm.Message{Content: "confidential"}}}},
	}}, nil
}

func (f *HuaweiConfidentialClientFake) ListModels(ctx context.Context) ([]confllm.ModelInfo, error) {
	return []confllm.ModelInfo{{ID: "huawei-confidential-model", OwnedBy: "huawei"}}, nil
}

func (f *HuaweiConfidentialClientFake) Health(ctx context.Context) confllm.HealthStatus {
	// K7：密态等级唯一事实源 = meta 包；fake 不得硬编码 "A"，缺省 unknown（与 AliyunFake 对齐）。
	return confllm.HealthStatus{Ready: true, MinConfidentialityClass: "unknown"}
}
