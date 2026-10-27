package providers

import (
	"context"
	"net/http"
	"strings"

	"security-ai-gateway/gateway/confllm-adapter"
)

// huaweiClientImpl 华为云密态客户端真实实现。
//
// 华为"密态推理"技术脉络：TEE（Kunpeng virtCCA/CCA CPU 域 + 昇腾 NPU TEE 域）+ 分布式 RoT
// + xEnclave 远程证明 + HYOK 客户自持密钥（A+K 双信任根异构机密计算）。
//
// **2026-10-27 调研关键结论**：华为密态推理并非独立的"私有 SDK 产品"，而是「在 ModelArts 托管推理
// endpoint 上开启 confidential_inference 配置开关（tee_type / data_encryption / model_encryption）」。
// 该 endpoint 通过标准 RESTful 接口 + IAM Token 头 `X-Auth-Token` 调用；官方仅提供 Python SDK，
// **无 Go SDK、无类阿里 pai-cc 的 CLI 工具**。
//
// 因此本实现 = `BaseHTTPProvider` 包装（HTTP/REST 真实调用路径）+ `X-Auth-Token` 鉴权 + attestation
// hook——这是诚实且正确的 realization，而非"待 SDK 替换的占位"。K1 的 `vendor-sdk` 传输抽象在华为侧
// 落地为 HTTP/REST（与阿里 pai-cc 是同一抽象层 `VendorSDKClient` 的两种 realization，符合 D1 设计）。
// attestation hook 维持占位（Verdict=unknown，R4）：xEnclave 远程证明是平台能力，公开文档未给出
// 客户端可调用的证明校验 API，留待真机桥接。
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
	// 华为密态推理鉴权 = IAM Token 头 `X-Auth-Token`（非 OpenAI 兼容的 `Authorization: Bearer`）。
	// BaseHTTPProvider.doRequest/Stream 先注入 `Authorization: Bearer <key>`，此处统一替换为华为文档化鉴权方案。
	//
	// 防御要点（评审结论）：
	// 1) 仅在 Bearer 前缀精确匹配时替换；若未来 BaseHTTPProvider 改以 "bearer "/无空格注入，将静默 no-op
	//    而残留 Bearer——此时属 base 侧回归，须同步调整。更彻底的修复是给 BaseHTTPProvider 增加
	//    auth-scheme/auth-header 字段，使华为直接注入 X-Auth-Token 而消除 Bearer 中间态（见备忘录 §5）。
	// 2) Bearer 注入与替换在同一 goroutine 同步完成、请求发出前已替换，不会被并发看到中间态；且本包日志/错误
	//    归一均不回显 Authorization 头，无泄漏风险。
	// 3) 空凭证不会到达此处（resolveCredential 提前返回 pending-credential，fail-closed）。
	b.customizeReq = func(req *http.Request) {
		if auth := req.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
			req.Header.Del("Authorization")
			req.Header.Set("X-Auth-Token", strings.TrimPrefix(auth, "Bearer "))
		}
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
