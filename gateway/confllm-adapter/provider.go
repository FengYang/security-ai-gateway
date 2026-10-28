// Package confllm 提供「密态大模型上游适配器」的统一契约与基础设施。
//
// 设计依据：docs/详细设计/confllm/密态大模型接入-架构设计.md (v2)。
//
// 设计要点：
//   - ConfidentialLLMProvider 是 9 家 A 类厂商的统一契约（Chat/Stream/ListModels/Health …）。
//   - TransportKind 区分 http 与 vendor-sdk 两种传输范式；SDK 型走 VendorSDKClient 抽象。
//   - 密态四字段（confidentiality_class / attestation / data_retention / deployment）是一等公民，
//     缺省 unknown，定义见 meta 子包。
//   - 凭据经 SecretRef 注入，绝不落日志/错误报文（见 secret 子包与 §7 共享知识）。
//   - 本包对 gateway-admin-service 零硬依赖，可独立 go test（见 §7 QA-5）。
package confllm

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"security-ai-gateway/gateway/confllm-adapter/attest"
	"security-ai-gateway/gateway/confllm-adapter/meta"
	"security-ai-gateway/gateway/confllm-adapter/secret"
)

// defaultRequestTimeout 默认上游请求超时（可被 WithHTTPClient / WithTransport 覆盖）。
const defaultRequestTimeout = 30 * time.Second

// ---------- 区域 / 部署形态 / 传输形态 枚举 ----------

// Region 厂商所属区域（国内/国外），用于路由与合规判断。
type Region string

const (
	// RegionDomestic 国内厂商。
	RegionDomestic Region = "domestic"
	// RegionForeign 国外厂商。
	RegionForeign Region = "foreign"
)

// Deployment 部署形态枚举（§7.5）。
type Deployment string

const (
	// DeploymentManaged 厂商托管 API。
	DeploymentManaged Deployment = "managed"
	// DeploymentSelfHostedCVM 客户自建于机密 CVM/集群。
	DeploymentSelfHostedCVM Deployment = "self-hosted-cvm"
	// DeploymentProxyMediated 经客户端本地 proxy 中转（如 Privatemode）。
	DeploymentProxyMediated Deployment = "proxy-mediated"
)

// TransportKind 传输范式枚举（v2 D1 修订）。
type TransportKind string

const (
	// TransportHTTP 标准 OpenAI 兼容 HTTP（httptest mock 内核 + 差异 fixture）。
	TransportHTTP TransportKind = "http"
	// TransportVendorSDK 厂商私有密态 SDK（阿里/华为专用密态 SDK）。
	TransportVendorSDK TransportKind = "vendor-sdk"
)

// ---------- 密态四字段（委托 meta 子包，保证单一事实源）----------

// ConfidentialityMeta 密态元数据（四类字段，缺省 unknown）。
type ConfidentialityMeta = meta.ConfidentialityMeta

// ---------- 凭据抽象（委托 secret 子包）----------

// SecretRef 指向 broker .env 凭据库的引用。
type SecretRef = secret.SecretRef

// Credential 解析后的凭据（不落盘、不进日志）。
type Credential = secret.Credential

// SecretResolver 凭据解析器接口（实现由 admin-service 基于 broker 提供）。
type SecretResolver = secret.SecretResolver

// ---------- 证明抽象（委托 attest 子包）----------

// Evidence 证明证据（quote / token）。
type Evidence = attest.Evidence

// VerificationResult 证明校验结果。
type VerificationResult = attest.VerificationResult

// Verdict 证明结论枚举。
type Verdict = attest.Verdict

// AttestationVerifier 可插拔证明校验器（本期 noop/log-only/占位，Verdict=unknown）。
type AttestationVerifier = attest.AttestationVerifier

// ---------- 能力矩阵 ----------

// Capabilities 厂商能力声明（P1-3）。
type Capabilities struct {
	SupportsTools     bool     `json:"supportsTools"`
	SupportsVision    bool     `json:"supportsVision"`
	MaxContext        int      `json:"maxContext"`
	ThinkingMode      bool     `json:"thinkingMode"`
	Protocols         []string `json:"protocols,omitempty"`
	AllowedVendorKeys []string `json:"allowedVendorKeys,omitempty"` // L2 白名单：允许透传的原生参数
}

// ---------- 配置模型（v2：增 Transport + VendorSDK）----------

// VendorSDKConfig SDK 型厂商传输配置（D1 / K1）。
//
// 凭据（AccessKey 等）一律走 SecretRef，不在此出现（§7.2）；本结构仅放安装期非密文参数。
type VendorSDKConfig struct {
	SDKName          string `yaml:"sdkName" json:"sdkName"`                   // 如 aliyun-confidential / huawei-confidential
	AttestBeforeCall bool   `yaml:"attestBeforeCall" json:"attestBeforeCall"` // 调用前是否先远程证明
	// ModelCode 百炼机密推理部署的模型 code（安装期配置，如 cmaas-glm-5.2；见 百炼机密推理-技术对接方案.md）。
	ModelCode string `yaml:"modelCode,omitempty" json:"modelCode,omitempty"`
	// WorkspaceID 百炼业务空间 ID（安装期配置）。
	WorkspaceID string `yaml:"workspaceId,omitempty" json:"workspaceId,omitempty"`
}

// ManagedConfig 托管形态配置。
type ManagedConfig struct {
	BaseURL    string `yaml:"baseURL" json:"baseURL"`
	AuthScheme string `yaml:"authScheme" json:"authScheme"`
}

// SelfHostedConfig 自建成形态配置。
type SelfHostedConfig struct {
	BaseURL  string `yaml:"baseURL" json:"baseURL"`
	GPUClass string `yaml:"gpuClass" json:"gpuClass"`
}

// ProxyMediatedConfig proxy 中转形态配置。
type ProxyMediatedConfig struct {
	ProxyURL       string `yaml:"proxyURL" json:"proxyURL"`
	TargetUpstream string `yaml:"targetUpstream" json:"targetUpstream"`
}

// AttestationConfig 证明相关配置。
type AttestationConfig struct {
	Mode      string `yaml:"mode" json:"mode"`           // none / ohttp / quote
	Verifier  string `yaml:"verifier" json:"verifier"`   // maa / nras / trustee / near / privatemode / none
	QuoteType string `yaml:"quoteType" json:"quoteType"` // tdx / sev-snp / nvidia-nras / attestation-token
}

// ProviderConfig 单个密态上游的静态配置（来自 CR/YAML）。
type ProviderConfig struct {
	// Type 厂商类型键（如 "tencent" / "aliyun-confidential" / "aliyun-bailian" /
	// "huawei-confidential" / "huawei-maas"），用于 NewFromConfig 选择工厂（K1 双服务裁决）。
	Type          string              `yaml:"type" json:"type"`
	ID            string              `yaml:"id" json:"id"`
	Region        Region              `yaml:"region" json:"region"`
	Deployment    Deployment          `yaml:"deployment" json:"deployment"`
	Transport     TransportKind       `yaml:"transport" json:"transport"`
	Endpoint      string              `yaml:"endpoint" json:"endpoint"`
	SecretRef     SecretRef           `yaml:"secretRef" json:"secretRef"`
	Meta          ConfidentialityMeta `yaml:"meta" json:"meta"`
	VendorOptions map[string]any      `yaml:"vendorOptions,omitempty" json:"vendorOptions,omitempty"`
	// LiteralKey 禁止使用的字面量 key 检测位（不参与序列化）。
	// ValidateConfig 识别「误把明文 key 写进配置」并 fail-closed（§7.10 QA2-19）。
	LiteralKey    string               `yaml:"-" json:"-"`
	VendorSDK     *VendorSDKConfig     `yaml:"vendorSDK,omitempty" json:"vendorSDK,omitempty"`
	Attestation   AttestationConfig    `yaml:"attestation,omitempty" json:"attestation,omitempty"`
	Managed       *ManagedConfig       `yaml:"managed,omitempty" json:"managed,omitempty"`
	SelfHosted    *SelfHostedConfig    `yaml:"selfHosted,omitempty" json:"selfHosted,omitempty"`
	ProxyMediated *ProxyMediatedConfig `yaml:"proxyMediated,omitempty" json:"proxyMediated,omitempty"`
	Capabilities  Capabilities         `yaml:"capabilities,omitempty" json:"capabilities,omitempty"`
}

// ---------- L1 归一化数据类型（OpenAI 兼容语义）----------

// Message 单条对话消息。
//
// Content 为 any：纯文本为 string；视觉/多模态请求为结构化 parts（如
// [{"type":"text",...},{"type":"image_url",...}]）。保持 any 是为了让视觉请求可被
// 正常解析（而非在 L1 解析阶段即失败），从而能经 P1-3 能力门禁判定，而非静默降级。
type Message struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// Usage token 用量。
type Usage struct {
	PromptTokens     int `json:"prompt_tokens"`
	CompletionTokens int `json:"completion_tokens"`
	TotalTokens      int `json:"total_tokens"`
}

// Choice 非流式响应中的一个候选。
type Choice struct {
	Index        int     `json:"index"`
	Message      Message `json:"message"`
	FinishReason string  `json:"finish_reason"`
}

// ChatResponse L1 归一化响应（OpenAI 兼容语义）。
type ChatResponse struct {
	ID      string   `json:"id"`
	Object  string   `json:"object"`
	Model   string   `json:"model"`
	Choices []Choice `json:"choices"`
	Usage   Usage    `json:"usage"`
}

// StreamChoice 流式响应中的一个候选增量。
type StreamChoice struct {
	Index        int     `json:"index"`
	Delta        Message `json:"delta"`
	FinishReason string  `json:"finish_reason"`
}

// StreamChunk 流式响应中的一帧。
type StreamChunk struct {
	ID      string         `json:"id"`
	Object  string         `json:"object"`
	Model   string         `json:"model"`
	Choices []StreamChoice `json:"choices"`
	Usage   Usage          `json:"usage"`
}

// StreamReader 流式响应读取器（Next 在流末返回 io.EOF）。
type StreamReader interface {
	Next() (*StreamChunk, error)
	Close() error
}

// ModelInfo 模型目录条目（ListModels）。
type ModelInfo struct {
	ID      string `json:"id"`
	OwnedBy string `json:"owned_by,omitempty"`
}

// HealthStatus 健康状态（含密态等级，供路由过滤）。
type HealthStatus struct {
	Ready                   bool   `json:"ready"`
	Detail                  string `json:"detail,omitempty"`
	PendingCredential       bool   `json:"pendingCredential,omitempty"`
	MinConfidentialityClass string `json:"minConfidentialityClass,omitempty"`
}

// ChatRequest L1 归一化请求（OpenAI 兼容语义）。
type ChatRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Stream      bool      `json:"stream"`
	Temperature float64   `json:"temperature,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	// VendorOptions L2 旁路原生参数（由 Provider 白名单裁剪后透传）。
	VendorOptions map[string]any `json:"-"`
	// Tools 函数调用声明（L1 标准字段）。非空 ⇒ 请求需要 tools 能力（P1-3 能力门禁）。
	Tools []any `json:"tools,omitempty"`
	// Reasoning 显式开启思考（reasoning/thinking/enable_thinking/reasoning_effort）。
	// true ⇒ 请求需要 thinking 能力（P1-3 能力门禁）。
	Reasoning bool `json:"reasoning,omitempty"`
	// Vision 请求隐含需要视觉能力（由 BuildL1ChatRequest 经原始体扫描得出，json:"-" 不入线）。
	// 直接构造 ChatRequest 的测试可显式置位；经 BuildL1ChatRequest 的路径自动探测。
	Vision bool `json:"-"`
}

// BuildL1ChatRequest 从原始 OpenAI 兼容 JSON 解析出 L1 请求（宽松解码，忽略未知字段）。
func BuildL1ChatRequest(raw []byte) (*ChatRequest, error) {
	var req ChatRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("解析 L1 请求失败: %w", err)
	}
	if req.Model == "" {
		return nil, fmt.Errorf("L1 请求缺少 model 字段")
	}
	// 能力探测（P1-3）：视觉（结构化 content parts）+ 思考（多厂商字段别名）。
	// 这些能力在请求体里不总是单一字段，故在此统一扫描一次，供 RequiredCapabilities 复用。
	req.Vision = detectVision(raw)
	if detectReasoning(raw) {
		req.Reasoning = true
	}
	return &req, nil
}

// RequiredCapabilities 返回请求声明/隐含需要的能力（P1-3）。
//
//	tools  ：携带 tools（函数调用）；
//	vision ：任一消息 content 为结构化图像 parts（非纯文本）；
//	thinking：显式开启思考（reasoning/thinking/enable_thinking/reasoning_effort）。
func (r *ChatRequest) RequiredCapabilities() []string {
	var caps []string
	if len(r.Tools) > 0 {
		caps = append(caps, "tools")
	}
	if r.Vision {
		caps = append(caps, "vision")
	}
	if r.Reasoning {
		caps = append(caps, "thinking")
	}
	return caps
}

// detectVision 扫描原始请求体，判定是否含视觉/多模态内容 parts（image_url/image/file 等）。
// 不依赖 Message.Content 的类型（any），直接对 raw 做结构探测，避免误判文本中的关键字。
func detectVision(raw []byte) bool {
	var probe struct {
		Messages []struct {
			Content any `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return false
	}
	for _, m := range probe.Messages {
		if _, ok := m.Content.(string); !ok && m.Content != nil {
			return true // 结构化内容（图像 parts 等）
		}
	}
	return false
}

// detectReasoning 扫描原始请求体，判定是否显式开启思考（多厂商字段别名兼容）。
func detectReasoning(raw []byte) bool {
	var flat struct {
		Reasoning       bool `json:"reasoning"`
		Thinking        bool `json:"thinking"`
		EnableThinking  bool `json:"enable_thinking"`
		ReasoningEffort any  `json:"reasoning_effort"`
	}
	if err := json.Unmarshal(raw, &flat); err != nil {
		return false
	}
	return flat.Reasoning || flat.Thinking || flat.EnableThinking || flat.ReasoningEffort != nil
}

// ProviderError 归一化错误（§7.1 错误码映射表）。
type ProviderError struct {
	Code       string `json:"code"`
	HTTPStatus int    `json:"-"`
	Message    string `json:"message"`
}

// 归一化错误码（§7.1）。
const (
	CodeUnauthorized      = "unauthorized"       // 401 凭据缺失/无效
	CodeRateLimited       = "rate_limited"       // 429 限流
	CodeInvalidRequest    = "invalid_request"    // 400 请求非法
	CodeUpstreamError     = "upstream_error"     // 5xx 上游错误（归并 502）
	CodeUpstreamTimeout   = "upstream_timeout"   // 504 超时/连接拒绝
	CodePendingCredential = "pending_credential" // 503 凭据未配置（§7.3 R5）

	// ---- 路由 / 配置策略错误码（非上游错误，§7.6 / §7.10）----
	CodeInvalidRoutePolicy     = "invalid_route_policy"      // 非法 min_confidentiality_class（§7.6 QA2-20）
	CodeNoProviderSatisfiesMin = "no_provider_satisfies_min" // 无候选满足 min（§7.6 QA2-21）
	CodeInvalidSecretLiteral   = "invalid_secret_literal"    // 配置含字面量 key（§7.10 QA2-19）
	CodeQuotaExceeded          = "quota_exceeded"            // 配额超限拒绝（策略层/上游共用；429）

	// ---- 能力门禁错误码（P1-3）----
	CodeUnsupportedCapability = "unsupported_capability" // 请求所需能力不被上游支持（如 tools/vision/thinking）
)

func (e *ProviderError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// SanitizedBody 返回脱敏的错误响应体（§7.2：不含上游原始响应体 / token）。
func (e *ProviderError) SanitizedBody() map[string]any {
	return map[string]any{"error": map[string]any{"code": e.Code, "message": e.Message}}
}

// NewProviderError 构造归一化错误。
func NewProviderError(code string, httpStatus int, msg string) *ProviderError {
	return &ProviderError{Code: code, HTTPStatus: httpStatus, Message: msg}
}

// ParseError 将任意 error 归并为 ProviderError（非 ProviderError 默认 upstream_error）。
func ParseError(err error) *ProviderError {
	if err == nil {
		return nil
	}
	if pe, ok := err.(*ProviderError); ok {
		return pe
	}
	return NewProviderError(CodeUpstreamError, http.StatusBadGateway, "上游调用失败")
}

// ---------- 统一契约接口 ----------

// ConfidentialLLMProvider 9 家 A 类厂商统一契约（Chat/Stream/ListModels/Health/元数据）。
type ConfidentialLLMProvider interface {
	ID() string
	Region() Region
	Metadata() ConfidentialityMeta
	Capabilities() Capabilities
	Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error)
	Stream(ctx context.Context, req *ChatRequest) (StreamReader, error)
	ListModels(ctx context.Context) ([]ModelInfo, error)
	Health(ctx context.Context) HealthStatus
}

// GraphProvider B 类任务式推理能力（可选接口，仅任务式 provider 实现）。
// A 类 chat 式 provider 不实现；调用方经类型断言探测，未实现 → unsupported_capability。
// 方法名刻意与 bclass 的 typed SubmitGraph/PollResult 区分（Go 同类型不能有同名异参方法）。
type GraphProvider interface {
	SubmitGraphJSON(ctx context.Context, spec json.RawMessage) (jobID string, err error)
	PollGraphJSON(ctx context.Context, jobID string) (status string, result json.RawMessage, err error)
}

// 任务式状态常量（与 bclass.SFJobStatus 取值一致，wire 直接透传归一化状态）。
const (
	GraphStatusPending = "pending"
	GraphStatusRunning = "running"
	GraphStatusDone    = "done"
	GraphStatusFailed  = "failed"
)

// ---------- Provider 可注入选项（QA-4 可注入抽象）----------

type providerOptions struct {
	logger         Logger
	httpClient     *http.Client
	transport      http.RoundTripper
	secretResolver SecretResolver
	attestation    AttestationVerifier
	staticCred     *Credential     // 测试 seam：绕过 resolver 直接注入凭据
	sdkClient      VendorSDKClient // SDK 型厂商测试注入（*Fake 验证用）
}

// ProviderOption 构造期可注入选项。
type ProviderOption func(*providerOptions)

func applyOptions(opts ...ProviderOption) *providerOptions {
	o := &providerOptions{
		logger:     NopLogger{},
		httpClient: &http.Client{Timeout: defaultRequestTimeout},
	}
	for _, fn := range opts {
		fn(o)
	}
	if o.transport != nil && o.httpClient != nil {
		o.httpClient.Transport = o.transport
	}
	if o.httpClient == nil {
		o.httpClient = &http.Client{Timeout: defaultRequestTimeout}
	}
	if o.attestation == nil {
		o.attestation = attest.NoopVerifier{}
	}
	return o
}

// ApplyOptions 导出封装：供 providers 子包构造期解析可注入选项（复用内部 applyOptions）。
func ApplyOptions(opts ...ProviderOption) *providerOptions {
	return applyOptions(opts...)
}

// ---------- providerOptions 导出访问器 ----------
//
// 跨包（providers 子包）无法直接访问未导出字段，故提供导出只读访问器；
// 保持字段封装的同时满足子包构造期取值需求（Go 允许跨包调用未导出类型的导出方法）。

// HTTPClient 返回注入的 HTTP 客户端（applyOptions 已保证非 nil）。
func (o *providerOptions) HTTPClient() *http.Client { return o.httpClient }

// SecretResolver 返回注入的凭据解析器（可能为 nil → 调用方须 fail-closed）。
func (o *providerOptions) SecretResolver() SecretResolver { return o.secretResolver }

// Logger 返回注入的结构化日志器（applyOptions 已保证非 nil）。
func (o *providerOptions) Logger() Logger { return o.logger }

// Attestation 返回注入的证明校验器（applyOptions 已保证非 nil）。
func (o *providerOptions) Attestation() AttestationVerifier { return o.attestation }

// StaticCred 返回测试 seam 注入的静态凭据（生产为 nil）。
func (o *providerOptions) StaticCred() *Credential { return o.staticCred }

// SDKClient 返回测试注入的 SDK 客户端（*Fake）；生产为 nil → 构造真实客户端。
func (o *providerOptions) SDKClient() VendorSDKClient { return o.sdkClient }

// WithLogger 注入结构化 Logger（脱敏白名单）。
func WithLogger(l Logger) ProviderOption {
	return func(o *providerOptions) { o.logger = l }
}

// WithHTTPClient 注入自定义 *http.Client（可携带离线 Transport）。
func WithHTTPClient(c *http.Client) ProviderOption {
	return func(o *providerOptions) { o.httpClient = c }
}

// WithTransport 注入自定义 http.RoundTripper（如离线拒绝非 loopback 的 Transport）。
func WithTransport(t http.RoundTripper) ProviderOption {
	return func(o *providerOptions) { o.transport = t }
}

// WithSecretResolver 注入凭据解析器（复用 broker SecretRef）。
func WithSecretResolver(r SecretResolver) ProviderOption {
	return func(o *providerOptions) { o.secretResolver = r }
}

// WithAttestation 注入证明校验器（noop/log-only/占位）。
func WithAttestation(v AttestationVerifier) ProviderOption {
	return func(o *providerOptions) { o.attestation = v }
}

// WithStaticCredential 测试 seam：直接注入凭据，绕过 SecretResolver。
// 仅用于离线 mock 契约测试；生产路径务必走 WithSecretResolver。
func WithStaticCredential(c *Credential) ProviderOption {
	return func(o *providerOptions) { o.staticCred = c }
}

// WithSDKClient 注入 SDK 型厂商客户端（阿里/华为 *Fake 离线验证用）。
// 生产路径留空 → 由 NewXxxProvider 构造真实客户端（按文档化密态 endpoint / SDK 契约）。
func WithSDKClient(c VendorSDKClient) ProviderOption {
	return func(o *providerOptions) { o.sdkClient = c }
}
