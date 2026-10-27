// Package providers 各密态上游适配器实现。
//
// 设计依据：docs/详细设计/confllm/密态大模型接入-架构设计.md (v2) + PRD §2 厂商调研。
//
// 形态：
//   - HTTP 型（腾讯/火山/NEAR/Privatemode/Azure/GCP/AWS/移动云骨架）：统一走 BaseHTTPProvider，
//     真实调用文档化 OpenAI 兼容 endpoint；凭据经 SecretRef 注入，错误归一为 6 类。
//   - SDK 型（阿里/华为）：VendorSDKClient 真实客户端（见 aliyun_client.go / huaweicloud_client.go）。
//   - B 类（隐语 SecretFlow）：SFBridge 真实桥接（see bclass/secretflow.go）。
//
// 所有厂商均实现真实调用路径（非 fake-only）；*Fake 仅用于离线契约验证。
package providers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/normalize"
)

// BaseHTTPProvider HTTP 型厂商通用基类（真实 net/http 客户端）。
// 各厂商通过字段配置 + customizeReq 差异钩子实现 OpenAI 兼容调用。
type BaseHTTPProvider struct {
	id                string
	region            confllm.Region
	meta              confllm.ConfidentialityMeta
	caps              confllm.Capabilities
	endpoint          string // 文档化 base URL（不含 /v1/chat/completions）
	chatPath          string // 默认 /v1/chat/completions
	modelsPath        string // 默认 /v1/models
	httpClient        *http.Client
	secretResolver    confllm.SecretResolver
	secretRef         confllm.SecretRef
	logger            confllm.Logger
	attestation       confllm.AttestationVerifier
	staticCred        *confllm.Credential
	vendorOptions     map[string]any
	allowedVendorKeys []string
	// customizeReq 厂商特定请求定制（如请求头/签名）。
	customizeReq func(req *http.Request)
}

// buildBaseHTTPProvider 由 ProviderConfig + 选项构造基类（各厂商 NewXxx 调用）。
func buildBaseHTTPProvider(cfg confllm.ProviderConfig, opts ...confllm.ProviderOption) *BaseHTTPProvider {
	o := confllm.ApplyOptions(opts...)
	b := &BaseHTTPProvider{
		id:                cfg.ID,
		region:            cfg.Region,
		meta:              cfg.Meta,
		caps:              cfg.Capabilities,
		endpoint:          strings.TrimRight(cfg.Endpoint, "/"),
		chatPath:          "/v1/chat/completions",
		modelsPath:        "/v1/models",
		httpClient:        o.HTTPClient(),
		secretResolver:    o.SecretResolver(),
		secretRef:         cfg.SecretRef,
		logger:            o.Logger(),
		attestation:       o.Attestation(),
		staticCred:        o.StaticCred(),
		vendorOptions:     cfg.VendorOptions,
		allowedVendorKeys: cfg.Capabilities.AllowedVendorKeys,
	}
	return b
}

// ---------- ConfidentialLLMProvider 接口实现 ----------

func (p *BaseHTTPProvider) ID() string                            { return p.id }
func (p *BaseHTTPProvider) Region() confllm.Region                { return p.region }
func (p *BaseHTTPProvider) Metadata() confllm.ConfidentialityMeta { return p.meta }
func (p *BaseHTTPProvider) Capabilities() confllm.Capabilities    { return p.caps }

// resolveCredential 解析凭据（测试 seam staticCred 优先；否则走 SecretResolver）。
// 凭据缺失/失败 → pending_credential（503，绝不降级直连，§7.3 R5）。
func (p *BaseHTTPProvider) resolveCredential(ctx context.Context) (*confllm.Credential, error) {
	if p.staticCred != nil {
		return p.staticCred, nil
	}
	if p.secretResolver == nil {
		return nil, confllm.NewProviderError(confllm.CodePendingCredential, http.StatusServiceUnavailable,
			"未配置 SecretResolver（凭据解析器）")
	}
	cred, err := p.secretResolver.Resolve(ctx, p.secretRef)
	if err != nil || cred == nil || len(cred.Key) == 0 {
		return nil, confllm.NewProviderError(confllm.CodePendingCredential, http.StatusServiceUnavailable,
			"凭据未配置或解析失败（pending-credential）")
	}
	return cred, nil
}

// runAttestationHook 调用证明校验器（noop/log-only/占位，Verdict=unknown，R4）。
func (p *BaseHTTPProvider) runAttestationHook(ctx context.Context) {
	if p.attestation == nil {
		return
	}
	_, _ = p.attestation.Verify(ctx, confllm.Evidence{Type: p.meta.Attestation, Issuer: p.id})
}

// buildBody 构造 L1 标准请求体并合并 L2 厂商原生参数（白名单裁剪，§7.8）。
func (p *BaseHTTPProvider) buildBody(req *confllm.ChatRequest) []byte {
	base := map[string]any{
		"model":    req.Model,
		"messages": req.Messages,
		"stream":   req.Stream,
	}
	if req.Temperature != 0 {
		base["temperature"] = req.Temperature
	}
	if req.MaxTokens != 0 {
		base["max_tokens"] = req.MaxTokens
	}
	effective := mergeVendor(p.vendorOptions, req.VendorOptions)
	merged := normalize.MergeVendorOptions(base, effective, p.allowedVendorKeys)
	raw, _ := json.Marshal(merged)
	return raw
}

// doRequest 执行一次 HTTP 请求（POST/GET），返回原始响应体 + 状态码 + 归一化错误。
// 传输错误（连接拒绝/超时/上下文取消）→ upstream_timeout / upstream_error（§7.1）。
func (p *BaseHTTPProvider) doRequest(ctx context.Context, method, url string, body []byte, key []byte) ([]byte, int, *confllm.ProviderError) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, 0, confllm.NewProviderError(confllm.CodeInvalidRequest, http.StatusBadRequest, "构造请求失败")
	}
	req.Header.Set("Content-Type", "application/json")
	// 凭据注入：仅注入 Authorization，绝不进入日志/错误报文（§7.2）。
	if len(key) > 0 {
		req.Header.Set("Authorization", "Bearer "+string(key))
	}
	if p.customizeReq != nil {
		p.customizeReq(req)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		if isTimeoutError(err) {
			return nil, 0, confllm.NewProviderError(confllm.CodeUpstreamTimeout, http.StatusGatewayTimeout,
				"上游连接/读取超时（504）")
		}
		return nil, 0, confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway,
			"上游传输错误（502）")
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return raw, resp.StatusCode, normalize.MapHTTPError(resp.StatusCode, raw)
	}
	return raw, resp.StatusCode, nil
}

func (p *BaseHTTPProvider) chatURL() string   { return p.endpoint + p.chatPath }
func (p *BaseHTTPProvider) modelsURL() string { return p.endpoint + p.modelsPath }

// Chat 非流式调用（真实 HTTP 路径）。
func (p *BaseHTTPProvider) Chat(ctx context.Context, req *confllm.ChatRequest) (*confllm.ChatResponse, error) {
	start := time.Now()
	cred, err := p.resolveCredential(ctx)
	if err != nil {
		return nil, err
	}
	p.runAttestationHook(ctx)
	raw, status, perr := p.doRequest(ctx, http.MethodPost, p.chatURL(), p.buildBody(req), cred.Key)
	// 脱敏结构化日志：仅 provider/model/status/duration，绝不含 key/Authorization/上游 body（§7.10）。
	p.logger.Infof(ctx, "confllm upstream chat", "provider", p.id, "model", req.Model, "status", status, "duration", time.Since(start).String())
	if perr != nil {
		return nil, perr
	}
	return normalize.ParseChatCompletion(raw)
}

// Stream 流式调用（真实 SSE 路径）。
func (p *BaseHTTPProvider) Stream(ctx context.Context, req *confllm.ChatRequest) (confllm.StreamReader, error) {
	cred, err := p.resolveCredential(ctx)
	if err != nil {
		return nil, err
	}
	p.runAttestationHook(ctx)

	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, p.chatURL(), bytes.NewReader(p.buildBody(req)))
	if err != nil {
		return nil, confllm.NewProviderError(confllm.CodeInvalidRequest, http.StatusBadRequest, "构造流式请求失败")
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Authorization", "Bearer "+string(cred.Key))
	hr.Header.Set("Accept", "text/event-stream")
	if p.customizeReq != nil {
		p.customizeReq(hr)
	}
	resp, err := p.httpClient.Do(hr)
	if err != nil {
		if isTimeoutError(err) {
			return nil, confllm.NewProviderError(confllm.CodeUpstreamTimeout, http.StatusGatewayTimeout, "上游流式连接超时")
		}
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway, "上游流式传输错误")
	}
	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		return nil, normalize.MapHTTPError(resp.StatusCode, raw)
	}
	return normalize.NewStreamReader(resp.Body), nil
}

// ListModels 列出模型（真实 GET /v1/models）。
func (p *BaseHTTPProvider) ListModels(ctx context.Context) ([]confllm.ModelInfo, error) {
	cred, err := p.resolveCredential(ctx)
	if err != nil {
		return nil, err
	}
	raw, _, perr := p.doRequest(ctx, http.MethodGet, p.modelsURL(), nil, cred.Key)
	if perr != nil {
		return nil, perr
	}
	var listing struct {
		Data []confllm.ModelInfo `json:"data"`
	}
	if err := json.Unmarshal(raw, &listing); err != nil {
		return nil, confllm.NewProviderError(confllm.CodeUpstreamError, http.StatusBadGateway,
			"解析模型列表失败")
	}
	return listing.Data, nil
}

// Health 健康检查：以 ListModels 可达性判定（短超时）。
func (p *BaseHTTPProvider) Health(ctx context.Context) confllm.HealthStatus {
	hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := p.ListModels(hctx); err != nil {
		pe := confllm.ParseError(err)
		if pe.Code == confllm.CodePendingCredential {
			return confllm.HealthStatus{Ready: false, PendingCredential: true, Detail: "pending-credential", MinConfidentialityClass: p.meta.ConfidentialityClass}
		}
		return confllm.HealthStatus{Ready: false, Detail: pe.Message, MinConfidentialityClass: p.meta.ConfidentialityClass}
	}
	return confllm.HealthStatus{Ready: true, MinConfidentialityClass: p.meta.ConfidentialityClass}
}

// HTTPClient 返回底层 *http.Client（只读；不含凭据，仅供离线强制断言 transport 类型）。
func (p *BaseHTTPProvider) HTTPClient() *http.Client { return p.httpClient }

// ---------- 工具 ----------

// mergeVendor 合并配置级与请求级 L2 原生参数。
func mergeVendor(cfg, req map[string]any) map[string]any {
	if len(cfg) == 0 {
		return req
	}
	if len(req) == 0 {
		return cfg
	}
	out := make(map[string]any, len(cfg)+len(req))
	for k, v := range cfg {
		out[k] = v
	}
	for k, v := range req {
		out[k] = v
	}
	return out
}

// isTimeoutError 判断是否为超时/连接类错误（§7.1：拆「延迟超时」与「连接拒绝」两源）。
func isTimeoutError(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "deadline exceeded") {
		return true
	}
	// 连接拒绝（proxy 未起 / 端点不可达）视为上游不可达，归并超时类以便快速 failover。
	if strings.Contains(err.Error(), "connection refused") || strings.Contains(err.Error(), "no such host") {
		return true
	}
	return false
}

var _ = fmt.Sprintf
