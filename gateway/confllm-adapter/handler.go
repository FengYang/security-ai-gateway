package confllm

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"security-ai-gateway/gateway/confllm-adapter/meta"
)

// ConfllmHandler 库内密态推理 handler（数据面入口）。
//
// 设计：§1.2 / §7.9 / §7.10。依赖 SecretResolver / Logger / AttestationVerifier 可注入；
// 仅依赖 Provider 统一契约与 Registry，对 gateway-admin-service 零硬依赖（可独立测试）。
type ConfllmHandler struct {
	reg      *Registry
	resolver SecretResolver
	logger   Logger
	attester AttestationVerifier
}

// HandlerOption 可注入选项（QA-4 / QA-5）。
type HandlerOption func(*ConfllmHandler)

// WithHandlerResolver 注入凭据解析器（复用 broker SecretRef）。
func WithHandlerResolver(r SecretResolver) HandlerOption {
	return func(h *ConfllmHandler) { h.resolver = r }
}

// WithHandlerLogger 注入结构化日志（脱敏白名单）。
func WithHandlerLogger(l Logger) HandlerOption {
	return func(h *ConfllmHandler) { h.logger = l }
}

// WithHandlerAttestation 注入证明校验器（noop/log-only/占位）。
func WithHandlerAttestation(a AttestationVerifier) HandlerOption {
	return func(h *ConfllmHandler) { h.attester = a }
}

// NewConfllmHandler 构造 handler（reg 为空则用 GlobalRegistry）。
func NewConfllmHandler(reg *Registry, opts ...HandlerOption) *ConfllmHandler {
	h := &ConfllmHandler{reg: reg, logger: NopLogger{}}
	if h.reg == nil {
		h.reg = GlobalRegistry
	}
	for _, o := range opts {
		o(h)
	}
	return h
}

// reservedTail 固定端段（非 provider 标识）：出现即表示「未指定 provider」。
// 例：/v1/confllm/chat/completions 中的 chat 是动词，不是 providerID。
var reservedTail = map[string]bool{"chat": true, "models": true, "health": true}

// providerIDFromRequest 从 query(?provider=) 或路径(/v1/confllm/{id}/...) 提取 provider 标识。
func (h *ConfllmHandler) providerIDFromRequest(r *http.Request) string {
	if id := r.URL.Query().Get("provider"); id != "" {
		return id
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 3 && parts[0] == "v1" && parts[1] == "confllm" {
		if reservedTail[parts[2]] {
			return ""
		}
		return parts[2]
	}
	return ""
}

// Chat 核心调用逻辑：查表 → 能力门禁 → Provider.Chat → 证明校验（noop/log）→ 返回。
func (h *ConfllmHandler) Chat(ctx context.Context, providerID string, req *ChatRequest) (*ChatResponse, error) {
	p, ok := h.reg.Lookup(providerID)
	if !ok {
		return nil, NewProviderError(CodeInvalidRequest, http.StatusNotFound, "provider 不存在: "+providerID)
	}
	// P1-3 能力门禁：不支持某能力的上游收到该能力请求时，早失败返回 unsupported_capability，
	// 而非静默降级打到上游才 4xx/5xx（§7.1 错误码映射表）。
	if pe := h.checkCapabilities(p, req); pe != nil {
		return nil, pe
	}
	resp, err := p.Chat(ctx, req)
	h.attest(ctx, p)
	if err != nil {
		return nil, ParseError(err)
	}
	return resp, nil
}

// checkCapabilities P1-3 能力门禁：比对请求所需能力与 provider 声明能力矩阵。
// 任一所需能力不被支持 ⇒ 返回 unsupported_capability（422），阻断后再转发上游（避免静默降级）。
func (h *ConfllmHandler) checkCapabilities(p ConfidentialLLMProvider, req *ChatRequest) *ProviderError {
	caps := p.Capabilities()
	var missing []string
	for _, need := range req.RequiredCapabilities() {
		switch need {
		case "tools":
			if !caps.SupportsTools {
				missing = append(missing, "tools")
			}
		case "vision":
			if !caps.SupportsVision {
				missing = append(missing, "vision")
			}
		case "thinking":
			if !caps.ThinkingMode {
				missing = append(missing, "thinking")
			}
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return NewProviderError(CodeUnsupportedCapability, http.StatusUnprocessableEntity,
		"provider 不支持所请求的能力: "+strings.Join(missing, ","))
}

// attest 调用证明校验器（本期 noop/log-only/占位，Verdict=unknown，R4）。
func (h *ConfllmHandler) attest(ctx context.Context, p ConfidentialLLMProvider) {
	if h.attester == nil {
		return
	}
	_, _ = h.attester.Verify(ctx, Evidence{Type: p.Metadata().Attestation, Issuer: p.ID()})
}

// HandleChat POST /v1/confllm/chat/completions 或 /v1/confllm/{id}/chat/completions。
func (h *ConfllmHandler) HandleChat(w http.ResponseWriter, r *http.Request) {
	providerID := h.providerIDFromRequest(r)
	if providerID == "" {
		writeErr(w, NewProviderError(CodeInvalidRequest, http.StatusBadRequest,
			"缺少 provider 标识（query ?provider= 或 /v1/confllm/{id}/chat/completions）"))
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, NewProviderError(CodeInvalidRequest, http.StatusBadRequest, "读取请求体失败"))
		return
	}
	req, err := BuildL1ChatRequest(raw)
	if err != nil {
		writeErr(w, NewProviderError(CodeInvalidRequest, http.StatusBadRequest, err.Error()))
		return
	}
	resp, err := h.Chat(r.Context(), providerID, req)
	if err != nil {
		writeErr(w, ParseError(err))
		return
	}
	writeJSON(w, resp)
}

// HandleStream POST /v1/confllm/stream/chat/completions：流式 SSE 透传（脱敏）。
func (h *ConfllmHandler) HandleStream(w http.ResponseWriter, r *http.Request) {
	providerID := h.providerIDFromRequest(r)
	if providerID == "" {
		writeErr(w, NewProviderError(CodeInvalidRequest, http.StatusBadRequest, "缺少 provider 标识"))
		return
	}
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeErr(w, NewProviderError(CodeInvalidRequest, http.StatusBadRequest, "读取请求体失败"))
		return
	}
	req, err := BuildL1ChatRequest(raw)
	if err != nil {
		writeErr(w, NewProviderError(CodeInvalidRequest, http.StatusBadRequest, err.Error()))
		return
	}
	req.Stream = true
	p, ok := h.reg.Lookup(providerID)
	if !ok {
		writeErr(w, NewProviderError(CodeInvalidRequest, http.StatusNotFound, "provider 不存在: "+providerID))
		return
	}
	// P1-3 能力门禁：流式路径同样需拦截不支持的能力请求（HandleStream 不经 h.Chat）。
	if pe := h.checkCapabilities(p, req); pe != nil {
		writeErr(w, pe)
		return
	}
	sr, err := p.Stream(r.Context(), req)
	if err != nil {
		writeErr(w, ParseError(err))
		return
	}
	if sr != nil {
		defer sr.Close()
	}
	w.Header().Set("Content-Type", "text/event-stream")
	flusher, _ := w.(http.Flusher)
	for {
		chunk, err := sr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return
		}
		data, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", data)
		if flusher != nil {
			flusher.Flush()
		}
	}
	fmt.Fprintf(w, "data: [DONE]\n\n")
}

// HandleModels GET /v1/confllm/models：聚合各上游模型 + 每家密态元数据（?provider= 过滤单家）。
//
// 响应结构（§7.5/§7.7/§7.11，wire 键名以 meta.WireMetadata 为准）：
//   - providers[]：每家必有 7 个密态字段（禁 omitempty）——confidentialityClass、attestation、
//     attestationVerdict（恒 "unknown"，R4）、verificationStatus（恒 "claim-unverified"，
//     §7.11 裁定：内部结构即使为 claim-with-reference-unverified，wire 也一律归一为该值）、
//     dataRetention、deployment、connectivity（never-tested / pending-credential）。
//   - models[]：每条模型携带同样密态元数据，便于前端按密态等级呈现。
func (h *ConfllmHandler) HandleModels(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("provider")

	// wire 结构复用 meta.WireMetadata（匿名嵌入 → JSON 展平），避免两侧各自实现漂移。
	// 举证要求：attestationVerdict 恒 unknown、verificationStatus 恒 claim-unverified，
	// 均禁 omitempty，故每条目完整携带 7 个密态字段（PRD P0-3 举证边界）。
	type providerView struct {
		Provider string `json:"provider"`
		meta.WireMetadata
	}
	type modelView struct {
		Provider string `json:"provider"`
		Model    string `json:"model"`
		OwnedBy  string `json:"ownedBy,omitempty"`
		meta.WireMetadata
	}

	providersOut := make([]providerView, 0)
	modelsOut := make([]modelView, 0)
	for _, p := range h.reg.All() {
		if target != "" && p.ID() != target {
			continue
		}
		// 连通性举证（§7.5 / PRD P0-3）：凭据未配置（Health().PendingCredential）的 provider
		// 报 pending-credential —— 若一律报 never-tested，等于把「从未发起过调用」与
		// 「压根没凭据」混为一谈（如移动云骨架）；其余报 never-tested。
		// P0/P1 绝不臆测 smoke-ok（smoke-ok 仅由 -tags=integration + 真实凭据的运行写入）。
		conn := meta.ConnNeverTested
		if p.Health(r.Context()).PendingCredential {
			conn = meta.ConnPendingCredential
		}
		wire := meta.ToWireMetadata(p.Metadata(), conn)
		providersOut = append(providersOut, providerView{
			Provider:     p.ID(),
			WireMetadata: wire,
		})
		models, err := p.ListModels(r.Context())
		if err != nil {
			continue // 单家失败不影响整体（health 已可见）
		}
		for _, mi := range models {
			modelsOut = append(modelsOut, modelView{
				Provider:     p.ID(),
				Model:        mi.ID,
				OwnedBy:      mi.OwnedBy,
				WireMetadata: wire,
			})
		}
	}
	writeJSON(w, map[string]any{"providers": providersOut, "models": modelsOut})
}

// HandleHealth GET /v1/confllm/health：健康聚合。
func (h *ConfllmHandler) HandleHealth(w http.ResponseWriter, r *http.Request) {
	agg := AggregateHealth(r.Context(), h.reg.All())
	writeJSON(w, agg)
}

// writeJSON 输出 200 JSON。
func writeJSON(w http.ResponseWriter, body any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(body)
}

// writeErr 输出脱敏错误（不含上游原始 body / token，§7.2）。
func writeErr(w http.ResponseWriter, pe *ProviderError) {
	if pe == nil {
		pe = NewProviderError(CodeUpstreamError, http.StatusBadGateway, "未知错误")
	}
	status := pe.HTTPStatus
	if status == 0 {
		status = http.StatusBadGateway
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(pe.SanitizedBody())
}
