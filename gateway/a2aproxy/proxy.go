package a2aproxy

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"security-ai-gateway/gateway/a2a"
)

// Proxy is the A2A data plane. It is safe for concurrent use.
type Proxy struct {
	cfg           Config
	snapshots     *SnapshotStore
	governance    Governance
	contentSafety ContentSafety // T-4：内容检查层（L3）；nil → 不介入（可信域 MVP 可选）
	metrics       *A2AMetrics   // T-5：§6.5 数据面指标；始终非 nil
	transport     *http.Transport
	client        *http.Client
}

// New builds the proxy. governance may be nil, in which case the fail-closed
// DenyAllGovernance is used (no call can succeed until a policy engine is
// wired in).
func New(cfg Config, snapshots *SnapshotStore, governance Governance) (*Proxy, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if snapshots == nil {
		return nil, fmt.Errorf("a2aproxy: snapshot store is required")
	}
	if governance == nil {
		governance = DenyAllGovernance{}
	}
	transport := guardedTransport(cfg.MaxIdleConns, cfg.DevAllowLoopback)
	return &Proxy{
		cfg:        cfg,
		snapshots:  snapshots,
		governance: governance,
		metrics:    NewA2AMetrics(),
		transport:  transport,
		client: &http.Client{
			Transport:     transport,
			Timeout:       cfg.BackendTimeout,
			CheckRedirect: noCrossHostRedirect,
		},
	}, nil
}

// Metrics 返回数据面指标集合（T-5；§6.5）。始终非 nil。
func (p *Proxy) Metrics() *A2AMetrics {
	return p.metrics
}

// MetricsHandler 暴露数据面 /metrics（Prometheus 文本格式；内网使用，勿公网暴露）。
//
// 与 Handler() 分离挂载理由：/metrics 属运维面，可由调用方按内网策略自行决定是否挂载
// 与是否加鉴权，避免把观测面强加给数据面路由（与 Governance.Observer 的 caller-supplied
// 模式对称）。
func (p *Proxy) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		p.metrics.Render(w)
	})
}

// Handler returns the HTTP handler with mode-specific routes.
func (p *Proxy) Handler() http.Handler {
	mux := http.NewServeMux()
	if p.cfg.PublicMode == PublicModeHost {
		mux.HandleFunc("POST /a2a", p.withTracingSpan(spanInvoke, p.handleInvoke))
		mux.HandleFunc("GET /.well-known/agent-card.json", p.withTracingSpan(spanDiscovery, p.handleDiscovery))
	} else {
		mux.HandleFunc("POST /a2a/{tenant}/{agent}", p.withTracingSpan(spanInvoke, p.handleInvoke))
		mux.HandleFunc("GET /a2a/{tenant}/{agent}/.well-known/agent-card.json", p.withTracingSpan(spanDiscovery, p.handleDiscovery))
	}
	mux.HandleFunc("GET /healthz", p.handleHealth)
	return mux
}

// Close releases idle backend connections.
func (p *Proxy) Close() {
	if p.transport != nil {
		p.transport.CloseIdleConnections()
	}
}

// SetContentSafety wires the L3 content-safety checker (T-4). A nil checker
// means the data plane does not perform content inspection (trusted-domain
// MVP default); content safety is engaged only when an implementation is
// provided (e.g. a bridge to the output-guard service).
func (p *Proxy) SetContentSafety(cs ContentSafety) {
	p.contentSafety = cs
}

// route is the resolved invoke target.
type route struct {
	tenant string
	agent  string
}

// resolveRoute extracts tenant/agent from the request. The second return
// value is false when the request does not address a known route shape.
func (p *Proxy) resolveRoute(r *http.Request) (route, bool) {
	if p.cfg.PublicMode == PublicModeHost {
		host := hostOnly(r.Host)
		for tenant, domain := range p.cfg.TenantDomains {
			suffix := "." + strings.ToLower(domain)
			if strings.HasSuffix(strings.ToLower(host), suffix) {
				agent := strings.TrimSuffix(strings.ToLower(host), suffix)
				if agent == "" || strings.Contains(agent, ".") {
					return route{}, false
				}
				return route{tenant: tenant, agent: agent}, true
			}
		}
		return route{}, false
	}
	// Path mode: /a2a/{tenant}/{agent}
	trimmed := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(trimmed, "/")
	if len(parts) != 3 || parts[0] != "a2a" || parts[1] == "" || parts[2] == "" {
		return route{}, false
	}
	return route{tenant: parts[1], agent: parts[2]}, true
}

func hostOnly(hostport string) string {
	if i := strings.LastIndex(hostport, ":"); i >= 0 && !strings.Contains(hostport[i+1:], "]") {
		hostport = hostport[:i]
	}
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostport)), ".")
}

// handleInvoke is the frozen data-plane pipeline:
// route -> auth -> route-tenant -> registry -> L1 -> ACL -> ratelimit -> backend.
func (p *Proxy) handleInvoke(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rt, ok := p.resolveRoute(r)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Registry readiness: without a snapshot the data plane fails closed.
	snap := p.snapshots.Current()
	if snap == nil {
		http.Error(w, "a2a registry unavailable", http.StatusServiceUnavailable)
		return
	}

	// Authentication (fail-closed).
	principal, err := p.governance.Authenticate(ctx, r)
	if err != nil || principal == nil || principal.Tenant == "" {
		p.writeRPC(w, nil, a2a.NewRPCError(a2a.CodeUnauthenticated, a2a.ReasonUnauthenticated))
		return
	}
	requestID := requestIDOf(r)

	// Route tenant must equal the authenticated tenant (F-2 §2.3).
	effectiveTenant, rpcErr := a2a.ResolveRouteTenant(principal.Tenant, rt.tenant)
	if rpcErr != nil {
		p.observeDenied(ctx, requestID, rt, principal, "", rpcErr)
		p.writeRPC(w, nil, rpcErr)
		return
	}

	// Registry lookup (tenant+name). Unknown agents are a plain 404 (no
	// audit noise); an agent present but signature-invalid must never be
	// callable (defensive: the control plane removes those from snapshots).
	agentRec, found := snap.Lookup(effectiveTenant, rt.agent)
	if !found {
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}
	if agentRec.SignatureStatus != "valid" {
		p.observeDenied(ctx, requestID, rt, principal, "", a2a.NewRPCError(a2a.CodeUnauthorized, a2a.ReasonUntrustedKey))
		http.Error(w, "unknown agent", http.StatusNotFound)
		return
	}
	card, err := agentRec.ParseAgentCard()
	if err != nil {
		// A snapshot card that no longer decodes is a registry defect:
		// fail closed rather than proxying to a stale backend address.
		p.writeRPC(w, nil, a2a.NewRPCError(a2a.CodeInternalError, a2a.ReasonCardInvalid))
		return
	}

	// L1 protocol pipeline (version/content-type/envelope/method/tenant/skill).
	meta, httpErr := a2a.ParseHTTPRequest(r, effectiveTenant, card)
	if httpErr != nil {
		p.observeProtocolError(ctx, requestID, rt, principal, meta, httpErr)
		a2a.WriteHTTPError(w, httpErr)
		return
	}

	// ACL (allow-only, exact > wildcard > default deny; T-3 engine).
	if err := p.governance.Authorize(ctx, principal, effectiveTenant, rt.agent, meta.Skill.Name); err != nil {
		rpc := a2a.NewRPCError(a2a.CodeUnauthorized, a2a.ReasonUnknownSkill)
		reason := a2a.ReasonUnknownSkill
		if r := aclReasonOf(err); r != "" {
			rpc = a2a.NewRPCError(a2a.CodeUnauthorized, r)
			reason = r
		}
		p.observeDenied(ctx, requestID, rt, principal, meta.Skill.Name, rpc)
		// T-5：a2a_authz_denies_total{agent,reason}（reason 与 audit/错误 data.reason 同源）。
		p.metrics.ObserveAuthzDeny(rt.agent, reason)
		p.writeRPC(w, meta.Envelope.ID, rpc)
		return
	}

	// Rate limit (tenant|agent|skill; 429 + Retry-After).
	if retryAfter, err := p.governance.RateLimit(ctx, effectiveTenant, rt.agent, meta.Skill.Name); err != nil {
		p.observeDenied(ctx, requestID, rt, principal, meta.Skill.Name, a2a.NewRPCError(a2a.CodeInternalError, internalReason))
		p.metrics.ObserveRateLimit(p.rateLimitScope(), "error")
		p.writeRPC(w, meta.Envelope.ID, a2a.NewRPCError(a2a.CodeInternalError, internalReason))
		return
	} else if retryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		p.observeThrottled(ctx, requestID, rt, principal, meta)
		// T-5：a2a_rate_limit_decisions_total{scope,decision=throttled}
		p.metrics.ObserveRateLimit(p.rateLimitScope(), "throttled")
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}
	// T-5：a2a_rate_limit_decisions_total{scope,decision=allow}
	p.metrics.ObserveRateLimit(p.rateLimitScope(), "allow")

	// T-4 内容安全检查：请求侧（用户输入）。必须在**转发之前**完成——
	// 命中 deny 时原文不出网关；检查器异常则 fail-open（放行）并审计 result=error。
	if decision, contErr := p.checkRequestContent(ctx, rt, principal, meta); contErr != nil {
		p.observeContentAction(ctx, requestID, rt, principal, meta, ContentActionEvent{
			Action: "error", Result: "error", ErrorCode: strconv.Itoa(a2a.CodeInternalError),
		})
	} else if decision.Action == ContentActionDeny {
		p.observeContentAction(ctx, requestID, rt, principal, meta, decision.toEvent("deny", "blocked"))
		p.writeRPC(w, meta.Envelope.ID, a2a.NewRPCError(a2a.CodeContentBlocked, a2a.ReasonContentBlocked))
		return
	}

	// Backend forwarding with the SSRF-guarded client.
	if err := CheckBackendURL(agentRec.BackendURL, p.cfg.DevAllowLoopback); err != nil {
		p.writeRPC(w, meta.Envelope.ID, a2a.NewRPCError(a2a.CodeInternalError, internalReason))
		return
	}
	p.forward(ctx, w, r, rt, principal, meta, agentRec, requestID)
}

// forward proxies the raw envelope to the backend and maps the response.
// The backend URL has already passed CheckBackendURL in handleInvoke.
func (p *Proxy) forward(ctx context.Context, w http.ResponseWriter, r *http.Request, rt route, principal *Principal, meta *a2a.RequestMeta, agentRec *SnapshotAgent, requestID string) {
	ctx, cancel := context.WithTimeout(ctx, p.cfg.BackendTimeout)
	defer cancel()

	backendReq, err := http.NewRequestWithContext(ctx, http.MethodPost, agentRec.BackendURL, strings.NewReader(string(meta.Envelope.Raw)))
	if err != nil {
		p.writeRPC(w, meta.Envelope.ID, a2a.NewRPCError(a2a.CodeInternalError, internalReason))
		return
	}
	copyForwardHeaders(backendReq.Header, r.Header)
	if ct := r.Header.Get("Content-Type"); ct != "" {
		backendReq.Header.Set("Content-Type", ct)
	}
	// T-5：traceparent 注入后端请求 → 任务上下文跨服务贯通（G-6）。
	injectTraceContext(ctx, backendReq.Header)
	// F-2 §2.4: strip the governance skill header by default; only inject the
	// verified value when explicitly configured.
	backendReq.Header.Del(a2a.HeaderSkill)
	if p.cfg.ForwardSkillHeader && meta.Skill.Name != "*" {
		backendReq.Header.Set(a2a.HeaderSkill, meta.Skill.Name)
		backendReq.Header.Set(a2a.HeaderSkill+"-Source", "gateway")
	}

	resp, err := p.client.Do(backendReq)
	if err != nil {
		p.observeResult(ctx, requestID, rt, principal, meta, "", "error", strconv.Itoa(a2a.CodeServerError), http.StatusBadGateway)
		p.writeRPC(w, meta.Envelope.ID, a2a.NewRPCError(a2a.CodeServerError, internalReason))
		return
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := readAllLimited(resp.Body, p.cfg.MaxResponseBytes)
	if err != nil {
		p.observeResult(ctx, requestID, rt, principal, meta, "", "error", strconv.Itoa(a2a.CodeServerError), resp.StatusCode)
		p.writeRPC(w, meta.Envelope.ID, a2a.NewRPCError(a2a.CodeServerError, internalReason))
		return
	}
	if resp.StatusCode != http.StatusOK {
		// The agent backend must answer the JSON-RPC endpoint with 200.
		p.observeResult(ctx, requestID, rt, principal, meta, "", "error", strconv.Itoa(a2a.CodeServerError), resp.StatusCode)
		p.writeRPC(w, meta.Envelope.ID, a2a.NewRPCError(a2a.CodeServerError, internalReason))
		return
	}

	respMeta := ExtractResponseMeta(raw)

	// T-4 内容安全检查：响应侧（模型输出）。在写响应前完成：
	// deny 直接阻断；redact 改写 raw 后照常下发；检查器失败 fail-open（放行）并审计。
	if p.contentSafety != nil {
		var decision ContentCheckDecision
		csRaw, decision, contErr := p.checkResponseContent(ctx, rt, principal, meta, raw)
		switch {
		case contErr != nil:
			// 检查器异常：MVP 放行，不计为内容命中；审计 result=error 供观测。
			p.observeContentAction(ctx, requestID, rt, principal, meta, ContentActionEvent{
				Action: "error", Result: "error", ErrorCode: strconv.Itoa(a2a.CodeInternalError),
			})
		case decision.Action == ContentActionDeny:
			p.observeContentAction(ctx, requestID, rt, principal, meta, decision.toEvent("deny", "blocked"))
			p.writeRPC(w, meta.Envelope.ID, a2a.NewRPCError(a2a.CodeContentBlocked, a2a.ReasonContentBlocked))
			return
		case decision.Action == ContentActionRedact && len(csRaw) > 0:
			p.observeContentAction(ctx, requestID, rt, principal, meta, decision.toEvent("redact", "redacted"))
			raw = csRaw
		}
	}

	a2a.SetVersionHeader(w)
	copyResponseHeaders(w.Header(), resp.Header)
	w.Header().Set("Content-Type", responseContentType(r.Header.Get("Content-Type")))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)

	result := "success"
	errorCode := ""
	if respMeta.IsError {
		result = "error"
		errorCode = strconv.Itoa(respMeta.ErrorCode)
	}
	p.observeResult(ctx, requestID, rt, principal, meta, respMeta.State, result, errorCode, http.StatusOK)
	// T-3b：观测到任务状态 → 归一化并发送 Task 审计事件（不阻断协议；写失败进 outbox）。
	p.observeTaskEvent(ctx, requestID, rt, principal, meta, respMeta, result, errorCode)
}

// observeTaskEvent 在数据面观测到任务状态时构造并发送归一化 Task 审计事件。
//
// 仅记观测到的状态、不合成；事件不含任何正文（R-2）。观测/发送失败不得影响
// 正常响应（与治理拒绝类审计不同，Task 审计失败进 outbox，不 fail-closed 请求）。
func (p *Proxy) observeTaskEvent(ctx context.Context, requestID string, rt route, principal *Principal, meta *a2a.RequestMeta, respMeta ResponseMeta, result, errorCode string) {
	if respMeta.State == "" {
		return
	}
	tenant, _ := a2a.ResolveRouteTenant(principal.Tenant, rt.tenant)
	if tenant == "" {
		tenant = principal.Tenant
	}
	state := NormalizeTaskState(respMeta.State)
	now := time.Now().UTC()
	ev := TaskEvent{
		EventID:     newTaskEventID(),
		Timestamp:   now.Format(time.RFC3339Nano),
		RequestID:   requestID,
		Tenant:      tenant,
		Agent:       rt.agent,
		Skill:       meta.Skill.Name,
		SkillSource: string(meta.Skill.Source),
		TaskID:      respMeta.TaskID,
		ContextID:   respMeta.ContextID,
		State:       state,
		Result:      result,
		ErrorCode:   errorCode,
		A2AVersion:  meta.Version,
		Producer:    string(TaskProducerGateway),
		DedupKey:    TaskEventDedupKey(tenant, rt.agent, respMeta.TaskID, state),
	}

	// T-5 观测：a2a_tasks_total{tenant,agent,skill,state} 递增。
	p.metrics.ObserveTaskState(tenant, rt.agent, meta.Skill.Name, state)
	// T-5 观测：耗时跟踪（起点＝首次观测该 task_id；终态且起点已知才落样本，
	// 并回填 audit 的 duration_ms —— F-6 D-F6-5/SM-9/SM-10「不伪造起点」）。
	p.metrics.TrackTaskStart(tenant, rt.agent, respMeta.TaskID, now)
	if isTerminalState(state) {
		if durationMs, ok := p.metrics.ObserveTerminalTask(tenant, rt.agent, respMeta.TaskID, now); ok {
			ev.DurationMs = durationMs
		}
	}

	if p.governance != nil {
		p.governance.ObserveTask(ctx, ev)
	}
}

// rateLimitScope 取限流器上报的键范围（T-5）。Governance 未实现 RateLimitScopeObserver
// 时按 unknown 计——观测归因降级，不影响判定。
func (p *Proxy) rateLimitScope() string {
	if obs, ok := p.governance.(RateLimitScopeObserver); ok {
		return obs.LastRateLimitScope()
	}
	return RateLimitScopeUnknown
}

// contentCheckContext 抽取内容检查所需的公共上下文（tenant/agent/skill/method）。
//
// tenant 口径与 observeTaskEvent 一致：路由租户优先，回落到 principal 租户。
func contentCheckContext(rt route, principal *Principal, meta *a2a.RequestMeta) (tenant, skill, method string) {
	tenant, _ = a2a.ResolveRouteTenant(principal.Tenant, rt.tenant)
	if tenant == "" {
		tenant = principal.Tenant
	}
	return tenant, meta.Skill.Name, meta.Envelope.Method
}

// checkParts 对一段 JSON 正文抽取 parts 并交给内容检查层。
//
// 不可解析或不含 parts 时不介入（放行）：内容安全层不阻断它读不懂的协议结构。
func (p *Proxy) checkParts(ctx context.Context, tenant, agent, skill, method string, isResponse bool, body []byte) (ContentCheckDecision, error) {
	parts, err := extractParts(body)
	if err != nil || len(parts) == 0 {
		return ContentCheckDecision{Action: ContentActionAllow}, nil
	}
	return p.contentSafety.Check(ctx, ContentCheckRequest{
		Tenant:     tenant,
		Agent:      agent,
		Skill:      skill,
		Method:     method,
		IsResponse: isResponse,
		Parts:      parts,
	})
}

// checkRequestContent 在**转发之前**检查用户输入（SendMessage 的 message.parts）。
//
// 请求侧只认 deny（阻断请求，原文不出网关）；redact 对输入无语义，按放行处理。
// 非 SendMessage 方法（如 GetTask）无用户输入正文，不检查。
func (p *Proxy) checkRequestContent(ctx context.Context, rt route, principal *Principal, meta *a2a.RequestMeta) (ContentCheckDecision, error) {
	if p.contentSafety == nil || meta.Envelope.Method != a2a.MethodSendMessage {
		return ContentCheckDecision{Action: ContentActionAllow}, nil
	}
	tenant, skill, method := contentCheckContext(rt, principal, meta)
	d, err := p.checkParts(ctx, tenant, rt.agent, skill, method, false, meta.Envelope.Raw)
	if err != nil {
		return ContentCheckDecision{Action: ContentActionAllow}, err
	}
	if d.Action != ContentActionDeny {
		return ContentCheckDecision{Action: ContentActionAllow}, nil
	}
	return d, nil
}

// checkResponseContent 在**写回响应之前**检查模型输出（result/artifact 各级 parts）。
//
// 返回 (可能的改写结果 raw, 综合决策, 错误)：
//   - deny：原 raw 返回，由调用方阻断；
//   - redact：返回改写后的 raw；若改写失败则**升级为 deny**（不得原文下发生命中的正文）；
//   - allow/其余：原 raw 返回。
func (p *Proxy) checkResponseContent(ctx context.Context, rt route, principal *Principal, meta *a2a.RequestMeta, raw []byte) ([]byte, ContentCheckDecision, error) {
	tenant, skill, method := contentCheckContext(rt, principal, meta)
	d, err := p.checkParts(ctx, tenant, rt.agent, skill, method, true, raw)
	if err != nil {
		return raw, ContentCheckDecision{Action: ContentActionAllow}, err
	}
	switch d.Action {
	case ContentActionDeny:
		return raw, d, nil
	case ContentActionRedact:
		if redacted := redactParts(raw); len(redacted) > 0 {
			return redacted, d, nil
		}
		// 改写失败 → fail-closed：升级为 deny，避免把命中的正文原文下发。
		return raw, ContentCheckDecision{
			Action: ContentActionDeny,
			Tier:   d.Tier,
			Reason: d.Reason + ";redact_failed",
		}, nil
	}
	return raw, d, nil
}

// observeContentAction 发送 a2a_content_action 审计事件（元数据级，不落正文）。
func (p *Proxy) observeContentAction(ctx context.Context, requestID string, rt route, principal *Principal, meta *a2a.RequestMeta, ev ContentActionEvent) {
	tenant, _ := a2a.ResolveRouteTenant(principal.Tenant, rt.tenant)
	if tenant == "" {
		tenant = principal.Tenant
	}
	ev.EventID = newTaskEventID()
	ev.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
	ev.RequestID = requestID
	ev.Tenant = tenant
	ev.Agent = rt.agent
	ev.Skill = meta.Skill.Name
	ev.Method = meta.Envelope.Method
	if p.governance != nil {
		p.governance.ObserveContent(ctx, ev)
	}
}

// toEvent 由检查决策构造审计事件（action/result 由调用方按 deny/redact 填）。
func (d ContentCheckDecision) toEvent(action, result string) ContentActionEvent {
	return ContentActionEvent{Tier: d.Tier, Action: action, Result: result}
}

// handleDiscovery serves the registered card at the well-known path.
func (p *Proxy) handleDiscovery(w http.ResponseWriter, r *http.Request) {
	snap := p.snapshots.Current()
	if snap == nil {
		http.Error(w, "a2a registry unavailable", http.StatusServiceUnavailable)
		return
	}
	rt, ok := p.resolveDiscoveryRoute(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	agentRec, found := snap.Lookup(rt.tenant, rt.agent)
	if !found || agentRec.SignatureStatus != "valid" {
		http.NotFound(w, r)
		return
	}
	etag := `"a2a-` + rt.tenant + `-` + rt.agent + `-` + strconv.FormatUint(agentRec.Revision, 10) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Content-Type", "application/json")
	if match := r.Header.Get("If-None-Match"); match != "" && strings.Contains(match, etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(agentRec.Card)
}

// resolveDiscoveryRoute resolves tenant/agent for discovery requests.
func (p *Proxy) resolveDiscoveryRoute(r *http.Request) (route, bool) {
	if p.cfg.PublicMode == PublicModeHost {
		host := hostOnly(r.Host)
		for tenant, domain := range p.cfg.TenantDomains {
			suffix := "." + strings.ToLower(domain)
			if strings.HasSuffix(strings.ToLower(host), suffix) {
				agent := strings.TrimSuffix(strings.ToLower(host), suffix)
				if agent == "" || strings.Contains(agent, ".") {
					return route{}, false
				}
				return route{tenant: tenant, agent: agent}, true
			}
		}
		return route{}, false
	}
	trimmed := strings.Trim(r.URL.Path, "/")
	const marker = "/.well-known/agent-card.json"
	idx := strings.Index(trimmed, marker)
	if idx <= 0 {
		return route{}, false
	}
	parts := strings.Split(trimmed[:idx], "/")
	if len(parts) != 3 || parts[0] != "a2a" || parts[1] == "" || parts[2] == "" {
		return route{}, false
	}
	return route{tenant: parts[1], agent: parts[2]}, true
}

// handleHealth reports registry readiness (data plane fail-closed source).
func (p *Proxy) handleHealth(w http.ResponseWriter, _ *http.Request) {
	snap := p.snapshots.Current()
	ready := snap != nil
	revision := uint64(0)
	if ready {
		revision = snap.Revision()
	}
	w.Header().Set("Content-Type", "application/json")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"a2a_registry_ready":    ready,
		"a2a_registry_revision": revision,
	})
}

// writeRPC writes a JSON-RPC error with the frozen HTTP 200 mapping.
func (p *Proxy) writeRPC(w http.ResponseWriter, id json.RawMessage, rpc *a2a.RPCError) {
	a2a.WriteRPCError(w, id, rpc)
}

// --- audit helpers -------------------------------------------------------

func (p *Proxy) baseEvent(requestID string, rt route, principal *Principal) AuditEvent {
	return AuditEvent{
		Tenant:     principal.Tenant,
		Agent:      rt.agent,
		RequestID:  requestID,
		A2AVersion: a2a.SupportedVersion,
	}
}

func (p *Proxy) observeDenied(ctx context.Context, requestID string, rt route, principal *Principal, skill string, rpc *a2a.RPCError) {
	ev := p.baseEvent(requestID, rt, principal)
	ev.Skill = skillOrWildcard(skill)
	ev.Result = "denied"
	if rpc != nil {
		ev.ErrorCode = strconv.Itoa(rpc.Code)
	}
	p.governance.Observe(ctx, ev)
}

func (p *Proxy) observeThrottled(ctx context.Context, requestID string, rt route, principal *Principal, meta *a2a.RequestMeta) {
	ev := p.baseEvent(requestID, rt, principal)
	if meta != nil {
		ev.Skill = meta.Skill.Name
		ev.SkillSource = string(meta.Skill.Source)
		ev.Method = meta.Envelope.Method
	}
	ev.Result = "throttled"
	ev.HTTPStatus = http.StatusTooManyRequests
	p.governance.Observe(ctx, ev)
}

func (p *Proxy) observeProtocolError(ctx context.Context, requestID string, rt route, principal *Principal, meta *a2a.RequestMeta, httpErr *a2a.HTTPError) {
	ev := p.baseEvent(requestID, rt, principal)
	if meta != nil {
		ev.Skill = meta.Skill.Name
		ev.SkillSource = string(meta.Skill.Source)
		ev.Method = meta.Envelope.Method
	}
	ev.Result = "error"
	ev.HTTPStatus = httpErr.Status
	if httpErr.RPC != nil {
		ev.ErrorCode = strconv.Itoa(httpErr.RPC.Code)
	}
	p.governance.Observe(ctx, ev)
}

func (p *Proxy) observeResult(ctx context.Context, requestID string, rt route, principal *Principal, meta *a2a.RequestMeta, state, result, errorCode string, httpStatus int) {
	ev := p.baseEvent(requestID, rt, principal)
	ev.Skill = meta.Skill.Name
	ev.SkillSource = string(meta.Skill.Source)
	ev.Method = meta.Envelope.Method
	ev.State = state
	ev.Result = result
	ev.ErrorCode = errorCode
	ev.HTTPStatus = httpStatus
	p.governance.Observe(ctx, ev)
}

func skillOrWildcard(skill string) string {
	if skill == "" {
		return "*"
	}
	return skill
}

func aclReasonOf(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "unknown_skill"):
		return a2a.ReasonUnknownSkill
	case strings.Contains(msg, "acl_denied"):
		return aclDeniedReason
	default:
		return ""
	}
}

// --- misc helpers --------------------------------------------------------

func requestIDOf(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("X-Request-Id")); v != "" && len(v) <= 128 {
		return v
	}
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "a2a-unknown-request"
	}
	return "a2a-" + hex.EncodeToString(b[:])
}

// hopByHopHeaders are not forwarded to the backend (RFC 7230 §6.1).
// Authorization is stripped as well: the gateway terminates authentication
// and the agent backend must never observe the caller's bearer token.
var hopByHopHeaders = map[string]bool{
	"Connection": true, "Proxy-Connection": true, "Keep-Alive": true,
	"Proxy-Authenticate": true, "Proxy-Authorization": true, "Te": true,
	"Trailer": true, "Transfer-Encoding": true, "Upgrade": true,
	"Content-Length": true, "Accept-Encoding": true, "Host": true,
	"Authorization": true,
	a2a.HeaderSkill: true, a2a.HeaderSkill + "-Source": true,
}

func copyForwardHeaders(dst, src http.Header) {
	for k, vs := range src {
		if hopByHopHeaders[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if hopByHopHeaders[ck] || ck == "Etag" || ck == "Content-Type" {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// responseContentType keeps the A2A media type when the client used it.
func responseContentType(requestContentType string) string {
	mt, _, err := mime.ParseMediaType(requestContentType)
	if err == nil && strings.EqualFold(mt, "application/a2a+json") {
		return "application/a2a+json"
	}
	return "application/json"
}

// ResponseMeta is the L1 response whitelist (F-2 §2.2). It is extracted
// best-effort for audit/metrics; the body itself is never retained.
type ResponseMeta struct {
	TaskID    string
	ContextID string
	MessageID string
	State     string
	IsError   bool
	ErrorCode int
}

// ExtractResponseMeta reads only the whitelisted response fields. Malformed
// responses yield an empty meta and never fail the request.
func ExtractResponseMeta(raw []byte) ResponseMeta {
	var top struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &top); err != nil {
		return ResponseMeta{}
	}
	if top.Error != nil {
		return ResponseMeta{IsError: true, ErrorCode: top.Error.Code}
	}
	var result struct {
		ID        string `json:"id"`
		TaskID    string `json:"taskId"`
		ContextID string `json:"contextId"`
		MessageID string `json:"messageId"`
		Task      *struct {
			ID        string `json:"id"`
			ContextID string `json:"contextId"`
			Status    *struct {
				State string `json:"state"`
			} `json:"status"`
		} `json:"task"`
		Status *struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if err := json.Unmarshal(top.Result, &result); err != nil {
		return ResponseMeta{}
	}
	meta := ResponseMeta{TaskID: result.TaskID, ContextID: result.ContextID, MessageID: result.MessageID}
	if result.Task != nil {
		if result.Task.ID != "" {
			meta.TaskID = result.Task.ID
		}
		if result.Task.ContextID != "" {
			meta.ContextID = result.Task.ContextID
		}
		if result.Task.Status != nil {
			meta.State = result.Task.Status.State
		}
	}
	if result.ID != "" && meta.TaskID == "" {
		meta.TaskID = result.ID
	}
	if result.Status != nil && meta.State == "" {
		meta.State = result.Status.State
	}
	return meta
}
