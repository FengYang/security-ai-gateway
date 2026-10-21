package a2aproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"security-ai-gateway/gateway/a2aguardrail/protocol"
)

// DefaultContentSafetyTimeout bounds one guardrail check. The A2A data plane
// is synchronous, so the guardrail must not become an unbounded latency tail.
const DefaultContentSafetyTimeout = 2 * time.Second

const maxContentSafetyResponseBytes = 64 << 10

// HTTPContentSafety adapts the A2A L3 interface to the standalone guardrail
// service. The service owns the output-guard policy engine; this adapter only
// maps parts and decisions.
type HTTPContentSafety struct {
	url        string
	token      string
	client     *http.Client
	failClosed bool
}

// NewHTTPContentSafety validates the endpoint and constructs the adapter.
// failClosed=true converts transport/protocol errors into a deny decision;
// false preserves the frozen MVP fail-open behavior and returns the error to
// the proxy for result=error auditing.
func NewHTTPContentSafety(endpoint, token string, timeout time.Duration, failClosed bool) (*HTTPContentSafety, error) {
	endpoint = strings.TrimSpace(endpoint)
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("a2aproxy: 内容安全 URL 非法: %q", endpoint)
	}
	if timeout <= 0 {
		timeout = DefaultContentSafetyTimeout
	}
	return &HTTPContentSafety{
		url:   endpoint,
		token: strings.TrimSpace(token),
		client: &http.Client{
			Timeout: timeout,
			Transport: &http.Transport{
				MaxIdleConns:        16,
				MaxIdleConnsPerHost: 16,
				IdleConnTimeout:     90 * time.Second,
			},
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		failClosed: failClosed,
	}, nil
}

// Check implements ContentSafety.
func (h *HTTPContentSafety) Check(ctx context.Context, req ContentCheckRequest) (ContentCheckDecision, error) {
	wire := protocol.Request{
		Tenant:     req.Tenant,
		Agent:      req.Agent,
		Skill:      req.Skill,
		Method:     req.Method,
		IsResponse: req.IsResponse,
		Parts:      toProtocolParts(req.Parts),
	}
	body, err := json.Marshal(wire)
	if err != nil {
		return h.failure(fmt.Errorf("a2aproxy: 编码内容检查请求失败: %w", err))
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(body))
	if err != nil {
		return h.failure(fmt.Errorf("a2aproxy: 构造内容检查请求失败: %w", err))
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "a2aproxy-content-safety")
	if h.token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+h.token)
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return h.failure(fmt.Errorf("a2aproxy: 内容检查请求失败: %w", err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return h.failure(fmt.Errorf("a2aproxy: 内容检查服务状态 %d", resp.StatusCode))
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxContentSafetyResponseBytes+1))
	if err != nil {
		return h.failure(fmt.Errorf("a2aproxy: 读取内容检查响应失败: %w", err))
	}
	if len(raw) > maxContentSafetyResponseBytes {
		return h.failure(fmt.Errorf("a2aproxy: 内容检查响应过大"))
	}
	var out protocol.Response
	if err := json.Unmarshal(raw, &out); err != nil {
		return h.failure(fmt.Errorf("a2aproxy: 解码内容检查响应失败: %w", err))
	}
	switch out.Action {
	case protocol.ActionAllow, protocol.ActionDeny, protocol.ActionRedact:
	default:
		return h.failure(fmt.Errorf("a2aproxy: 内容检查返回未知动作 %q", out.Action))
	}
	return ContentCheckDecision{
		Action: ContentAction(out.Action),
		Tier:   out.Tier,
		Reason: out.Reason,
	}, nil
}

func (h *HTTPContentSafety) failure(err error) (ContentCheckDecision, error) {
	if h.failClosed {
		return ContentCheckDecision{
			Action: ContentActionDeny,
			Tier:   "unavailable",
			Reason: "content_safety_unavailable",
		}, nil
	}
	return ContentCheckDecision{}, err
}

func toProtocolParts(parts []Part) []protocol.Part {
	out := make([]protocol.Part, 0, len(parts))
	for _, p := range parts {
		pp := protocol.Part{
			Kind:     protocol.PartKind(p.Kind),
			Text:     p.Text,
			MimeType: p.MimeType,
			Data:     p.Data,
		}
		if p.Kind == PartKindFile {
			pp.File = &protocol.FilePart{
				Name:     p.File.Name,
				MimeType: p.File.MimeType,
				URI:      p.File.URI,
				Bytes:    p.File.Bytes,
			}
		}
		out = append(out, pp)
	}
	return out
}
