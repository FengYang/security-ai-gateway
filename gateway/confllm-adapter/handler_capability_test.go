package confllm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// capProvider 能力门禁测试用 provider：声明一组能力，并标记 Chat/Stream 是否被真正调用，
// 用于断言「不支持的能力请求在转发前被拦截」（P1-3，而非静默降级打到上游）。
type capProvider struct {
	id           string
	caps         Capabilities
	chatCalled   bool
	streamCalled bool
}

func (p *capProvider) ID() string                              { return p.id }
func (p *capProvider) Region() Region                         { return RegionDomestic }
func (p *capProvider) Metadata() ConfidentialityMeta          { return ConfidentialityMeta{ConfidentialityClass: "A"} }
func (p *capProvider) Capabilities() Capabilities             { return p.caps }
func (p *capProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	p.chatCalled = true
	return &ChatResponse{ID: "t", Object: "chat.completion", Model: req.Model,
		Choices: []Choice{{Index: 0, Message: Message{Role: "assistant", Content: "ok"}}}}, nil
}
func (p *capProvider) Stream(ctx context.Context, req *ChatRequest) (StreamReader, error) {
	p.streamCalled = true
	return nil, nil
}
func (p *capProvider) ListModels(ctx context.Context) ([]ModelInfo, error) { return nil, nil }
func (p *capProvider) Health(ctx context.Context) HealthStatus             { return HealthStatus{Ready: true} }

func newCapHandler(providers ...ConfidentialLLMProvider) *ConfllmHandler {
	reg := NewRegistry()
	for _, p := range providers {
		reg.Register(p)
	}
	return NewConfllmHandler(reg)
}

// TestCapabilityGateUnsupported 验证：不支持某能力的 provider 收到该能力请求时，
// 返回 422 + unsupported_capability，且 Chat/Stream 绝不被调用（早失败，非静默降级）。
func TestCapabilityGateUnsupported(t *testing.T) {
	p := &capProvider{id: "p", caps: Capabilities{}} // 三项能力均不支持
	h := newCapHandler(p)
	srv := httptest.NewServer(http.HandlerFunc(h.HandleChat))
	defer srv.Close()

	cases := []struct {
		name string
		body string
	}{
		{"tools", `{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"x"}}]}`},
		{"vision", `{"model":"m","messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"http://x/y.png"}}]}]}`},
		{"thinking", `{"model":"m","messages":[{"role":"user","content":"hi"}],"reasoning":true}`},
		{"thinking-alias", `{"model":"m","messages":[{"role":"user","content":"hi"}],"enable_thinking":true}`},
	}
	for _, c := range cases {
		resp, err := http.Post(srv.URL+"/v1/confllm/chat/completions?provider=p", "application/json", strings.NewReader(c.body))
		if err != nil {
			t.Fatalf("[%s] 请求失败：%v", c.name, err)
		}
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		code := ""
		if e, ok := body["error"].(map[string]any); ok {
			code, _ = e["code"].(string)
		}
		status := resp.StatusCode
		resp.Body.Close()

		if status != http.StatusUnprocessableEntity {
			t.Fatalf("[%s] 期望 422，实际 %d", c.name, status)
		}
		if code != CodeUnsupportedCapability {
			t.Fatalf("[%s] 期望错误码 %q，实际 %q", c.name, CodeUnsupportedCapability, code)
		}
		if p.chatCalled {
			t.Fatalf("[%s] 能力门禁未拦截，Chat 被错误调用", c.name)
		}
		// 重置标记以便下一用例独立断言
		p.chatCalled = false
	}
}

// TestCapabilityGateSupported 验证：provider 声明支持该能力时，请求正常转发（200，Chat 被调用）。
func TestCapabilityGateSupported(t *testing.T) {
	p := &capProvider{id: "p", caps: Capabilities{SupportsTools: true, SupportsVision: true, ThinkingMode: true}}
	h := newCapHandler(p)
	srv := httptest.NewServer(http.HandlerFunc(h.HandleChat))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/confllm/chat/completions?provider=p", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"x"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("支持 tools 的 provider 期望 200，实际 %d", resp.StatusCode)
	}
	if !p.chatCalled {
		t.Fatal("支持 tools 的 provider 应正常调用 Chat")
	}
}

// TestCapabilityGateNoRequirement 验证：无能力要求的普通请求，即便 provider 零能力也不应被门禁拦截。
func TestCapabilityGateNoRequirement(t *testing.T) {
	p := &capProvider{id: "p", caps: Capabilities{}}
	h := newCapHandler(p)
	srv := httptest.NewServer(http.HandlerFunc(h.HandleChat))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/confllm/chat/completions?provider=p", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("无能力要求的普通请求期望 200，实际 %d", resp.StatusCode)
	}
	if !p.chatCalled {
		t.Fatal("普通请求应正常调用 Chat")
	}
}

// TestCapabilityGateStreamUnsupported 验证：流式路径（HandleStream 不经 h.Chat）同样拦截不支持的能力。
func TestCapabilityGateStreamUnsupported(t *testing.T) {
	p := &capProvider{id: "p", caps: Capabilities{}}
	h := newCapHandler(p)
	srv := httptest.NewServer(http.HandlerFunc(h.HandleStream))
	defer srv.Close()

	resp, err := http.Post(srv.URL+"/v1/confllm/stream/chat/completions?provider=p", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"x"}}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("流式路径能力门禁期望 422，实际 %d", resp.StatusCode)
	}
	if p.streamCalled {
		t.Fatal("流式路径能力门禁未拦截，Stream 被错误调用")
	}
}
