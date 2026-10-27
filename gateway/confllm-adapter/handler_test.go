package confllm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// testProvider 库内 handler 测试用最小实现。
type testProvider struct {
	id     string
	cls    string
	models []ModelInfo
}

func (p *testProvider) ID() string     { return p.id }
func (p *testProvider) Region() Region { return RegionDomestic }
func (p *testProvider) Metadata() ConfidentialityMeta {
	return ConfidentialityMeta{ConfidentialityClass: p.cls}
}
func (p *testProvider) Capabilities() Capabilities { return Capabilities{} }
func (p *testProvider) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	return &ChatResponse{
		ID:      "t",
		Object:  "chat.completion",
		Model:   req.Model,
		Choices: []Choice{{Index: 0, Message: Message{Role: "assistant", Content: "ok"}}},
	}, nil
}
func (p *testProvider) Stream(ctx context.Context, req *ChatRequest) (StreamReader, error) {
	return nil, nil
}
func (p *testProvider) ListModels(ctx context.Context) ([]ModelInfo, error) { return p.models, nil }
func (p *testProvider) Health(ctx context.Context) HealthStatus {
	return HealthStatus{Ready: true, MinConfidentialityClass: p.cls}
}

func newTestHandler() *ConfllmHandler {
	reg := NewRegistry()
	reg.Register(&testProvider{id: "p1", cls: "A", models: []ModelInfo{{ID: "m1"}}})
	reg.Register(&testProvider{id: "p2", cls: "B"})
	return NewConfllmHandler(reg)
}

func TestHandlerChatOK(t *testing.T) {
	h := newTestHandler()
	srv := httptest.NewServer(http.HandlerFunc(h.HandleChat))
	defer srv.Close()

	// 缺少 provider 标识 → 400。
	resp, err := http.Post(srv.URL+"/v1/confllm/chat/completions", "application/json", strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusBadRequest {
		resp.Body.Close()
		t.Fatalf("缺 provider 期望 400，实际 %d", resp.StatusCode)
	}
	resp.Body.Close()

	// 正确 provider（query ?provider=）→ 200 + 正常响应。
	resp2, err := http.Post(srv.URL+"/v1/confllm/chat/completions?provider=p1", "application/json",
		strings.NewReader(`{"model":"m","messages":[{"role":"user","content":"hi"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", resp2.StatusCode)
	}
	var out ChatResponse
	if err := json.NewDecoder(resp2.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Choices[0].Message.Content != "ok" {
		t.Fatalf("内容不符：%q", out.Choices[0].Message.Content)
	}
}

func TestHandlerUnknownProvider(t *testing.T) {
	h := newTestHandler()
	srv := httptest.NewServer(http.HandlerFunc(h.HandleChat))
	defer srv.Close()
	resp, err := http.Post(srv.URL+"/v1/confllm/chat/completions?provider=nope", "application/json", strings.NewReader(`{"model":"m"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("未知 provider 期望 404，实际 %d", resp.StatusCode)
	}
}

func TestHandlerModels(t *testing.T) {
	h := newTestHandler()
	srv := httptest.NewServer(http.HandlerFunc(h.HandleModels))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/confllm/models")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", resp.StatusCode)
	}
	var out struct {
		Models []struct {
			Provider string `json:"provider"`
			Model    string `json:"model"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Models) != 1 {
		t.Fatalf("期望 1 个模型（p1 有模型，p2 无），实际 %d", len(out.Models))
	}
	if out.Models[0].Provider != "p1" || out.Models[0].Model != "m1" {
		t.Fatalf("模型条目不符：%v", out.Models)
	}
}

func TestHandlerHealth(t *testing.T) {
	h := newTestHandler()
	srv := httptest.NewServer(http.HandlerFunc(h.HandleHealth))
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/v1/confllm/health")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("期望 200，实际 %d", resp.StatusCode)
	}
	var agg HealthAggregate
	if err := json.NewDecoder(resp.Body).Decode(&agg); err != nil {
		t.Fatal(err)
	}
	if agg.Total != 2 || agg.Ready != 2 {
		t.Fatalf("健康聚合不符：%v", agg)
	}
}
