package confllm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/confllm-adapter/meta"
)

// testProvider 库内 handler 测试用最小实现。
type testProvider struct {
	id      string
	cls     string
	models  []ModelInfo
	pending bool // Health().PendingCredential（连通性举证：pending-credential）
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
	if p.pending {
		return HealthStatus{Ready: false, PendingCredential: true, Detail: "pending-credential", MinConfidentialityClass: p.cls}
	}
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
	if s, ok := out.Choices[0].Message.Content.(string); !ok || s != "ok" {
		t.Fatalf("内容不符：%v", out.Choices[0].Message.Content)
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

// TestHandlerConnectivityEvidence 【§7.5.1 / PRD P0-3】
// health 与 models 两个端点都必须暴露 connectivity，且凭据未配置的 provider 报
// pending-credential（不得一律报 never-tested，否则「没凭据」与「从未调用」不可分辨）。
func TestHandlerConnectivityEvidence(t *testing.T) {
	reg := NewRegistry()
	reg.Register(&testProvider{id: "p-ready", cls: "A"})
	reg.Register(&testProvider{id: "p-pending", cls: "C", pending: true})
	h := NewConfllmHandler(reg)

	// 1) /v1/confllm/health
	rec := httptest.NewRecorder()
	h.HandleHealth(rec, httptest.NewRequest(http.MethodGet, "/v1/confllm/health", nil))
	var raw struct {
		Providers []map[string]json.RawMessage `json:"providers"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatalf("health 响应非合法 JSON：%v", err)
	}
	if len(raw.Providers) != 2 {
		t.Fatalf("health providers 期望 2 条，实际 %d", len(raw.Providers))
	}
	got := map[string]string{}
	for _, e := range raw.Providers {
		var id, conn string
		_ = json.Unmarshal(e["id"], &id)
		c, ok := e["connectivity"]
		if !ok {
			t.Fatalf("health 条目 %s 缺失 connectivity（§7.5.1：health 必须暴露该字段）", id)
		}
		_ = json.Unmarshal(c, &conn)
		got[id] = conn
	}
	if got["p-pending"] != meta.ConnPendingCredential {
		t.Fatalf("health p-pending connectivity=%q 期望 pending-credential", got["p-pending"])
	}
	if got["p-ready"] != meta.ConnNeverTested {
		t.Fatalf("health p-ready connectivity=%q 期望 never-tested", got["p-ready"])
	}

	// 2) /v1/confllm/models（同一口径）
	rec2 := httptest.NewRecorder()
	h.HandleModels(rec2, httptest.NewRequest(http.MethodGet, "/v1/confllm/models", nil))
	var out modelsWireProbe
	if err := json.Unmarshal(rec2.Body.Bytes(), &out); err != nil {
		t.Fatalf("models 响应非合法 JSON：%v", err)
	}
	got2 := map[string]string{}
	for _, e := range out.Providers {
		got2[e.Provider] = e.Connectivity
	}
	if got2["p-pending"] != meta.ConnPendingCredential {
		t.Fatalf("models p-pending connectivity=%q 期望 pending-credential", got2["p-pending"])
	}
	if got2["p-ready"] != meta.ConnNeverTested {
		t.Fatalf("models p-ready connectivity=%q 期望 never-tested", got2["p-ready"])
	}
}

// modelsWireProbe /v1/confllm/models 的 providers[] 探测结构（仅 connectivity 举证用）。
type modelsWireProbe struct {
	Providers []struct {
		Provider     string `json:"provider"`
		Connectivity string `json:"connectivity"`
	} `json:"providers"`
}
