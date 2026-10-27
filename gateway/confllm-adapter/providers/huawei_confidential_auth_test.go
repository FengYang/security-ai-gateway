package providers

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"security-ai-gateway/gateway/confllm-adapter"
)

// TestHuaweiConfidentialAuthScheme 证明 huawei-confidential 真实客户端使用华为文档化
// IAM Token 头 `X-Auth-Token`（而非 OpenAI 兼容的 `Authorization: Bearer`），覆盖 Chat/Stream/ListModels 三路径。
//
// 离线守卫注意（评审 R4）：TestMain 将 http.DefaultTransport 替换为 mock.OfflineTransport 并在末尾断言
// EgressAttempts()==0。本测试**必须**注入独立真实 transport（`&http.Transport{}`）直连 127.0.0.1，
// 绝不走 http.DefaultTransport，否则会触发离线守卫计数，导致 TestMain 以退出码 1 失败。
func TestHuaweiConfidentialAuthScheme(t *testing.T) {
	var mu sync.Mutex
	captured := struct {
		auth  string
		xAuth string
	}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		captured.auth = r.Header.Get("Authorization")
		captured.xAuth = r.Header.Get("X-Auth-Token")
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"m1","owned_by":"p"}]}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}],"usage":{}}`))
	}))
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{}}
	ctx := context.Background()

	p, err := NewHuaweiProvider(confllm.ProviderConfig{ID: "hw", Endpoint: srv.URL},
		confllm.WithHTTPClient(client),
		confllm.WithStaticCredential(&confllm.Credential{Key: []byte("hw-token")}))
	if err != nil {
		t.Fatalf("构造 huawei-confidential 失败：%v", err)
	}

	// Chat 路径：断言仅 X-Auth-Token、无 Authorization Bearer。
	if _, err := p.Chat(ctx, &confllm.ChatRequest{Model: "m", Messages: []confllm.Message{{Role: "user", Content: "hi"}}}); err != nil {
		t.Fatalf("Chat 失败：%v", err)
	}
	mu.Lock()
	if captured.auth != "" {
		t.Fatalf("华为密态推理不应发送 Authorization Bearer，实际 Authorization=%q", captured.auth)
	}
	if captured.xAuth != "hw-token" {
		t.Fatalf("华为密态推理应发送 X-Auth-Token=hw-token，实际 X-Auth-Token=%q", captured.xAuth)
	}
	mu.Unlock()

	// Stream 路径：同样仅 X-Auth-Token。
	mu.Lock()
	captured.auth, captured.xAuth = "", ""
	mu.Unlock()
	sr, err := p.Stream(ctx, &confllm.ChatRequest{Model: "m", Stream: true})
	if err != nil {
		t.Fatalf("Stream 失败：%v", err)
	}
	for {
		if _, e := sr.Next(); e == io.EOF {
			break
		} else if e != nil {
			t.Fatalf("Stream Next 失败：%v", e)
		}
	}
	_ = sr.Close()
	mu.Lock()
	if captured.auth != "" {
		t.Fatalf("华为密态推理 Stream 不应发送 Authorization Bearer，实际 Authorization=%q", captured.auth)
	}
	if captured.xAuth != "hw-token" {
		t.Fatalf("华为密态推理 Stream 应发送 X-Auth-Token=hw-token，实际 X-Auth-Token=%q", captured.xAuth)
	}
	mu.Unlock()

	// ListModels 路径（经 doRequest 的 GET 分支）：同样仅 X-Auth-Token。
	mu.Lock()
	captured.auth, captured.xAuth = "", ""
	mu.Unlock()
	if _, err := p.ListModels(ctx); err != nil {
		t.Fatalf("ListModels 失败：%v", err)
	}
	mu.Lock()
	if captured.auth != "" {
		t.Fatalf("华为密态推理 ListModels 不应发送 Authorization Bearer，实际 Authorization=%q", captured.auth)
	}
	if captured.xAuth != "hw-token" {
		t.Fatalf("华为密态推理 ListModels 应发送 X-Auth-Token=hw-token，实际 X-Auth-Token=%q", captured.xAuth)
	}
	mu.Unlock()

	// 空 Key 负例：未注入凭据时 resolveCredential 提前返回 pending-credential，请求不会发出
	//（customizeReq 不被触发），fail-closed 符合预期。
	mu.Lock()
	captured.auth, captured.xAuth = "", ""
	mu.Unlock()
	pNoCred, err := NewHuaweiProvider(confllm.ProviderConfig{ID: "hw", Endpoint: srv.URL},
		confllm.WithHTTPClient(client))
	if err != nil {
		t.Fatalf("构造无凭据 huawei-confidential 失败：%v", err)
	}
	if _, err := pNoCred.Chat(ctx, &confllm.ChatRequest{Model: "m", Messages: []confllm.Message{{Role: "user", Content: "hi"}}}); err == nil {
		t.Fatal("空 Key 期望 pending-credential 错误，返回 nil")
	} else if code := confllm.ParseError(err).Code; code != confllm.CodePendingCredential {
		t.Fatalf("空 Key 期望 pending-credential，实际 %s", code)
	}
	mu.Lock()
	if captured.xAuth != "" {
		t.Fatalf("空 Key 不应发出任何请求（不应有 X-Auth-Token），实际 X-Auth-Token=%q", captured.xAuth)
	}
	mu.Unlock()
}
