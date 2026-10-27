package confllm_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/providers"
)

// TestHandlerCredentialNotLeaked P0-4②：凭据绝不进日志/错误报文（canary 举证）。
//
// PRD 原文要求：注入 canary `SECRET_CANARY_9f3a` 的 fake SecretResolver，覆盖
// **401 / 429 / timeout / 上游 body 回显** 四场景；断言：
//   - BufferLogger 结构化 kv 序列化后不含 canary 与 `Authorization` 原文；
//   - 错误响应不含上游原始 body；
//   - 日志字段集合 ⊆ {provider, model, status, duration, request_id}。
//
// 采用外部测试包（confllm_test）以 import providers 子包，避免循环依赖。
func TestHandlerCredentialNotLeaked(t *testing.T) {
	const canary = "SECRET_CANARY_9f3a"

	// disposed 记录上游实际收到的 Authorization 头（用于证明「凭据确已注入」，防止测试空跑）。
	var (
		mu        sync.Mutex
		gotAuth   string
		gotHeader http.Header
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		mu.Lock()
		gotAuth = r.Header.Get("Authorization")
		gotHeader = r.Header.Clone()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")

		switch body.Model {
		case "case401":
			w.WriteHeader(http.StatusUnauthorized)
			// 上游原始 body 故意回显凭据（模拟最坏情况的上游泄漏）
			_, _ = w.Write([]byte(`{"error":{"message":"invalid api key ` + canary + `"}}`))
		case "case429":
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"quota exceeded for ` + canary + `"}}`))
		case "caseTimeout":
			time.Sleep(400 * time.Millisecond)
			_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"late"}}]}`))
		case "caseBodyEcho":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"trace":"upstream boom","leaked":"` + canary + `"}`))
		default:
			_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{}}`))
		}
	}))
	defer srv.Close()

	// canaryResolver 伪造凭据解析器，返回带 canary 的凭据。
	resolver := canaryResolver{canary: canary}

	cases := []struct {
		name     string
		model    string
		deadline time.Duration // 超时场景使用短 ctx
	}{
		{"401", "case401", 0},
		{"429", "case429", 0},
		{"timeout", "caseTimeout", 120 * time.Millisecond},
		{"bodyEcho", "caseBodyEcho", 0},
	}

	allowedFields := map[string]bool{
		"msg": true, "provider": true, "model": true,
		"status": true, "duration": true, "request_id": true,
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			gotAuth, gotHeader = "", nil
			mu.Unlock()

			buf := confllm.NewBufferLogger()
			p, err := providers.NewTencentProvider(
				confllm.ProviderConfig{ID: "leak-probe", Endpoint: srv.URL},
				confllm.WithSecretResolver(resolver),
				confllm.WithLogger(buf),
				confllm.WithHTTPClient(&http.Client{Transport: &http.Transport{}}),
			)
			if err != nil {
				t.Fatalf("构造 provider 失败：%v", err)
			}

			ctx := context.Background()
			if tc.deadline > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, tc.deadline)
				defer cancel()
			}
			_, chatErr := p.Chat(ctx, &confllm.ChatRequest{
				Model:    tc.model,
				Messages: []confllm.Message{{Role: "user", Content: "hi"}},
			})

			// ① 证明凭据已真实注入到上游请求（否则本测试的断言毫无意义）。
			mu.Lock()
			auth := gotAuth
			hdr := gotHeader
			mu.Unlock()
			if !strings.Contains(auth, canary) {
				t.Fatalf("前置断言失败：上游未收到含 canary 的 Authorization=%q，测试空跑", auth)
			}

			// ② 日志所有字段值不得含 canary，也不得含 Authorization 原文。
			for _, f := range buf.Fields() {
				if strings.Contains(f.Value, canary) {
					t.Fatalf("日志字段 %s 泄漏凭据原文（§7.2）：%q", f.Key, f.Value)
				}
				if strings.Contains(f.Value, "Bearer ") {
					t.Fatalf("日志字段 %s 含 Authorization 原文（§7.2）：%q", f.Key, f.Value)
				}
				if !allowedFields[f.Key] {
					t.Fatalf("日志字段 %s 不在白名单 %v 内（§7.10 脱敏白名单）", f.Key, allowedFields)
				}
			}

			// ③ 错误响应不得含上游原始 body / canary。
			if chatErr != nil {
				raw, merr := json.Marshal(confllm.ParseError(chatErr).SanitizedBody())
				if merr != nil {
					t.Fatalf("序列化错误体失败：%v", merr)
				}
				if strings.Contains(string(raw), canary) {
					t.Fatalf("错误响应泄漏凭据原文（§7.2）：%s", string(raw))
				}
				if strings.Contains(string(raw), "upstream boom") {
					t.Fatalf("错误响应含上游原始 body（§7.2）：%s", string(raw))
				}
			}
			_ = hdr
		})
	}
}

// canaryResolver 返回固定 canary 凭据的 SecretResolver（测试伪造）。
type canaryResolver struct{ canary string }

func (r canaryResolver) Resolve(_ context.Context, _ confllm.SecretRef) (*confllm.Credential, error) {
	return &confllm.Credential{Key: []byte(r.canary)}, nil
}
