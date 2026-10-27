// Package providers — 密态上游适配器契约测试（T05：真·断网离线，mock 内核 + golden request）。
//
// 计数口径（K1 终裁，§7.4，唯一权威）：9 家真实 HTTP × 6 类（Chat/Stream/ListModels/401/429/Timeout）
// + 2 家 SDK *Fake × 3（Chat/Stream/ListModels）= 54 + 6 = 60；B 类 SFFake × 2（另见
// bclass/secretflow_contract_test.go）= 62。移动云骨架单独 1 项（contract 之外，见
// TestMobileCloudPending），不进 12 家（10 密态核心 + 2 非密态 HTTP）计数。
//
// 离线强制（§7.9 QA2-08~12）：TestMain 替换 http.DefaultTransport + net.DefaultResolver；
// 每个 provider 断言 Transport 为 *mock.OfflineTransport 且 Endpoint 为 127.0.0.1；运行后
// 断言 EgressAttempts()==0；负向用例显式断言错误含 "offline guard"。
//
// golden request（§7.4 QA2-13/14）：捕获实际出站 method/path/header/body，比对
// fixtures/<provider>_golden_request.json（含 NEAR /v1/model/list 真实路径锁定）。
package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"security-ai-gateway/gateway/confllm-adapter"
	"security-ai-gateway/gateway/confllm-adapter/mock"
	bclass "security-ai-gateway/gateway/confllm-adapter/providers/bclass"
)

// TestMain 真·断网（§7.9-3）：替换 DefaultTransport 与 DNS Resolver，运行后断言零出网。
func TestMain(m *testing.M) {
	origTransport := http.DefaultTransport
	origResolver := net.DefaultResolver
	http.DefaultTransport = mock.NewOfflineTransport()
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			return nil, errors.New("offline guard: DNS 被禁止")
		},
	}
	mock.ResetEgressAttempts()
	code := m.Run()
	http.DefaultTransport = origTransport
	net.DefaultResolver = origResolver
	if got := mock.EgressAttempts(); got != 0 {
		fmt.Fprintf(os.Stderr, "[offline guard] 断言失败：EgressAttempts=%d（应为 0；负向用例须自 Reset）\n", got)
		os.Exit(1)
	}
	os.Exit(code)
}

// endpointRE loopback 断言（§7.9-4）。
var endpointRE = regexp.MustCompile(`^http://127\.0\.0\.1:\d+$`)

// offlineClient 构造离线 http.Client（scenario 非空时注入 X-Mock-Scenario 驱动 mock fixture）。
func offlineClient(scenario string) *http.Client {
	return &http.Client{Transport: mock.NewOfflineScenarioTransport(scenario)}
}

// buildProvider 构造 HTTP 型厂商（离线 client + 可选 static 凭据 seam）。
func buildProvider(t *testing.T, factory confllm.ProviderFactory, endpoint, scenario string, withCred bool) confllm.ConfidentialLLMProvider {
	t.Helper()
	opts := []confllm.ProviderOption{confllm.WithHTTPClient(offlineClient(scenario))}
	if withCred {
		opts = append(opts, confllm.WithStaticCredential(&confllm.Credential{Key: []byte("test-key")}))
	}
	p, err := factory(confllm.ProviderConfig{ID: "test", Endpoint: endpoint}, opts...)
	if err != nil {
		t.Fatalf("构造 provider 失败：%v", err)
	}
	return p
}

// assertOfflineTransport 断言 Transport 为 *mock.OfflineTransport 且 Endpoint 为 loopback（§7.9-4）。
func assertOfflineTransport(t *testing.T, p confllm.ConfidentialLLMProvider, endpoint string) {
	t.Helper()
	type clientProvider interface{ HTTPClient() *http.Client }
	cp, ok := p.(clientProvider)
	if !ok {
		t.Fatalf("provider 未暴露 HTTPClient（无法断言离线 transport）")
	}
	if _, ok := cp.HTTPClient().Transport.(*mock.OfflineTransport); !ok {
		t.Fatalf("provider Transport 必须为 *mock.OfflineTransport，实际 %T", cp.HTTPClient().Transport)
	}
	if !endpointRE.MatchString(endpoint) {
		t.Fatalf("ProviderConfig.Endpoint 必须匹配 %s，实际 %q", endpointRE.String(), endpoint)
	}
}

// httpProviderCase 9 家真实 HTTP 厂商（含 K1 双服务裁决的 2 枚非密态 HTTP：aliyun-bailian / huawei-maas）。
type httpProviderCase struct {
	name    string
	factory confllm.ProviderFactory
	golden  string
}

func httpProviderCases() []httpProviderCase {
	return []httpProviderCase{
		{"tencent", NewTencentProvider, "tencent"},
		{"volcengine", NewVolcengineProvider, "volcengine"},
		{"nearai", NewNEARAIProvider, "nearai"},
		{"privatemode", NewPrivatemodeProvider, "privatemode"},
		{"azure", NewAzureProvider, "azure"},
		{"gcp", NewGCPProvider, "gcp"},
		{"aws", NewAWSProvider, "aws"},
		{"aliyun-bailian", NewAliyunBailianProvider, "aliyun-bailian"},
		{"huawei-maas", NewHuaweiMaaSProvider, "huawei-maas"},
	}
}

// TestContractMatrix 9 家真实 HTTP × 6 类（每家每方法均断言，§7.4 QA2-15；K1 终裁计数 54 项）。
func TestContractMatrix(t *testing.T) {
	k := mock.NewKernel(nil)
	defer k.Close()
	newReq := func() *confllm.ChatRequest {
		return &confllm.ChatRequest{Model: "m", Messages: []confllm.Message{{Role: "user", Content: "hi"}}}
	}
	for _, pc := range httpProviderCases() {
		pc := pc
		t.Run(pc.name, func(t *testing.T) {
			// 1) Chat（chat_ok）
			p := buildProvider(t, pc.factory, k.URL(), "chat_ok", true)
			assertOfflineTransport(t, p, k.URL())
			resp, err := p.Chat(context.Background(), newReq())
			if err != nil {
				t.Fatalf("Chat 失败：%v", err)
			}
			if len(resp.Choices) == 0 || resp.Choices[0].Message.Content != "hello from mock" {
				t.Fatalf("Chat 内容不符：%+v", resp)
			}

			// 2) Stream（chat_stream）
			ps := buildProvider(t, pc.factory, k.URL(), "chat_stream", true)
			sr, err := ps.Stream(context.Background(), &confllm.ChatRequest{Model: "m", Stream: true})
			if err != nil {
				t.Fatalf("Stream 失败：%v", err)
			}
			n := 0
			for {
				_, e := sr.Next()
				if e == io.EOF {
					break
				}
				if e != nil {
					t.Fatalf("Stream Next 失败：%v", e)
				}
				n++
			}
			_ = sr.Close()
			if n != 2 {
				t.Fatalf("Stream 期望 2 帧，实际 %d", n)
			}

			// 3) ListModels（list）
			pl := buildProvider(t, pc.factory, k.URL(), "", true)
			assertOfflineTransport(t, pl, k.URL())
			models, err := pl.ListModels(context.Background())
			if err != nil {
				t.Fatalf("ListModels 失败：%v", err)
			}
			if len(models) != 1 || models[0].ID != "mock-model" {
				t.Fatalf("ListModels 不符：%v", models)
			}

			// 4) 401（auth_401）
			expectChatErrorCode(t, pc.factory, k.URL(), "auth_401", confllm.CodeUnauthorized, true)
			// 5) 429（rate_429）
			expectChatErrorCode(t, pc.factory, k.URL(), "rate_429", confllm.CodeRateLimited, true)
			// 6) Timeout（timeout + 短 ctx）
			pt := buildProvider(t, pc.factory, k.URL(), "timeout", true)
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if _, err := pt.Chat(ctx, newReq()); err == nil {
				t.Fatal("Timeout 期望错误")
			} else if code := confllm.ParseError(err).Code; code != confllm.CodeUpstreamTimeout {
				t.Fatalf("Timeout 期望 upstream_timeout，实际 %s", code)
			}
		})
	}
}

func expectChatErrorCode(t *testing.T, factory confllm.ProviderFactory, endpoint, scenario, wantCode string, withCred bool) {
	t.Helper()
	p := buildProvider(t, factory, endpoint, scenario, withCred)
	_, err := p.Chat(context.Background(), &confllm.ChatRequest{Model: "m", Messages: []confllm.Message{{Role: "user", Content: "hi"}}})
	if err == nil {
		t.Fatalf("[%s] 期望错误 %s，返回 nil", scenario, wantCode)
	}
	if code := confllm.ParseError(err).Code; code != wantCode {
		t.Fatalf("[%s] 期望 %s，实际 %s（%v）", scenario, wantCode, code, err)
	}
}

// goldenMessage / goldenRequest 与 fixtures/<provider>_golden_request.json 对齐。
type goldenMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type goldenRequest struct {
	DocURL              string          `json:"docURL"`
	RetrievedAt         string          `json:"retrievedAt"`
	Version             string          `json:"version"`
	Method              string          `json:"method"`
	ChatPath            string          `json:"chatPath"`
	ModelsPath          string          `json:"modelsPath"`
	ContentType         string          `json:"contentType"`
	AuthorizationScheme string          `json:"authorizationScheme"`
	Model               string          `json:"model"`
	Stream              bool            `json:"stream"`
	Messages            []goldenMessage `json:"messages"`
}

func loadGolden(t *testing.T, name string) goldenRequest {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "fixtures", name+"_golden_request.json"))
	if err != nil {
		t.Fatalf("读取 golden 失败：%v", err)
	}
	var g goldenRequest
	if err := json.Unmarshal(raw, &g); err != nil {
		t.Fatalf("解析 golden 失败：%v", err)
	}
	if g.DocURL == "" || g.RetrievedAt == "" {
		t.Fatalf("golden 缺少 docURL/retrievedAt：%s", name)
	}
	return g
}

type capturedReq struct {
	Method      string
	Path        string
	ContentType string
	Auth        string
	Body        []byte
}

// TestGoldenRequests 捕获实际出站请求比对 golden（路径锁定，NEAR /v1/model/list 反例，§7.4）。
func TestGoldenRequests(t *testing.T) {
	for _, pc := range httpProviderCases() {
		pc := pc
		t.Run(pc.name, func(t *testing.T) {
			g := loadGolden(t, pc.golden)
			var (
				mu   sync.Mutex
				last capturedReq
			)
			capture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				mu.Lock()
				last = capturedReq{
					Method:      r.Method,
					Path:        r.URL.Path,
					ContentType: r.Header.Get("Content-Type"),
					Auth:        r.Header.Get("Authorization"),
					Body:        body,
				}
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				if r.Method == http.MethodGet {
					_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"m1","owned_by":"p"}]}`))
					return
				}
				_, _ = w.Write([]byte(`{"id":"c","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"x"},"finish_reason":"stop"}],"usage":{}}`))
			}))
			defer capture.Close()

			p := buildProvider(t, pc.factory, capture.URL, "", true)
			assertOfflineTransport(t, p, capture.URL)

			// Chat：method/path/content-type/auth/body.
			if _, err := p.Chat(context.Background(), &confllm.ChatRequest{
				Model:    g.Model,
				Stream:   g.Stream,
				Messages: toMessages(g.Messages),
			}); err != nil {
				t.Fatalf("Chat 失败：%v", err)
			}
			mu.Lock()
			chatReq := last
			mu.Unlock()
			if chatReq.Method != g.Method {
				t.Fatalf("Chat method=%s 期望 %s", chatReq.Method, g.Method)
			}
			if chatReq.Path != g.ChatPath {
				t.Fatalf("Chat path=%s 期望 %s（golden 锁定真实路径）", chatReq.Path, g.ChatPath)
			}
			if chatReq.ContentType != g.ContentType {
				t.Fatalf("Content-Type=%q 期望 %q", chatReq.ContentType, g.ContentType)
			}
			if !strings.HasPrefix(chatReq.Auth, g.AuthorizationScheme+" ") {
				t.Fatalf("Authorization=%q 期望 %s 前缀", chatReq.Auth, g.AuthorizationScheme)
			}
			var sent struct {
				Model    string          `json:"model"`
				Stream   bool            `json:"stream"`
				Messages []goldenMessage `json:"messages"`
			}
			if err := json.Unmarshal(chatReq.Body, &sent); err != nil {
				t.Fatalf("请求体非法 JSON：%s", string(chatReq.Body))
			}
			if sent.Model != g.Model || sent.Stream != g.Stream {
				t.Fatalf("body model/stream 不符：%+v", sent)
			}
			if len(sent.Messages) != len(g.Messages) || sent.Messages[0].Content != g.Messages[0].Content {
				t.Fatalf("body messages 不符：%+v", sent.Messages)
			}

			// ListModels：锁定真实 modelsPath（NEAR /v1/model/list 反例）。
			if _, err := p.ListModels(context.Background()); err != nil {
				t.Fatalf("ListModels 失败：%v", err)
			}
			mu.Lock()
			listReq := last
			mu.Unlock()
			if listReq.Path != g.ModelsPath {
				t.Fatalf("ListModels path=%s 期望 %s（golden 锁定真实路径，§7.4）", listReq.Path, g.ModelsPath)
			}
		})
	}
}

func toMessages(g []goldenMessage) []confllm.Message {
	out := make([]confllm.Message, 0, len(g))
	for _, m := range g {
		out = append(out, confllm.Message{Role: m.Role, Content: m.Content})
	}
	return out
}

// sdkFake SDK 型 Fake 公共形态（VendorSDKClient + SetFail）。
type sdkFake interface {
	confllm.VendorSDKClient
	SetFail(bool)
}

func assertSDKFake(t *testing.T, p confllm.ConfidentialLLMProvider, fake sdkFake) {
	t.Helper()
	// Chat
	resp, err := p.Chat(context.Background(), &confllm.ChatRequest{Model: "m"})
	if err != nil {
		t.Fatalf("fake Chat 失败：%v", err)
	}
	if !strings.HasPrefix(resp.ID, "fake-") {
		t.Fatalf("fake Chat id 不符：%s", resp.ID)
	}
	// Stream
	sr, err := p.Stream(context.Background(), &confllm.ChatRequest{Model: "m"})
	if err != nil {
		t.Fatalf("fake Stream 失败：%v", err)
	}
	n := 0
	for {
		_, e := sr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatalf("fake Stream Next 失败：%v", e)
		}
		n++
	}
	_ = sr.Close()
	if n != 2 {
		t.Fatalf("fake Stream 期望 2 帧，实际 %d", n)
	}
	// ListModels
	models, err := p.ListModels(context.Background())
	if err != nil {
		t.Fatalf("fake ListModels 失败：%v", err)
	}
	if len(models) != 1 {
		t.Fatalf("fake ListModels 期望 1，实际 %d", len(models))
	}
	// 强失败路径
	fake.SetFail(true)
	if _, err := p.Chat(context.Background(), &confllm.ChatRequest{Model: "m"}); err == nil {
		t.Fatal("fake fail 模式应返回错误")
	}
}

// TestSDKFakeContracts 2 家 SDK *Fake × 3（Chat/Stream/ListModels）+ 强失败（§7.4）。
func TestSDKFakeContracts(t *testing.T) {
	t.Run("aliyun", func(t *testing.T) {
		fake := NewAliyunConfidentialClientFake()
		p, err := NewAliyunProvider(confllm.ProviderConfig{ID: "aliyun"}, confllm.WithSDKClient(fake))
		if err != nil {
			t.Fatal(err)
		}
		assertSDKFake(t, p, fake)
	})
	t.Run("huaweicloud", func(t *testing.T) {
		fake := NewHuaweiConfidentialClientFake()
		p, err := NewHuaweiProvider(confllm.ProviderConfig{ID: "huaweicloud"}, confllm.WithSDKClient(fake))
		if err != nil {
			t.Fatal(err)
		}
		assertSDKFake(t, p, fake)
	})
}

// TestDefaultMetaUnknown 逐家穷举缺省（§7.5 QA2-03）：9 家 A 类 managed/自建默认 unknown；
// B 类 SecretFlow 为密码学密态，默认 Class=B（§1.5），但同样未验证（IsVerified 恒 false）。
func TestDefaultMetaUnknown(t *testing.T) {
	cases := []struct {
		name      string
		wantClass string
		meta      func(t *testing.T) confllm.ConfidentialityMeta
	}{
		{"tencent", "unknown", func(t *testing.T) confllm.ConfidentialityMeta { return mustMeta(t, NewTencentProvider) }},
		{"volcengine", "unknown", func(t *testing.T) confllm.ConfidentialityMeta { return mustMeta(t, NewVolcengineProvider) }},
		{"nearai", "unknown", func(t *testing.T) confllm.ConfidentialityMeta { return mustMeta(t, NewNEARAIProvider) }},
		{"privatemode", "unknown", func(t *testing.T) confllm.ConfidentialityMeta { return mustMeta(t, NewPrivatemodeProvider) }},
		{"azure", "unknown", func(t *testing.T) confllm.ConfidentialityMeta { return mustMeta(t, NewAzureProvider) }},
		{"gcp", "unknown", func(t *testing.T) confllm.ConfidentialityMeta { return mustMeta(t, NewGCPProvider) }},
		{"aws", "unknown", func(t *testing.T) confllm.ConfidentialityMeta { return mustMeta(t, NewAWSProvider) }},
		{"aliyun", "unknown", func(t *testing.T) confllm.ConfidentialityMeta {
			p, err := NewAliyunProvider(confllm.ProviderConfig{ID: "aliyun"}, confllm.WithSDKClient(NewAliyunConfidentialClientFake()))
			if err != nil {
				t.Fatal(err)
			}
			return p.Metadata()
		}},
		{"huaweicloud", "unknown", func(t *testing.T) confllm.ConfidentialityMeta {
			p, err := NewHuaweiProvider(confllm.ProviderConfig{ID: "huaweicloud"}, confllm.WithSDKClient(NewHuaweiConfidentialClientFake()))
			if err != nil {
				t.Fatal(err)
			}
			return p.Metadata()
		}},
		{"secretflow(B)", "B", func(t *testing.T) confllm.ConfidentialityMeta {
			return bclass.NewSecretFlowProvider("sf", bclass.NewSFBridge("", "", nil)).Metadata()
		}},
	}
	if len(cases) != 10 {
		t.Fatalf("默认缺省穷举应为 10 家，实际 %d", len(cases))
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			m := c.meta(t)
			if m.ConfidentialityClass != c.wantClass {
				t.Fatalf("%s 默认 class=%q 期望 %q", c.name, m.ConfidentialityClass, c.wantClass)
			}
			if m.IsVerified() {
				t.Fatalf("%s 默认不应 verified（引用≠已验证）", c.name)
			}
		})
	}
}

func mustMeta(t *testing.T, factory confllm.ProviderFactory) confllm.ConfidentialityMeta {
	t.Helper()
	p, err := factory(confllm.ProviderConfig{ID: "x"},
		confllm.WithHTTPClient(offlineClient("")),
		confllm.WithStaticCredential(&confllm.Credential{Key: []byte("k")}))
	if err != nil {
		t.Fatalf("构造 provider 失败：%v", err)
	}
	return p.Metadata()
}

// TestMobileCloudPending 移动云骨架（第 11，仅 1 项 pending，不进 10 家计数，§7.4）。
func TestMobileCloudPending(t *testing.T) {
	p, err := NewMobileCloudProvider(confllm.ProviderConfig{ID: "mobilecloud"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Chat(context.Background(), &confllm.ChatRequest{Model: "m"})
	if err == nil {
		t.Fatal("移动云骨架应返回 pending-credential")
	}
	pe := confllm.ParseError(err)
	if pe.Code != confllm.CodePendingCredential || pe.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("移动云期望 pending_credential/503，实际 %s/%d", pe.Code, pe.HTTPStatus)
	}
	if !p.Health(context.Background()).PendingCredential {
		t.Fatal("移动云 Health 应标记 pending-credential")
	}
}

// TestOfflineGuardRejectsNonLoopback 负向用例（§7.9-5）：错误必须含 "offline guard"。
func TestOfflineGuardRejectsNonLoopback(t *testing.T) {
	tr := mock.NewOfflineTransport()
	req, err := http.NewRequest("GET", "http://10.0.0.1/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = tr.RoundTrip(req)
	if err == nil || !strings.Contains(err.Error(), "offline guard") {
		t.Fatalf("应被离线保护拒绝且错误含 offline guard：%v", err)
	}
	mock.ResetEgressAttempts() // 负向用例不计入 TestMain 的 EgressAttempts==0 断言
}
