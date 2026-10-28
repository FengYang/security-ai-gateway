package confllm

// handler_graphs_test — B 类任务式推理端点（D2）验收测试。
//
// 纪律：
//   - 离线（P0-5）：仅 httptest，无真实网络；不触 http.DefaultTransport / net.DefaultResolver；
//   - 本地 fake provider（同时实现 ConfidentialLLMProvider 与 GraphProvider），不依赖 bclass 子包；
//   - 覆盖：① 提交 202 ② 轮询四态 wire 形态（result/error 省略规则）③ A 类打 graphs → 422
//     ④ B 类打 chat/stream → 422 且 Chat/Stream 未被调用（计数断言）⑤ 缺 provider → 400
//     ⑥ 凭据不进响应体（轻量）。
//     另含 405 方法门禁与「轮询调用失败 ≠ 任务失败」语义断言。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/confllm-adapter/meta"
)

// graphsFake B 类任务式 fake：同时实现 ConfidentialLLMProvider 与 GraphProvider；
// Chat/Stream 带调用计数（断言 B 类绝不进 chat/stream）。
//
// PollGraphJSON 遵循与 bclass 相同的约定：status 非空 + err 非 nil ⇒ 任务级失败详情；
// status 为空 + err 非 nil ⇒ 轮询调用本身失败。
type graphsFake struct {
	id          string
	apiKey      string // 伪凭据 canary 载体（P0-4 轻量断言用）
	chatCalls   int
	streamCalls int
	submitted   []json.RawMessage
	submitErr   error
	pollJobID   string
	pollStatus  string
	pollOut     json.RawMessage
	pollErr     error
}

func (p *graphsFake) ID() string     { return p.id }
func (p *graphsFake) Region() Region { return RegionDomestic }
func (p *graphsFake) Metadata() ConfidentialityMeta {
	return ConfidentialityMeta{ConfidentialityClass: meta.ClassB}
}
func (p *graphsFake) Capabilities() Capabilities {
	return Capabilities{Protocols: []string{"secretflow-graph"}}
}
func (p *graphsFake) ListModels(context.Context) ([]ModelInfo, error) {
	return nil, nil
}
func (p *graphsFake) Health(context.Context) HealthStatus {
	return HealthStatus{Ready: true, MinConfidentialityClass: meta.ClassB}
}

func (p *graphsFake) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	p.chatCalls++
	return &ChatResponse{ID: "t", Object: "chat.completion", Model: req.Model}, nil
}

func (p *graphsFake) Stream(ctx context.Context, req *ChatRequest) (StreamReader, error) {
	p.streamCalls++
	return graphsEOFStream{}, nil
}

func (p *graphsFake) SubmitGraphJSON(ctx context.Context, spec json.RawMessage) (string, error) {
	p.submitted = append(p.submitted, spec)
	if p.submitErr != nil {
		return "", p.submitErr
	}
	return "job-" + p.id, nil
}

func (p *graphsFake) PollGraphJSON(ctx context.Context, jobID string) (string, json.RawMessage, error) {
	p.pollJobID = jobID
	return p.pollStatus, p.pollOut, p.pollErr
}

// graphsEOFStream 防 Stream 被错误调用时 nil 解引用（正常路径绝不触达）。
type graphsEOFStream struct{}

func (graphsEOFStream) Next() (*StreamChunk, error) { return nil, io.EOF }
func (graphsEOFStream) Close() error                { return nil }

// aclassFake 仅实现 ConfidentialLLMProvider 的 A 类 fake（chat 式，无 GraphProvider）。
type aclassFake struct {
	id string
}

func (p *aclassFake) ID() string     { return p.id }
func (p *aclassFake) Region() Region { return RegionDomestic }
func (p *aclassFake) Metadata() ConfidentialityMeta {
	return ConfidentialityMeta{ConfidentialityClass: meta.ClassA}
}
func (p *aclassFake) Capabilities() Capabilities { return Capabilities{} }
func (p *aclassFake) Chat(ctx context.Context, req *ChatRequest) (*ChatResponse, error) {
	return &ChatResponse{ID: "t", Object: "chat.completion", Model: req.Model}, nil
}
func (p *aclassFake) Stream(ctx context.Context, req *ChatRequest) (StreamReader, error) {
	return graphsEOFStream{}, nil
}
func (p *aclassFake) ListModels(context.Context) ([]ModelInfo, error) { return nil, nil }
func (p *aclassFake) Health(context.Context) HealthStatus             { return HealthStatus{Ready: true} }

func newGraphsHandler(providers ...ConfidentialLLMProvider) *ConfllmHandler {
	reg := NewRegistry()
	for _, p := range providers {
		reg.Register(p)
	}
	return NewConfllmHandler(reg)
}

// graphsResultMux 轮询端点经 ServeMux 路由（HandleGraphResult 用 r.PathValue("jobID")，
// 只有经 pattern 路由的请求才能取到路径参数）。不注册方法前缀，让 handler 内 405 门禁可被测到。
func graphsResultMux(h *ConfllmHandler) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/confllm/graphs/{jobID}", h.HandleGraphResult)
	mux.HandleFunc("/v1/confllm/{id}/graphs/{jobID}", h.HandleGraphResult)
	mux.HandleFunc("/v1/confllm/graphs", h.HandleGraphSubmit)
	mux.HandleFunc("/v1/confllm/chat/completions", h.HandleChat)
	mux.HandleFunc("/v1/confllm/stream/chat/completions", h.HandleStream)
	return mux
}

func doJSON(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, rdr)
	h.ServeHTTP(rec, req)
	return rec
}

// decodeErrCode 解析 writeErr 形态 {"error":{"code":...}}。
func decodeErrCode(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("响应非合法 JSON：%v\n%s", err, rec.Body.String())
	}
	if e, ok := body["error"].(map[string]any); ok {
		code, _ := e["code"].(string)
		return code
	}
	return ""
}

// ① POST 提交成功 202 + job_id 回显（query 与路径两种 provider 提取均覆盖）。
func TestHandlerGraphSubmitOK(t *testing.T) {
	f := &graphsFake{id: "g1"}
	h := newGraphsHandler(f)
	submit := http.HandlerFunc(h.HandleGraphSubmit)

	// query ?provider=
	rec := doJSON(t, submit, http.MethodPost, "/v1/confllm/graphs?provider=g1", `{"name":"flow","dag":{"op":"x"}}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("提交期望 202，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var out graphSubmitResp
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("提交响应非法：%v", err)
	}
	if out.JobID != "job-g1" {
		t.Fatalf("job_id 回显=%q 期望 job-g1", out.JobID)
	}
	if len(f.submitted) != 1 || !strings.Contains(string(f.submitted[0]), `"name":"flow"`) {
		t.Fatalf("图规格未透传到 provider：%v", f.submitted)
	}

	// 路径 /v1/confllm/{id}/graphs
	rec2 := doJSON(t, submit, http.MethodPost, "/v1/confllm/g1/graphs", `{"name":"flow2","dag":{}}`)
	if rec2.Code != http.StatusAccepted {
		t.Fatalf("路径式提交期望 202，实际 %d：%s", rec2.Code, rec2.Body.String())
	}
	if len(f.submitted) != 2 {
		t.Fatalf("路径式提交未达 provider，submitted=%d", len(f.submitted))
	}

	// 空 body / 非 object / 非法 JSON → 400 invalid_request。
	for _, c := range []struct{ name, body string }{
		{"empty", ""},
		{"null", "null"},
		{"array", `[1,2]`},
		{"bad", `{invalid`},
	} {
		rec3 := doJSON(t, submit, http.MethodPost, "/v1/confllm/graphs?provider=g1", c.body)
		if rec3.Code != http.StatusBadRequest {
			t.Fatalf("[%s] 期望 400，实际 %d", c.name, rec3.Code)
		}
		if code := decodeErrCode(t, rec3); code != CodeInvalidRequest {
			t.Fatalf("[%s] 期望 invalid_request，实际 %q", c.name, code)
		}
	}
}

// ② GET 轮询 pending/running/done/failed 四态 wire 形态（含 result/error 省略规则）。
func TestHandlerGraphResultWireStates(t *testing.T) {
	cases := []struct {
		name       string
		status     string
		out        json.RawMessage
		err        error
		wantResult bool
		wantError  string // 非空 ⇒ 期望 error 字段等于该值
	}{
		{"pending", GraphStatusPending, nil, nil, false, ""},
		{"running", GraphStatusRunning, nil, nil, false, ""},
		{"done", GraphStatusDone, json.RawMessage(`{"answer":42}`), nil, true, ""},
		{"failed", GraphStatusFailed, nil, NewProviderError(CodeUpstreamError, http.StatusBadGateway, "task exploded"), false, "task exploded"},
		{"failed-with-partial-output", GraphStatusFailed, json.RawMessage(`{"partial":1}`), NewProviderError(CodeUpstreamError, http.StatusBadGateway, "task exploded"), true, "task exploded"},
	}
	for _, c := range cases {
		f := &graphsFake{
			id:         "g1",
			pollStatus: c.status,
			pollOut:    c.out,
			pollErr:    c.err,
		}
		h := newGraphsHandler(f)
		mux := graphsResultMux(h)

		rec := doJSON(t, mux, http.MethodGet, "/v1/confllm/graphs/job-9?provider=g1", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("[%s] 期望 200，实际 %d：%s", c.name, rec.Code, rec.Body.String())
		}
		var wire graphResultResp
		if err := json.Unmarshal(rec.Body.Bytes(), &wire); err != nil {
			t.Fatalf("[%s] wire 解析失败：%v", c.name, err)
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(rec.Body.Bytes(), &fields)

		if wire.JobID != "job-9" {
			t.Fatalf("[%s] job_id=%q 期望 job-9", c.name, wire.JobID)
		}
		if wire.Status != c.status {
			t.Fatalf("[%s] status=%q 期望 %q（透传归一化状态）", c.name, wire.Status, c.status)
		}
		_, hasResult := fields["result"]
		if hasResult != c.wantResult {
			t.Fatalf("[%s] result 键存在=%v 期望 %v（omitempty 规则）", c.name, hasResult, c.wantResult)
		}
		_, hasError := fields["error"]
		if c.wantError == "" && hasError {
			t.Fatalf("[%s] 非失败态不得出现 error 字段：%s", c.name, rec.Body.String())
		}
		if c.wantError != "" {
			if !hasError {
				t.Fatalf("[%s] 失败态必须携带 error 字段：%s", c.name, rec.Body.String())
			}
			if wire.Error != c.wantError {
				t.Fatalf("[%s] error=%q 期望 %q", c.name, wire.Error, c.wantError)
			}
		}
		if f.pollJobID != "job-9" {
			t.Fatalf("[%s] provider 收到 jobID=%q 期望 job-9", c.name, f.pollJobID)
		}
	}
}

// ②补「轮询调用失败 ≠ 任务失败」：status 为空 + err → writeErr 归一化（非 200 wire）。
func TestHandlerGraphResultPollFailure(t *testing.T) {
	f := &graphsFake{id: "g1", pollErr: NewProviderError(CodePendingCredential, http.StatusServiceUnavailable, "隐语桥接未配置")}
	h := newGraphsHandler(f)
	mux := graphsResultMux(h)

	rec := doJSON(t, mux, http.MethodGet, "/v1/confllm/graphs/job-9?provider=g1", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("轮询调用失败期望 503，实际 %d", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != CodePendingCredential {
		t.Fatalf("期望 pending_credential，实际 %q", code)
	}
}

// ③ A 类 provider（只实现 ConfidentialLLMProvider）打 graphs 端点 → 422 unsupported_capability。
func TestHandlerGraphsRejectsAclass(t *testing.T) {
	f := &aclassFake{id: "a1"}
	h := newGraphsHandler(f)
	mux := graphsResultMux(h)

	rec := doJSON(t, mux, http.MethodPost, "/v1/confllm/graphs?provider=a1", `{"name":"g","dag":{}}`)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("A 类打提交端点期望 422，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != CodeUnsupportedCapability {
		t.Fatalf("期望 unsupported_capability，实际 %q", code)
	}

	rec2 := doJSON(t, mux, http.MethodGet, "/v1/confllm/graphs/job-1?provider=a1", "")
	if rec2.Code != http.StatusUnprocessableEntity {
		t.Fatalf("A 类打轮询端点期望 422，实际 %d", rec2.Code)
	}
	if code := decodeErrCode(t, rec2); code != CodeUnsupportedCapability {
		t.Fatalf("期望 unsupported_capability，实际 %q", code)
	}
}

// ④ B 类 provider 打 chat/stream → 422 unsupported_capability，且 Chat/Stream 未被调用（计数断言）。
func TestHandlerChatRejectsGraphProvider(t *testing.T) {
	f := &graphsFake{id: "g1"}
	h := newGraphsHandler(f)
	mux := graphsResultMux(h)

	chatBody := `{"model":"m","messages":[{"role":"user","content":"hi"}]}`
	rec := doJSON(t, mux, http.MethodPost, "/v1/confllm/chat/completions?provider=g1", chatBody)
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("B 类打 chat 期望 422，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if code := decodeErrCode(t, rec); code != CodeUnsupportedCapability {
		t.Fatalf("chat 期望 unsupported_capability，实际 %q", code)
	}

	rec2 := doJSON(t, mux, http.MethodPost, "/v1/confllm/stream/chat/completions?provider=g1", chatBody)
	if rec2.Code != http.StatusUnprocessableEntity {
		t.Fatalf("B 类打 stream 期望 422，实际 %d：%s", rec2.Code, rec2.Body.String())
	}
	if code := decodeErrCode(t, rec2); code != CodeUnsupportedCapability {
		t.Fatalf("stream 期望 unsupported_capability，实际 %q", code)
	}

	if f.chatCalls != 0 || f.streamCalls != 0 {
		t.Fatalf("B 类 Chat/Stream 绝不可被调用：chatCalls=%d streamCalls=%d", f.chatCalls, f.streamCalls)
	}
}

// ⑤ 缺 provider → 400 invalid_request（提交与轮询两条路径）。
func TestHandlerGraphsMissingProvider(t *testing.T) {
	h := newGraphsHandler(&graphsFake{id: "g1"})
	mux := graphsResultMux(h)

	rec := doJSON(t, mux, http.MethodPost, "/v1/confllm/graphs", `{"name":"g","dag":{}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 provider 提交期望 400，实际 %d", rec.Code)
	}
	if code := decodeErrCode(t, rec); code != CodeInvalidRequest {
		t.Fatalf("期望 invalid_request，实际 %q", code)
	}

	rec2 := doJSON(t, mux, http.MethodGet, "/v1/confllm/graphs/job-1", "")
	if rec2.Code != http.StatusBadRequest {
		t.Fatalf("缺 provider 轮询期望 400，实际 %d", rec2.Code)
	}
	if code := decodeErrCode(t, rec2); code != CodeInvalidRequest {
		t.Fatalf("期望 invalid_request，实际 %q", code)
	}
}

// ⑥ 凭据/敏感信息不进响应体（轻量断言；完整 P0-4 见 credential_leak_test.go）。
func TestHandlerGraphsNoCredentialLeak(t *testing.T) {
	const canary = "SECRET_CANARY_9f3a"
	f := &graphsFake{
		id:        "g1",
		apiKey:    canary,
		submitErr: NewProviderError(CodeUpstreamError, http.StatusBadGateway, "隐语 HTTP 提交失败"),
	}
	h := newGraphsHandler(f)
	mux := graphsResultMux(h)

	// 成功路径。
	f.submitErr = nil
	recOK := doJSON(t, mux, http.MethodPost, "/v1/confllm/graphs?provider=g1", `{"name":"g","dag":{}}`)
	// 失败路径。
	f.submitErr = NewProviderError(CodeUpstreamError, http.StatusBadGateway, "隐语 HTTP 提交失败")
	recErr := doJSON(t, mux, http.MethodPost, "/v1/confllm/graphs?provider=g1", `{"name":"g","dag":{}}`)
	// 轮询路径。
	f.pollStatus = GraphStatusDone
	f.pollOut = json.RawMessage(`{"answer":1}`)
	recPoll := doJSON(t, mux, http.MethodGet, "/v1/confllm/graphs/job-1?provider=g1", "")

	for _, c := range []struct {
		name string
		rec  *httptest.ResponseRecorder
	}{
		{"submit-ok", recOK},
		{"submit-err", recErr},
		{"poll", recPoll},
	} {
		body := c.rec.Body.String()
		if strings.Contains(body, canary) {
			t.Fatalf("[%s] 响应体泄漏凭据 canary：%s", c.name, body)
		}
		if strings.Contains(body, "Authorization") || strings.Contains(body, "Bearer ") {
			t.Fatalf("[%s] 响应体泄漏凭据头形态：%s", c.name, body)
		}
	}
}

// 405 方法门禁：提交仅 POST、轮询仅 GET。
func TestHandlerGraphsMethodNotAllowed(t *testing.T) {
	h := newGraphsHandler(&graphsFake{id: "g1"})
	mux := graphsResultMux(h)

	rec := doJSON(t, mux, http.MethodGet, "/v1/confllm/graphs?provider=g1", "")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET 打提交端点期望 405，实际 %d", rec.Code)
	}

	rec2 := doJSON(t, mux, http.MethodPost, "/v1/confllm/graphs/job-1?provider=g1", "")
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST 打轮询端点期望 405，实际 %d", rec2.Code)
	}
}
