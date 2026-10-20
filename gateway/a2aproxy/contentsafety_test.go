package a2aproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/a2a"
)

// T-4 内容安全接入测试：Part 解析、动作（allow/deny/redact）、审计事件 a2a_content_action、
// 以及"请求侧检查必须在转发之前"这一关键时序约束。

// --- Part 解析 -------------------------------------------------------------

func TestExtractPartsKinds(t *testing.T) {
	raw := []byte(`{"params":{"message":{"parts":[
		{"kind":"text","text":"hello"},
		{"kind":"file","file":{"name":"a.txt","mimeType":"text/plain","uri":"https://x/a.txt","bytes":"aGVsbG8="}},
		{"kind":"data","data":{"k":1},"mimeType":"application/json"}
	]}}}`)
	parts, err := extractParts(raw)
	if err != nil {
		t.Fatalf("extractParts: %v", err)
	}
	if len(parts) != 3 {
		t.Fatalf("parts = %d, want 3 (%+v)", len(parts), parts)
	}
	if parts[0].Kind != PartKindText || parts[0].Text != "hello" {
		t.Errorf("text part = %+v", parts[0])
	}
	if parts[1].Kind != PartKindFile || parts[1].File.Name != "a.txt" || parts[1].File.MimeType != "text/plain" {
		t.Errorf("file meta = %+v", parts[1].File)
	}
	if parts[1].File.URI != "https://x/a.txt" {
		t.Errorf("file uri = %q（URL 形态经 file.uri 承载）", parts[1].File.URI)
	}
	if string(parts[1].File.Bytes) != "hello" {
		t.Errorf("file bytes = %q, want hello", parts[1].File.Bytes)
	}
	if parts[2].Kind != PartKindData || string(parts[2].Data) != `{"k":1}` {
		t.Errorf("data part = Kind=%s Data=%s", parts[2].Kind, parts[2].Data)
	}
}

// TestExtractPartsNested 覆盖 result/artifact/message 各级 parts 的递归收集：
// 内容安全层必须同时看到 direct task message 与 artifact 内的 parts。
func TestExtractPartsNested(t *testing.T) {
	raw := []byte(`{"result":{"kind":"task","id":"t-1",
		"status":{"message":{"parts":[{"kind":"text","text":"status"}]}},
		"artifacts":[{"artifactId":"ar-1","parts":[{"kind":"text","text":"artifact"}]}]}}`)
	parts, err := extractParts(raw)
	if err != nil {
		t.Fatalf("extractParts: %v", err)
	}
	if len(parts) != 2 {
		t.Fatalf("parts = %d, want 2 (%+v)", len(parts), parts)
	}
	// Go map 迭代顺序随机，parts 收集顺序不确定；安全检查对顺序不敏感，按集合断言。
	got := map[string]bool{}
	for _, p := range parts {
		if p.Kind != PartKindText {
			t.Errorf("kind = %s, want text", p.Kind)
		}
		got[p.Text] = true
	}
	if !got["status"] || !got["artifact"] {
		t.Errorf("嵌套 parts 收集不全: %+v", got)
	}
}

// TestExtractPartsNoParts 无 parts 或不可解析时不产出 Part（内容安全层不介入）。
func TestExtractPartsNoParts(t *testing.T) {
	if parts, err := extractParts([]byte(`{"result":{"id":"t-1"}}`)); err != nil || len(parts) != 0 {
		t.Errorf("无 parts: parts=%d err=%v, want 0/nil", len(parts), err)
	}
	if parts, err := extractParts(nil); err != nil || len(parts) != 0 {
		t.Errorf("空正文: parts=%d err=%v, want 0/nil", len(parts), err)
	}
	// 不可解析：返回错误，但调用方（checkParts）按放行处理，不阻断协议。
	if _, err := extractParts([]byte(`{not json`)); err == nil {
		t.Error("期望非法 JSON 返回错误")
	}
}

// --- 脱敏改写 --------------------------------------------------------------

func TestRedactParts(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"t-1","status":{"state":"TASK_STATE_COMPLETED"},
		"artifacts":[{"parts":[{"kind":"text","text":"secret answer"}]}]}}`)
	out := redactParts(raw)
	if len(out) == 0 {
		t.Fatal("redactParts 返回空")
	}
	s := string(out)
	if strings.Contains(s, "secret answer") {
		t.Fatalf("脱敏后仍含正文: %s", s)
	}
	// 非正文字段必须保留（审计/协议需要 id 与 state）。
	var decoded struct {
		ID     int `json:"id"`
		Result struct {
			ID     string `json:"id"`
			Status struct {
				State string `json:"state"`
			} `json:"status"`
			Artifacts []struct {
				Parts []json.RawMessage `json:"parts"`
			} `json:"artifacts"`
		} `json:"result"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("decode redacted: %v", err)
	}
	if decoded.ID != 1 || decoded.Result.ID != "t-1" || decoded.Result.Status.State != "TASK_STATE_COMPLETED" {
		t.Errorf("脱敏破坏了非正文字段: %+v", decoded)
	}
	if len(decoded.Result.Artifacts) != 1 || len(decoded.Result.Artifacts[0].Parts) != 1 {
		t.Fatalf("parts 结构异常: %+v", decoded.Result.Artifacts)
	}
	if !strings.Contains(string(decoded.Result.Artifacts[0].Parts[0]), "[REDACTED]") {
		t.Errorf("parts 未替换为 [REDACTED]: %s", decoded.Result.Artifacts[0].Parts[0])
	}
}

func TestRedactPartsInvalid(t *testing.T) {
	// 不可解析时返回 nil，由 checkResponseContent 升级为 deny（不得原文下发）。
	if got := redactParts([]byte(`{not json`)); got != nil {
		t.Errorf("非法 JSON 应返回 nil, got %s", got)
	}
	if got := redactParts(nil); got != nil {
		t.Errorf("空正文应返回 nil, got %s", got)
	}
}

// --- 默认实现 --------------------------------------------------------------

func TestDenyAllContentSafety(t *testing.T) {
	d, err := DenyAllContentSafety{}.Check(context.Background(), ContentCheckRequest{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if d.Action != ContentActionDeny {
		t.Errorf("action = %s, want deny", d.Action)
	}
}

func TestStaticContentSafetyNilCheckerAllows(t *testing.T) {
	// 未接线（集成前默认）：不介入，与 Governance.Observer 的 caller-supplied 模式对称。
	d, err := StaticContentSafety{}.Check(context.Background(), ContentCheckRequest{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if d.Action != ContentActionAllow {
		t.Errorf("action = %s, want allow", d.Action)
	}
}

// --- 检查侧：请求 / 响应 ----------------------------------------------------

func newTestProxy(t *testing.T, gov Governance) (*Proxy, *httptest.Server) {
	t.Helper()
	const tenant, agent = "tenant-a", "test-agent"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"t-1","status":{"state":"TASK_STATE_COMPLETED"},
			"artifacts":[{"parts":[{"kind":"text","text":"backend answer"}]}]}}`))
	}))
	t.Cleanup(backend.Close)

	snapshots := NewSnapshotStore()
	if err := snapshots.ForceReplace(&Snapshot{
		RegistryRevision: 1,
		Agents: []SnapshotAgent{{
			Tenant: tenant, Name: agent, Revision: 1,
			Card:            json.RawMessage(`{"name":"x","version":"1.0.0","description":"d","supportedInterfaces":[{"url":"http://gw/a2a/tenant-a/test-agent","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[{"id":"hello_world","name":"h","description":"d","tags":[]}],"signatures":[{"protected":"x","signature":"y"}]}`),
			BackendURL:      backend.URL,
			SignatureStatus: "valid",
		}},
	}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	p, err := New(Config{PublicMode: PublicModePath, GatewayPublicBase: "http://gw", DevAllowLoopback: true}, snapshots, gov)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	t.Cleanup(p.Close)
	srv := httptest.NewServer(p.Handler())
	t.Cleanup(srv.Close)
	return p, srv
}

// doProxySend 经代理发一条含 parts 的 SendMessage。
func doProxySend(t *testing.T, srv *httptest.Server, tenant, agent string) (*http.Response, []byte) {
	t.Helper()
	return doProxySendBody(t, srv, tenant, agent,
		`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"kind":"text","text":"hi"}]}}}`)
}

// doProxySendBody 经代理发送自定义请求体（用于构造无 parts 的请求）。
func doProxySendBody(t *testing.T, srv *httptest.Server, tenant, agent, body string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, srv.URL+"/a2a/"+tenant+"/"+agent, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	req.Header.Set("X-Test-Tenant", tenant)
	req.Header.Set(a2a.HeaderSkill, "hello_world")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return resp, raw
}

// TestContentSafetyRequestDenyBlocksBeforeBackend 是 T-4 的关键时序用例：
// 请求侧命中 deny 时**后端不得被调用**（原文不出网关）。
func TestContentSafetyRequestDenyBlocksBeforeBackend(t *testing.T) {
	var backendHits int
	const tenant, agent = "tenant-a", "test-agent"
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	}))
	defer backend.Close()

	snapshots := NewSnapshotStore()
	if err := snapshots.ForceReplace(&Snapshot{
		RegistryRevision: 1,
		Agents: []SnapshotAgent{{
			Tenant: tenant, Name: agent, Revision: 1,
			Card:            json.RawMessage(`{"name":"x","version":"1.0.0","description":"d","supportedInterfaces":[{"url":"http://gw/a2a/tenant-a/test-agent","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[{"id":"hello_world","name":"h","description":"d","tags":[]}],"signatures":[{"protected":"x","signature":"y"}]}`),
			BackendURL:      backend.URL,
			SignatureStatus: "valid",
		}},
	}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	gov := newTestGovernance()
	p, err := New(Config{PublicMode: PublicModePath, GatewayPublicBase: "http://gw", DevAllowLoopback: true}, snapshots, gov)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	defer p.Close()
	p.SetContentSafety(StaticContentSafety{Checker: func(_ context.Context, req ContentCheckRequest) (ContentCheckDecision, error) {
		if req.IsResponse {
			t.Errorf("请求被阻断时不应触发响应侧检查（req=%+v）", req)
		}
		return ContentCheckDecision{Action: ContentActionDeny, Tier: "standard", Reason: "bad word"}, nil
	}})
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	_, raw := doProxySend(t, srv, tenant, agent)
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode (%s): %v", raw, err)
	}
	if env.Error == nil || env.Error.Code != a2a.CodeContentBlocked {
		t.Fatalf("期望 content_blocked(%d)，实际: %s", a2a.CodeContentBlocked, raw)
	}
	if env.Error.Data == nil || !strings.Contains(string(env.Error.Data), a2a.ReasonContentBlocked) {
		t.Errorf("error.data 缺少 reason=%s: %s", a2a.ReasonContentBlocked, env.Error.Data)
	}
	if backendHits != 0 {
		t.Errorf("后端被调用 %d 次，请求侧 deny 必须在转发前拦截（不得外发原文）", backendHits)
	}
	evs := gov.recordedContentEvents()
	if len(evs) != 1 {
		t.Fatalf("审计事件 = %d, want 1", len(evs))
	}
	if evs[0].Action != "deny" || evs[0].Result != "blocked" || evs[0].Tier != "standard" {
		t.Errorf("审计事件 = %+v", evs[0])
	}
	if evs[0].Tenant != tenant || evs[0].Agent != agent || evs[0].Skill != "hello_world" {
		t.Errorf("审计事件归属异常: %+v", evs[0])
	}
	if strings.Contains(string(raw), "hi") && backendHits == 0 {
		// 仅语义提示，无需断言：响应不得回显输入正文。
		_ = raw
	}
}

// TestContentSafetyResponseDeny 响应侧命中 deny：阻断响应，不回传模型输出。
func TestContentSafetyResponseDeny(t *testing.T) {
	gov := newTestGovernance()
	p, srv := newTestProxy(t, gov)
	p.SetContentSafety(StaticContentSafety{Checker: func(_ context.Context, req ContentCheckRequest) (ContentCheckDecision, error) {
		if !req.IsResponse {
			return ContentCheckDecision{Action: ContentActionAllow}, nil
		}
		return ContentCheckDecision{Action: ContentActionDeny, Tier: "strict", Reason: "unsafe output"}, nil
	}})
	_, raw := doProxySend(t, srv, "tenant-a", "test-agent")
	if strings.Contains(string(raw), "backend answer") {
		t.Fatalf("deny 后仍回传了模型输出: %s", raw)
	}
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error == nil || env.Error.Code != a2a.CodeContentBlocked {
		t.Fatalf("期望 content_blocked，实际: %s", raw)
	}
	evs := gov.recordedContentEvents()
	if len(evs) != 1 || evs[0].Action != "deny" || evs[0].Result != "blocked" || evs[0].Tier != "strict" {
		t.Fatalf("审计事件 = %+v, want 1 deny/blocked/strict", evs)
	}
}

// TestContentSafetyResponseRedact 响应侧命中 redact：正文被改写，其余字段保留。
func TestContentSafetyResponseRedact(t *testing.T) {
	gov := newTestGovernance()
	p, srv := newTestProxy(t, gov)
	p.SetContentSafety(StaticContentSafety{Checker: func(_ context.Context, req ContentCheckRequest) (ContentCheckDecision, error) {
		if !req.IsResponse {
			return ContentCheckDecision{Action: ContentActionAllow}, nil
		}
		return ContentCheckDecision{Action: ContentActionRedact, Tier: "standard", Reason: "pii"}, nil
	}})
	_, raw := doProxySend(t, srv, "tenant-a", "test-agent")
	if strings.Contains(string(raw), "backend answer") {
		t.Fatalf("redact 后仍含原文: %s", raw)
	}
	if !strings.Contains(string(raw), "[REDACTED]") {
		t.Fatalf("缺少脱敏标记: %s", raw)
	}
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error != nil {
		t.Fatalf("redact 不应报错: %+v", env.Error)
	}
	if env.Result == nil || !strings.Contains(string(env.Result), `"TASK_STATE_COMPLETED"`) {
		t.Errorf("脱敏不应破坏任务状态字段: %s", env.Result)
	}
	evs := gov.recordedContentEvents()
	if len(evs) != 1 || evs[0].Action != "redact" || evs[0].Result != "redacted" {
		t.Fatalf("审计事件 = %+v, want 1 redact/redacted", evs)
	}
}

// TestContentSafetyCheckerErrorFailsOpen 检查器异常：放行（不阻断业务），但审计 result=error。
func TestContentSafetyCheckerErrorFailsOpen(t *testing.T) {
	gov := newTestGovernance()
	p, srv := newTestProxy(t, gov)
	p.SetContentSafety(StaticContentSafety{Checker: func(_ context.Context, _ ContentCheckRequest) (ContentCheckDecision, error) {
		return ContentCheckDecision{}, errors.New("classifier down")
	}})
	_, raw := doProxySend(t, srv, "tenant-a", "test-agent")
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error != nil {
		t.Fatalf("检查器异常应 fail-open（放行），实际报错: %+v", env.Error)
	}
	if env.Result == nil || !strings.Contains(string(env.Result), "backend answer") {
		t.Errorf("fail-open 应原样回传后端响应: %s", env.Result)
	}
	// 请求侧与响应侧各调用一次检查器，各自记一条 error（fail-open 但可观测）。
	evs := gov.recordedContentEvents()
	if len(evs) != 2 {
		t.Fatalf("审计事件 = %d, want 2（请求侧 + 响应侧各一条）", len(evs))
	}
	for i, ev := range evs {
		if ev.Action != "error" || ev.Result != "error" {
			t.Errorf("审计事件[%d] = %+v, want error/error", i, ev)
		}
		if ev.ErrorCode == "" {
			t.Errorf("审计事件[%d] 缺少 error_code", i)
		}
	}
}

// TestContentSafetyNilMeansPassthrough 未注入 ContentSafety 时完全不介入（可信域 MVP 默认）。
func TestContentSafetyNilMeansPassthrough(t *testing.T) {
	h := newHarness(t)
	if h.proxy.contentSafety != nil {
		t.Fatal("默认应无 ContentSafety")
	}
	_, raw := h.invoke(t, "SendMessage", `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-cs","role":"ROLE_USER","parts":[{"text":"hi"}]}}}`, nil)
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error != nil {
		t.Fatalf("未接线不应产生内容阻断: %+v", env.Error)
	}
	if len(h.gov.recordedContentEvents()) != 0 {
		t.Errorf("未接线不应产生内容审计事件: %+v", h.gov.recordedContentEvents())
	}
}

// TestContentSafetyNoPartsNotBlocked 响应无 parts 时检查层不介入：
// 内容安全层不得因为它读不懂结构而阻断合法协议流量。
func TestContentSafetyNoPartsNotBlocked(t *testing.T) {
	const tenant, agent = "tenant-a", "test-agent"
	var engaged bool
	// 后端返回无 parts 的合法任务响应。
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"t-noparts","status":{"state":"TASK_STATE_COMPLETED"}}}`))
	}))
	defer backend.Close()

	snapshots := NewSnapshotStore()
	card := json.RawMessage(`{"name":"x","version":"1.0.0","description":"d","supportedInterfaces":[{"url":"http://gw/a2a/tenant-a/test-agent","protocolBinding":"JSONRPC","protocolVersion":"1.0"}],"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[{"id":"hello_world","name":"h","description":"d","tags":[]}],"signatures":[{"protected":"x","signature":"y"}]}`)
	if err := snapshots.ForceReplace(&Snapshot{
		RegistryRevision: 1,
		Agents:           []SnapshotAgent{{Tenant: tenant, Name: agent, Revision: 1, Card: card, BackendURL: backend.URL, SignatureStatus: "valid"}},
	}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	gov := newTestGovernance()
	p, err := New(Config{PublicMode: PublicModePath, GatewayPublicBase: "http://gw", DevAllowLoopback: true}, snapshots, gov)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	defer p.Close()
	// DenyAll：若检查层介入则必定被阻断；本用例期望它不介入。
	p.SetContentSafety(StaticContentSafety{Checker: func(_ context.Context, _ ContentCheckRequest) (ContentCheckDecision, error) {
		engaged = true
		return ContentCheckDecision{Action: ContentActionDeny}, nil
	}})
	srv := httptest.NewServer(p.Handler())
	defer srv.Close()

	// 请求体同样不含 parts：确保请求侧、响应侧都不介入。
	_, raw := doProxySendBody(t, srv, tenant, agent,
		`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-np","role":"ROLE_USER"}}}`)
	if engaged {
		t.Error("请求/响应均无 parts 时不应调用检查器")
	}
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error != nil {
		t.Fatalf("无 parts 响应不应被阻断: %+v", env.Error)
	}
	if !strings.Contains(string(raw), "t-noparts") {
		t.Errorf("应原样回传后端响应: %s", raw)
	}
}

// TestCheckPartsUnparsableAllows 不可解析正文：checkParts 放行（不阻断协议）。
func TestCheckPartsUnparsableAllows(t *testing.T) {
	p := &Proxy{contentSafety: DenyAllContentSafety{}}
	d, err := p.checkParts(context.Background(), "t", "a", "s", "SendMessage", true, []byte(`{not json`))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if d.Action != ContentActionAllow {
		t.Errorf("不可解析正文应放行, got %s", d.Action)
	}
}

// TestCheckRequestContentSkipsNonSendMessage 非 SendMessage 方法无用户输入正文，不做请求侧检查。
func TestCheckRequestContentSkipsNonSendMessage(t *testing.T) {
	p := &Proxy{contentSafety: DenyAllContentSafety{}}
	meta := &a2a.RequestMeta{Envelope: &a2a.Envelope{Method: a2a.MethodGetTask, Raw: []byte(`{"params":{"id":"t-1"}}`)}}
	d, err := p.checkRequestContent(context.Background(), route{tenant: "t", agent: "a"}, &Principal{Tenant: "t"}, meta)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if d.Action != ContentActionAllow {
		t.Errorf("GetTask 不应触发请求侧检查, got %s", d.Action)
	}
}

// TestCheckResponseContentEmptyBodyAllows 空正文：无 parts → 检查层不介入（allow）。
func TestCheckResponseContentEmptyBodyAllows(t *testing.T) {
	p := &Proxy{contentSafety: StaticContentSafety{Checker: func(_ context.Context, _ ContentCheckRequest) (ContentCheckDecision, error) {
		return ContentCheckDecision{Action: ContentActionRedact, Tier: "standard", Reason: "pii"}, nil
	}}}
	_, d, err := p.checkResponseContent(context.Background(), route{tenant: "t", agent: "a"}, &Principal{Tenant: "t"},
		&a2a.RequestMeta{Envelope: &a2a.Envelope{Method: a2a.MethodSendMessage}}, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if d.Action != ContentActionAllow {
		t.Errorf("空正文应放行, got %s", d.Action)
	}
}

// TestContentSafetyTenantFallsBackToRoute 审计事件租户口径：路由租户优先于 principal 租户。
func TestContentSafetyTenantFallsBackToRoute(t *testing.T) {
	gov := newTestGovernance()
	p, srv := newTestProxy(t, gov)
	var gotTenant string
	p.SetContentSafety(StaticContentSafety{Checker: func(_ context.Context, req ContentCheckRequest) (ContentCheckDecision, error) {
		gotTenant = req.Tenant
		return ContentCheckDecision{Action: ContentActionDeny, Reason: "x"}, nil
	}})
	_, _ = doProxySend(t, srv, "tenant-a", "test-agent")
	if gotTenant != "tenant-a" {
		t.Errorf("检查请求 tenant = %q, want tenant-a", gotTenant)
	}
	evs := gov.recordedContentEvents()
	if len(evs) == 0 || evs[0].Tenant != "tenant-a" {
		t.Errorf("审计事件租户异常: %+v", evs)
	}
}
