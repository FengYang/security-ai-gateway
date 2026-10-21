package a2aproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"security-ai-gateway/gateway/a2a"
	"security-ai-gateway/gateway/a2a/testagent"
)

// --- test governance -------------------------------------------------------

// testGovernance is the allow-all policy engine used to exercise the data
// plane. It records every observation for assertions.
type testGovernance struct {
	mu            sync.Mutex
	events        []AuditEvent
	taskEvents    []TaskEvent
	contentEvents []ContentActionEvent
	deny          map[string]bool // "tenant|agent|skill" denied by ACL
	denyAuth      bool
	retry         int // >0 => throttle every call
}

func newTestGovernance() *testGovernance {
	return &testGovernance{deny: map[string]bool{}}
}

func (g *testGovernance) Authenticate(_ context.Context, r *http.Request) (*Principal, error) {
	if g.denyAuth {
		return nil, fmt.Errorf("test: unauthenticated")
	}
	tenant := r.Header.Get("X-Test-Tenant")
	if tenant == "" {
		return nil, fmt.Errorf("test: missing tenant header")
	}
	return &Principal{Tenant: tenant, Subject: "test-subject", Roles: []string{"a2a_caller"}}, nil
}

func (g *testGovernance) Authorize(_ context.Context, _ *Principal, tenant, agent, skill string) error {
	if g.deny[tenant+"|"+agent+"|"+skill] {
		return fmt.Errorf("acl_denied: %s/%s/%s", tenant, agent, skill)
	}
	return nil
}

func (g *testGovernance) RateLimit(context.Context, string, string, string) (int, error) {
	return g.retry, nil
}

func (g *testGovernance) Observe(_ context.Context, ev AuditEvent) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.events = append(g.events, ev)
}

func (g *testGovernance) ObserveTask(_ context.Context, ev TaskEvent) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.taskEvents = append(g.taskEvents, ev)
}

func (g *testGovernance) ObserveContent(_ context.Context, ev ContentActionEvent) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.contentEvents = append(g.contentEvents, ev)
}

func (g *testGovernance) recorded() []AuditEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEvent, len(g.events))
	copy(out, g.events)
	return out
}

// recordedTaskEvents 返回已观测的 Task 审计事件（T-3b）。
func (g *testGovernance) recordedTaskEvents() []TaskEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]TaskEvent, len(g.taskEvents))
	copy(out, g.taskEvents)
	return out
}

// recordedContentEvents 返回已观测的内容安全审计事件（T-4）。
func (g *testGovernance) recordedContentEvents() []ContentActionEvent {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]ContentActionEvent, len(g.contentEvents))
	copy(out, g.contentEvents)
	return out
}

// --- harness ---------------------------------------------------------------

type harness struct {
	proxySrv  *httptest.Server
	agentSrv  *httptest.Server
	gov       *testGovernance
	snapshots *SnapshotStore
	proxy     *Proxy // T-4：用于注入 ContentSafety
	tenant    string
	agent     string
}

// newHarness starts a signed testagent, registers it in a snapshot and
// mounts the proxy in path mode on a loopback gateway base.
func newHarness(t *testing.T) *harness {
	t.Helper()
	const (
		tenant = "tenant-a"
		agent  = "test-agent"
	)
	gwBase := "http://gateway.test"
	publicURL := gwBase + "/a2a/" + tenant + "/" + agent

	ag, err := testagent.New(testagent.Config{PublicURL: publicURL, Tenant: tenant, Name: "Test Agent"})
	if err != nil {
		t.Fatalf("testagent: %v", err)
	}
	agentSrv := httptest.NewServer(ag.Handler())
	t.Cleanup(agentSrv.Close)

	cardRaw, err := json.Marshal(ag.Card())
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}
	snapshots := NewSnapshotStore()
	snap := &Snapshot{
		RegistryRevision: 1,
		GeneratedAt:      time.Now().UTC(),
		Agents: []SnapshotAgent{{
			Tenant:          tenant,
			Name:            agent,
			Revision:        1,
			Card:            cardRaw,
			PublicURL:       publicURL,
			DiscoveryURL:    publicURL + "/.well-known/agent-card.json",
			BackendURL:      agentSrv.URL + "/a2a",
			Skills:          []SnapshotSkill{{ID: "hello_world", Name: "Hello World"}},
			SignatureStatus: "valid",
		}},
	}
	if err := snapshots.ForceReplace(snap); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	gov := newTestGovernance()
	cfg := Config{
		PublicMode:        PublicModePath,
		GatewayPublicBase: gwBase,
		SnapshotFile:      "", // in-memory store
		DevAllowLoopback:  true,
	}
	proxy, err := New(cfg, snapshots, gov)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	t.Cleanup(proxy.Close)
	proxySrv := httptest.NewServer(proxy.Handler())
	t.Cleanup(proxySrv.Close)

	return &harness{proxySrv: proxySrv, agentSrv: agentSrv, gov: gov, snapshots: snapshots, proxy: proxy, tenant: tenant, agent: agent}
}

// agentCardRaw 返回 harness 已注册 agent 的签名卡片字节。
//
// 供 host 模式等变体用例复用：从快照取回卡片，避免重复构造 testagent 与快照。
func (h *harness) agentCardRaw(t *testing.T) []byte {
	t.Helper()
	snap := h.snapshots.Current()
	if snap == nil {
		t.Fatal("快照缺失")
	}
	rec, ok := snap.Lookup(h.tenant, h.agent)
	if !ok {
		t.Fatalf("快照未包含 %s/%s", h.tenant, h.agent)
	}
	return rec.Card
}

// invoke sends a data-plane request through the proxy.
func (h *harness) invoke(t *testing.T, method, body string, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.proxySrv.URL+"/a2a/"+h.tenant+"/"+h.agent, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	req.Header.Set("X-Test-Tenant", h.tenant)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := h.proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("%s: %v", method, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return resp, raw
}

// rpcEnvelope is the decoded JSON-RPC envelope. error.data may be an object
// (gateway-generated reason) or the google.rpc.ErrorInfo array produced by
// a2a-go backends, so it stays raw.
type rpcEnvelope struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int             `json:"code"`
		Message string          `json:"message"`
		Data    json.RawMessage `json:"data"`
	} `json:"error"`
}

// errorReason extracts the gateway reason from error.data when present.
func (e rpcEnvelope) errorReason() string {
	if e.Error == nil || len(e.Error.Data) == 0 {
		return ""
	}
	var obj struct {
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(e.Error.Data, &obj); err != nil {
		return ""
	}
	return obj.Reason
}

func decodeEnvelope(t *testing.T, raw []byte) rpcEnvelope {
	t.Helper()
	var env rpcEnvelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("decode envelope (%s): %v", raw, err)
	}
	return env
}

// taskState reads the observed state from both response shapes:
// SendMessage wraps the final event ({"task":{...}}), GetTask/CancelTask
// return the task directly.
func taskState(t *testing.T, result json.RawMessage) string {
	t.Helper()
	var both struct {
		Task *struct {
			ID     string `json:"id"`
			Status struct {
				State string `json:"state"`
			} `json:"status"`
		} `json:"task"`
		ID     string `json:"id"`
		Status struct {
			State string `json:"state"`
		} `json:"status"`
	}
	if err := json.Unmarshal(result, &both); err != nil {
		t.Fatalf("decode task: %v", err)
	}
	if both.Task != nil && both.Task.Status.State != "" {
		return both.Task.Status.State
	}
	return both.Status.State
}

// taskIDOf reads the task id from both response shapes.
func taskIDOf(t *testing.T, result json.RawMessage) string {
	t.Helper()
	var both struct {
		Task *struct {
			ID string `json:"id"`
		} `json:"task"`
		ID string `json:"id"`
	}
	if err := json.Unmarshal(result, &both); err != nil {
		t.Fatalf("decode task id: %v", err)
	}
	if both.Task != nil && both.Task.ID != "" {
		return both.Task.ID
	}
	return both.ID
}

// --- V-1: task lifecycle through the data plane ----------------------------

func TestProxyTaskLifecycle(t *testing.T) {
	h := newHarness(t)

	// SendMessage with the governance skill header.
	resp, raw := h.invoke(t, "SendMessage", `{
		"jsonrpc":"2.0","id":1,"method":"SendMessage",
		"params":{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"hello"}]}}
	}`, map[string]string{a2a.HeaderSkill: "hello_world"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SendMessage status = %d (%s)", resp.StatusCode, raw)
	}
	if got := resp.Header.Get(a2a.HeaderVersion); got != a2a.SupportedVersion {
		t.Fatalf("response A2A-Version = %q", got)
	}
	env := decodeEnvelope(t, raw)
	if env.Error != nil {
		t.Fatalf("SendMessage error: %+v", env.Error)
	}
	state := taskState(t, env.Result)
	if state != "TASK_STATE_COMPLETED" {
		t.Fatalf("state = %s", state)
	}
	taskID := taskIDOf(t, env.Result)
	if taskID == "" {
		t.Fatalf("missing task id: %s", env.Result)
	}

	// GetTask.
	resp, raw = h.invoke(t, "GetTask", `{"jsonrpc":"2.0","id":2,"method":"GetTask","params":{"id":`+quote(taskID)+`}}`, nil)
	env = decodeEnvelope(t, raw)
	if env.Error != nil {
		t.Fatalf("GetTask error: %+v", env.Error)
	}
	if got := taskState(t, env.Result); got != "TASK_STATE_COMPLETED" {
		t.Fatalf("GetTask state = %s", got)
	}

	// CancelTask on a new task (cancelable before completion? testagent
	// completes immediately, so cancel must fail with -32002).
	resp, raw = h.invoke(t, "CancelTask", `{"jsonrpc":"2.0","id":3,"method":"CancelTask","params":{"id":`+quote(taskID)+`}}`, nil)
	env = decodeEnvelope(t, raw)
	if env.Error == nil || env.Error.Code != a2a.CodeTaskNotCancelable {
		t.Fatalf("CancelTask on terminal task: %+v", env.Error)
	}

	// ListTasks.
	resp, raw = h.invoke(t, "ListTasks", `{"jsonrpc":"2.0","id":4,"method":"ListTasks","params":{}}`, nil)
	env = decodeEnvelope(t, raw)
	if env.Error != nil {
		t.Fatalf("ListTasks error: %+v", env.Error)
	}

	// Audit observed the request and the response state (metadata only).
	events := h.gov.recorded()
	var sawSend, sawState bool
	for _, ev := range events {
		if ev.Method == "SendMessage" && ev.Result == "success" {
			sawSend = true
			if ev.State == "TASK_STATE_COMPLETED" {
				sawState = true
			}
			if ev.Skill != "hello_world" || ev.SkillSource != "header" {
				t.Fatalf("audit skill = %s/%s", ev.Skill, ev.SkillSource)
			}
		}
	}
	if !sawSend || !sawState {
		t.Fatalf("audit missing send/state: %+v", events)
	}
}

func TestProxyInputRequiredAndCancel(t *testing.T) {
	h := newHarness(t)
	resp, raw := h.invoke(t, "SendMessage", `{
		"jsonrpc":"2.0","id":1,"method":"SendMessage",
		"params":{"message":{"messageId":"m-2","role":"ROLE_USER","parts":[{"text":"need input"}],"metadata":{"ga.test.final_state":"TASK_STATE_INPUT_REQUIRED"}}}
	}`, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	env := decodeEnvelope(t, raw)
	if env.Error != nil {
		t.Fatalf("SendMessage error: %+v", env.Error)
	}
	if got := taskState(t, env.Result); got != "TASK_STATE_INPUT_REQUIRED" {
		t.Fatalf("state = %s", got)
	}
	taskID := taskIDOf(t, env.Result)
	resp, raw = h.invoke(t, "CancelTask", `{"jsonrpc":"2.0","id":2,"method":"CancelTask","params":{"id":`+quote(taskID)+`}}`, nil)
	env = decodeEnvelope(t, raw)
	if env.Error != nil {
		t.Fatalf("CancelTask error: %+v", env.Error)
	}
	if got := taskState(t, env.Result); got != "TASK_STATE_CANCELED" {
		t.Fatalf("cancel state = %s", got)
	}
}

func mustField(t *testing.T, raw json.RawMessage, path ...string) json.RawMessage {
	t.Helper()
	cur := raw
	for _, p := range path {
		var m map[string]json.RawMessage
		if err := json.Unmarshal(cur, &m); err != nil {
			t.Fatalf("unmarshal %s: %v", cur, err)
		}
		next, ok := m[p]
		if !ok {
			t.Fatalf("field %v missing in %s", path, cur)
		}
		cur = next
	}
	return cur
}

func quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}

// --- V-5: version / method / content-type contract --------------------------

func TestProxyVersionMatrix(t *testing.T) {
	h := newHarness(t)
	body := `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-ver","role":"ROLE_USER","parts":[{"text":"hi"}]}}}`
	cases := []struct {
		name    string
		version string
		set     bool
		code    int
	}{
		{"1.0", "1.0", true, 0},
		{"1.0.1", "1.0.1", true, 0},
		{"missing", "", false, a2a.CodeVersionNotSupported},
		{"0.3", "0.3", true, a2a.CodeVersionNotSupported},
		{"1.1", "1.1", true, a2a.CodeVersionNotSupported},
		{"2.0", "2.0", true, a2a.CodeVersionNotSupported},
		{"malformed", "one-dot-oh", true, a2a.CodeInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := map[string]string{}
			if tc.set {
				headers[a2a.HeaderVersion] = tc.version
			} else {
				headers[a2a.HeaderVersion] = "" // explicitly unset below
			}
			resp, raw := h.invokeWithVersion(t, body, tc.version, tc.set)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			env := decodeEnvelope(t, raw)
			if tc.code == 0 {
				if env.Error != nil {
					t.Fatalf("unexpected error: %+v", env.Error)
				}
				return
			}
			if env.Error == nil || env.Error.Code != tc.code {
				t.Fatalf("error = %+v, want code %d", env.Error, tc.code)
			}
		})
	}
}

// invokeWithVersion sends a request with explicit version-header control.
func (h *harness) invokeWithVersion(t *testing.T, body, version string, set bool) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.proxySrv.URL+"/a2a/"+h.tenant+"/"+h.agent, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Test-Tenant", h.tenant)
	if set {
		req.Header.Set(a2a.HeaderVersion, version)
	}
	resp, err := h.proxySrv.Client().Do(req)
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

func TestProxyMethodMatrix(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		method string
		code   int
	}{
		{"SendStreamingMessage", a2a.CodeUnsupportedOperation},
		{"SubscribeToTask", a2a.CodeUnsupportedOperation},
		{"GetTaskPushNotificationConfig", a2a.CodePushNotificationNotSupported},
		{"CreateTaskPushNotificationConfig", a2a.CodePushNotificationNotSupported},
		{"GetExtendedAgentCard", a2a.CodeExtendedCardNotConfigured},
		{"SomethingElse", a2a.CodeMethodNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			body := `{"jsonrpc":"2.0","id":1,"method":"` + tc.method + `","params":{}}`
			resp, raw := h.invoke(t, tc.method, body, nil)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}
			env := decodeEnvelope(t, raw)
			if env.Error == nil || env.Error.Code != tc.code {
				t.Fatalf("error = %+v, want %d", env.Error, tc.code)
			}
		})
	}
}

func TestProxyEnvelopeRejections(t *testing.T) {
	h := newHarness(t)
	cases := []struct {
		name string
		body string
		code int
	}{
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}]`, a2a.CodeInvalidRequest},
		{"duplicate_key", `{"jsonrpc":"2.0","jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}`, a2a.CodeInvalidRequest},
		{"bad_jsonrpc", `{"jsonrpc":"1.0","id":1,"method":"GetTask","params":{}}`, a2a.CodeInvalidRequest},
		{"notification", `{"jsonrpc":"2.0","method":"GetTask","params":{}}`, a2a.CodeInvalidRequest},
		{"unknown_method_shape", `{"jsonrpc":"2.0","id":1,"method":42,"params":{}}`, a2a.CodeInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, raw := h.invoke(t, tc.name, tc.body, nil)
			env := decodeEnvelope(t, raw)
			if env.Error == nil || env.Error.Code != tc.code {
				t.Fatalf("error = %+v, want %d", env.Error, tc.code)
			}
		})
	}
}

func TestProxyContentTypeAndSize(t *testing.T) {
	h := newHarness(t)

	// Unsupported content type -> HTTP 415 (transport-level).
	req, _ := http.NewRequest(http.MethodPost, h.proxySrv.URL+"/a2a/"+h.tenant+"/"+h.agent, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}`))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Test-Tenant", h.tenant)
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	resp, err := h.proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", resp.StatusCode)
	}

	// a2a+json is accepted.
	req, _ = http.NewRequest(http.MethodPost, h.proxySrv.URL+"/a2a/"+h.tenant+"/"+h.agent, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"x"}}`))
	req.Header.Set("Content-Type", "application/a2a+json")
	req.Header.Set("X-Test-Tenant", h.tenant)
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	resp, err = h.proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s)", resp.StatusCode, raw)
	}
	env := decodeEnvelope(t, raw)
	if env.Error == nil || env.Error.Code != a2a.CodeTaskNotFound {
		t.Fatalf("error = %+v, want task-not-found", env.Error)
	}

	// Oversized body -> HTTP 413.
	big := `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"parts":[{"text":"` + strings.Repeat("a", (1<<20)+16) + `"}]}}}`
	resp2, _ := h.invoke(t, "SendMessage", big, nil)
	if resp2.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp2.StatusCode)
	}
}

// --- governance hooks -------------------------------------------------------

func TestProxyGovernanceHooks(t *testing.T) {
	t.Run("unauthenticated", func(t *testing.T) {
		h := newHarness(t)
		h.gov.denyAuth = true
		_, raw := h.invoke(t, "GetTask", `{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"x"}}`, nil)
		env := decodeEnvelope(t, raw)
		if env.Error == nil || env.Error.Code != a2a.CodeUnauthenticated {
			t.Fatalf("error = %+v, want -31401", env.Error)
		}
	})
	t.Run("acl_denied", func(t *testing.T) {
		h := newHarness(t)
		h.gov.deny[h.tenant+"|"+h.agent+"|hello_world"] = true
		_, raw := h.invoke(t, "SendMessage", `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{}}`, map[string]string{a2a.HeaderSkill: "hello_world"})
		env := decodeEnvelope(t, raw)
		if env.Error == nil || env.Error.Code != a2a.CodeUnauthorized || env.errorReason() != "acl_denied" {
			t.Fatalf("error = %+v, want -31403 acl_denied", env.Error)
		}
		for _, ev := range h.gov.recorded() {
			if ev.Result == "denied" && ev.ErrorCode != "-31403" {
				t.Fatalf("audit denied event = %+v", ev)
			}
		}
	})
	t.Run("rate_limited", func(t *testing.T) {
		h := newHarness(t)
		h.gov.retry = 7
		resp, _ := h.invoke(t, "GetTask", `{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"id":"x"}}`, nil)
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Fatalf("status = %d, want 429", resp.StatusCode)
		}
		if got := resp.Header.Get("Retry-After"); got != "7" {
			t.Fatalf("Retry-After = %q", got)
		}
	})
	t.Run("unknown_agent_404", func(t *testing.T) {
		h := newHarness(t)
		req, _ := http.NewRequest(http.MethodPost, h.proxySrv.URL+"/a2a/"+h.tenant+"/other", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
		req.Header.Set("X-Test-Tenant", h.tenant)
		resp, err := h.proxySrv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("status = %d, want 404 (%s)", resp.StatusCode, raw)
		}
		if strings.Contains(string(raw), h.agentSrv.URL) {
			t.Fatalf("backend url leaked: %s", raw)
		}
	})
	t.Run("tenant_mismatch", func(t *testing.T) {
		h := newHarness(t)
		req, _ := http.NewRequest(http.MethodPost, h.proxySrv.URL+"/a2a/tenant-b/"+h.agent, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
		req.Header.Set("X-Test-Tenant", h.tenant)
		resp, err := h.proxySrv.Client().Do(req)
		if err != nil {
			t.Fatalf("do: %v", err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		env := decodeEnvelope(t, raw)
		if env.Error == nil || env.Error.Code != a2a.CodeUnauthorized || env.errorReason() != "tenant_mismatch" {
			t.Fatalf("error = %+v, want -31403 tenant_mismatch", env.Error)
		}
	})
}

// --- skill contract -----------------------------------------------------------

func TestProxySkillContract(t *testing.T) {
	h := newHarness(t)
	send := func(skillHeader, meta string) rpcEnvelope {
		body := `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-skill","role":"ROLE_USER","parts":[{"text":"x"}]}` + meta + `}}`
		headers := map[string]string{}
		if skillHeader != "" {
			headers[a2a.HeaderSkill] = skillHeader
		}
		_, raw := h.invoke(t, "SendMessage", body, headers)
		return decodeEnvelope(t, raw)
	}
	if env := send("hello_world", ""); env.Error != nil {
		t.Fatalf("valid skill: %+v", env.Error)
	}
	if env := send("", `,"metadata":{"ga.skill":"hello_world"}`); env.Error != nil {
		t.Fatalf("request metadata skill: %+v", env.Error)
	}
	// Conflict between header and metadata.
	_, raw := h.invoke(t, "SendMessage", `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-conflict","role":"ROLE_USER","parts":[{"text":"x"}],"metadata":{"ga.skill":"other"}}}}`, map[string]string{a2a.HeaderSkill: "hello_world"})
	env := decodeEnvelope(t, raw)
	if env.Error == nil || env.Error.Code != a2a.CodeInvalidParams || env.errorReason() != "skill_conflict" {
		t.Fatalf("conflict error = %+v", env.Error)
	}
	// Unknown skill -> fail-closed -31403.
	if env := send("nope", ""); env.Error == nil || env.Error.Code != a2a.CodeUnauthorized || env.errorReason() != "unknown_skill" {
		t.Fatalf("unknown skill error = %+v", env.Error)
	}
	// Wildcard (no carrier) -> agent-level; allow-all governance admits it.
	if env := send("", ""); env.Error != nil {
		t.Fatalf("wildcard skill: %+v", env.Error)
	}
}

// --- discovery ---------------------------------------------------------------

func TestProxyDiscovery(t *testing.T) {
	h := newHarness(t)
	url := h.proxySrv.URL + "/a2a/" + h.tenant + "/" + h.agent + "/.well-known/agent-card.json"
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("get card: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s)", resp.StatusCode, raw)
	}
	if strings.Contains(string(raw), h.agentSrv.URL) {
		t.Fatalf("backend url leaked in card: %s", raw)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("conditional get: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional status = %d, want 304", resp2.StatusCode)
	}

	// Unknown agent discovery -> 404, no backend leak.
	resp3, err := http.Get(h.proxySrv.URL + "/a2a/" + h.tenant + "/nope/.well-known/agent-card.json")
	if err != nil {
		t.Fatalf("get unknown card: %v", err)
	}
	raw3, _ := io.ReadAll(resp3.Body)
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown discovery status = %d", resp3.StatusCode)
	}
	if strings.Contains(string(raw3), h.agentSrv.URL) {
		t.Fatalf("backend url leaked: %s", raw3)
	}
}

// --- readiness ----------------------------------------------------------------

func TestProxyRegistryUnavailableFailsClosed(t *testing.T) {
	gov := newTestGovernance()
	cfg := Config{PublicMode: PublicModePath, GatewayPublicBase: "http://gateway.test", DevAllowLoopback: true}
	proxy, err := New(cfg, NewSnapshotStore(), gov)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	defer proxy.Close()
	srv := httptest.NewServer(proxy.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/a2a/tenant-a/test-agent", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	req.Header.Set("X-Test-Tenant", "tenant-a")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", resp.StatusCode)
	}

	// healthz reports not ready.
	hresp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	raw, _ := io.ReadAll(hresp.Body)
	_ = hresp.Body.Close()
	if hresp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("healthz status = %d", hresp.StatusCode)
	}
	if !bytes.Contains(raw, []byte(`"a2a_registry_ready":false`)) {
		t.Fatalf("healthz body = %s", raw)
	}
}

func TestProxyDenyAllGovernanceDefault(t *testing.T) {
	h := newHarness(t)
	// Rebuild the proxy with the fail-closed default governance.
	cfg := Config{PublicMode: PublicModePath, GatewayPublicBase: "http://gateway.test", DevAllowLoopback: true}
	proxy, err := New(cfg, h.snapshots, nil)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	defer proxy.Close()
	srv := httptest.NewServer(proxy.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/a2a/"+h.tenant+"/"+h.agent, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	env := decodeEnvelope(t, raw)
	if env.Error == nil || env.Error.Code != a2a.CodeUnauthenticated {
		t.Fatalf("error = %+v, want -31401 (fail-closed)", env.Error)
	}
}

// --- header hygiene -----------------------------------------------------------

func TestProxyStripsAuthorizationFromBackend(t *testing.T) {
	var gotAuth, gotSkill string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotSkill = r.Header.Get(a2a.HeaderSkill)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"task":{"id":"t-1","status":{"state":"TASK_STATE_COMPLETED"}}}}`))
	}))
	defer backend.Close()

	const tenant, agent = "tenant-a", "test-agent"
	snapshots := NewSnapshotStore()
	if err := snapshots.ForceReplace(&Snapshot{
		RegistryRevision: 1,
		GeneratedAt:      time.Now().UTC(),
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
	proxy, err := New(Config{PublicMode: PublicModePath, GatewayPublicBase: "http://gw", DevAllowLoopback: true}, snapshots, gov)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	defer proxy.Close()
	srv := httptest.NewServer(proxy.Handler())
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/a2a/"+tenant+"/"+agent, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"x"}]}}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	req.Header.Set("X-Test-Tenant", tenant)
	req.Header.Set(a2a.HeaderSkill, "hello_world")
	req.Header.Set("Authorization", "Bearer super-secret-token")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s)", resp.StatusCode, raw)
	}
	if gotAuth != "" {
		t.Fatalf("Authorization leaked to backend: %q", gotAuth)
	}
	if gotSkill != "" {
		t.Fatalf("governance skill header leaked to backend: %q", gotSkill)
	}
}

// --- host mode (production discovery shape) ---------------------------------

func TestProxyHostModeRouting(t *testing.T) {
	const (
		tenant = "tenant-a"
		agent  = "test-agent"
		domain = "gw.example.com"
	)
	ag, err := testagent.New(testagent.Config{PublicURL: "https://" + agent + "." + domain + "/a2a", Tenant: tenant})
	if err != nil {
		t.Fatalf("testagent: %v", err)
	}
	agentSrv := httptest.NewServer(ag.Handler())
	defer agentSrv.Close()
	cardRaw, err := json.Marshal(ag.Card())
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}
	snapshots := NewSnapshotStore()
	if err := snapshots.ForceReplace(&Snapshot{
		RegistryRevision: 1,
		GeneratedAt:      time.Now().UTC(),
		Agents: []SnapshotAgent{{
			Tenant: tenant, Name: agent, Revision: 1, Card: cardRaw,
			PublicURL: "https://" + agent + "." + domain + "/a2a", BackendURL: agentSrv.URL + "/a2a",
			SignatureStatus: "valid",
		}},
	}); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	gov := newTestGovernance()
	proxy, err := New(Config{
		PublicMode:       PublicModeHost,
		TenantDomains:    map[string]string{tenant: domain},
		DevAllowLoopback: true,
	}, snapshots, gov)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	defer proxy.Close()
	srv := httptest.NewServer(proxy.Handler())
	defer srv.Close()

	// Invoke via host header.
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/a2a", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-host","role":"ROLE_USER","parts":[{"text":"hi"}]}}}`))
	req.Host = agent + "." + domain
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	req.Header.Set("X-Test-Tenant", tenant)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s)", resp.StatusCode, raw)
	}
	env := decodeEnvelope(t, raw)
	if env.Error != nil {
		t.Fatalf("host-mode invoke error: %+v", env.Error)
	}

	// Discovery via host header.
	req, _ = http.NewRequest(http.MethodGet, srv.URL+"/.well-known/agent-card.json", nil)
	req.Host = agent + "." + domain
	resp, err = srv.Client().Do(req)
	if err != nil {
		t.Fatalf("discovery: %v", err)
	}
	raw, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("discovery status = %d (%s)", resp.StatusCode, raw)
	}
	if strings.Contains(string(raw), agentSrv.URL) {
		t.Fatalf("backend url leaked in host-mode card: %s", raw)
	}

	// Unknown host -> 404.
	req, _ = http.NewRequest(http.MethodPost, srv.URL+"/a2a", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}`))
	req.Host = "other.gw.example.com"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	req.Header.Set("X-Test-Tenant", tenant)
	resp, err = srv.Client().Do(req)
	if err != nil {
		t.Fatalf("unknown host: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown host status = %d, want 404", resp.StatusCode)
	}
}

// --- response meta extraction -------------------------------------------------

func TestExtractResponseMeta(t *testing.T) {
	cases := []struct {
		name  string
		raw   string
		state string
		task  string
		isErr bool
		code  int
	}{
		{"task", `{"result":{"task":{"id":"t-1","contextId":"c-1","status":{"state":"TASK_STATE_WORKING"}}}}`, "TASK_STATE_WORKING", "t-1", false, 0},
		{"message", `{"result":{"messageId":"m-1","taskId":"t-2"}}`, "", "t-2", false, 0},
		{"error", `{"error":{"code":-32001,"message":"Task not found"}}`, "", "", true, -32001},
		{"garbage", `not json`, "", "", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			meta := ExtractResponseMeta([]byte(tc.raw))
			if meta.State != tc.state || meta.TaskID != tc.task || meta.IsError != tc.isErr || meta.ErrorCode != tc.code {
				t.Fatalf("meta = %+v", meta)
			}
		})
	}
}
