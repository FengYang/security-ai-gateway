package testagent

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	protocol "security-ai-gateway/gateway/a2a"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2asrv"
)

func TestAgentTaskLifecycleAndCard(t *testing.T) {
	base, agent := startAgent(t)
	client := &http.Client{Timeout: 5 * time.Second}

	send := rpcCall(t, client, base+"/a2a", `{
		"jsonrpc":"2.0","id":"1","method":"SendMessage",
		"params":{"message":{"messageId":"m-1","role":"ROLE_USER","parts":[{"text":"hello"}]}}
	}`)
	task := decodeTaskResult(t, send)
	if task.ID == "" || task.Status.State != sdk.TaskStateCompleted {
		t.Fatalf("task = %+v", task)
	}

	getBody := `{"jsonrpc":"2.0","id":"2","method":"GetTask","params":{"id":` + quote(string(task.ID)) + `}}`
	got := rpcCall(t, client, base+"/a2a", getBody)
	fetched := decodeTaskResult(t, got)
	if fetched.ID != task.ID || fetched.Status.State != sdk.TaskStateCompleted {
		t.Fatalf("fetched = %+v", fetched)
	}

	resp, err := client.Get(base + a2asrv.WellKnownAgentCardPath)
	if err != nil {
		t.Fatalf("GET card: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read card: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("card status = %d (%s)", resp.StatusCode, raw)
	}
	card, cardErr := protocol.DecodeAndValidateAgentCard(raw, protocol.CardValidationOptions{
		PublicURL: base + "/a2a",
	})
	if cardErr != nil {
		t.Fatalf("card validation: %v", cardErr)
	}
	resolver, err := protocol.NewPinnedKeyResolver(agent.PinnedKeys(), nil)
	if err != nil {
		t.Fatalf("pinned resolver: %v", err)
	}
	if err := protocol.VerifyCardSignatures(context.Background(), raw, card, resolver); err != nil {
		t.Fatalf("card signature: %v", err)
	}
}

func TestAgentInputRequiredAndCancel(t *testing.T) {
	base, _ := startAgent(t)
	client := &http.Client{Timeout: 5 * time.Second}
	send := rpcCall(t, client, base+"/a2a", `{
		"jsonrpc":"2.0","id":"1","method":"SendMessage",
		"params":{"message":{"messageId":"m-2","role":"ROLE_USER","parts":[{"text":"need input"}],"metadata":{"ga.test.final_state":"TASK_STATE_INPUT_REQUIRED"}}}
	}`)
	task := decodeTaskResult(t, send)
	if task.Status.State != sdk.TaskStateInputRequired {
		t.Fatalf("state = %s, want input-required", task.Status.State)
	}
	cancelBody := `{"jsonrpc":"2.0","id":"2","method":"CancelTask","params":{"id":` + quote(string(task.ID)) + `}}`
	canceled := rpcCall(t, client, base+"/a2a", cancelBody)
	canceledTask := decodeTaskResult(t, canceled)
	if canceledTask.Status.State != sdk.TaskStateCanceled {
		t.Fatalf("state = %s, want canceled", canceledTask.Status.State)
	}
}

func startAgent(t *testing.T) (string, *Agent) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + ln.Addr().String()
	agent, err := New(Config{PublicURL: base + "/a2a"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv := &http.Server{Handler: agent.Handler()}
	go func() {
		_ = srv.Serve(ln)
	}()
	t.Cleanup(func() {
		_ = srv.Shutdown(context.Background())
	})
	return base, agent
}

func rpcCall(t *testing.T, client *http.Client, url, body string) json.RawMessage {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(protocol.HeaderVersion, protocol.SupportedVersion)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("rpc: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read rpc: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d (%s)", resp.StatusCode, raw)
	}
	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode rpc: %v (%s)", err, raw)
	}
	if envelope.Error != nil {
		t.Fatalf("rpc error %d: %s", envelope.Error.Code, envelope.Error.Message)
	}
	if len(envelope.Result) == 0 {
		t.Fatalf("missing result: %s", raw)
	}
	return envelope.Result
}

func decodeTaskResult(t *testing.T, raw json.RawMessage) sdk.Task {
	t.Helper()
	var wrapper struct {
		Task *sdk.Task `json:"task"`
	}
	if err := json.Unmarshal(raw, &wrapper); err == nil && wrapper.Task != nil {
		return *wrapper.Task
	}
	var direct sdk.Task
	if err := json.Unmarshal(raw, &direct); err != nil {
		t.Fatalf("decode task: %v (%s)", err, raw)
	}
	return direct
}

func quote(s string) string {
	raw, _ := json.Marshal(s)
	return string(raw)
}
