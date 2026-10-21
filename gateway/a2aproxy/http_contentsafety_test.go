package a2aproxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"security-ai-gateway/gateway/a2aguardrail/protocol"
)

func TestHTTPContentSafetyMapsPartsAndDecision(t *testing.T) {
	var gotAuth string
	var got protocol.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &got); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"action":"deny","tier":"high","reason":"category=A1-01;rule=r1"}`))
	}))
	defer srv.Close()

	cs, err := NewHTTPContentSafety(srv.URL+"/v1/content/check", "secret", time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	d, err := cs.Check(context.Background(), ContentCheckRequest{
		Tenant: "t1", Agent: "a1", Skill: "hello_world", Method: "SendMessage", IsResponse: true,
		Parts: []Part{
			{Kind: PartKindText, Text: "hello"},
			{Kind: PartKindFile, File: PartFile{Name: "a.txt", MimeType: "text/plain", Bytes: []byte("file-body")}},
			{Kind: PartKindData, MimeType: "application/json", Data: json.RawMessage(`{"k":1}`)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if d.Action != ContentActionDeny || d.Tier != "high" {
		t.Fatalf("decision=%+v", d)
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("authorization=%q", gotAuth)
	}
	if got.Tenant != "t1" || got.Agent != "a1" || got.Skill != "hello_world" || !got.IsResponse {
		t.Errorf("metadata=%+v", got)
	}
	if len(got.Parts) != 3 {
		t.Fatalf("parts=%d", len(got.Parts))
	}
	if got.Parts[0].Kind != protocol.PartKindText || got.Parts[0].Text != "hello" {
		t.Errorf("text part=%+v", got.Parts[0])
	}
	if got.Parts[1].File == nil || got.Parts[1].File.Name != "a.txt" || string(got.Parts[1].File.Bytes) != "file-body" {
		t.Errorf("file part=%+v", got.Parts[1])
	}
	if string(got.Parts[2].Data) != `{"k":1}` {
		t.Errorf("data part=%+v", got.Parts[2])
	}
}

func TestHTTPContentSafetyActions(t *testing.T) {
	for _, action := range []string{"allow", "deny", "redact"} {
		t.Run(action, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(protocol.Response{Action: protocol.Action(action)})
			}))
			defer srv.Close()
			cs, err := NewHTTPContentSafety(srv.URL, "", time.Second, false)
			if err != nil {
				t.Fatal(err)
			}
			d, err := cs.Check(context.Background(), ContentCheckRequest{})
			if err != nil {
				t.Fatal(err)
			}
			if string(d.Action) != action {
				t.Errorf("action=%s, want %s", d.Action, action)
			}
		})
	}
}

func TestHTTPContentSafetyInvalidAction(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"action":"maybe"}`))
	}))
	defer srv.Close()
	cs, err := NewHTTPContentSafety(srv.URL, "", time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.Check(context.Background(), ContentCheckRequest{}); err == nil {
		t.Fatal("expected invalid action error")
	}
}

func TestHTTPContentSafetyFailOpenAndClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	defer srv.Close()

	open, err := NewHTTPContentSafety(srv.URL, "", time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := open.Check(context.Background(), ContentCheckRequest{}); err == nil {
		t.Fatal("fail-open should surface the transport/protocol error")
	}

	closed, err := NewHTTPContentSafety(srv.URL, "", time.Second, true)
	if err != nil {
		t.Fatal(err)
	}
	d, err := closed.Check(context.Background(), ContentCheckRequest{})
	if err != nil {
		t.Fatalf("fail-closed should not return an error: %v", err)
	}
	if d.Action != ContentActionDeny || d.Reason != "content_safety_unavailable" {
		t.Fatalf("fail-closed decision=%+v", d)
	}
}

func TestNewHTTPContentSafetyRejectsInvalidURL(t *testing.T) {
	for _, raw := range []string{"", "ftp://x/y", "http:///missing-host", "://bad"} {
		if _, err := NewHTTPContentSafety(raw, "", time.Second, false); err == nil {
			t.Errorf("expected invalid URL %q to fail", raw)
		}
	}
}
