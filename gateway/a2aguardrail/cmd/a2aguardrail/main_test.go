package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"security-ai-gateway/gateway/a2aguardrail"
	"security-ai-gateway/gateway/a2aguardrail/protocol"
)

func TestGuardrailHandlerAuthAndCheck(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("categories.json", `[{"id":"A1-01","default_level":"high","default_action":"block"}]`)
	write("keywords/a1-01.json", `{"category":"A1-01","rules":[{"id":"r1","keyword":"BAD","type":"contains"}]}`)
	engine, err := a2aguardrail.NewEngine(dir, 0)
	if err != nil {
		t.Fatal(err)
	}
	// The trailing newline mirrors a secret mounted from a file; the handler
	// must trim it on both sides.
	h := newMux(engine, "tok\n")

	req := httptest.NewRequest(http.MethodPost, "/v1/content/check", strings.NewReader(`{"parts":[{"kind":"text","text":"BAD"}]}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status=%d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/content/check", strings.NewReader(`{"parts":[{"kind":"text","text":"BAD"}]}`))
	req.Header.Set("Authorization", "Bearer tok")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("check status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out protocol.Response
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Action != protocol.ActionDeny {
		t.Fatalf("action=%s, want deny", out.Action)
	}

	req = httptest.NewRequest(http.MethodGet, "/readyz", nil)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("readyz status=%d", rec.Code)
	}
}
