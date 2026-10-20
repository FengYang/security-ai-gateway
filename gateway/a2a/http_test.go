package a2a

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func validHTTPBody() []byte {
	return []byte(`{"jsonrpc":"2.0","id":"req-1","method":"SendMessage","params":{"tenant":"tenant-a","message":{"messageId":"m-1","metadata":{"ga.skill":"hello_world"}}}}`)
}

func TestParseHTTPRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/a2a", bytes.NewReader(validHTTPBody()))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderVersion, "1.0")
	req.Header.Set(HeaderSkill, "hello_world")
	meta, httpErr := ParseHTTPRequest(req, "tenant-a", testCard())
	if httpErr != nil {
		t.Fatalf("ParseHTTPRequest: %v", httpErr)
	}
	if meta.Envelope.Method != MethodSendMessage {
		t.Fatalf("method = %q", meta.Envelope.Method)
	}
	if meta.Tenant != "tenant-a" || meta.Skill.Name != "hello_world" || meta.Skill.Source != SkillSourceHeader {
		t.Fatalf("meta = %+v", meta)
	}
	if meta.Version != SupportedVersion {
		t.Fatalf("version = %q", meta.Version)
	}
}

func TestParseHTTPRequestRejectsTransportErrors(t *testing.T) {
	t.Run("method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/a2a", nil)
		_, httpErr := ParseHTTPRequest(req, "tenant-a", testCard())
		if httpErr == nil || httpErr.Status != http.StatusMethodNotAllowed {
			t.Fatalf("httpErr = %v", httpErr)
		}
	})
	t.Run("content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/a2a", bytes.NewReader(validHTTPBody()))
		req.Header.Set("Content-Type", "text/plain")
		req.Header.Set(HeaderVersion, "1.0")
		_, httpErr := ParseHTTPRequest(req, "tenant-a", testCard())
		if httpErr == nil || httpErr.Status != http.StatusUnsupportedMediaType {
			t.Fatalf("httpErr = %v", httpErr)
		}
	})
	t.Run("oversized", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/a2a", bytes.NewReader(bytes.Repeat([]byte("a"), MaxBodyBytes+1)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(HeaderVersion, "1.0")
		_, httpErr := ParseHTTPRequest(req, "tenant-a", testCard())
		if httpErr == nil || httpErr.Status != http.StatusRequestEntityTooLarge {
			t.Fatalf("httpErr = %v", httpErr)
		}
	})
}

func TestParseHTTPRequestRPCErrors(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		body    []byte
		code    int
		reason  string
	}{
		{
			name:   "missing version",
			body:   validHTTPBody(),
			code:   CodeVersionNotSupported,
			reason: ReasonVersionNotSupported,
		},
		{
			name:    "unsupported version",
			headers: map[string]string{HeaderVersion: "0.3"},
			body:    validHTTPBody(),
			code:    CodeVersionNotSupported,
			reason:  ReasonVersionNotSupported,
		},

		{
			name:    "tenant mismatch",
			headers: map[string]string{HeaderVersion: "1.0"},
			body:    []byte(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"tenant":"tenant-b"}}`),
			code:    CodeUnauthorized,
			reason:  ReasonTenantMismatch,
		},
		{
			name:    "unknown skill",
			headers: map[string]string{HeaderVersion: "1.0", HeaderSkill: "unknown"},
			body:    []byte(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}`),
			code:    CodeUnauthorized,
			reason:  ReasonUnknownSkill,
		},
		{
			name:    "skill conflict",
			headers: map[string]string{HeaderVersion: "1.0", HeaderSkill: "hello_world"},
			body:    []byte(`{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"metadata":{"ga.skill":"other"}}}`),
			code:    CodeInvalidParams,
			reason:  ReasonSkillConflict,
		},
		{
			name:    "streaming",
			headers: map[string]string{HeaderVersion: "1.0"},
			body:    []byte(`{"jsonrpc":"2.0","id":1,"method":"SendStreamingMessage","params":{}}`),
			code:    CodeUnsupportedOperation,
			reason:  ReasonStreamingNotSupported,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/a2a", bytes.NewReader(tc.body))
			req.Header.Set("Content-Type", "application/json")
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			_, httpErr := ParseHTTPRequest(req, "tenant-a", testCard())
			if httpErr == nil {
				t.Fatal("expected error")
			}
			if httpErr.Status != http.StatusOK {
				t.Fatalf("status = %d", httpErr.Status)
			}
			assertRPCCode(t, httpErr.RPC, tc.code)
			if httpErr.RPC.Reason != tc.reason {
				t.Fatalf("reason = %q, want %q", httpErr.RPC.Reason, tc.reason)
			}
		})
	}
}

func TestWriteRPCError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteRPCError(rec, json.RawMessage(`1`), NewRPCError(CodeVersionNotSupported, ReasonVersionNotSupported))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if got := rec.Header().Get(HeaderVersion); got != SupportedVersion {
		t.Fatalf("response version = %q", got)
	}
	var got struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Error   struct {
			Code    int               `json:"code"`
			Message string            `json:"message"`
			Data    map[string]string `json:"data"`
		} `json:"error"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.JSONRPC != "2.0" || got.ID != 1 || got.Error.Code != CodeVersionNotSupported || got.Error.Data["reason"] != ReasonVersionNotSupported {
		t.Fatalf("response = %+v", got)
	}
}

func TestWriteHTTPError(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteHTTPError(rec, &HTTPError{Status: http.StatusRequestEntityTooLarge})
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d", rec.Code)
	}
	body, _ := io.ReadAll(rec.Body)
	if strings.Contains(string(body), "jsonrpc") {
		t.Fatalf("transport error must not contain a JSON-RPC body: %s", body)
	}
}
