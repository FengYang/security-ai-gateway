package a2a

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestParseEnvelopeValid(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":"req-1","method":"SendMessage","params":{"tenant":"tenant-a","message":{"messageId":"m-1","taskId":"t-1","contextId":"c-1","metadata":{"ga.skill":"hello_world"}},"metadata":{"ga.skill":"hello_world"}}}`)
	env, err := ParseEnvelope(raw)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if env.Method != MethodSendMessage {
		t.Fatalf("method = %q", env.Method)
	}
	if string(env.ID) != `"req-1"` {
		t.Fatalf("id = %s", env.ID)
	}
	if !bytes.Equal(env.Raw, raw) {
		t.Fatal("raw body was not preserved")
	}
}

func TestParseEnvelopeRejectsDuplicateKey(t *testing.T) {
	raw := []byte(`{"jsonrpc":"2.0","id":1,"id":2,"method":"GetTask","params":{}}`)
	_, err := ParseEnvelope(raw)
	assertRPCCode(t, err, CodeInvalidRequest)
}

func TestParseEnvelopeRejectsBatch(t *testing.T) {
	_, err := ParseEnvelope([]byte(`[{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{}}]`))
	assertRPCCode(t, err, CodeInvalidRequest)
}

func TestParseEnvelopeRejectsNotification(t *testing.T) {
	_, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","method":"GetTask","params":{}}`))
	assertRPCCode(t, err, CodeInvalidRequest)
}

func TestParseEnvelopeRejectsMalformedJSON(t *testing.T) {
	_, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0",`))
	assertRPCCode(t, err, CodeParseError)
}

func TestParseEnvelopeRejectsInvalidUTF8(t *testing.T) {
	raw := append([]byte(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":{"x":"`), 0xff, '"', '}')
	_, err := ParseEnvelope(raw)
	assertRPCCode(t, err, CodeParseError)
}

func TestParseEnvelopeRejectsArrayParams(t *testing.T) {
	_, err := ParseEnvelope([]byte(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":[]}`))
	assertRPCCode(t, err, CodeInvalidParams)
}

func TestParseEnvelopeRejectsDeepJSON(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"jsonrpc":"2.0","id":1,"method":"GetTask","params":`)
	for i := 0; i < MaxJSONDepth+2; i++ {
		b.WriteString(`{"a":`)
	}
	b.WriteString(`1`)
	b.WriteString(strings.Repeat("}", MaxJSONDepth+2))
	b.WriteString(`}`)
	_, err := ParseEnvelope([]byte(b.String()))
	assertRPCCode(t, err, CodeInvalidRequest)
}

func TestParseEnvelopeRejectsOversizedBody(t *testing.T) {
	_, err := ParseEnvelope(bytes.Repeat([]byte("a"), MaxBodyBytes+1))
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("error = %v, want ErrBodyTooLarge", err)
	}
}

func TestCheckMethod(t *testing.T) {
	cases := []struct {
		method string
		code   int
	}{
		{MethodSendMessage, 0},
		{MethodGetTask, 0},
		{MethodListTasks, 0},
		{MethodCancelTask, 0},
		{MethodSendStreamingMessage, CodeUnsupportedOperation},
		{MethodSubscribeToTask, CodeUnsupportedOperation},
		{MethodCreatePushConfig, CodePushNotificationNotSupported},
		{MethodGetExtendedCard, CodeExtendedCardNotConfigured},
		{"UnknownMethod", CodeMethodNotFound},
	}
	for _, tc := range cases {
		err := CheckMethod(tc.method)
		if tc.code == 0 {
			if err != nil {
				t.Fatalf("%s: unexpected error %v", tc.method, err)
			}
			continue
		}
		assertRPCCode(t, err, tc.code)
	}
	if rpc := CheckMethod(MethodSendStreamingMessage); rpc.Reason != ReasonStreamingNotSupported {
		t.Fatalf("streaming reason = %q", rpc.Reason)
	}
}

func TestCheckContentType(t *testing.T) {
	for _, ct := range []string{"application/json", "application/json; charset=utf-8", "application/a2a+json"} {
		if err := CheckContentType(ct); err != nil {
			t.Fatalf("%s: %v", ct, err)
		}
	}
	assertRPCCode(t, CheckContentType("text/plain"), CodeUnsupportedContentType)
	assertRPCCode(t, CheckContentType(""), CodeUnsupportedContentType)
}

func assertRPCCode(t *testing.T, err error, want int) *RPCError {
	t.Helper()
	var rpc *RPCError
	if !errors.As(err, &rpc) {
		t.Fatalf("error type = %T (%v), want *RPCError", err, err)
	}
	if rpc.Code != want {
		t.Fatalf("code = %d (%s), want %d", rpc.Code, rpc.Reason, want)
	}
	return rpc
}
