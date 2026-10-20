package a2a

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime"
	"strings"
)

// JSON-RPC method names frozen by A2A v1.0 / a2a-go v2.6.0.
const (
	MethodSendMessage          = "SendMessage"
	MethodSendStreamingMessage = "SendStreamingMessage"
	MethodGetTask              = "GetTask"
	MethodListTasks            = "ListTasks"
	MethodCancelTask           = "CancelTask"
	MethodSubscribeToTask      = "SubscribeToTask"
	MethodCreatePushConfig     = "CreateTaskPushNotificationConfig"
	MethodGetPushConfig        = "GetTaskPushNotificationConfig"
	MethodListPushConfigs      = "ListTaskPushNotificationConfigs"
	MethodDeletePushConfig     = "DeleteTaskPushNotificationConfig"
	MethodGetExtendedCard      = "GetExtendedAgentCard"
)

// SupportedMethods are the four blocking methods admitted by the MVP.
var SupportedMethods = []string{
	MethodSendMessage,
	MethodGetTask,
	MethodListTasks,
	MethodCancelTask,
}

// Envelope is the L1 view of a JSON-RPC 2.0 request. It contains only the
// fields allowed by the frozen whitelist; Parts/artifacts/history are never
// decoded here.
type Envelope struct {
	ID     json.RawMessage
	Method string
	Params json.RawMessage
	Raw    []byte
}

// ParseEnvelope parses and validates a data-plane JSON-RPC request.
//
// Error mapping follows the frozen contract:
//   - malformed JSON / invalid UTF-8 -> -32700
//   - batch, duplicate key, bad envelope/id/jsonrpc/params shape -> -32600
//   - malformed params object -> -32602
//   - oversized body -> ErrBodyTooLarge (HTTP 413)
func ParseEnvelope(raw []byte) (*Envelope, error) {
	if len(raw) > MaxBodyBytes {
		return nil, ErrBodyTooLarge
	}
	if err := checkStrictJSON(raw, MaxJSONDepth, true); err != nil {
		switch {
		case errors.Is(err, errDuplicateKey), errors.Is(err, errDepthExceeded), errors.Is(err, errNotObject):
			return nil, NewRPCError(CodeInvalidRequest, ReasonInvalidRequest)
		default:
			return nil, NewRPCError(CodeParseError, ReasonParseError)
		}
	}

	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || top == nil {
		return nil, NewRPCError(CodeInvalidRequest, ReasonInvalidRequest)
	}

	jsonrpc, ok := rawString(top["jsonrpc"])
	if !ok || jsonrpc != "2.0" {
		return nil, NewRPCError(CodeInvalidRequest, ReasonInvalidRequest)
	}

	id, ok := top["id"]
	if !ok || !validJSONRPCID(id) {
		// Notifications and batch requests are outside the MVP contract.
		return nil, NewRPCError(CodeInvalidRequest, ReasonInvalidRequest)
	}

	method, ok := rawString(top["method"])
	if !ok || strings.TrimSpace(method) == "" {
		return nil, NewRPCError(CodeInvalidRequest, ReasonInvalidRequest)
	}

	params, ok := top["params"]
	if !ok || len(bytes.TrimSpace(params)) == 0 || bytes.Equal(bytes.TrimSpace(params), []byte("null")) {
		params = json.RawMessage("{}")
	} else if trimmed := bytes.TrimSpace(params); len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, NewRPCError(CodeInvalidParams, ReasonInvalidParams)
	}

	return &Envelope{
		ID:     append(json.RawMessage(nil), id...),
		Method: method,
		Params: append(json.RawMessage(nil), params...),
		Raw:    append([]byte(nil), raw...),
	}, nil
}

func rawString(raw json.RawMessage) (string, bool) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func validJSONRPCID(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return false
	}
	dec := json.NewDecoder(bytes.NewReader(trimmed))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return false
	}
	switch v.(type) {
	case string, json.Number:
		return true
	default:
		return false
	}
}

// CheckMethod applies the frozen method allowlist and reserved-method errors.
func CheckMethod(method string) *RPCError {
	switch method {
	case MethodSendMessage, MethodGetTask, MethodListTasks, MethodCancelTask:
		return nil
	case MethodSendStreamingMessage, MethodSubscribeToTask:
		return NewRPCError(CodeUnsupportedOperation, ReasonStreamingNotSupported)
	case MethodCreatePushConfig, MethodGetPushConfig, MethodListPushConfigs, MethodDeletePushConfig:
		return NewRPCError(CodePushNotificationNotSupported, ReasonPushNotSupported)
	case MethodGetExtendedCard:
		return NewRPCError(CodeExtendedCardNotConfigured, ReasonExtendedCardNotConfigured)
	default:
		return NewRPCError(CodeMethodNotFound, ReasonMethodNotFound)
	}
}

// CheckContentType accepts both the SDK-compatible application/json and the
// A2A media type. Other values map to HTTP 415 / -32005.
func CheckContentType(contentType string) *RPCError {
	if strings.TrimSpace(contentType) == "" {
		return NewRPCError(CodeUnsupportedContentType, "content_type_required")
	}
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return NewRPCError(CodeUnsupportedContentType, "content_type_invalid")
	}
	switch strings.ToLower(mediaType) {
	case "application/json", "application/a2a+json":
		return nil
	default:
		return NewRPCError(CodeUnsupportedContentType, "content_type_unsupported")
	}
}
