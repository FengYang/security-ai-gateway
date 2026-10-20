package a2a

import (
	"errors"
	"fmt"
)

// Frozen protocol limits (P2-2 F-2/F-3).
const (
	// MaxBodyBytes is the data-plane JSON-RPC request body limit (1 MiB).
	MaxBodyBytes = 1 << 20
	// MaxAgentCardBytes is the registration AgentCard limit (64 KiB).
	MaxAgentCardBytes = 64 << 10
	// MaxJSONDepth is the maximum accepted JSON nesting depth.
	MaxJSONDepth = 32
	// SupportedVersion is the only accepted A2A protocol major/minor version.
	SupportedVersion = "1.0"
)

// Frozen HTTP header names.
const (
	HeaderVersion    = "A2A-Version"
	HeaderExtensions = "A2A-Extensions"
	HeaderSkill      = "X-GA-A2A-Skill"
)

// JSON-RPC / A2A error codes (a2a-go v2.6.0 internal/jsonrpc).
const (
	CodeParseError                   = -32700
	CodeInvalidRequest               = -32600
	CodeMethodNotFound               = -32601
	CodeInvalidParams                = -32602
	CodeInternalError                = -32603
	CodeServerError                  = -32000
	CodeTaskNotFound                 = -32001
	CodeTaskNotCancelable            = -32002
	CodePushNotificationNotSupported = -32003
	CodeUnsupportedOperation         = -32004
	CodeUnsupportedContentType       = -32005
	CodeInvalidAgentResponse         = -32006
	CodeExtendedCardNotConfigured    = -32007
	CodeExtensionSupportRequired     = -32008
	CodeVersionNotSupported          = -32009
	// CodeContentBlocked 是**网关扩展码**（P2-2 T-4），非 a2a-go 规范常量：
	// 规范错误码集无「策略性内容阻断」语义，复用既有码会丢失内容归因；取 -32000..-32099
	// 服务端错误区中紧邻 -32009 的下一可用值以降低未来冲突风险。详见设计 doc §6.4。
	CodeContentBlocked  = -32010
	CodeUnauthenticated = -31401
	CodeUnauthorized    = -31403
)

// Stable audit/error reasons used by the frozen contract.
const (
	ReasonInvalidRequest               = "invalid_request"
	ReasonParseError                   = "parse_error"
	ReasonInvalidParams                = "invalid_params"
	ReasonMethodNotFound               = "method_not_found"
	ReasonUnsupportedOperation         = "unsupported_operation"
	ReasonStreamingNotSupported        = "streaming_not_supported"
	ReasonPushNotSupported             = "push_not_supported"
	ReasonExtendedCardNotConfigured    = "extended_card_not_configured"
	ReasonExtensionSupportRequired     = "extension_support_required"
	ReasonVersionNotSupported          = "version_not_supported"
	ReasonContentBlocked               = "content_blocked"
	ReasonInvalidVersion               = "invalid_version"
	ReasonSkillConflict                = "skill_conflict"
	ReasonInvalidSkill                 = "invalid_skill"
	ReasonUnknownSkill                 = "unknown_skill"
	ReasonTenantMismatch               = "tenant_mismatch"
	ReasonUnauthenticated              = "unauthenticated"
	ReasonCardTooLarge                 = "card_too_large"
	ReasonCardInvalid                  = "card_invalid"
	ReasonUnsupportedBinding           = "unsupported_binding"
	ReasonURLNotGateway                = "url_not_gateway"
	ReasonUnsupportedCapability        = "unsupported_capability"
	ReasonUnsupportedRequiredExtension = "unsupported_required_extension"
	ReasonUnsupportedSecurityScheme    = "unsupported_security_scheme"
	ReasonSignatureInvalid             = "signature_invalid"
	ReasonUntrustedKey                 = "untrusted_key"
	ReasonJKUNotAllowed                = "jku_not_allowed"
)

var (
	// ErrBodyTooLarge is returned by ParseEnvelope before any JSON-RPC
	// processing. The HTTP layer must map it to 413.
	ErrBodyTooLarge = errors.New("a2a: request body too large")
	// ErrCardTooLarge is returned by DecodeAgentCard. The control plane maps
	// it to HTTP 413 / card_too_large.
	ErrCardTooLarge = errors.New("a2a: agent card too large")
	// ErrJKUNotAllowed is returned by PinnedKeyResolver when a signature
	// carries a jku outside the verifier-side allowlist.
	ErrJKUNotAllowed = errors.New("a2a: jku not allowed")
	// ErrUntrustedKey is returned when no pinned key matches the signature kid.
	ErrUntrustedKey = errors.New("a2a: untrusted key")
	// ErrNoValidSignature is returned when no card signature verifies.
	ErrNoValidSignature = errors.New("a2a: no valid signature")
)

// RPCError is a JSON-RPC error with a stable audit reason.
// It intentionally carries no request body content.
type RPCError struct {
	Code    int
	Reason  string
	Message string
}

// Error implements error.
func (e *RPCError) Error() string {
	if e == nil {
		return "<nil>"
	}
	return fmt.Sprintf("a2a rpc error %d (%s): %s", e.Code, e.Reason, e.Message)
}

// NewRPCError builds an RPCError with the canonical message for code.
func NewRPCError(code int, reason string) *RPCError {
	return &RPCError{Code: code, Reason: reason, Message: rpcMessage(code)}
}

func rpcMessage(code int) string {
	switch code {
	case CodeParseError:
		return "Parse error"
	case CodeInvalidRequest:
		return "Invalid Request"
	case CodeMethodNotFound:
		return "Method not found"
	case CodeInvalidParams:
		return "Invalid params"
	case CodeInternalError:
		return "Internal error"
	case CodeServerError:
		return "Server error"
	case CodeTaskNotFound:
		return "Task not found"
	case CodeTaskNotCancelable:
		return "Task cannot be canceled"
	case CodePushNotificationNotSupported:
		return "Push Notification not supported"
	case CodeUnsupportedOperation:
		return "This operation is not supported"
	case CodeUnsupportedContentType:
		return "Incompatible content types"
	case CodeInvalidAgentResponse:
		return "Invalid agent response"
	case CodeExtendedCardNotConfigured:
		return "Extended card not configured"
	case CodeExtensionSupportRequired:
		return "Extension support required"
	case CodeVersionNotSupported:
		return "Version not supported"
	case CodeContentBlocked:
		return "Content blocked by policy"
	case CodeUnauthenticated:
		return "Unauthenticated"
	case CodeUnauthorized:
		return "Unauthorized"
	default:
		return "A2A error"
	}
}
