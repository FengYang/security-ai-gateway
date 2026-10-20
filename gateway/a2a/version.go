package a2a

import (
	"regexp"
	"strings"
)

var (
	supportedVersionRE = regexp.MustCompile(`^1\.0(?:\.\d+)?$`)
	numericVersionRE   = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)
)

// NegotiateVersion applies the frozen 1.0-only policy.
//
// Missing header is treated as 0.3 by the specification and is therefore
// rejected with -32009. A syntactically invalid value is an invalid request
// (-32600); a well-formed but unsupported version (0.3, 2.0, 1.1, ...) is
// -32009.
func NegotiateVersion(header string) *RPCError {
	v := strings.TrimSpace(header)
	if v == "" {
		return NewRPCError(CodeVersionNotSupported, ReasonVersionNotSupported)
	}
	if supportedVersionRE.MatchString(v) {
		return nil
	}
	if numericVersionRE.MatchString(v) {
		return NewRPCError(CodeVersionNotSupported, ReasonVersionNotSupported)
	}
	return NewRPCError(CodeInvalidRequest, ReasonInvalidVersion)
}

// CheckExtensions applies the frozen optional-extension policy. MVP supports
// no extension; A2A-Extensions is an activation list, and optional entries
// are passed through unparsed. Required extensions are rejected at
// registration by ValidateAgentCard, so there is no runtime -32008 here yet.
func CheckExtensions(header string) *RPCError {
	_ = header
	return nil
}
