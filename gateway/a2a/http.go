package a2a

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
)

// RequestMeta is the L1 result consumed by the governance layer. It contains
// no message Parts or artifacts.
type RequestMeta struct {
	Envelope *Envelope
	Version  string
	Skill    Skill
	Tenant   string
}

// HTTPError couples the HTTP status with an optional JSON-RPC error.
// RPC errors use HTTP 200 (frozen data-plane mapping); 413/415/405 are
// transport-level failures and carry no JSON-RPC body.
type HTTPError struct {
	Status int
	RPC    *RPCError
}

// Error implements error.
func (e *HTTPError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.RPC != nil {
		return fmt.Sprintf("a2a http %d: %v", e.Status, e.RPC)
	}
	return fmt.Sprintf("a2a http %d", e.Status)
}

// ParseHTTPRequest performs the frozen L1 pipeline:
// method/content-type -> body limit -> version/extensions -> envelope ->
// method allowlist -> tenant -> skill. It consumes r.Body; the raw body is
// available in meta.Envelope.Raw for the proxy.
func ParseHTTPRequest(r *http.Request, authTenant string, card *sdk.AgentCard) (*RequestMeta, *HTTPError) {
	if r.Method != http.MethodPost {
		return nil, &HTTPError{Status: http.StatusMethodNotAllowed}
	}
	if rpc := CheckContentType(r.Header.Get("Content-Type")); rpc != nil {
		return nil, &HTTPError{Status: http.StatusUnsupportedMediaType, RPC: rpc}
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, &HTTPError{Status: http.StatusBadRequest, RPC: NewRPCError(CodeInvalidRequest, ReasonInvalidRequest)}
	}
	if len(raw) > MaxBodyBytes {
		return nil, &HTTPError{Status: http.StatusRequestEntityTooLarge}
	}

	version := r.Header.Get(HeaderVersion)
	if rpc := NegotiateVersion(version); rpc != nil {
		return nil, &HTTPError{Status: http.StatusOK, RPC: rpc}
	}
	if rpc := CheckExtensions(r.Header.Get(HeaderExtensions)); rpc != nil {
		return nil, &HTTPError{Status: http.StatusOK, RPC: rpc}
	}

	env, err := ParseEnvelope(raw)
	if err != nil {
		if errors.Is(err, ErrBodyTooLarge) {
			return nil, &HTTPError{Status: http.StatusRequestEntityTooLarge}
		}
		var rpc *RPCError
		if errors.As(err, &rpc) {
			return nil, &HTTPError{Status: http.StatusOK, RPC: rpc}
		}
		return nil, &HTTPError{Status: http.StatusOK, RPC: NewRPCError(CodeInternalError, ReasonInvalidRequest)}
	}
	if rpc := CheckMethod(env.Method); rpc != nil {
		return nil, &HTTPError{Status: http.StatusOK, RPC: rpc}
	}

	requestTenant, _, rpc := RequestTenant(env.Params)
	if rpc != nil {
		return nil, &HTTPError{Status: http.StatusOK, RPC: rpc}
	}
	interfaceTenant := ""
	if card != nil && len(card.SupportedInterfaces) == 1 && card.SupportedInterfaces[0] != nil {
		interfaceTenant = card.SupportedInterfaces[0].Tenant
	}
	tenant, rpc := ResolveTenant(authTenant, requestTenant, interfaceTenant)
	if rpc != nil {
		return nil, &HTTPError{Status: http.StatusOK, RPC: rpc}
	}

	skill, rpc := ExtractSkill(r.Header.Get(HeaderSkill), env.Params)
	if rpc != nil {
		return nil, &HTTPError{Status: http.StatusOK, RPC: rpc}
	}
	if rpc := ValidateSkillForCard(skill, card); rpc != nil {
		return nil, &HTTPError{Status: http.StatusOK, RPC: rpc}
	}

	return &RequestMeta{
		Envelope: env,
		Version:  SupportedVersion,
		Skill:    skill,
		Tenant:   tenant,
	}, nil
}

// SetVersionHeader writes the negotiated response version. The data plane
// must call it on successful proxy responses; WriteRPCError calls it too.
func SetVersionHeader(w http.ResponseWriter) {
	w.Header().Set(HeaderVersion, SupportedVersion)
}

// WriteRPCError writes a JSON-RPC error response with HTTP 200, as required
// by the frozen data-plane mapping.
func WriteRPCError(w http.ResponseWriter, id json.RawMessage, rpc *RPCError) {
	if rpc == nil {
		rpc = NewRPCError(CodeInternalError, ReasonInvalidRequest)
	}
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	SetVersionHeader(w)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error": map[string]any{
			"code":    rpc.Code,
			"message": rpc.Message,
			"data":    map[string]string{"reason": rpc.Reason},
		},
	})
}

// WriteHTTPError writes transport-level failures (405/413/415) as plain HTTP
// errors. JSON-RPC failures (HTTP 200) are delegated to WriteRPCError.
func WriteHTTPError(w http.ResponseWriter, e *HTTPError) {
	if e == nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if e.Status == http.StatusOK && e.RPC != nil {
		WriteRPCError(w, nil, e.RPC)
		return
	}
	http.Error(w, http.StatusText(e.Status), e.Status)
}
