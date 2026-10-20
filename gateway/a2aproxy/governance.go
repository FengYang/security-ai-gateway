package a2aproxy

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Principal is the authenticated caller identity. Tenant is the security
// tenant from the auth system; it is the only tenant used for policy.
type Principal struct {
	Tenant  string
	Subject string
	Roles   []string
}

// HasRole reports whether the principal carries role.
func (p *Principal) HasRole(role string) bool {
	for _, r := range p.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// Governance is the data-plane policy hook set (T-1 wiring; T-3 implements
// the production policy engine). Every method must fail closed: when in
// doubt, deny.
type Governance interface {
	// Authenticate resolves the caller principal from the request.
	// A nil principal with nil error means "anonymous" and is denied.
	Authenticate(ctx context.Context, r *http.Request) (*Principal, error)
	// Authorize decides whether the principal may invoke agent/skill.
	// skill is "*" when no skill carrier was supplied.
	Authorize(ctx context.Context, p *Principal, tenant, agent string, skill string) error
	// RateLimit applies the tenant|agent|skill budget. A positive retryAfter
	// means "reject with HTTP 429 + Retry-After".
	RateLimit(ctx context.Context, tenant, agent, skill string) (retryAfter int, err error)
	// Observe records a metadata-only audit event (never message content).
	Observe(ctx context.Context, ev AuditEvent)
}

// AuditEvent is the metadata-only governance observation (R-2). It never
// carries Parts, artifacts or history; sizes are counted, not stored.
type AuditEvent struct {
	Tenant      string
	Agent       string
	Skill       string
	SkillSource string
	Method      string
	TaskID      string
	ContextID   string
	State       string // observed task state, empty for request-only events
	Result      string // success|error|canceled|rejected|denied|throttled
	ErrorCode   string // JSON-RPC/HTTP error code, if any
	HTTPStatus  int
	A2AVersion  string
	RequestID   string
	TraceID     string
}

// DenyAllGovernance is the fail-closed default: without a configured policy
// engine every data-plane call is rejected (-31403). It exists so the proxy
// can never accidentally run open.
type DenyAllGovernance struct{}

// Authenticate always fails closed.
func (DenyAllGovernance) Authenticate(context.Context, *http.Request) (*Principal, error) {
	return nil, fmt.Errorf("a2aproxy: no governance configured")
}

// Authorize always denies.
func (DenyAllGovernance) Authorize(context.Context, *Principal, string, string, string) error {
	return fmt.Errorf("a2aproxy: no governance configured")
}

// RateLimit always denies.
func (DenyAllGovernance) RateLimit(context.Context, string, string, string) (int, error) {
	return 0, fmt.Errorf("a2aproxy: no governance configured")
}

// Observe drops events (there is no sink in the default configuration).
func (DenyAllGovernance) Observe(context.Context, AuditEvent) {}

// AuthenticatedReason is the stable data.reason for a denied call.
const AuthenticatedReason = "unauthenticated"

// unauthorizedTenantReason is the stable data.reason for tenant mismatches.
const unauthorizedTenantReason = "tenant_mismatch"

// aclDeniedReason is the stable data.reason for ACL denials.
const aclDeniedReason = "acl_denied"

// rateLimitedReason is the stable data.reason for throttled calls.
const rateLimitedReason = "rate_limited"

// internalReason is the stable data.reason for internal failures.
const internalReason = "internal_error"

// principalFromRequest is a small helper used by governance implementations
// and tests to read a bearer token.
func principalFromRequest(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if h == "" {
		return ""
	}
	if !strings.HasPrefix(h, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
}

// readAllLimited reads at most limit+1 bytes so callers can detect overflow.
func readAllLimited(r io.Reader, limit int64) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, fmt.Errorf("a2aproxy: read body: %w", err)
	}
	if int64(len(raw)) > limit {
		return nil, errResponseTooLarge
	}
	return raw, nil
}
