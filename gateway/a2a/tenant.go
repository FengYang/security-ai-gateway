package a2a

import (
	"bytes"
	"encoding/json"
)

// RequestTenant extracts the A2A routing tenant from params.tenant.
// This value is never used as the security tenant; see ResolveTenant.
func RequestTenant(params json.RawMessage) (string, bool, *RPCError) {
	if len(bytes.TrimSpace(params)) == 0 {
		return "", false, nil
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(params, &top); err != nil || top == nil {
		return "", false, NewRPCError(CodeInvalidParams, ReasonInvalidParams)
	}
	raw, exists := top["tenant"]
	if !exists || len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", false, nil
	}
	var tenant string
	if err := json.Unmarshal(raw, &tenant); err != nil {
		return "", false, NewRPCError(CodeInvalidParams, ReasonInvalidParams)
	}
	return tenant, true, nil
}

// ResolveTenant checks the three tenant carriers frozen by F-2:
// authenticated tenant, params.tenant and interface.tenant.
//
// The authenticated tenant is the only security principal. Any present
// routing/interface tenant that differs fails closed with -31403. The
// returned effective tenant is always the authenticated tenant.
func ResolveTenant(authTenant, requestTenant, interfaceTenant string) (string, *RPCError) {
	if authTenant == "" {
		return "", NewRPCError(CodeUnauthenticated, ReasonUnauthenticated)
	}
	if requestTenant != "" && requestTenant != authTenant {
		return "", NewRPCError(CodeUnauthorized, ReasonTenantMismatch)
	}
	if interfaceTenant != "" && interfaceTenant != authTenant {
		return "", NewRPCError(CodeUnauthorized, ReasonTenantMismatch)
	}
	return authTenant, nil
}

// ResolveRouteTenant checks the host/path routing tenant against the
// authenticated tenant. An empty route tenant means "not supplied".
func ResolveRouteTenant(authTenant, routeTenant string) (string, *RPCError) {
	return ResolveTenant(authTenant, routeTenant, "")
}
