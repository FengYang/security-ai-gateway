// Package a2aproxy implements the P2-2 A2A data plane: a thin, protocol-aware
// proxy in front of registered agents.
//
// Scope (frozen F-1..F-5): JSON-RPC 2.0 over HTTP(S), blocking calls only,
// A2A-Version 1.0-only, registered agents only, same-tenant only.
//
// The proxy owns three responsibilities:
//  1. routing: resolve the target agent from the registry snapshot
//     (path mode /a2a/{tenant}/{agent} for local use, host mode
//     {agent}.{tenant_domain} for production) and serve well-known cards;
//  2. the L1 protocol pipeline (gateway/a2a) plus governance hooks
//     (authenticate / authorize / rate-limit / observe) with a fail-closed
//     default: without a governance provider every request is denied;
//  3. backend forwarding with an SSRF guard: backend URLs come from the
//     registry snapshot only and are dialed under the frozen address rules.
//
// The proxy never logs or persists message Parts/artifacts/history (R-2).
package a2aproxy
