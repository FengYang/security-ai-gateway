// Package a2a implements the frozen P2-2 protocol foundation shared by the
// A2A data plane and the gateway-core control plane.
//
// Scope (MVP): JSON-RPC 2.0 over HTTP(S), blocking calls only,
// A2A-Version 1.0-only, registered agents only.
//
// This package deliberately contains no network I/O and no registry storage.
// It owns the protocol envelope, version/skill/tenant negotiation and the
// AgentCard validation/trust primitives. The data plane and the control plane
// wire these primitives into their own HTTP handlers.
package a2a
