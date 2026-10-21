// Package protocol defines the HTTP wire contract between the A2A data plane
// and the standalone L1 guardrail service.
//
// The contract is intentionally small and metadata-only at the envelope level:
// parts are forwarded only because the guardrail must inspect their content;
// the service must never log or persist part bodies.
package protocol

import "encoding/json"

// Action is the content-check decision.
type Action string

const (
	ActionAllow  Action = "allow"
	ActionDeny   Action = "deny"
	ActionRedact Action = "redact"
)

// PartKind mirrors the A2A Part discriminator.
type PartKind string

const (
	PartKindText PartKind = "text"
	PartKindFile PartKind = "file"
	PartKindData PartKind = "data"
)

// FilePart carries the file metadata and (optionally) decoded bytes. JSON
// encodes []byte as base64; the service only uses it for inspection.
type FilePart struct {
	Name     string `json:"name,omitempty"`
	MimeType string `json:"mimeType,omitempty"`
	URI      string `json:"uri,omitempty"`
	Bytes    []byte `json:"bytes,omitempty"`
}

// Part is the normalized A2A part view sent to the guardrail.
type Part struct {
	Kind     PartKind        `json:"kind"`
	Text     string          `json:"text,omitempty"`
	MimeType string          `json:"mimeType,omitempty"`
	File     *FilePart       `json:"file,omitempty"`
	Data     json.RawMessage `json:"data,omitempty"`
}

// Request is the guardrail check request.
type Request struct {
	Tenant     string `json:"tenant"`
	Agent      string `json:"agent"`
	Skill      string `json:"skill"`
	Method     string `json:"method"`
	IsResponse bool   `json:"is_response"`
	Parts      []Part `json:"parts"`
}

// Response is the guardrail decision.
type Response struct {
	Action Action `json:"action"`
	Tier   string `json:"tier,omitempty"`
	Reason string `json:"reason,omitempty"`
}
