package a2a

import (
	"fmt"
	"net/url"
	"strings"
	"unicode/utf8"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
)

// CardValidationOptions are supplied by the registry at registration time.
type CardValidationOptions struct {
	// Tenant is the authenticated registration tenant.
	Tenant string
	// PublicURL is the gateway-form interface URL expected in the signed card.
	// Empty disables the exact comparison (not recommended for production).
	PublicURL string
}

// CardError is a control-plane validation failure with a frozen reason code.
type CardError struct {
	Reason  string
	Field   string
	Message string
}

// Error implements error.
func (e *CardError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Field != "" {
		return fmt.Sprintf("a2a card %s (%s): %s", e.Reason, e.Field, e.Message)
	}
	return fmt.Sprintf("a2a card %s: %s", e.Reason, e.Message)
}

func cardError(reason, field, format string, args ...any) *CardError {
	return &CardError{Reason: reason, Field: field, Message: fmt.Sprintf(format, args...)}
}

// DecodeAgentCard strictly decodes an A2A v1.0 AgentCard. It rejects invalid
// UTF-8, duplicate keys, depth > 32, unknown fields and trailing data. All
// failures map to card_invalid except the 64 KiB size limit.
func DecodeAgentCard(raw []byte) (*sdk.AgentCard, *CardError) {
	if len(raw) > MaxAgentCardBytes {
		return nil, cardError(ReasonCardTooLarge, "", "card exceeds %d bytes", MaxAgentCardBytes)
	}
	if err := checkStrictJSON(raw, MaxJSONDepth, true); err != nil {
		return nil, cardError(ReasonCardInvalid, "", "JSON invalid: %v", err)
	}
	var card sdk.AgentCard
	if err := decodeStrictObject(raw, &card); err != nil {
		return nil, cardError(ReasonCardInvalid, "", "decode failed: %v", err)
	}
	return &card, nil
}

// ValidateAgentCard enforces the frozen AgentCard v1.0 shape and the MVP
// capability/security restrictions. Signature cryptographic verification is
// deliberately separate (see VerifyCardSignatures).
func ValidateAgentCard(card *sdk.AgentCard, opts CardValidationOptions) *CardError {
	if card == nil {
		return cardError(ReasonCardInvalid, "", "card is nil")
	}
	if n := utf8.RuneCountInString(card.Name); n < 1 || n > 128 {
		return cardError(ReasonCardInvalid, "name", "length must be 1..128 runes")
	}
	if strings.TrimSpace(card.Description) == "" {
		return cardError(ReasonCardInvalid, "description", "must be non-empty")
	}
	if strings.TrimSpace(card.Version) == "" {
		return cardError(ReasonCardInvalid, "version", "must be non-empty")
	}

	if len(card.SupportedInterfaces) != 1 {
		return cardError(ReasonUnsupportedBinding, "supportedInterfaces", "exactly one interface is required")
	}
	iface := card.SupportedInterfaces[0]
	if iface == nil {
		return cardError(ReasonUnsupportedBinding, "supportedInterfaces[0]", "must not be null")
	}
	if iface.ProtocolBinding != sdk.TransportProtocolJSONRPC {
		return cardError(ReasonUnsupportedBinding, "supportedInterfaces[0].protocolBinding", "only JSONRPC is admitted")
	}
	if !supportedVersionRE.MatchString(string(iface.ProtocolVersion)) {
		return cardError(ReasonUnsupportedBinding, "supportedInterfaces[0].protocolVersion", "must be 1.0 or 1.0.x")
	}
	if err := validateInterfaceURL(iface.URL, opts.PublicURL); err != nil {
		return cardError(ReasonURLNotGateway, "supportedInterfaces[0].url", "%v", err)
	}
	if iface.Tenant != "" && opts.Tenant != "" && iface.Tenant != opts.Tenant {
		return cardError(ReasonTenantMismatch, "supportedInterfaces[0].tenant", "must equal the registration tenant")
	}

	if card.Capabilities.Streaming {
		return cardError(ReasonUnsupportedCapability, "capabilities.streaming", "must be false")
	}
	if card.Capabilities.PushNotifications {
		return cardError(ReasonUnsupportedCapability, "capabilities.pushNotifications", "must be false")
	}
	if card.Capabilities.ExtendedAgentCard {
		return cardError(ReasonUnsupportedCapability, "capabilities.extendedAgentCard", "must be false")
	}
	for i := range card.Capabilities.Extensions {
		if card.Capabilities.Extensions[i].Required {
			return cardError(ReasonUnsupportedRequiredExtension, fmt.Sprintf("capabilities.extensions[%d].required", i), "required extensions are not supported")
		}
	}

	if len(card.SecuritySchemes) != 0 || len(card.SecurityRequirements) != 0 {
		return cardError(ReasonUnsupportedSecurityScheme, "securitySchemes/securityRequirements", "must be empty in MVP")
	}
	if len(card.DefaultInputModes) == 0 {
		return cardError(ReasonCardInvalid, "defaultInputModes", "must be non-empty")
	}
	if len(card.DefaultOutputModes) == 0 {
		return cardError(ReasonCardInvalid, "defaultOutputModes", "must be non-empty")
	}

	if len(card.Skills) > 64 {
		return cardError(ReasonCardInvalid, "skills", "at most 64 skills")
	}
	seen := make(map[string]struct{}, len(card.Skills))
	for i := range card.Skills {
		skill := &card.Skills[i]
		if !skillIDRE.MatchString(skill.ID) {
			return cardError(ReasonCardInvalid, fmt.Sprintf("skills[%d].id", i), "invalid skill id")
		}
		if _, dup := seen[skill.ID]; dup {
			return cardError(ReasonCardInvalid, fmt.Sprintf("skills[%d].id", i), "duplicate skill id %q", skill.ID)
		}
		seen[skill.ID] = struct{}{}
		if strings.TrimSpace(skill.Name) == "" || strings.TrimSpace(skill.Description) == "" {
			return cardError(ReasonCardInvalid, fmt.Sprintf("skills[%d]", i), "name and description must be non-empty")
		}
		if skill.Tags == nil {
			return cardError(ReasonCardInvalid, fmt.Sprintf("skills[%d].tags", i), "field must be present (may be an empty array)")
		}
	}

	if len(card.Signatures) < 1 || len(card.Signatures) > 16 {
		return cardError(ReasonSignatureInvalid, "signatures", "must contain 1..16 signatures")
	}
	for i := range card.Signatures {
		if strings.TrimSpace(card.Signatures[i].Protected) == "" || strings.TrimSpace(card.Signatures[i].Signature) == "" {
			return cardError(ReasonSignatureInvalid, fmt.Sprintf("signatures[%d]", i), "protected and signature must be non-empty")
		}
	}

	if card.Provider != nil {
		if strings.TrimSpace(card.Provider.Org) == "" {
			return cardError(ReasonCardInvalid, "provider.organization", "must be non-empty")
		}
		if _, err := normalizeHTTPURL(card.Provider.URL, false); err != nil {
			return cardError(ReasonCardInvalid, "provider.url", "%v", err)
		}
	}
	if card.DocumentationURL != "" {
		if _, err := normalizeHTTPURL(card.DocumentationURL, true); err != nil {
			return cardError(ReasonCardInvalid, "documentationUrl", "%v", err)
		}
	}
	if card.IconURL != "" {
		if _, err := normalizeHTTPURL(card.IconURL, true); err != nil {
			return cardError(ReasonCardInvalid, "iconUrl", "%v", err)
		}
	}

	return nil
}

func validateInterfaceURL(raw, expected string) error {
	got, err := normalizeHTTPURL(raw, false)
	if err != nil {
		return err
	}
	if expected == "" {
		return nil
	}
	want, err := normalizeHTTPURL(expected, false)
	if err != nil {
		return fmt.Errorf("expected public URL invalid: %w", err)
	}
	if got != want {
		return fmt.Errorf("must be the gateway-form URL %q", want)
	}
	return nil
}

// normalizeHTTPURL canonicalizes a public HTTP(S) URL for exact comparison.
// Credentials, fragments and (unless explicitly allowed) queries are rejected.
func normalizeHTTPURL(raw string, allowQuery bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("must be non-empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", fmt.Errorf("only http/https are allowed")
	}
	if u.Host == "" || u.Hostname() == "" {
		return "", fmt.Errorf("host is required")
	}
	if u.User != nil {
		return "", fmt.Errorf("userinfo is not allowed")
	}
	if u.Fragment != "" {
		return "", fmt.Errorf("fragment is not allowed")
	}
	if !allowQuery && (u.RawQuery != "" || u.ForceQuery) {
		return "", fmt.Errorf("query is not allowed")
	}
	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	u.Path = strings.TrimRight(u.Path, "/")
	if u.Path == "" {
		u.Path = ""
	}
	return u.String(), nil
}

// DecodeAndValidateAgentCard is the normal registry entry point.
func DecodeAndValidateAgentCard(raw []byte, opts CardValidationOptions) (*sdk.AgentCard, *CardError) {
	card, err := DecodeAgentCard(raw)
	if err != nil {
		return nil, err
	}
	if err := ValidateAgentCard(card, opts); err != nil {
		return nil, err
	}
	return card, nil
}
