package a2a

import (
	"bytes"
	"testing"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
)

func TestDecodeAndValidateAgentCard(t *testing.T) {
	card := testCard()
	raw := testCardJSON(t, card)
	got, err := DecodeAndValidateAgentCard(raw, CardValidationOptions{
		Tenant:    "tenant-a",
		PublicURL: "https://agent.example.com/a2a/",
	})
	if err != nil {
		t.Fatalf("DecodeAndValidateAgentCard: %v", err)
	}
	if got.Name != card.Name || len(got.Skills) != 1 {
		t.Fatalf("decoded card = %+v", got)
	}
}

func TestValidateAgentCardRejectsWrongURL(t *testing.T) {
	card := testCard()
	card.SupportedInterfaces[0].URL = "https://backend.internal/a2a"
	err := ValidateAgentCard(card, CardValidationOptions{
		Tenant:    "tenant-a",
		PublicURL: "https://agent.example.com/a2a",
	})
	assertCardReason(t, err, ReasonURLNotGateway)
}

func TestValidateAgentCardRejectsTenantMismatch(t *testing.T) {
	card := testCard()
	card.SupportedInterfaces[0].Tenant = "tenant-b"
	err := ValidateAgentCard(card, CardValidationOptions{Tenant: "tenant-a"})
	assertCardReason(t, err, ReasonTenantMismatch)
}

func TestValidateAgentCardRejectsStreaming(t *testing.T) {
	card := testCard()
	card.Capabilities.Streaming = true
	assertCardReason(t, ValidateAgentCard(card, CardValidationOptions{}), ReasonUnsupportedCapability)
}

func TestValidateAgentCardRejectsMissingTags(t *testing.T) {
	card := testCard()
	card.Skills[0].Tags = nil
	assertCardReason(t, ValidateAgentCard(card, CardValidationOptions{}), ReasonCardInvalid)
}

func TestValidateAgentCardRejectsMissingSignature(t *testing.T) {
	card := testCard()
	card.Signatures = nil
	assertCardReason(t, ValidateAgentCard(card, CardValidationOptions{}), ReasonSignatureInvalid)
}

func TestDecodeAgentCardRejectsDuplicateKey(t *testing.T) {
	raw := testCardJSON(t, testCard())
	raw = bytes.Replace(raw, []byte(`"name":"Test Agent"`), []byte(`"name":"A","name":"B"`), 1)
	_, err := DecodeAgentCard(raw)
	assertCardReason(t, err, ReasonCardInvalid)
}

func TestDecodeAgentCardRejectsUnknownField(t *testing.T) {
	raw := testCardJSON(t, testCard())
	raw = append(raw[:len(raw)-1], []byte(`,"unexpected":1}`)...)
	_, err := DecodeAgentCard(raw)
	assertCardReason(t, err, ReasonCardInvalid)
}

func TestDecodeAgentCardRejectsTooLarge(t *testing.T) {
	_, err := DecodeAgentCard(bytes.Repeat([]byte("a"), MaxAgentCardBytes+1))
	assertCardReason(t, err, ReasonCardTooLarge)
}

func TestValidateAgentCardRejectsMultipleInterfaces(t *testing.T) {
	card := testCard()
	second := *card.SupportedInterfaces[0]
	card.SupportedInterfaces = append(card.SupportedInterfaces, &second)
	assertCardReason(t, ValidateAgentCard(card, CardValidationOptions{}), ReasonUnsupportedBinding)
}

// TestValidateAgentCardRejectsRequiredExtension：VA-505（`required` 扩展拒绝）取证。
//
// 冻结口径（§2.4 / 规范 M-? 扩展）：客户端必须理解并遵守的扩展（`required=true`）在 MVP
// 一律拒绝，理由 reason=unsupported_required_extension；**runtime 无 -32008 产出点**
// （-32008 属注册期拒绝的语义码），故在卡片校验层取证。
func TestValidateAgentCardRejectsRequiredExtension(t *testing.T) {
	card := testCard()
	card.Capabilities.Extensions = []sdk.AgentExtension{
		{URI: "https://ext.example/optional", Required: false},
		{URI: "https://ext.example/mandatory", Required: true},
	}
	assertCardReason(t, ValidateAgentCard(card, CardValidationOptions{}), ReasonUnsupportedRequiredExtension)
}

// TestValidateAgentAllowsOptionalExtension：非 required 扩展不阻断注册（防过度拒绝）。
func TestValidateAgentAllowsOptionalExtension(t *testing.T) {
	card := testCard()
	card.Capabilities.Extensions = []sdk.AgentExtension{{URI: "https://ext.example/optional", Required: false}}
	if err := ValidateAgentCard(card, CardValidationOptions{}); err != nil {
		t.Fatalf("非 required 扩展应放行，实际 reason=%q (%s)", err.Reason, err.Message)
	}
}

func TestNormalizeHTTPURL(t *testing.T) {
	for _, raw := range []string{
		"https://user@example.com/a2a",
		"https://example.com/a2a?x=1",
		"ftp://example.com/a2a",
		"/relative",
		"",
	} {
		if _, err := normalizeHTTPURL(raw, false); err == nil {
			t.Fatalf("%q accepted", raw)
		}
	}
	got, err := normalizeHTTPURL("HTTPS://EXAMPLE.COM/a2a/", false)
	if err != nil || got != "https://example.com/a2a" {
		t.Fatalf("normalized = %q err=%v", got, err)
	}
}

func TestDecodeAndValidateAgentCardRequiresObject(t *testing.T) {
	_, err := DecodeAndValidateAgentCard([]byte(`[]`), CardValidationOptions{})
	assertCardReason(t, err, ReasonCardInvalid)
}

func assertCardReason(t *testing.T, err *CardError, want string) {
	t.Helper()
	if err == nil {
		t.Fatalf("nil card error, want %q", want)
	}
	if err.Reason != want {
		t.Fatalf("reason = %q (%s), want %q", err.Reason, err.Message, want)
	}
}
