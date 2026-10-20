package a2a

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2acrypto"
)

func TestVerifyCardSignatures(t *testing.T) {
	ctx := context.Background()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	card := testCard()
	card.Signatures = nil
	raw := testCardJSON(t, card)
	signer, err := a2acrypto.NewSigner(a2acrypto.SignerConfig{
		PrivateKey: priv,
		KeyID:      "test-key",
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := signer.Sign(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	card.Signatures = []sdk.AgentCardSignature{*sig}

	resolver, err := NewPinnedKeyResolver([]PinnedKey{{Kid: "test-key", PublicKey: pub}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCardSignatures(ctx, raw, card, resolver); err != nil {
		t.Fatalf("VerifyCardSignatures: %v", err)
	}
}

func TestVerifyCardSignaturesRejectsUntrustedKey(t *testing.T) {
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	card := testCard()
	card.Signatures = nil
	raw := testCardJSON(t, card)
	signer, _ := a2acrypto.NewSigner(a2acrypto.SignerConfig{PrivateKey: priv, KeyID: "test-key"})
	sig, err := signer.Sign(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	card.Signatures = []sdk.AgentCardSignature{*sig}
	resolver, _ := NewPinnedKeyResolver([]PinnedKey{{Kid: "test-key", PublicKey: wrongPub}}, nil)
	err = VerifyCardSignatures(ctx, raw, card, resolver)
	if !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("error = %v, want ErrNoValidSignature", err)
	}
}

func TestVerifyCardSignaturesRejectsJKUNotAllowed(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	card := testCard()
	card.Signatures = nil
	raw := testCardJSON(t, card)
	signer, _ := a2acrypto.NewSigner(a2acrypto.SignerConfig{
		PrivateKey: priv,
		KeyID:      "test-key",
		JWKSURL:    "https://evil.example/jwks.json",
	})
	sig, err := signer.Sign(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	card.Signatures = []sdk.AgentCardSignature{*sig}
	resolver, _ := NewPinnedKeyResolver([]PinnedKey{{Kid: "test-key", PublicKey: pub}}, nil)
	err = VerifyCardSignatures(ctx, raw, card, resolver)
	if err == nil || !strings.Contains(err.Error(), ErrJKUNotAllowed.Error()) {
		t.Fatalf("error = %v, want jku-not-allowed", err)
	}
}

func TestVerifyCardSignaturesAllowsListedJKU(t *testing.T) {
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	const jku = "https://trusted.example/jwks.json"
	card := testCard()
	card.Signatures = nil
	raw := testCardJSON(t, card)
	signer, _ := a2acrypto.NewSigner(a2acrypto.SignerConfig{
		PrivateKey: priv,
		KeyID:      "test-key",
		JWKSURL:    jku,
	})
	sig, err := signer.Sign(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	card.Signatures = []sdk.AgentCardSignature{*sig}
	resolver, err := NewPinnedKeyResolver([]PinnedKey{{Kid: "test-key", PublicKey: pub}}, []string{jku})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCardSignatures(ctx, raw, card, resolver); err != nil {
		t.Fatalf("VerifyCardSignatures: %v", err)
	}
}

func TestNewPinnedKeyResolverRejectsDuplicateAndInsecureJKU(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := NewPinnedKeyResolver([]PinnedKey{
		{Kid: "k", PublicKey: pub},
		{Kid: "k", PublicKey: pub},
	}, nil); err == nil {
		t.Fatal("duplicate kid accepted")
	}
	if _, err := NewPinnedKeyResolver(nil, []string{"http://example.com/jwks.json"}); err == nil {
		t.Fatal("insecure jku allowlist accepted")
	}
}

func TestVerifyCardSignaturesRequiresSignatures(t *testing.T) {
	card := testCard()
	card.Signatures = nil
	err := VerifyCardSignatures(context.Background(), json.RawMessage(`{}`), card, &PinnedKeyResolver{})
	if err == nil {
		t.Fatal("missing signatures accepted")
	}
}
