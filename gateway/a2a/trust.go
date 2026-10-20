package a2a

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
	"github.com/a2aproject/a2a-go/v2/a2acrypto"
)

// PinnedKey is one verifier-side trusted AgentCard signing key.
// The registry scopes the resolver to a single tenant/provider pair.
type PinnedKey struct {
	Kid       string
	Alg       string
	PublicKey crypto.PublicKey
}

// PinnedKeyResolver is a verifier-side key store. jku is never used to fetch
// or select a key; it is only checked against an explicit allowlist.
type PinnedKeyResolver struct {
	keys       map[string]PinnedKey
	allowedJKU map[string]struct{}
}

// NewPinnedKeyResolver builds an immutable resolver. Duplicate kids and
// non-HTTPS allowlist entries are rejected.
func NewPinnedKeyResolver(keys []PinnedKey, allowedJKU []string) (*PinnedKeyResolver, error) {
	r := &PinnedKeyResolver{
		keys:       make(map[string]PinnedKey, len(keys)),
		allowedJKU: make(map[string]struct{}, len(allowedJKU)),
	}
	for _, k := range keys {
		k.Kid = strings.TrimSpace(k.Kid)
		if k.Kid == "" {
			return nil, fmt.Errorf("a2a: pinned key kid must be non-empty")
		}
		if k.PublicKey == nil {
			return nil, fmt.Errorf("a2a: pinned key %q has nil public key", k.Kid)
		}
		if _, dup := r.keys[k.Kid]; dup {
			return nil, fmt.Errorf("a2a: duplicate pinned key kid %q", k.Kid)
		}
		r.keys[k.Kid] = k
	}
	for _, raw := range allowedJKU {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || strings.ToLower(u.Scheme) != "https" || u.Host == "" {
			return nil, fmt.Errorf("a2a: jku allowlist entry must be an absolute https URL: %q", raw)
		}
		r.allowedJKU[raw] = struct{}{}
	}
	return r, nil
}

// ResolveKey implements a2acrypto.KeyResolver.
func (r *PinnedKeyResolver) ResolveKey(_ context.Context, kid, untrustedJKU string) (crypto.PublicKey, error) {
	if r == nil {
		return nil, ErrUntrustedKey
	}
	if untrustedJKU != "" {
		if _, ok := r.allowedJKU[untrustedJKU]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrJKUNotAllowed, untrustedJKU)
		}
	}
	k, ok := r.keys[kid]
	if !ok {
		return nil, fmt.Errorf("%w: kid %q", ErrUntrustedKey, kid)
	}
	return k.PublicKey, nil
}

// VerifyCardSignatures verifies at least one AgentCard JWS signature against
// the pinned resolver. a2acrypto canonicalizes the raw card (RFC 8785) and
// excludes the top-level signatures field.
func VerifyCardSignatures(ctx context.Context, raw json.RawMessage, card *sdk.AgentCard, resolver a2acrypto.KeyResolver) error {
	if card == nil {
		return fmt.Errorf("a2a: nil agent card")
	}
	if len(card.Signatures) < 1 || len(card.Signatures) > 16 {
		return fmt.Errorf("a2a: signatures must contain 1..16 entries")
	}
	if resolver == nil {
		return ErrUntrustedKey
	}
	verifier := a2acrypto.NewVerifier(a2acrypto.VerifierConfig{KeyResolver: resolver})
	var lastErr error
	for i := range card.Signatures {
		if err := verifier.Verify(ctx, raw, &card.Signatures[i]); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	if lastErr == nil {
		lastErr = ErrNoValidSignature
	}
	return fmt.Errorf("%w: %w", ErrNoValidSignature, lastErr)
}
