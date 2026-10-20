package a2aproxy

import (
	"crypto/subtle"
	"fmt"
	"os"

	"security-ai-gateway/gateway/cryptop"
)

// aclCryptoProvider ACL 表签名/验签所用 Provider（P0-4 §5.4.4 组⑫）。
//
// profile 取自 `CRYPTO_PROFILE`（§12.3；默认 intl，与现役 HMAC-SHA256 逐字节等价）。
var aclCryptoProvider = newACLCryptoProvider()

func newACLCryptoProvider() cryptop.Provider {
	profile := os.Getenv("CRYPTO_PROFILE")
	if profile == "" {
		profile = string(cryptop.ProfileIntl)
	}
	p, err := cryptop.New(cryptop.Profile(profile))
	if err != nil {
		panic("a2aproxy: 初始化 cryptop provider 失败（CRYPTO_PROFILE=" + profile + "）: " + err.Error())
	}
	return p
}

// ACLSigner signs and verifies ACL tables (HMAC over CanonicalBytes).
//
// Same family as route.Signer / mcpsec.Signer / ratelimit.Signer: the
// control plane signs the table with the shared K_rx key and the data plane
// verifies it before replacing the live policy. The A2A ACL domain keeps its
// own key namespace ("acl" vs the rate-limit table) but shares the
// distribution channel and the key material — same channel, same key
// (frozen checklist §2.4: independent policy domain, not merged with MCP).
type ACLSigner struct {
	key []byte
}

// NewACLSigner constructs a signer; the key must be at least 32 bytes.
func NewACLSigner(key []byte) (*ACLSigner, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("a2aproxy: ACL 签名密钥长度不足（%d < 32）", len(key))
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &ACLSigner{key: k}, nil
}

// SignTable signs the ACL table and writes the Signature field.
func (s *ACLSigner) SignTable(t *ACLTable) error {
	canon, err := t.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("a2aproxy: ACL 表编码失败: %w", err)
	}
	// MAC goes through cryptop (intl=HMAC-SHA256; sm=HMAC-SM3; §5.4.4 group 12).
	t.Signature = aclCryptoProvider.HMAC(s.key, canon)
	return nil
}

// VerifyTable verifies the ACL table signature.
func (s *ACLSigner) VerifyTable(t *ACLTable) bool {
	if t == nil {
		return false
	}
	canon, err := t.CanonicalBytes()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(t.Signature, aclCryptoProvider.HMAC(s.key, canon)) == 1
}

// VerifyACLTableBytes verifies a signed ACL table received from the control
// plane: strict decode (unknown fields rejected) + signature check.
//
// A table that fails either step must not replace the live policy.
func (s *ACLSigner) VerifyACLTableBytes(data []byte) (*ACLTable, error) {
	t, err := DecodeACLTable(data)
	if err != nil {
		return nil, err
	}
	if !s.VerifyTable(t) {
		return nil, fmt.Errorf("a2aproxy: ACL 表签名校验失败")
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return t, nil
}
