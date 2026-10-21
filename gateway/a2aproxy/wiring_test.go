package a2aproxy

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeSignedACL(t *testing.T, path string, key []byte, rules []ACLRule) {
	t.Helper()
	signer, err := NewACLSigner(key)
	if err != nil {
		t.Fatalf("NewACLSigner: %v", err)
	}
	tbl := &ACLTable{Version: 1, IssuedAt: time.Now().UTC().Format(time.RFC3339), Rules: rules}
	if err := signer.SignTable(tbl); err != nil {
		t.Fatalf("SignTable: %v", err)
	}
	raw, err := json.Marshal(tbl)
	if err != nil {
		t.Fatalf("marshal ACL: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write ACL: %v", err)
	}
}

func writeSignedRateLimit(t *testing.T, path string, key []byte, rules []RateLimitRule) {
	t.Helper()
	signer, err := NewRateLimitSigner(key)
	if err != nil {
		t.Fatalf("NewRateLimitSigner: %v", err)
	}
	tbl := &RateLimitTable{Version: 1, IssuedAt: time.Now().UTC().Format(time.RFC3339), Rules: rules}
	if err := signer.SignTable(tbl); err != nil {
		t.Fatalf("SignTable: %v", err)
	}
	raw, err := json.Marshal(tbl)
	if err != nil {
		t.Fatalf("marshal RL: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write RL: %v", err)
	}
}

func TestNewGovernanceFromConfig(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x2a}, 32)
	keyHex := hex.EncodeToString(key)
	aclPath := filepath.Join(dir, "acl.json")
	rlPath := filepath.Join(dir, "rl.json")
	auditPath := filepath.Join(dir, "audit.jsonl")

	writeSignedACL(t, aclPath, key, []ACLRule{{Tenant: "tenant-a", Agent: "agent-a", Skill: "hello_world"}})
	writeSignedRateLimit(t, rlPath, key, []RateLimitRule{{Tenant: "tenant-a", Agent: "agent-a", Skill: "hello_world", RPM: 1}})

	cfg := Config{
		ACLFile:             aclPath,
		ACLSigningKey:       keyHex,
		RateLimitFile:       rlPath,
		RateLimitSigningKey: keyHex,
		AuthTokens:          "tok-a=tenant-a:subject-a:viewer",
		AuditSinkFile:       auditPath,
	}
	gov, closer, err := NewGovernanceFromConfig(cfg)
	if err != nil {
		t.Fatalf("NewGovernanceFromConfig: %v", err)
	}
	if gov == nil || closer == nil {
		t.Fatal("governance/closer must be non-nil")
	}

	req := httptest.NewRequest(http.MethodPost, "/a2a/tenant-a/agent-a", nil)
	req.Header.Set("Authorization", "Bearer tok-a")
	p, err := gov.Authenticate(context.Background(), req)
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	ctx := context.Background()
	if err := gov.Authorize(ctx, p, "tenant-a", "agent-a", "hello_world"); err != nil {
		t.Fatalf("Authorize allowed: %v", err)
	}
	if err := gov.Authorize(ctx, p, "tenant-a", "agent-a", "other"); err == nil {
		t.Fatal("Authorize should deny unknown skill")
	}
	if retry, err := gov.RateLimit(ctx, "tenant-a", "agent-a", "hello_world"); err != nil || retry != 0 {
		t.Fatalf("first RateLimit = (%d,%v), want (0,nil)", retry, err)
	}
	if retry, err := gov.RateLimit(ctx, "tenant-a", "agent-a", "hello_world"); err != nil || retry <= 0 {
		t.Fatalf("second RateLimit = (%d,%v), want retryAfter>0", retry, err)
	}

	gov.Observe(ctx, AuditEvent{Tenant: "tenant-a", Agent: "agent-a", Result: "ok"})
	if err := closer.Close(); err != nil {
		t.Fatalf("close sink: %v", err)
	}
	raw, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	if !strings.Contains(string(raw), `"type":"a2a_governance"`) {
		t.Fatalf("audit sink missing event: %s", raw)
	}
}

func TestNewGovernanceFromConfigRejectsTamperedACL(t *testing.T) {
	dir := t.TempDir()
	key := bytes.Repeat([]byte{0x3b}, 32)
	aclPath := filepath.Join(dir, "acl.json")
	writeSignedACL(t, aclPath, key, []ACLRule{{Tenant: "tenant-a", Agent: "agent-a", Skill: "hello_world"}})
	raw, _ := os.ReadFile(aclPath)
	raw = bytes.Replace(raw, []byte(`"hello_world"`), []byte(`"tampered"`), 1)
	if err := os.WriteFile(aclPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, _, err := NewGovernanceFromConfig(Config{ACLFile: aclPath, ACLSigningKey: hex.EncodeToString(key)})
	if err == nil {
		t.Fatal("tampered ACL must be rejected")
	}
}

func TestParseAuthTokens(t *testing.T) {
	tokens, err := ParseAuthTokens("tok-a=tenant-a:sub-a:viewer|admin,tok-b=tenant-b:sub-b")
	if err != nil {
		t.Fatalf("ParseAuthTokens: %v", err)
	}
	if len(tokens) != 2 || tokens["tok-a"].Tenant != "tenant-a" || len(tokens["tok-a"].Roles) != 2 {
		t.Fatalf("tokens = %+v", tokens)
	}
	if _, err := ParseAuthTokens("bad-entry"); err == nil {
		t.Fatal("malformed token entry must be rejected")
	}
}

func TestNewGovernanceFromConfigWithoutACLIsFailClosed(t *testing.T) {
	gov, closer, err := NewGovernanceFromConfig(Config{})
	if err != nil || gov != nil || closer != nil {
		t.Fatalf("no-ACL config = (%v,%v,%v), want (nil,nil,nil)", gov, closer, err)
	}
}
