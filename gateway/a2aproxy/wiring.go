package a2aproxy

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
)

// T-3/T-3a/T-3b/T-4 integration wiring.
//
// The standalone data plane keeps the same caller-supplied shape as the
// proxy itself: the operator supplies a signed ACL table, a signed
// rate-limit table, a principal resolver and an audit sink. Missing pieces
// stay fail-closed / no-limit exactly as frozen:
//   - no ACL table -> DenyAllGovernance (every call rejected);
//   - no rate-limit table -> no limit (availability-protective default);
//   - no auth tokens -> Authenticate denies;
//   - no audit sink -> events dropped.

// decodeSigningKey decodes a hex-encoded HMAC key.
func decodeSigningKey(raw string) ([]byte, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("a2aproxy: 签名密钥为空")
	}
	key, err := hex.DecodeString(raw)
	if err != nil {
		return nil, fmt.Errorf("a2aproxy: 签名密钥必须为 hex 编码: %w", err)
	}
	return key, nil
}

// LoadSignedACLFile reads, strictly decodes and verifies a signed ACL table.
func LoadSignedACLFile(path, keyHex string) (*ACLTable, error) {
	key, err := decodeSigningKey(keyHex)
	if err != nil {
		return nil, err
	}
	signer, err := NewACLSigner(key)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("a2aproxy: 读取 ACL 文件失败: %w", err)
	}
	t, err := signer.VerifyACLTableBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("a2aproxy: ACL 表校验失败: %w", err)
	}
	return t, nil
}

// LoadSignedRateLimitFile reads, strictly decodes and verifies a signed
// A2A rate-limit table.
func LoadSignedRateLimitFile(path, keyHex string) (*RateLimitTable, error) {
	key, err := decodeSigningKey(keyHex)
	if err != nil {
		return nil, err
	}
	signer, err := NewRateLimitSigner(key)
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("a2aproxy: 读取限流文件失败: %w", err)
	}
	t, err := signer.VerifyRateLimitTableBytes(raw)
	if err != nil {
		return nil, fmt.Errorf("a2aproxy: 限流表校验失败: %w", err)
	}
	return t, nil
}

// ParseAuthTokens parses "token=tenant:subject:role1|role2,...".
//
// The static token map is the MVP integration seam; production deployments
// replace it with the auth-service/JWT principal resolver.
func ParseAuthTokens(raw string) (map[string]Principal, error) {
	out := map[string]Principal{}
	for _, entry := range splitComma(raw) {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		token, rest, ok := cutHalf(entry, "=")
		if !ok || token == "" || rest == "" {
			return nil, fmt.Errorf("a2aproxy: 非法 A2A_AUTH_TOKENS 条目 %q", entry)
		}
		if _, dup := out[token]; dup {
			return nil, fmt.Errorf("a2aproxy: A2A_AUTH_TOKENS 重复 token")
		}
		parts := strings.SplitN(rest, ":", 3)
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return nil, fmt.Errorf("a2aproxy: 非法 A2A_AUTH_TOKENS 条目 %q（需 tenant:subject[:roles]）", entry)
		}
		p := Principal{Tenant: parts[0], Subject: parts[1]}
		if len(parts) == 3 && parts[2] != "" {
			p.Roles = strings.Split(parts[2], "|")
		}
		out[token] = p
	}
	return out, nil
}

// TokenPrincipalResolver returns a request resolver backed by a static
// bearer-token map. An unknown/missing token returns nil (fail-closed).
func TokenPrincipalResolver(tokens map[string]Principal) func(*http.Request) *Principal {
	return func(r *http.Request) *Principal {
		token := principalFromRequest(r)
		if token == "" {
			return nil
		}
		p, ok := tokens[token]
		if !ok {
			return nil
		}
		cp := p
		return &cp
	}
}

// FileAuditSink appends metadata-only audit events as JSON lines.
//
// It is the integration seam for the audit pipeline: a deployment can swap
// it for the WORM/audit-sidecar sink without changing the proxy.
type FileAuditSink struct {
	mu sync.Mutex
	f  *os.File
}

// OpenFileAuditSink opens (creates/appends) the JSON-lines audit sink.
func OpenFileAuditSink(path string) (*FileAuditSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("a2aproxy: 打开审计落盘文件失败: %w", err)
	}
	return &FileAuditSink{f: f}, nil
}

type auditLine struct {
	Type  string `json:"type"`
	Event any    `json:"event"`
}

func (s *FileAuditSink) write(line auditLine) {
	if s == nil || s.f == nil {
		return
	}
	raw, err := json.Marshal(line)
	if err != nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _ = s.f.Write(append(raw, '\n'))
}

// Observe implements the governance audit sink.
func (s *FileAuditSink) Observe(_ context.Context, ev AuditEvent) {
	s.write(auditLine{Type: "a2a_governance", Event: ev})
}

// ObserveTask implements the Task audit sink (T-3b).
func (s *FileAuditSink) ObserveTask(_ context.Context, ev TaskEvent) {
	s.write(auditLine{Type: "a2a_task_event", Event: ev})
}

// ObserveContent implements the content-action audit sink (T-4).
func (s *FileAuditSink) ObserveContent(_ context.Context, ev ContentActionEvent) {
	s.write(auditLine{Type: "a2a_content_action", Event: ev})
}

// Close flushes and closes the sink.
func (s *FileAuditSink) Close() error {
	if s == nil || s.f == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.f.Close()
}

// NewGovernanceFromConfig builds the production T-3/T-3a/T-3b/T-4 wiring
// from a validated Config.
//
// Returns (nil, nil, nil) when no ACL table is configured: the caller keeps
// the fail-closed DenyAllGovernance default. A configured-but-invalid policy
// is a startup error (never fail open).
func NewGovernanceFromConfig(cfg Config) (*StaticGovernance, io.Closer, error) {
	if cfg.ACLFile == "" {
		return nil, nil, nil
	}
	acl, err := LoadSignedACLFile(cfg.ACLFile, cfg.ACLSigningKey)
	if err != nil {
		return nil, nil, err
	}
	engine := NewACLEngine()
	if err := engine.Replace(acl); err != nil {
		return nil, nil, err
	}

	var limiter Limiter
	if cfg.RateLimitFile != "" {
		rl, err := LoadSignedRateLimitFile(cfg.RateLimitFile, cfg.RateLimitSigningKey)
		if err != nil {
			return nil, nil, err
		}
		rlEngine := NewRateLimitEngine()
		if err := rlEngine.Replace(rl); err != nil {
			return nil, nil, err
		}
		limiter = rlEngine
	}

	var resolve func(*http.Request) *Principal
	if cfg.AuthTokens != "" {
		tokens, err := ParseAuthTokens(cfg.AuthTokens)
		if err != nil {
			return nil, nil, err
		}
		resolve = TokenPrincipalResolver(tokens)
	}

	gov := &StaticGovernance{
		ResolvePrincipal: resolve,
		ACL:              engine,
		Limiter:          limiter,
	}
	var closer io.Closer
	if cfg.AuditSinkFile != "" {
		sink, err := OpenFileAuditSink(cfg.AuditSinkFile)
		if err != nil {
			return nil, nil, err
		}
		gov.Observer = sink.Observe
		gov.TaskObserver = sink.ObserveTask
		gov.ContentObserver = sink.ObserveContent
		closer = sink
	}
	return gov, closer, nil
}
