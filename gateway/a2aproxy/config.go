package a2aproxy

import (
	"fmt"
	"os"
	"time"
)

// PublicMode selects the discovery/invoke URL shape frozen by F-3.
type PublicMode string

const (
	// PublicModePath serves /a2a/{tenant}/{agent} (local/联调 only).
	PublicModePath PublicMode = "path"
	// PublicModeHost serves {agent}.{tenant_domain} (production).
	PublicModeHost PublicMode = "host"
)

// Default values frozen by the P2-2 contract.
const (
	DefaultListenAddr       = ":8086"
	DefaultSnapshotPoll     = 5 * time.Second
	DefaultBackendTimeout   = 30 * time.Second
	DefaultMaxResponseBytes = 16 << 20 // 16 MiB (F-2 §2.2)
	DefaultMaxIdleConns     = 64
)

// Config is the data-plane configuration. All fields have safe defaults;
// production values come from the deployment manifests.
type Config struct {
	// ListenAddr is the proxy listen address.
	ListenAddr string
	// MetricsAddr 是运维面 /metrics 的独立监听地址（T-5）。
	// 为空或与 ListenAddr 相同 → /metrics 挂在主端口；建议内网场景显式分离。
	MetricsAddr string
	// PublicMode selects host or path discovery (F-3).
	PublicMode PublicMode
	// GatewayPublicBase is the path-mode gateway base, e.g.
	// "https://a2a.example.com". Required in path mode.
	GatewayPublicBase string
	// TenantDomains maps tenant -> base domain for host mode,
	// e.g. {"tenant-a": "a2a.tenant-a.example.com"}.
	TenantDomains map[string]string

	// SnapshotFile is a local registry snapshot JSON file (dev mode).
	// Mutually exclusive with SnapshotURL.
	SnapshotFile string
	// SnapshotURL is the control-plane /internal/a2a/snapshot endpoint.
	SnapshotURL string
	// SnapshotToken is the internal token for SnapshotURL.
	SnapshotToken string
	// SnapshotPoll is the snapshot refresh interval.
	SnapshotPoll time.Duration

	// BackendTimeout bounds a single backend call.
	BackendTimeout time.Duration
	// MaxResponseBytes caps the backend response body (F-2: 16 MiB).
	MaxResponseBytes int64
	// MaxIdleConns bounds the backend connection pool.
	MaxIdleConns int

	// ForwardSkillHeader mirrors the verified skill to the backend with
	// X-GA-A2A-Skill-Source: gateway (F-2 §2.4). Default false = strip.
	ForwardSkillHeader bool
	// DevAllowLoopback relaxes the backend dial guard for loopback
	// addresses (F-5 §5.9 forbids them in production). It exists only for
	// local development/E2E tests where the agent runs on 127.0.0.1 and
	// must never be enabled in a production deployment.
	DevAllowLoopback bool
}

// Validate checks the configuration and applies defaults.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		c.ListenAddr = DefaultListenAddr
	}
	switch c.PublicMode {
	case PublicModePath, PublicModeHost:
	case "":
		c.PublicMode = PublicModePath
	default:
		return fmt.Errorf("a2aproxy: unknown public mode %q", c.PublicMode)
	}
	if c.SnapshotFile != "" && c.SnapshotURL != "" {
		return fmt.Errorf("a2aproxy: snapshot file and url are mutually exclusive")
	}
	if c.PublicMode == PublicModePath && c.GatewayPublicBase == "" {
		return fmt.Errorf("a2aproxy: gateway public base is required in path mode")
	}
	if c.SnapshotPoll <= 0 {
		c.SnapshotPoll = DefaultSnapshotPoll
	}
	if c.BackendTimeout <= 0 {
		c.BackendTimeout = DefaultBackendTimeout
	}
	if c.MaxResponseBytes <= 0 {
		c.MaxResponseBytes = DefaultMaxResponseBytes
	}
	if c.MaxIdleConns <= 0 {
		c.MaxIdleConns = DefaultMaxIdleConns
	}
	return nil
}

// ConfigFromEnv builds the configuration from environment variables.
// It is the deployment entry point; tests construct Config directly and may
// feed the snapshot store themselves.
func ConfigFromEnv() (*Config, error) {
	cfg := &Config{
		ListenAddr:         envOr("A2A_PROXY_ADDR", DefaultListenAddr),
		PublicMode:         PublicMode(envOr("A2A_PUBLIC_MODE", string(PublicModePath))),
		GatewayPublicBase:  os.Getenv("A2A_GATEWAY_PUBLIC_BASE"),
		TenantDomains:      parseTenantDomains(os.Getenv("A2A_TENANT_DOMAINS")),
		SnapshotFile:       os.Getenv("A2A_REGISTRY_SNAPSHOT_FILE"),
		SnapshotURL:        os.Getenv("A2A_REGISTRY_SNAPSHOT_URL"),
		SnapshotToken:      os.Getenv("A2A_REGISTRY_SNAPSHOT_TOKEN"),
		ForwardSkillHeader: os.Getenv("A2A_FORWARD_SKILL_HEADER") == "true",
		DevAllowLoopback:   os.Getenv("A2A_DEV_ALLOW_LOOPBACK_BACKEND") == "true",
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.SnapshotFile == "" && cfg.SnapshotURL == "" {
		return nil, fmt.Errorf("a2aproxy: A2A_REGISTRY_SNAPSHOT_FILE or A2A_REGISTRY_SNAPSHOT_URL is required")
	}
	return cfg, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parseTenantDomains parses "tenant-a=a2a.tenant-a.example.com,tenant-b=..."
// into a map. Malformed entries are rejected by the caller via Validate
// (host mode requires the mapping for the requested tenant).
func parseTenantDomains(raw string) map[string]string {
	if raw == "" {
		return nil
	}
	out := make(map[string]string)
	for _, entry := range splitComma(raw) {
		tenant, domain, ok := cutHalf(entry, "=")
		if !ok || tenant == "" || domain == "" {
			continue
		}
		out[tenant] = domain
	}
	return out
}

func splitComma(raw string) []string {
	var out []string
	start := 0
	for i := 0; i < len(raw); i++ {
		if raw[i] == ',' {
			out = append(out, raw[start:i])
			start = i + 1
		}
	}
	out = append(out, raw[start:])
	return out
}

func cutHalf(raw, sep string) (string, string, bool) {
	for i := 0; i+len(sep) <= len(raw); i++ {
		if raw[i:i+len(sep)] == sep {
			return raw[:i], raw[i+len(sep):], true
		}
	}
	return raw, "", false
}
