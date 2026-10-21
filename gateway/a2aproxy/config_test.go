package a2aproxy

import (
	"testing"
	"time"
)

func TestValidateContentSafety(t *testing.T) {
	base := Config{
		PublicMode:        PublicModePath,
		GatewayPublicBase: "http://gateway.example",
	}
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{name: "disabled"},
		{name: "token without url", mutate: func(c *Config) { c.ContentSafetyToken = "t" }, wantErr: true},
		{name: "fail closed without url", mutate: func(c *Config) { c.ContentSafetyFailClosed = true }, wantErr: true},
		{name: "bad scheme", mutate: func(c *Config) { c.ContentSafetyURL = "ftp://guardrail/check" }, wantErr: true},
		{name: "valid", mutate: func(c *Config) {
			c.ContentSafetyURL = "http://guardrail:8087/v1/content/check"
			c.ContentSafetyToken = "t"
			c.ContentSafetyFailClosed = true
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			if tt.mutate != nil {
				tt.mutate(&cfg)
			}
			err := cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && cfg.ContentSafetyTimeout != DefaultContentSafetyTimeout {
				t.Fatalf("timeout = %s, want %s", cfg.ContentSafetyTimeout, DefaultContentSafetyTimeout)
			}
		})
	}
}

func TestConfigContentSafetyTimeoutOverride(t *testing.T) {
	cfg := Config{
		PublicMode:           PublicModePath,
		GatewayPublicBase:    "http://gateway.example",
		ContentSafetyURL:     "http://guardrail:8087/v1/content/check",
		ContentSafetyTimeout: 750 * time.Millisecond,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if cfg.ContentSafetyTimeout != 750*time.Millisecond {
		t.Fatalf("timeout = %s, want 750ms", cfg.ContentSafetyTimeout)
	}
}
