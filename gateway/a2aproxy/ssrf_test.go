package a2aproxy

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestCheckBackendURL(t *testing.T) {
	cases := []struct {
		name      string
		url       string
		allowLoop bool
		wantErr   bool
	}{
		{"in-cluster private ok", "http://research-agent.team-research.svc.cluster.local:8080", false, false},
		{"https ok", "https://agent.example.com/a2a", false, false},
		{"loopback rejected", "http://127.0.0.1:9001/a2a", false, true},
		{"loopback allowed in dev", "http://127.0.0.1:9001/a2a", true, false},
		{"localhost rejected", "http://localhost:9001/a2a", false, true},
		{"link-local rejected", "http://169.254.169.254/latest/meta-data", false, true},
		{"ipv6 loopback rejected", "http://[::1]:9001/a2a", false, true},
		{"unspecified rejected", "http://0.0.0.0:9001/a2a", false, true},
		{"userinfo rejected", "http://user:pass@10.0.0.1:8080", false, true},
		{"ftp scheme rejected", "ftp://10.0.0.1:8080", false, true},
		{"empty host rejected", "http:///a2a", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckBackendURL(tc.url, tc.allowLoop)
			if tc.wantErr && err == nil {
				t.Fatalf("CheckBackendURL(%q) = nil, want error", tc.url)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("CheckBackendURL(%q) = %v, want nil", tc.url, err)
			}
			if tc.wantErr && err != nil && !strings.Contains(err.Error(), "forbidden") {
				t.Fatalf("error = %v, want errBackendForbidden", err)
			}
		})
	}
}

func TestNoCrossHostRedirectPolicy(t *testing.T) {
	via := []*http.Request{{URL: mustParseURL(t, "http://agent-a.example.com/x")}}
	if err := noCrossHostRedirect(&http.Request{URL: mustParseURL(t, "http://agent-a.example.com/y")}, via); err != nil {
		t.Fatalf("same-host redirect must pass: %v", err)
	}
	if err := noCrossHostRedirect(&http.Request{URL: mustParseURL(t, "http://evil.example.com/y")}, via); err == nil {
		t.Fatal("cross-host redirect must be refused")
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return u
}
