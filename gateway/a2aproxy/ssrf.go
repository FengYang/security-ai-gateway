package a2aproxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// errResponseTooLarge marks a backend response above the frozen 16 MiB cap.
var errResponseTooLarge = errors.New("a2aproxy: response too large")

// errBackendForbidden marks a backend URL rejected by the SSRF guard.
var errBackendForbidden = errors.New("a2aproxy: backend url forbidden")

// CheckBackendURL applies the frozen registration-time backend URL rules
// (F-5 §5.9): http/https only, no userinfo, no loopback/link-local/
// multicast/unspecified addresses. Private ranges are allowed because agent
// backends are in-cluster services. allowLoopback is the dev-only override.
func CheckBackendURL(raw string, allowLoopback bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("%w: invalid url: %v", errBackendForbidden, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q (only http/https)", errBackendForbidden, u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("%w: userinfo not allowed", errBackendForbidden)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("%w: empty host", errBackendForbidden)
	}
	if err := checkDialHost(host, allowLoopback); err != nil {
		return err
	}
	return nil
}

// checkDialHost rejects the address classes frozen by §5.9. DNS names are
// re-checked at dial time (see guardedDialContext) against the resolved IPs,
// which defeats DNS rebinding.
func checkDialHost(host string, allowLoopback bool) error {
	if ip := net.ParseIP(host); ip != nil {
		if err := checkDialIP(ip, allowLoopback); err != nil {
			return err
		}
		return nil
	}
	lower := strings.ToLower(strings.TrimSuffix(host, "."))
	if !allowLoopback && (lower == "localhost" || strings.HasSuffix(lower, ".localhost")) {
		return fmt.Errorf("%w: loopback host %q", errBackendForbidden, host)
	}
	return nil
}

func checkDialIP(ip net.IP, allowLoopback bool) error {
	if !allowLoopback && ip.IsLoopback() {
		return fmt.Errorf("%w: loopback address %s is not dialable", errBackendForbidden, ip)
	}
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("%w: address %s is not dialable", errBackendForbidden, ip)
	}
	return nil
}

// guardedDialContext resolves the host at dial time and validates every
// resolved address, so a DNS name that flips between a public and a
// loopback/private-metadata address cannot bypass the guard.
func guardedDialContext(ctx context.Context, network, addr string, allowLoopback bool) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: bad addr %q: %v", errBackendForbidden, addr, err)
	}
	if err := checkDialHost(host, allowLoopback); err != nil {
		return nil, err
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%w: resolve %q: %v", errBackendForbidden, host, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: no addresses for %q", errBackendForbidden, host)
	}
	for _, ip := range ips {
		if err := checkDialIP(ip, allowLoopback); err != nil {
			return nil, err
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ips[0].String(), port))
}

// guardedTransport is the backend HTTP transport: dial guard, no redirects
// across hosts (§5.9), bounded pool.
func guardedTransport(maxIdle int, allowLoopback bool) *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return guardedDialContext(ctx, network, addr, allowLoopback)
		},
		MaxIdleConns:          maxIdle,
		MaxIdleConnsPerHost:   maxIdle,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
}

// noCrossHostRedirect refuses redirects that change host; the agent backend
// must serve the JSON-RPC endpoint itself.
func noCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return errors.New("a2aproxy: too many redirects")
	}
	if len(via) > 0 && !strings.EqualFold(req.URL.Host, via[0].URL.Host) {
		return fmt.Errorf("%w: cross-host redirect to %s", errBackendForbidden, req.URL.Host)
	}
	return nil
}
