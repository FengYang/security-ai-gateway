package a2aproxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/a2a"
	"security-ai-gateway/gateway/a2a/testagent"
)

// rlTestGov 复用 testGovernance 的鉴权/授权/观测（放行一切），将 RateLimit
// 委托给真实 RateLimitEngine，用于数据面 429/Retry-After 端到端验证。
type rlTestGov struct {
	*testGovernance
	engine *RateLimitEngine
}

func (g *rlTestGov) RateLimit(_ context.Context, tenant, agent, skill string) (int, error) {
	return g.engine.Allow(tenant, agent, skill)
}

// throttleHarness 构造带真实 RateLimitEngine 的数据面。
type throttleHarness struct {
	proxySrv *httptest.Server
	gov      *rlTestGov
	tenant   string
	agent    string
}

// newThrottleHarness 复用 newHarness 的注册快照构造，但治理替换为
// rlTestGov（testGovernance 放行 + 真实限流引擎 + 观测记录）。
func newThrottleHarness(t *testing.T, engine *RateLimitEngine) *throttleHarness {
	t.Helper()
	const (
		tenant = "tenant-a"
		agent  = "test-agent"
	)
	gwBase := "http://gateway.test"
	publicURL := gwBase + "/a2a/" + tenant + "/" + agent

	ag, err := testagent.New(testagent.Config{PublicURL: publicURL, Tenant: tenant, Name: "Test Agent"})
	if err != nil {
		t.Fatalf("testagent: %v", err)
	}
	agentSrv := httptest.NewServer(ag.Handler())
	t.Cleanup(agentSrv.Close)

	cardRaw, err := json.Marshal(ag.Card())
	if err != nil {
		t.Fatalf("marshal card: %v", err)
	}
	snapshots := NewSnapshotStore()
	snap := &Snapshot{
		RegistryRevision: 1,
		GeneratedAt:      time.Now().UTC(),
		Agents: []SnapshotAgent{{
			Tenant:          tenant,
			Name:            agent,
			Revision:        1,
			Card:            cardRaw,
			PublicURL:       publicURL,
			DiscoveryURL:    publicURL + "/.well-known/agent-card.json",
			BackendURL:      agentSrv.URL + "/a2a",
			Skills:          []SnapshotSkill{{ID: "hello_world", Name: "Hello World"}},
			SignatureStatus: "valid",
		}},
	}
	if err := snapshots.ForceReplace(snap); err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	gov := &rlTestGov{testGovernance: newTestGovernance(), engine: engine}

	cfg := Config{
		PublicMode:        PublicModePath,
		GatewayPublicBase: gwBase,
		DevAllowLoopback:  true,
	}
	proxy, err := New(cfg, snapshots, gov)
	if err != nil {
		t.Fatalf("proxy: %v", err)
	}
	t.Cleanup(proxy.Close)
	proxySrv := httptest.NewServer(proxy.Handler())
	t.Cleanup(proxySrv.Close)

	return &throttleHarness{proxySrv: proxySrv, gov: gov, tenant: tenant, agent: agent}
}

func (h *throttleHarness) send(t *testing.T, skillHeader string) (*http.Response, []byte) {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"SendMessage","params":{"message":{"messageId":"m-rl","role":"ROLE_USER","parts":[{"text":"x"}]}}}`
	req, err := http.NewRequest(http.MethodPost, h.proxySrv.URL+"/a2a/"+h.tenant+"/"+h.agent, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(a2a.HeaderVersion, a2a.SupportedVersion)
	req.Header.Set("X-Test-Tenant", h.tenant)
	if skillHeader != "" {
		req.Header.Set(a2a.HeaderSkill, skillHeader)
	}
	resp, err := h.proxySrv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(resp.Body)
	return resp, raw
}

// TestProxyRateLimitExactKey 数据面端到端：精确键 tenant|agent|skill 第 2 次超阈值 → 429 + Retry-After + throttled 审计。
func TestProxyRateLimitExactKey(t *testing.T) {
	engine := NewRateLimitEngine()
	if err := engine.Replace(&RateLimitTable{Version: 1, IssuedAt: time.Unix(1725500000, 0).UTC().Format(time.RFC3339), Rules: []RateLimitRule{
		{Tenant: "tenant-a", Agent: "test-agent", Skill: "hello_world", RPM: 1},
	}}); err != nil {
		t.Fatal(err)
	}
	h := newThrottleHarness(t, engine)

	// 第 1 次：放行（2xx）。
	resp1, _ := h.send(t, "hello_world")
	if resp1.StatusCode >= 400 {
		t.Fatalf("第1次应放行, status=%d", resp1.StatusCode)
	}
	// 第 2 次（同窗口）：限流 429 + Retry-After。
	resp2, body2 := h.send(t, "hello_world")
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("第2次应 429, status=%d body=%s", resp2.StatusCode, string(body2))
	}
	if ra := resp2.Header.Get("Retry-After"); ra == "" || ra == "0" {
		t.Fatalf("应包含 Retry-After > 0, got %q", ra)
	}
	// 观测到 throttled 审计事件（Result=throttled, HTTPStatus=429）。
	if !h.hasThrottledEvent() {
		t.Fatal("应观测到 Result=throttled 审计事件")
	}
}

// TestProxyRateLimitWildcardKey 数据面端到端：skill 不可得（"*"）→ 命中通配键 tenant|agent|* 限流。
func TestProxyRateLimitWildcardKey(t *testing.T) {
	engine := NewRateLimitEngine()
	if err := engine.Replace(&RateLimitTable{Version: 1, IssuedAt: time.Unix(1725500000, 0).UTC().Format(time.RFC3339), Rules: []RateLimitRule{
		{Tenant: "tenant-a", Agent: "test-agent", Skill: WildcardSkill, RPM: 1},
	}}); err != nil {
		t.Fatal(err)
	}
	h := newThrottleHarness(t, engine)

	// 不携带 skill（*）→ 通配键；第 1 次放行、第 2 次 429。
	resp1, _ := h.send(t, "")
	if resp1.StatusCode >= 400 {
		t.Fatalf("通配第1次应放行, status=%d", resp1.StatusCode)
	}
	resp2, body2 := h.send(t, "")
	if resp2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("通配第2次应 429, status=%d body=%s", resp2.StatusCode, string(body2))
	}
	if ra := resp2.Header.Get("Retry-After"); ra == "" {
		t.Fatal("通配限流应含 Retry-After")
	}
}

// hasThrottledEvent 检查观测事件中是否有 Result=throttled。
func (h *throttleHarness) hasThrottledEvent() bool {
	for _, ev := range h.gov.recorded() {
		if ev.Result == "throttled" && ev.HTTPStatus == http.StatusTooManyRequests {
			return true
		}
	}
	return false
}
