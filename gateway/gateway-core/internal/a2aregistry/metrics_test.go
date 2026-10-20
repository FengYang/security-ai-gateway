package a2aregistry

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// T-5 可观测：注册中心控制面指标（§6.5）。
//
//	a2a_agent_registry_size{status}     注册 Agent 数（按生命周期状态；抓取时统计）
//	a2a_registry_revision                注册表全局 revision（Gauge，始终输出）
//	a2a_signature_failures_total{reason} 验签失败计数（按原因）

func renderRegistryMetrics(t *testing.T, reg *Registry) string {
	t.Helper()
	var sb strings.Builder
	reg.RenderMetrics(&sb)
	return sb.String()
}

// TestRegistryMetricsEmpty 空库：Gauge 恒输出（保证门禁可判「已注册」），大小为 0 系列。
func TestRegistryMetricsEmpty(t *testing.T) {
	reg := newTestRegistry(t)
	out := renderRegistryMetrics(t, reg)
	if !strings.Contains(out, "# TYPE a2a_agent_registry_size gauge") {
		t.Errorf("缺少 size gauge: %s", out)
	}
	if !strings.Contains(out, "a2a_registry_revision 0") {
		t.Errorf("空库 revision 应为 0（不伪造「已初始化」）: %s", out)
	}
	if !strings.Contains(out, "# TYPE a2a_signature_failures_total counter") {
		t.Errorf("缺少验签失败计数: %s", out)
	}
	if strings.Contains(out, `a2a_agent_registry_size{status=`) {
		t.Errorf("空库不应输出 status 系列: %s", out)
	}
}

// TestRegistryMetricsCountsAgents 注册后按生命周期状态计数、revision 随注册递增。
func TestRegistryMetricsCountsAgents(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	ctx := context.Background()

	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	detail, status, err := reg.Register(ctx, adminAuth("tenant-a"), "alice", "req-1", "trace-1", RegisterRequest{
		Name:       "research-agent",
		ProviderID: "team-research",
		Card:       card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}, "")
	if err != nil || status != http.StatusCreated {
		t.Fatalf("注册失败: %v (status=%d)", err, status)
	}

	out := renderRegistryMetrics(t, reg)
	if !strings.Contains(out, `a2a_agent_registry_size{status="active"} 1`) {
		t.Errorf("期望 1 个 active Agent: %s", out)
	}
	if strings.Contains(out, "a2a_registry_revision 0\n") {
		t.Errorf("注册后 revision 不应为 0: %s", out)
	}
	_ = detail
}

// TestRegistryMetricsSignatureFailure 验签失败按原因计数。
func TestRegistryMetricsSignatureFailure(t *testing.T) {
	reg := newTestRegistry(t)
	reg.Metrics().ObserveSignatureFailure(SigFailSignatureInvalid)
	reg.Metrics().ObserveSignatureFailure(SigFailSignatureInvalid)
	reg.Metrics().ObserveSignatureFailure(SigFailUnknownKey)
	reg.Metrics().ObserveSignatureFailure("")

	out := renderRegistryMetrics(t, reg)
	for _, want := range []string{
		`a2a_signature_failures_total{reason="signature_invalid"} 3`, // 含空 reason 归一
		`a2a_signature_failures_total{reason="unknown_key"} 1`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("渲染缺少 %q: %s", want, out)
		}
	}
}

// TestRegistryMetricsDegraded 存储不可用：观测降级而非拉取失败（仍输出全部指标族）。
func TestRegistryMetricsDegraded(t *testing.T) {
	reg := &Registry{store: NewUnavailable(), degraded: true, metrics: newMetrics()}
	out := renderRegistryMetrics(t, reg)
	for _, want := range []string{
		"# TYPE a2a_agent_registry_size gauge",
		"a2a_registry_revision 0",
		"# TYPE a2a_signature_failures_total counter",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("降级时缺少 %q: %s", want, out)
		}
	}
}
