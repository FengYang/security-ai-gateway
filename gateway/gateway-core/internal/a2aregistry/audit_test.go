package a2aregistry

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
)

// findEvent 在审计链中按 action 找第一条事件。
func findEvent(t *testing.T, chain *policyaudit.Chain, action string) *policyaudit.Event {
	t.Helper()
	for _, e := range chain.List(0) {
		if e.Action == action {
			ev := e
			return &ev
		}
	}
	return nil
}

// TestAuditEventCarriesFrozenFields 注册事件的审计字段集须符合冻结 §5.7。
func TestAuditEventCarriesFrozenFields(t *testing.T) {
	chain := &policyaudit.Chain{}
	reg := newTestRegistryWithAudit(t, chain)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	if _, _, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-9", RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}, ""); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	ev := findEvent(t, chain, "a2a.agent.register")
	if ev == nil {
		t.Fatal("审计链缺 a2a.agent.register 事件")
	}
	// §5.7 字段集逐项核对。
	if ev.Actor != "alice" {
		t.Fatalf("actor = %q, want alice", ev.Actor)
	}
	if ev.ActorTenant != "tenant-a" {
		t.Fatalf("actor_tenant = %q, want tenant-a", ev.ActorTenant)
	}
	if ev.TargetTenant != "tenant-a" {
		t.Fatalf("target_tenant = %q, want tenant-a", ev.TargetTenant)
	}
	if ev.Agent != "research-agent" {
		t.Fatalf("agent = %q, want research-agent", ev.Agent)
	}
	if ev.Provider != "team-research" {
		t.Fatalf("provider = %q, want team-research", ev.Provider)
	}
	if ev.OldRevision != 0 || ev.NewRevision != 1 {
		t.Fatalf("revision = %d→%d, want 0→1", ev.OldRevision, ev.NewRevision)
	}
	if ev.ContentHash == "" {
		t.Fatal("content_hash 不得为空")
	}
	if ev.Reason != "" {
		t.Fatalf("成功事件 reason 应为空，实际 %q", ev.Reason)
	}
	if ev.RequestID != "req-1" {
		t.Fatalf("request_id = %q, want req-1", ev.RequestID)
	}
	if ev.TraceID != "trace-9" {
		t.Fatalf("trace_id = %q, want trace-9", ev.TraceID)
	}
	if ev.Result != "ok" {
		t.Fatalf("result = %q, want ok", ev.Result)
	}
	// 不得回显卡正文。
	if ev.NewValue == string(card) {
		t.Fatal("审计事件不得回显卡正文")
	}
}

// TestAuditKeyEventUsesFingerprint 密钥事件只入公钥指纹（不回显材料）。
func TestAuditKeyEventUsesFingerprint(t *testing.T) {
	chain := &policyaudit.Chain{}
	reg := newTestRegistryWithAudit(t, chain)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)

	ev := findEvent(t, chain, "a2a.key.import")
	if ev == nil {
		t.Fatal("审计链缺 a2a.key.import 事件")
	}
	if ev.Field == "" {
		t.Fatal("密钥事件须带 kid/alg")
	}
	if ev.ContentHash == "" {
		t.Fatal("密钥事件须带公钥指纹")
	}
	// 指纹不得等于公钥原文。
	if ev.ContentHash == signer.jwkJSON {
		t.Fatal("审计事件不得回显公钥材料")
	}
	// field 形如 kid/alg。
	if ev.Field != "ed-1/EdDSA" {
		t.Fatalf("field = %q, want ed-1/EdDSA", ev.Field)
	}
}

// TestRejectedRegistrationIsAudited 治理拒绝（未信任 kid）须留痕。
func TestRejectedRegistrationIsAudited(t *testing.T) {
	chain := &policyaudit.Chain{}
	reg := newTestRegistryWithAudit(t, chain)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)

	other := newTestSigner(t, "ed-unknown")
	card := other.signedCard(t, "https://gateway.example.com/a2a/tenant-a/research-agent", "tenant-a", "research-agent")
	_, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-1", RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}, "")
	if err == nil {
		t.Fatal("未信任 kid 应被拒绝")
	}
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", status)
	}
	ev := findEvent(t, chain, "a2a.agent.register")
	if ev == nil {
		t.Fatal("治理拒绝未落审计链")
	}
	if ev.Result != "rejected" {
		t.Fatalf("result = %q, want rejected", ev.Result)
	}
	if ev.Reason != codeUntrustedKey {
		t.Fatalf("reason = %q, want %q", ev.Reason, codeUntrustedKey)
	}
	if ev.Actor != "alice" || ev.TargetTenant != "tenant-a" {
		t.Fatalf("拒绝事件身份字段异常: %+v", ev)
	}
	// 拒绝事件不得写入 agent 记录。
	detail, gstatus, gerr := reg.Get(adminAuth("tenant-a"), "research-agent")
	if gerr == nil && gstatus == http.StatusOK {
		t.Fatalf("被拒绝的注册不应入库: %+v", detail)
	}
}

// TestRejectedWithoutAuditChainFailsClosed 无审计链时治理拒绝 → fail-closed（503）。
func TestRejectedWithoutAuditChainFailsClosed(t *testing.T) {
	reg := newTestRegistryWithAudit(t, nil) // 显式无审计链
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)

	other := newTestSigner(t, "ed-unknown")
	card := other.signedCard(t, "https://gateway.example.com/a2a/tenant-a/research-agent", "tenant-a", "research-agent")
	_, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-1", RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}, "")
	if err == nil {
		t.Fatal("未信任 kid 应被拒绝")
	}
	// 无处留痕 → 不得放行，也不得当作已拒绝而 422：须 fail-closed。
	if status != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503（无审计链时治理拒绝须 fail-closed）", status)
	}
	var re *regError
	if !errors.As(err, &re) || re.Code != codeRegistryUnavailable {
		t.Fatalf("错误码 = %v, want %s", err, codeRegistryUnavailable)
	}
	// 事件须保留在 outbox 待重试（不静默丢弃）。
	rows, derr := reg.store.DrainOutbox(64)
	if derr != nil {
		t.Fatalf("排空 outbox 失败: %v", derr)
	}
	if len(rows) == 0 {
		t.Fatal("拒绝事件应保留在 outbox 待重试，不得静默丢弃")
	}
}

// TestUpdateAuditCarriesRevisionChange 更新事件须带 old/new revision。
func TestUpdateAuditCarriesRevisionChange(t *testing.T) {
	chain := &policyaudit.Chain{}
	reg := newTestRegistryWithAudit(t, chain)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	if _, _, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-1", RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}, ""); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	// 改后端（内容不变、后端变 → revision+1）。
	if _, _, err := reg.Replace(context.Background(), adminAuth("tenant-a"), "alice", "req-2", "trace-2", "research-agent",
		agentETag("research-agent", 1), RegisterRequest{
			Name: "research-agent", ProviderID: "team-research", Card: card,
			BackendURL: "http://agent2.team-research.svc.cluster.local:8080",
		}, ""); err != nil {
		t.Fatalf("更新失败: %v", err)
	}
	ev := findEvent(t, chain, "a2a.agent.update")
	if ev == nil {
		t.Fatal("审计链缺 a2a.agent.update 事件")
	}
	if ev.OldRevision != 1 || ev.NewRevision != 2 {
		t.Fatalf("revision = %d→%d, want 1→2", ev.OldRevision, ev.NewRevision)
	}
}
