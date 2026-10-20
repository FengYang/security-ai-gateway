package a2aregistry

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
)

// adminAuth 构造 a2a_admin 身份。
func adminAuth(tenant string) Authn {
	return Authn{Tenant: tenant, Role: RoleA2AAdmin, Sub: "tester"}
}

// viewerAuth 构造 a2a_viewer 身份。
func viewerAuth(tenant string) Authn {
	return Authn{Tenant: tenant, Role: RoleA2AViewer, Sub: "viewer"}
}

// TestRegisterHappyPath 注册成功路径（含 revision/registry_revision/hash/URL）。
func TestRegisterHappyPath(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)

	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")

	detail, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1",
		"trace-1", RegisterRequest{
			Name:       "research-agent",
			ProviderID: "team-research",
			Card:       card,
			BackendURL: "http://agent.team-research.svc.cluster.local:8080",
			Labels:     map[string]string{"team": "research"},
		}, "")
	if err != nil {
		t.Fatalf("注册失败: %v (status=%d)", err, status)
	}
	if status != http.StatusCreated {
		t.Fatalf("status = %d, want 201", status)
	}
	if detail.Revision != 1 {
		t.Fatalf("revision = %d, want 1", detail.Revision)
	}
	if detail.RegistryRevision <= 0 {
		t.Fatalf("registry_revision = %d, want > 0", detail.RegistryRevision)
	}
	if !detail.Signature.Verified {
		t.Fatal("签名应验签通过")
	}
	if detail.Signature.Kid != "ed-1" || detail.Signature.Alg != "EdDSA" {
		t.Fatalf("签名元数据异常: %+v", detail.Signature)
	}
	if detail.ContentHash == "" || detail.RawHash == "" {
		t.Fatal("content_hash/raw_hash 不得为空")
	}
	if detail.PublicURL != publicURL {
		t.Fatalf("public_url = %q, want %q", detail.PublicURL, publicURL)
	}
	wantDiscovery := publicURL + "/.well-known/agent-card.json"
	if detail.DiscoveryURL != wantDiscovery {
		t.Fatalf("discovery_url = %q, want %q", detail.DiscoveryURL, wantDiscovery)
	}
	if len(detail.Skills) != 1 || detail.Skills[0].ID != "summarize" {
		t.Fatalf("skills 摘要异常: %+v", detail.Skills)
	}
	if detail.Status != "active" {
		t.Fatalf("status = %q, want active", detail.Status)
	}
}

// TestRegisterRejectsUntrustedSignature 未在信任库中的 kid → 422 untrusted_key。
func TestRegisterRejectsUntrustedSignature(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)

	// 另一把未导入的密钥
	other := newTestSigner(t, "ed-unknown")
	card := other.signedCard(t, "https://gateway.example.com/a2a/tenant-a/research-agent", "tenant-a", "research-agent")

	_, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1",
		"trace-1", RegisterRequest{
			Name: "research-agent", ProviderID: "team-research", Card: card,
			BackendURL: "http://agent.team-research.svc.cluster.local:8080",
		}, "")
	if err == nil {
		t.Fatal("未受信任 kid 的签名应被拒绝")
	}
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", status)
	}
	var re *regError
	if !errors.As(err, &re) || re.Code != codeUntrustedKey {
		t.Fatalf("错误码 = %v, want %s", err, codeUntrustedKey)
	}
}

// TestRegisterRejectsTamperedCard 篡改卡内容 → 验签失败（422 signature_invalid）。
func TestRegisterRejectsTamperedCard(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)

	card := signer.signedCard(t, "https://gateway.example.com/a2a/tenant-a/research-agent", "tenant-a", "research-agent")
	// 篡改 version（签名 payload 不含该改动 → 验签失败）
	tampered := tamperJSON(t, card, "version", "9.9.9")

	_, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1",
		"trace-1", RegisterRequest{
			Name: "research-agent", ProviderID: "team-research", Card: tampered,
			BackendURL: "http://agent.team-research.svc.cluster.local:8080",
		}, "")
	if err == nil {
		t.Fatal("篡改卡应被拒绝")
	}
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", status)
	}
	var re *regError
	if !errors.As(err, &re) || re.Code != codeSignatureInvalid {
		t.Fatalf("错误码 = %v, want %s", err, codeSignatureInvalid)
	}
}

// TestRegisterNameConflict 重复注册同名 → 409 name_conflict。
func TestRegisterNameConflict(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	req := RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}
	if _, _, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-1", req, ""); err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}
	_, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-2", "trace-1", req, "")
	if err == nil {
		t.Fatal("重复注册应冲突")
	}
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409", status)
	}
	var re *regError
	if !errors.As(err, &re) || re.Code != codeNameConflict {
		t.Fatalf("错误码 = %v, want %s", err, codeNameConflict)
	}
}

// TestRegisterRejectsInvalidName 非法名 / 保留词 → 400。
func TestRegisterRejectsInvalidName(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	for _, name := range []string{"Bad_Name", "-lead", "trail-", "api", "www", ""} {
		publicURL := "https://gateway.example.com/a2a/tenant-a/x"
		card := signer.signedCard(t, publicURL, "tenant-a", "x")
		_, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1",
			"trace-1", RegisterRequest{
				Name: name, ProviderID: "team-research", Card: card,
				BackendURL: "http://agent.team-research.svc.cluster.local:8080",
			}, "")
		if err == nil {
			t.Fatalf("name=%q 应被拒绝", name)
		}
		if status != http.StatusBadRequest {
			t.Fatalf("name=%q status = %d, want 400", name, status)
		}
	}
}

// TestRegisterRejectsLoopbackBackend loopback 后端 → 422 validation_failed。
func TestRegisterRejectsLoopbackBackend(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	_, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1",
		"trace-1", RegisterRequest{
			Name: "research-agent", ProviderID: "team-research", Card: card,
			BackendURL: "http://127.0.0.1:8080",
		}, "")
	if err == nil {
		t.Fatal("loopback 后端应被拒绝")
	}
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", status)
	}
}

// TestRegisterRequiresAdmin viewer 角色注册 → 403。
func TestRegisterRequiresAdmin(t *testing.T) {
	reg := newTestRegistry(t)
	_, status, err := reg.Register(context.Background(), viewerAuth("tenant-a"), "v", "req-1",
		"trace-1", RegisterRequest{Name: "a", ProviderID: "p", Card: []byte(`{}`), BackendURL: "http://x.svc:80"}, "")
	if err == nil {
		t.Fatal("viewer 不应能注册")
	}
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", status)
	}
}

// TestTenantIsolation 不同租户不可见（同名 agent 在另一租户不存在）。
func TestTenantIsolation(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	if _, _, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1",
		"trace-1", RegisterRequest{
			Name: "research-agent", ProviderID: "team-research", Card: card,
			BackendURL: "http://agent.team-research.svc.cluster.local:8080",
		}, ""); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	// 另一租户看不到
	_, status, err := reg.Get(viewerAuth("tenant-b"), "research-agent")
	if err == nil {
		t.Fatal("跨租户不应可见")
	}
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
	// 另一租户不能覆盖
	_, status, err = reg.Replace(context.Background(), adminAuth("tenant-b"), "bob", "req-2", "trace-1", "research-agent",
		agentETag("research-agent", 1), RegisterRequest{
			Name: "research-agent", ProviderID: "team-research", Card: card,
			BackendURL: "http://agent.team-research.svc.cluster.local:8080",
		}, "")
	if err == nil {
		t.Fatal("跨租户不应能覆盖")
	}
	if status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", status)
	}
}

// TestReplacePreconditions 缺 If-Match → 428；不匹配 → 412；内容变更 → revision+1。
func TestReplacePreconditions(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	req := RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}
	if _, _, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-1", req, ""); err != nil {
		t.Fatalf("注册失败: %v", err)
	}

	// 缺 If-Match
	_, status, err := reg.Replace(context.Background(), adminAuth("tenant-a"), "alice", "req-2", "trace-1", "research-agent", "", req, "")
	if err == nil {
		t.Fatal("缺 If-Match 应被拒绝")
	}
	if status != http.StatusPreconditionRequired {
		t.Fatalf("status = %d, want 428", status)
	}
	var re *regError
	if !errors.As(err, &re) || re.Code != codePreconditionRequired {
		t.Fatalf("错误码 = %v, want %s", err, codePreconditionRequired)
	}

	// If-Match 不匹配
	_, status, err = reg.Replace(context.Background(), adminAuth("tenant-a"), "alice", "req-3", "trace-1", "research-agent",
		agentETag("research-agent", 99), req, "")
	if err == nil {
		t.Fatal("If-Match 不匹配应被拒绝")
	}
	if status != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412", status)
	}
	if !errors.As(err, &re) || re.Code != codeRevisionConflict {
		t.Fatalf("错误码 = %v, want %s", err, codeRevisionConflict)
	}

	// 内容变更 → revision+1
	card2 := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	card2 = tamperJSON(t, card2, "version", "2.2.0")
	// 变更 version 会使签名失效 → 用重新签名代替
	card2 = signer.signedCardWithVersion(t, publicURL, "tenant-a", "research-agent", "2.2.0")
	det, status, err := reg.Replace(context.Background(), adminAuth("tenant-a"), "alice", "req-4", "trace-1", "research-agent",
		agentETag("research-agent", 1), RegisterRequest{
			Name: "research-agent", ProviderID: "team-research", Card: card2,
			BackendURL: "http://agent.team-research.svc.cluster.local:8080",
		}, "")
	if err != nil {
		t.Fatalf("替换失败: %v (status=%d)", err, status)
	}
	if det.Revision != 2 {
		t.Fatalf("revision = %d, want 2", det.Revision)
	}
	if det.RegistryRevision <= 1 {
		t.Fatalf("registry_revision = %d, want > 1", det.RegistryRevision)
	}
}

// TestReplaceIdempotentSameContent 相同内容 PUT → revision 不变。
func TestReplaceIdempotentSameContent(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	req := RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}
	if _, _, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-1", req, ""); err != nil {
		t.Fatalf("注册失败: %v", err)
	}
	det, _, err := reg.Replace(context.Background(), adminAuth("tenant-a"), "alice", "req-2", "trace-1", "research-agent",
		agentETag("research-agent", 1), req, "")
	if err != nil {
		t.Fatalf("替换失败: %v", err)
	}
	if det.Revision != 1 {
		t.Fatalf("相同内容 PUT 应保持 revision=1，实际 %d", det.Revision)
	}
}

// TestDeleteSoftDeletes 删除 → 软删墓碑，列表不含，include_deleted 可见。
func TestDeleteSoftDeletes(t *testing.T) {
	reg := newTestRegistry(t)
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
	status, err := reg.Delete(adminAuth("tenant-a"), "alice", "req-2", "trace-1", "research-agent", agentETag("research-agent", 1))
	if err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204", status)
	}
	// 默认列表不含
	items, _, err := reg.List(viewerAuth("tenant-a"), "", "", "", false, 0, "")
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("删除后列表应为空，实际 %d", len(items))
	}
	// include_deleted 可见
	items, _, err = reg.List(viewerAuth("tenant-a"), "", "", "", true, 0, "")
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(items) != 1 || items[0].Status != "deleted" {
		t.Fatalf("include_deleted 应可见墓碑：%+v", items)
	}
	// 恢复：PUT + If-Match → revision+1，审计 restore
	det, _, err := reg.Replace(context.Background(), adminAuth("tenant-a"), "alice", "req-3", "trace-1", "research-agent",
		agentETag("research-agent", 1), RegisterRequest{
			Name: "research-agent", ProviderID: "team-research", Card: card,
			BackendURL: "http://agent.team-research.svc.cluster.local:8080",
		}, "")
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if det.Revision != 2 || det.Status != "active" {
		t.Fatalf("恢复后 revision=%d status=%q，want 2/active", det.Revision, det.Status)
	}
}

// TestIdempotencySameBodySameResponse 同 key 同 body → 同响应。
// TestIdempotencyDifferentBodyConflict 同 key 不同 body → 409 idempotency_conflict。
func TestIdempotencySameBodySameResponse(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	req := RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}
	first, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-1", req, "idem-key-0001")
	if err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}
	if status != http.StatusCreated {
		t.Fatalf("首次 status = %d, want 201", status)
	}
	second, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-2", "trace-1", req, "idem-key-0001")
	if err != nil {
		t.Fatalf("幂等重放失败: %v", err)
	}
	if status != http.StatusOK {
		t.Fatalf("幂等重放 status = %d, want 200", status)
	}
	if second.Revision != first.Revision || second.ContentHash != first.ContentHash {
		t.Fatalf("幂等重放响应不一致：%+v vs %+v", first, second)
	}
}

func TestIdempotencyDifferentBodyConflict(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-a/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-a", "research-agent")
	req := RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}
	if _, _, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-1", req, "idem-key-0001"); err != nil {
		t.Fatalf("首次注册失败: %v", err)
	}
	card2 := signer.signedCardWithVersion(t, publicURL, "tenant-a", "research-agent", "3.0.0")
	_, status, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-2", "trace-1", RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card2,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}, "idem-key-0001")
	if err == nil {
		t.Fatal("同 key 不同 body 应冲突")
	}
	if status != http.StatusConflict {
		t.Fatalf("status = %d, want 409", status)
	}
	var re *regError
	if !errors.As(err, &re) || re.Code != codeIdempotencyConflict {
		t.Fatalf("错误码 = %v, want %s", err, codeIdempotencyConflict)
	}
}

// TestKeyRevokeRemovesAgentFromSnapshot 吊销密钥 → 受影响 agent 验签失败并移出快照。
func TestKeyRevokeRemovesAgentFromSnapshot(t *testing.T) {
	reg := newTestRegistry(t)
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
	// 快照含该 agent
	snap, _, err := reg.BuildSnapshot(context.Background())
	if err != nil {
		t.Fatalf("构建快照失败: %v", err)
	}
	if len(snap.Agents) != 1 {
		t.Fatalf("快照 agent 数 = %d, want 1", len(snap.Agents))
	}
	if snap.Agents[0].SignatureStatus != "valid" {
		t.Fatalf("signature_status = %q, want valid", snap.Agents[0].SignatureStatus)
	}
	// 吊销密钥
	if _, err := reg.RevokeKey(context.Background(), adminAuth("tenant-a"), "alice", "req-2", "trace-1", "team-research", "ed-1"); err != nil {
		t.Fatalf("吊销密钥失败: %v", err)
	}
	// 快照不再含该 agent（fail-closed）
	snap, _, err = reg.BuildSnapshot(context.Background())
	if err != nil {
		t.Fatalf("构建快照失败: %v", err)
	}
	if len(snap.Agents) != 0 {
		t.Fatalf("吊销后快照应不含该 agent，实际 %d", len(snap.Agents))
	}
	// 重验返回 422
	status, err := reg.Verify(context.Background(), adminAuth("tenant-a"), "alice", "req-3", "trace-1", "research-agent")
	if err == nil {
		t.Fatal("吊销后重验应失败")
	}
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", status)
	}
}

// TestSnapshotOnlyActiveAndVerified 快照仅含 active + 验签通过者。
func TestSnapshotOnlyActiveAndVerified(t *testing.T) {
	reg := newTestRegistry(t)
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
	if _, err := reg.Delete(adminAuth("tenant-a"), "alice", "req-2", "trace-1", "research-agent", agentETag("research-agent", 1)); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	snap, _, err := reg.BuildSnapshot(context.Background())
	if err != nil {
		t.Fatalf("构建快照失败: %v", err)
	}
	if len(snap.Agents) != 0 {
		t.Fatalf("已删除 agent 不应进快照，实际 %d", len(snap.Agents))
	}
}

// TestBackendURLNotEchoedToViewer viewer 不可见 backend_url。
func TestBackendURLNotEchoedToViewer(t *testing.T) {
	reg := newTestRegistry(t)
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
	det, _, err := reg.Get(viewerAuth("tenant-a"), "research-agent")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if det.BackendURL != "" {
		t.Fatalf("viewer 不得看到 backend_url，实际 %q", det.BackendURL)
	}
	admin, _, err := reg.Get(adminAuth("tenant-a"), "research-agent")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if admin.BackendURL == "" {
		t.Fatal("admin 应可见 backend_url")
	}
}

// TestPlatformAdminTargetTenant platform_admin 可经 X-GA-Tenant 指定目标租户。
func TestPlatformAdminTargetTenant(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-b", "team-research", signer)
	publicURL := "https://gateway.example.com/a2a/tenant-b/research-agent"
	card := signer.signedCard(t, publicURL, "tenant-b", "research-agent")
	authn := Authn{Role: RolePlatformAdmin, Sub: "root", Target: "tenant-b"}
	if _, _, err := reg.Register(context.Background(), authn, "root", "req-1", "trace-1", RegisterRequest{
		Name: "research-agent", ProviderID: "team-research", Card: card,
		BackendURL: "http://agent.team-research.svc.cluster.local:8080",
	}, ""); err != nil {
		t.Fatalf("platform_admin 注册失败: %v", err)
	}
	// 无 X-GA-Tenant 且自身无 tenant → 拒绝
	noTarget := Authn{Role: RolePlatformAdmin, Sub: "root"}
	_, status, err := reg.Get(noTarget, "research-agent")
	if err == nil {
		t.Fatal("platform_admin 未指定目标租户应被拒绝")
	}
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", status)
	}
}

// TestListFilters 列表过滤（name_prefix / skill / limit）。
func TestListFilters(t *testing.T) {
	reg := newTestRegistry(t)
	signer := newTestSigner(t, "ed-1")
	importKey(t, reg, "tenant-a", "team-research", signer)
	for _, name := range []string{"alpha", "beta", "gamma"} {
		publicURL := "https://gateway.example.com/a2a/tenant-a/" + name
		card := signer.signedCard(t, publicURL, "tenant-a", name)
		if _, _, err := reg.Register(context.Background(), adminAuth("tenant-a"), "alice", "req-1", "trace-1", RegisterRequest{
			Name: name, ProviderID: "team-research", Card: card,
			BackendURL: "http://agent.team-research.svc.cluster.local:8080",
		}, ""); err != nil {
			t.Fatalf("注册 %s 失败: %v", name, err)
		}
	}
	items, _, err := reg.List(viewerAuth("tenant-a"), "b", "", "", false, 0, "")
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(items) != 1 || items[0].Name != "beta" {
		t.Fatalf("name_prefix 过滤异常: %+v", items)
	}
	items, _, err = reg.List(viewerAuth("tenant-a"), "", "summarize", "", false, 0, "")
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(items) != 3 {
		t.Fatalf("skill 过滤应命中全部 3 个，实际 %d", len(items))
	}
	items, _, err = reg.List(viewerAuth("tenant-a"), "", "", "", false, 2, "")
	if err != nil {
		t.Fatalf("列表失败: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("limit 应生效，实际 %d", len(items))
	}
}

// TestStoreRevisionMonotonic registry_revision 单调递增。
func TestStoreRevisionMonotonic(t *testing.T) {
	reg := newTestRegistry(t)
	before := reg.store.GetRegistryRevision()
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
	after := reg.store.GetRegistryRevision()
	if after <= before {
		t.Fatalf("registry_revision 应递增：before=%d after=%d", before, after)
	}
}

// TestAuditOutboxDrained 变更后审计事件进入既有审计链（outbox 排空，不丢）。
func TestAuditOutboxDrained(t *testing.T) {
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
	rows, err := reg.store.DrainOutbox(64)
	if err != nil {
		t.Fatalf("排空 outbox 失败: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("审计链可用时 outbox 应排空，实际剩余 %d", len(rows))
	}
	// 审计链中应含注册与密钥导入事件
	events := chain.List(0)
	actions := map[string]bool{}
	for _, e := range events {
		actions[e.Action] = true
	}
	if !actions["a2a.key.import"] {
		t.Fatalf("审计链缺 a2a.key.import 事件：%+v", events)
	}
	if !actions["a2a.agent.register"] {
		t.Fatalf("审计链缺 a2a.agent.register 事件：%+v", events)
	}
	ok, idx := chain.Verify()
	if !ok {
		t.Fatalf("审计链断裂于第 %d 条", idx)
	}
}

// TestAuditOutboxRetainedWithoutChain 无审计链时事件保留在 outbox（不静默丢弃）。
func TestAuditOutboxRetainedWithoutChain(t *testing.T) {
	reg := newTestRegistryWithAudit(t, nil) // 显式无审计链
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
	rows, err := reg.store.DrainOutbox(64)
	if err != nil {
		t.Fatalf("排空 outbox 失败: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("无审计链时事件应保留在 outbox 待重试，不得静默丢弃")
	}
}

// tamperJSON 修改卡片中的某个顶层字段（用于构造篡改用例）。
func tamperJSON(t *testing.T, raw []byte, key string, value any) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("解析卡片失败: %v", err)
	}
	m[key] = value
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	return out
}
