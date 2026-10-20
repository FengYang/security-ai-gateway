package a2aregistry

import (
	"encoding/json"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"

	"security-ai-gateway/gateway/a2aproxy"
)

// buildDetail 由记录构造详情响应（§3.2 AgentRecord schema）。
// card 为 nil 时从记录中的原始卡字节解析（列表路径）。
// includeBackend 控制 backend_url 是否回显（仅 admin 可见，§3.2）。
func buildDetail(rec *AgentRecord, card *sdk.AgentCard, publicURL, discoveryURL string, includeBackend bool) *AgentDetail {
	if card == nil {
		var c sdk.AgentCard
		if err := json.Unmarshal(rec.CardJSON, &c); err == nil {
			card = &c
		}
	}
	skills := make([]SkillSummary, 0)
	if card != nil {
		for i := range card.Skills {
			skills = append(skills, SkillSummary{ID: card.Skills[i].ID, Name: card.Skills[i].Name})
		}
	}
	d := &AgentDetail{
		Name:             rec.Name,
		ProviderID:       rec.ProviderID,
		Revision:         rec.Revision,
		RegistryRevision: rec.RegistryRevision,
		AgentVersion:     rec.AgentVersion,
		ContentHash:      rec.ContentHash,
		RawHash:          rec.RawHash,
		Signature: SignatureInfo{
			Kid:      rec.SignatureKid,
			Alg:      rec.SignatureAlg,
			Verified: rec.SignatureVerified,
		},
		PublicURL:    publicURL,
		DiscoveryURL: discoveryURL,
		Skills:       skills,
		Status:       rec.Status,
		Source:       "registry",
		Labels:       rec.Labels,
		CreatedAt:    rec.CreatedAt,
		UpdatedAt:    rec.UpdatedAt,
	}
	if includeBackend {
		d.BackendURL = rec.BackendURL
	}
	return d
}

// isAdminRole 判断角色是否可管理（a2a_admin / platform_admin）。
func isAdminRole(role string) bool {
	return role == RoleA2AAdmin || role == RolePlatformAdmin
}

// snapshotAgentOf 由记录构造数据面快照条目（§5.8）。
// 直接复用 a2aproxy.SnapshotAgent，保证控制面产出与数据面消费结构同源。
func snapshotAgentOf(rec *AgentRecord, publicURL, discoveryURL string) a2aproxy.SnapshotAgent {
	skills := make([]a2aproxy.SnapshotSkill, 0)
	var c sdk.AgentCard
	if err := json.Unmarshal(rec.CardJSON, &c); err == nil {
		for i := range c.Skills {
			skills = append(skills, a2aproxy.SnapshotSkill{ID: c.Skills[i].ID, Name: c.Skills[i].Name})
		}
	}
	status := "invalid"
	if rec.SignatureVerified {
		status = "valid"
	}
	return a2aproxy.SnapshotAgent{
		Tenant:          rec.Tenant,
		Name:            rec.Name,
		Revision:        uint64(rec.Revision),
		Card:            rec.CardJSON,
		PublicURL:       publicURL,
		DiscoveryURL:    discoveryURL,
		BackendURL:      rec.BackendURL,
		Skills:          skills,
		SignatureStatus: status,
		Labels:          rec.Labels,
	}
}
