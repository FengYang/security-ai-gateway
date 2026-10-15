// Package main — N2 · 可信域与密钥生命周期管理（provider 凭据引用 + 密钥资产状态视图，§4.3.2）。
//
// 端点（租户会话前缀：TenantAuthMiddleware 双策略）：
//
//	GET /v1/adminext/tenant/secrets   密钥资产状态视图（只读；禁返回任何密钥材料）
//
// 归属边界（v1.7 澄清）：8 类密钥中**门户实际管理**仅 2 类——① 租户网关访问 JWT（表 ④，
// M3 覆盖）；② provider（cmaas）凭据**引用**（存表 ⑧ provider_cred_refs，仅 vault 句柄 +
// 元数据，禁明文）。其余 6 类（段① K_enc/K_sig、Seal 主密钥、审计锚点、attest-verify 证明
// 密钥、内部服务令牌、vault 封套）属 tee-infer / cryptopsvc / auth-service 侧资产，
// **门户仅登记状态、不持有、不落 tenant_store**（生命周期归架构图 §9.2 各组件）。
//
// 验收（V-S11）：8 类密钥的「门户管理 / 仅登记」归属标注正确；provider 凭据仅存 vault 引用句柄。
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// tenantSecretsPath 密钥资产视图端点路径。
const tenantSecretsPath = tenantSessionBase + "/secrets"

// 密钥归属标注（V-S11）。
const (
	keyOwnershipManaged    = "managed"    // 门户管理（实际持有凭据/引用）
	keyOwnershipRegistered = "registered" // 仅登记（门户不持有，展示状态）
)

// keyClassSpec 单类密钥归属规格（§4.3.2 全景表）。
type keyClassSpec struct {
	Class     string `json:"class"`     // 机器可读类名
	Label     string `json:"label"`     // 展示名
	Ownership string `json:"ownership"` // managed | registered
	Owner     string `json:"owner"`     // portal | tee-infer | cryptopsvc | auth-service | attest-verify
	Note      string `json:"note"`      // 生命周期要点
}

// tenantKeyClasses 8 类密钥归属全景（§4.3.2 表格逐行；新增须改此表——评审门禁）。
var tenantKeyClasses = []keyClassSpec{
	{"tenant_gateway_jwt", "租户网关访问 JWT（F2 自服务签发）", keyOwnershipManaged, "portal",
		"表 ④ api_keys（M3）；auth-service 经 CPS KeyRef otpmask/jwt/v1 签发；服务端仅存 jti + SHA-256 指纹，无解密面"},
	{"segment1_k_enc", "段① K_enc / K_sig", keyOwnershipRegistered, "tee-infer",
		"TEE 内 ECDH 派生，不离开 TEE，会话级（5min TTL）"},
	{"seal_master_key", "Seal 主密钥", keyOwnershipRegistered, "tee-infer",
		"-seal-file 或 OTPMASK_TDX_SEAL_KEY 注入，不落盘"},
	{"audit_anchor", "审计锚点（-audit-anchor）", keyOwnershipRegistered, "tee-infer",
		"链尾哈希；同宿主文件 / rfc3161 TSA"},
	{"attest_proof_key", "attest-verify 证明密钥", keyOwnershipRegistered, "attest-verify",
		"度量白名单 + TEE 度量比对"},
	{"internal_service_token", "内部服务令牌（签名器→tee-infer）", keyOwnershipRegistered, "auth-service",
		"部署期生成；同 Pod 回环注入 + tenant 绑定"},
	{"vault_envelope_key", "vault 封套密钥", keyOwnershipRegistered, "cryptopsvc",
		"KMS/HSM 管理"},
	{"provider_credential", "Provider（cmaas）凭据", keyOwnershipManaged, "portal",
		"表 ⑧ provider_cred_refs；仅 vault 句柄 + 元数据，禁明文"},
}

// providerCredRef provider 凭据引用（仅 vault 句柄 + 元数据；禁明文）。
type providerCredRef struct {
	Name      string `json:"name"`
	VaultRef  string `json:"vault_ref"`
	UpdatedAt int64  `json:"updated_at"`
}

// secretsView 密钥资产状态视图（只读）。
type secretsView struct {
	ProviderCredentials []providerCredRef `json:"provider_credentials"`
	KeyClasses          []keyClassSpec    `json:"key_classes"`
	ManagedCount        int               `json:"managed_count"`
	RegisteredCount     int               `json:"registered_count"`
}

// registerTenantSecretsMux 注册密钥资产视图端点（只读，无需 CSRF）。
func (h *tenantHandler) registerTenantSecretsMux(mux *http.ServeMux) {
	mux.HandleFunc("GET "+tenantSecretsPath, tenantAuthMiddleware(h.cfg, h.handleTenantSecrets))
}

// handleTenantSecrets 密钥资产状态视图（provider 凭据引用 + 8 类归属标注；禁返回密钥材料）。
func (h *tenantHandler) handleTenantSecrets(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	p, err := h.store.GetProvisioning(tenantID)
	if err != nil {
		log.Printf("[tenant-secrets] 读取开通配置失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	refs := []providerCredRef{}
	if p != nil && strings.TrimSpace(p.ProviderCredRefsJSON) != "" {
		if err := json.Unmarshal([]byte(p.ProviderCredRefsJSON), &refs); err != nil {
			log.Printf("[tenant-secrets] provider_cred_refs 解析失败 tenant=%s: %v", tenantID, err)
			refs = []providerCredRef{}
		}
	}
	if refs == nil {
		refs = []providerCredRef{}
	}

	managed, registered := 0, 0
	for _, kc := range tenantKeyClasses {
		switch kc.Ownership {
		case keyOwnershipManaged:
			managed++
		case keyOwnershipRegistered:
			registered++
		}
	}

	tenantWriteJSON(w, http.StatusOK, secretsView{
		ProviderCredentials: refs,
		KeyClasses:          tenantKeyClasses,
		ManagedCount:        managed,
		RegisteredCount:     registered,
	})
}

// validateProviderCredRefs 校验 provider 凭据引用（仅句柄 + 元数据；禁明文、禁重复名）。
func validateProviderCredRefs(refs []providerCredRef) (string, bool) {
	if len(refs) > 32 {
		return "provider 凭据引用条目过多（>32）", false
	}
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		name := strings.TrimSpace(ref.Name)
		if err := validateProviderName(name); err != nil {
			return fmt.Sprintf("provider 名称非法: %v", err), false
		}
		if _, dup := seen[name]; dup {
			return "provider 名称重复: " + name, false
		}
		seen[name] = struct{}{}
		vref := strings.TrimSpace(ref.VaultRef)
		if vref == "" || len(vref) > 256 {
			return "vault_ref 长度须为 1-256 字节", false
		}
		if strings.ContainsAny(vref, " \t\r\n") {
			return "vault_ref 不得含空白字符（须为 vault 句柄）", false
		}
	}
	return "", true
}

// normalizeProviderCredRefs 归一化引用（trim + 服务端补 updated_at）。
func normalizeProviderCredRefs(refs []providerCredRef, now int64) []providerCredRef {
	out := make([]providerCredRef, 0, len(refs))
	for _, ref := range refs {
		ref.Name = strings.TrimSpace(ref.Name)
		ref.VaultRef = strings.TrimSpace(ref.VaultRef)
		if ref.UpdatedAt == 0 {
			ref.UpdatedAt = now
		}
		out = append(out, ref)
	}
	return out
}

// marshalProviderCredRefs 序列化引用列表（落表 ⑧ provider_cred_refs）。
func marshalProviderCredRefs(refs []providerCredRef) (string, error) {
	if refs == nil {
		refs = []providerCredRef{}
	}
	b, err := json.Marshal(refs)
	if err != nil {
		return "", fmt.Errorf("tenant: 序列化 provider_cred_refs: %w", err)
	}
	return string(b), nil
}
