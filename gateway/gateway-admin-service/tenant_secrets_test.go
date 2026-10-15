package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecretsView_Ownership(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "s1@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	w := httptest.NewRecorder()
	h.handleTenantSecrets(w, tenantRequest("GET", tenantSecretsPath, "", tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var v secretsView
	if err := json.NewDecoder(w.Body).Decode(&v); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(v.KeyClasses) != 8 {
		t.Fatalf("应为 8 类密钥, got=%d", len(v.KeyClasses))
	}
	if v.ManagedCount != 2 || v.RegisteredCount != 6 {
		t.Errorf("归属计数不对: managed=%d registered=%d", v.ManagedCount, v.RegisteredCount)
	}
	// 门户管理仅 2 类：租户网关访问 JWT + provider 凭据
	managed := map[string]bool{}
	for _, kc := range v.KeyClasses {
		if kc.Ownership == keyOwnershipManaged {
			managed[kc.Class] = true
		}
		if kc.Owner == "" || kc.Label == "" {
			t.Errorf("类目字段缺失: %+v", kc)
		}
	}
	if !managed["tenant_gateway_jwt"] || !managed["provider_credential"] || len(managed) != 2 {
		t.Errorf("门户管理类目不对: %+v", managed)
	}
	if v.ProviderCredentials == nil {
		t.Error("provider_credentials 应为非 nil 空数组")
	}
}

// TestSecretsView_NoKeyMaterial 响应体绝不含任何密钥材料字段。
func TestSecretsView_NoKeyMaterial(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "s2@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	w := httptest.NewRecorder()
	h.handleTenantSecrets(w, tenantRequest("GET", tenantSecretsPath, "", tid, "u1"))
	body := strings.ToLower(w.Body.String())
	for _, banned := range []string{"secret", "password", "private_key", "api_key\"", "\"sk-"} {
		if strings.Contains(body, banned) {
			t.Errorf("响应不应含密钥材料字段 %q", banned)
		}
	}
}

// TestSecretsView_ProviderRefsViaProvisioning provider 凭据引用经 N1 PUT 落库后可视（仅句柄）。
func TestSecretsView_ProviderRefsViaProvisioning(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "s3@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	body := `{"scenario":"s2","trust_tier":"trusted","provider_cred_refs":[
		{"name":"bailian","vault_ref":"vault://cmaas/bailian/t-1"}]}`
	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, body, tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("开通应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	w2 := httptest.NewRecorder()
	h.handleTenantSecrets(w2, tenantRequest("GET", tenantSecretsPath, "", tid, "u1"))
	var v secretsView
	json.NewDecoder(w2.Body).Decode(&v)
	if len(v.ProviderCredentials) != 1 {
		t.Fatalf("应有 1 条 provider 引用, got=%d", len(v.ProviderCredentials))
	}
	ref := v.ProviderCredentials[0]
	if ref.Name != "bailian" || ref.VaultRef != "vault://cmaas/bailian/t-1" {
		t.Errorf("引用不对: %+v", ref)
	}
	if ref.UpdatedAt == 0 {
		t.Error("updated_at 应由服务端补全")
	}
}

// TestValidateProviderCredRefs 校验：名称非法/重复、vault_ref 含空白/超长被拒。
func TestValidateProviderCredRefs(t *testing.T) {
	cases := []struct {
		name string
		refs []providerCredRef
		ok   bool
	}{
		{"ok", []providerCredRef{{Name: "bailian", VaultRef: "vault://x/1"}}, true},
		{"empty-name", []providerCredRef{{Name: "", VaultRef: "vault://x/1"}}, false},
		{"dup-name", []providerCredRef{{Name: "a", VaultRef: "v/:1"}, {Name: "a", VaultRef: "v/:2"}}, false},
		{"space-in-ref", []providerCredRef{{Name: "a", VaultRef: "vault:// x"}}, false},
		{"empty-ref", []providerCredRef{{Name: "a", VaultRef: ""}}, false},
		{"upper-name", []providerCredRef{{Name: "Bailian", VaultRef: "v/:1"}}, false},
	}
	for _, c := range cases {
		if _, ok := validateProviderCredRefs(c.refs); ok != c.ok {
			t.Errorf("%s: 期望 ok=%v", c.name, c.ok)
		}
	}
}

// TestProvisioningPut_InvalidProviderRefs 非法引用 → 400（不落库）。
func TestProvisioningPut_InvalidProviderRefs(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "s4@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	body := `{"scenario":"s2","trust_tier":"trusted","provider_cred_refs":[{"name":"bailian","vault_ref":"bad ref"}]}`
	w := httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, body, tid, "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法 vault_ref 应 400, got=%d body=%s", w.Code, w.Body.String())
	}
}
