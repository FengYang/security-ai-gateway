// V-6 越权矩阵验收（本体 §9.1 Ⅰ/Ⅱ/Ⅲ）：租户侧端点的无声明拒绝、内部端点自然门禁、
// 路径遍历/方法逃逸/算法混淆加固，及「他租户参数」不得取到外部数据。
//
// 已由 M 系列测试覆盖的格子（usage/audit 强制注入、Key 跨租户 404、账单明细 404、
// admin 接管留痕、伪造 X-Tenant-ID 覆盖等）不重复；本文件补齐矩阵中其余逐格断言。
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestV6_MatrixI_TenantTokenOnInternalEndpoint_401：
// Ⅰ 矩阵「租户 A 会话 → 内部读端点」须 401（validRole 自然门禁，C-13）；
// 并覆盖 Ⅱ 矩阵「JWT 算法混淆（alg:none）」→ 401。
func TestV6_MatrixI_TenantTokenOnInternalEndpoint_401(t *testing.T) {
	cfg := testCfg()
	reached := false
	internal := authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		reached = true
		w.WriteHeader(http.StatusOK)
	})

	// 对照组：内部 auditor 令牌放行（机制有效，排除「一律 401」的假阳性）。
	okReq := httptest.NewRequest("GET", auditChainPath, nil)
	okReq.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{Sub: "aud-1", Role: roleAuditor}))
	w := httptest.NewRecorder()
	internal(w, okReq)
	if w.Code != http.StatusOK {
		t.Fatalf("auditor 内部令牌应放行（对照）, got=%d", w.Code)
	}

	// 租户 A 会话（role=tenant_user）→ 401。
	reached = false
	req := httptest.NewRequest("GET", auditChainPath, nil)
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{Sub: "u1", Role: tenantRole, Tenant: "t_A"}))
	w2 := httptest.NewRecorder()
	internal(w2, req)
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("租户令牌访问内部端点应 401, got=%d", w2.Code)
	}
	if reached {
		t.Error("租户令牌不得抵达内部 handler")
	}

	// alg:none 混淆（三段结构合法但无签名）→ 401。
	tenantMW := tenantAuthMiddleware(testCfg(), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	header := b64.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := b64.EncodeToString([]byte(`{"sub":"u1","tenant":"t_A","role":"tenant_user"}`))
	noneReq := httptest.NewRequest("GET", apiKeysPath, nil)
	noneReq.Header.Set("Authorization", "Bearer "+header+"."+payload+".")
	w3 := httptest.NewRecorder()
	tenantMW(w3, noneReq)
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("alg:none 混淆应 401, got=%d", w3.Code)
	}
}

// TestV6_MatrixI_NoTenantDeclaration_403：
// Ⅰ 矩阵「无 tenant 声明的租户令牌 → 403（L1）」逐端点组断言；
// 以及「内部 admin 无 target_tenant → 403（防全量枚举）」。
func TestV6_MatrixI_NoTenantDeclaration_403(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)

	cases := []struct {
		name   string
		method string
		path   string
		body   string
		call   func(*tenantHandler, http.ResponseWriter, *http.Request)
	}{
		{"keys 列表", "GET", apiKeysPath, "", (*tenantHandler).handleKeyList},
		{"usage", "GET", tenantUsagePath, "", (*tenantHandler).handleTenantUsage},
		{"bills 列表", "GET", tenantBillsPath, "", (*tenantHandler).handleTenantBills},
		{"bills 明细", "GET", tenantBillsPath + "/b-x", "", (*tenantHandler).handleTenantBillItem},
		{"policy 读", "GET", tenantPolicyPath, "", (*tenantHandler).handleTenantPolicyGet},
		{"policy 写", "PUT", tenantPolicyPath, "{}", (*tenantHandler).handleTenantPolicyPut},
		{"policy 生效", "POST", tenantPolicyApplyPath, "{}", (*tenantHandler).handleTenantPolicyApply},
		{"models", "GET", tenantModelsPath, "", (*tenantHandler).handleTenantModels},
		{"models 配置读", "GET", tenantModelsConfigPath, "", (*tenantHandler).handleTenantModelsConfigGet},
		{"audit", "GET", tenantAuditPath, "", (*tenantHandler).handleTenantAudit},
		{"plans", "GET", tenantPlansPath, "", (*tenantHandler).handleTenantPlans},
		{"subscription", "GET", tenantSubscriptionPath, "", (*tenantHandler).handleTenantSubscription},
		{"provisioning", "GET", tenantProvisioningPath, "", (*tenantHandler).handleTenantProvisioningGet},
		{"statement", "GET", tenantStatementPath, "", (*tenantHandler).handleTenantStatement},
		{"secrets", "GET", tenantSecretsPath, "", (*tenantHandler).handleTenantSecrets},
		{"attest", "GET", tenantAttestPath, "", (*tenantHandler).handleTenantAttest},
		{"dispatch 状态", "GET", tenantDispatchStatusPath, "", (*tenantHandler).handleDispatchStatus},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			// 令牌无 tenant 声明（防御纵深：即便越过中间件也不得放行）。
			tc.call(h, w, tenantRequest(tc.method, tc.path, tc.body, "", "u1"))
			if w.Code != http.StatusForbidden {
				t.Errorf("无 tenant 声明应 403（L1）, got=%d body=%s", w.Code, w.Body.String())
			}
		})
	}

	// 内部 admin 接管未携带 target_tenant（scope 空）→ 403，防全量枚举。
	adminReq := httptest.NewRequest("GET", tenantUsagePath, nil)
	adminReq = adminReq.WithContext(withTenantScope(adminReq.Context(),
		tenantScope{TenantID: "", IsAdmin: true, AdminSub: "alice"}))
	w := httptest.NewRecorder()
	h.handleTenantUsage(w, adminReq)
	if w.Code != http.StatusForbidden {
		t.Errorf("admin 无 target_tenant 应 403（防全量枚举）, got=%d", w.Code)
	}
}

// TestV6_MatrixII_PathTraversalIsolatedToSubtree：
// Ⅱ 矩阵「路径遍历 GET /tenant/keys/../audit-chain」→ 404/403，任何清洗重定向
// 都必须留在租户子树内（C-16 路由层隔离），不得抵达内部审计链端点。
func TestV6_MatrixII_PathTraversalIsolatedToSubtree(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	mux := http.NewServeMux()
	h.registerMux(mux)

	req := httptest.NewRequest("GET", "http://gw.local/v1/adminext/tenant/keys/../audit-chain", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	switch w.Code {
	case http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		loc := w.Header().Get("Location")
		if !strings.HasPrefix(loc, tenantSessionBase+"/") || strings.Contains(loc, "..") {
			t.Fatalf("路径遍历重定向逃逸租户子树: Location=%q", loc)
		}
	case http.StatusNotFound, http.StatusForbidden:
		// 直答拒绝，符合矩阵预期。
	default:
		t.Fatalf("路径遍历应 404/403（或子树内清洗重定向），got=%d body=%s", w.Code, w.Body.String())
	}
}

// TestV6_MatrixII_MethodEscapeAndListControl：
// Ⅱ 矩阵「HTTP 方法逃逸」：rotate 仅 POST，GET → 405；
// 对照：GET /tenant/keys 为合法列表端点，带租户会话须 200（不得误判逃逸）。
func TestV6_MatrixII_MethodEscapeAndListControl(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	mux := http.NewServeMux()
	h.registerMux(mux)

	req := httptest.NewRequest("GET", "http://gw.local"+apiKeysPath+"/k-3f9c2a/rotate", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET rotate 应 405, got=%d", w.Code)
	}

	// 列表端点对照：合法租户会话 → 200。
	token := newTenantJWT(h.jwtSecret, "u1", "t_1", "u@example.com", 3600)
	listReq := httptest.NewRequest("GET", "http://gw.local"+apiKeysPath, nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, listReq)
	if w2.Code != http.StatusOK {
		t.Fatalf("GET keys 列表应 200（合法列表端点）, got=%d body=%s", w2.Code, w2.Body.String())
	}
}

// TestV6_MatrixIII_ForeignTenantParamNoForeignData：
// Ⅲ 矩阵「他 tenant 参数」：租户 A 会话附带他租户参数时，端点仅返回 A 自身数据
// 或拒绝（C-1/C-15：过滤以令牌 tenant 声明为准，请求参数不得成为越权依据）。
func TestV6_MatrixIII_ForeignTenantParamNoForeignData(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	// models 端点依赖计费域（目录/套餐交集）；接线否则 503 而非 403/200。
	bh, _ := newTenantBillingTestHandler(t)
	h.billing = bh

	// A（t_1）的 Key 与策略；t_B 无任何数据。
	created := createKey(t, h, "v6-key")
	keyID, _ := created["id"].(string)
	polReq := tenantRequest("PUT", tenantPolicyPath,
		`{"whitelist":{"entries":[{"id":"e-1","kind":"literal","value":"v6-only-a"}]},"blacklist":{"entries":[]},"category_actions":{}}`,
		"t_1", "u1")
	polReq.Header.Set("If-Match", "0")
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, polReq)
	if w.Code != http.StatusOK {
		t.Fatalf("预置 A 策略失败: %d %s", w.Code, w.Body.String())
	}

	// keys 列表：?tenant=t_B 被忽略 → 200 且仅含 A 的 Key（「403 / 仅本租户」）。
	w = httptest.NewRecorder()
	h.handleKeyList(w, tenantRequest("GET", apiKeysPath+"?tenant=t_B", "", "t_1", "u1"))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), keyID) {
		t.Errorf("keys 附他租户参数应仅返回本租户数据: code=%d body=%s", w.Code, w.Body.String())
	}

	// policy 读：?tenant=t_B → 403，或 200 且返回 A 的策略（不得泄露 B/全量）。
	w = httptest.NewRecorder()
	h.handleTenantPolicyGet(w, tenantRequest("GET", tenantPolicyPath+"?tenant=t_B", "", "t_1", "u1"))
	if w.Code == http.StatusOK {
		if !strings.Contains(w.Body.String(), "v6-only-a") {
			t.Errorf("policy 附他租户参数应强制返回 A 的策略: %s", w.Body.String())
		}
	} else if w.Code != http.StatusForbidden {
		t.Errorf("policy 附他租户参数应 403 或返回本租户数据, got=%d", w.Code)
	}

	// models：?tenant=t_B → 403，或 200 本租户视图（catalog 未接线 = 空目录）。
	w = httptest.NewRecorder()
	h.handleTenantModels(w, tenantRequest("GET", tenantModelsPath+"?tenant=t_B", "", "t_1", "u1"))
	if w.Code != http.StatusOK && w.Code != http.StatusForbidden {
		t.Errorf("models 附他租户参数应 200（本租户）或 403, got=%d", w.Code)
	}
}
