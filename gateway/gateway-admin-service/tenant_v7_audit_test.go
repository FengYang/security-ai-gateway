// V-7 验收（本体 §1.4 V-7 / 附录 D）：全部 16 个自助操作审计动作的落链矩阵。
//
//   - 逐动作驱动真实 handler（注册/登录/登出/重置/Key 三动作/策略/模型/套餐三动作/
//     开通/声明重签/下发重放），在管理面审计链（G1，SHA-256 链）上逐条断言；
//   - 断言字段符合附录 D：Target / KeyFingerprint / Detail（摘要口径）；
//   - 断言敏感明文（密码 / 明文 Key / 明文邮箱 / 策略具体词）绝不入链；
//   - tenantAuditActions 过滤枚举覆盖全部 16 动作（§6.7）。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
)

// v7AuditActions 附录 D 全部 16 个动作（字面量用于断言常量与文档一一对应）。
var v7AuditActions = []string{
	"tenant_register", "tenant_login", "tenant_logout", "password_reset",
	"api_key_create", "api_key_rotate", "api_key_revoke",
	"policy_update", "policy_apply", "model_config_update",
	"plan_upgrade", "plan_downgrade", "plan_bind",
	"provisioning_update", "statement_reissue", "dispatch_replay",
}

// parseAuditEvents 逐行解析审计链事件文件（JSON Lines）。
func parseAuditEvents(t *testing.T, path string) []adminAuditEvent {
	t.Helper()
	raw := readAudit(t, path)
	var out []adminAuditEvent
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var e adminAuditEvent
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("审计行解析失败: %v; line=%s", err, line)
		}
		out = append(out, e)
	}
	return out
}

// findAuditEvent 返回首个指定动作的事件（不存在 → nil）。
func findAuditEvent(events []adminAuditEvent, action string) *adminAuditEvent {
	for i := range events {
		if events[i].Action == action {
			return &events[i]
		}
	}
	return nil
}

// TestV7_AuditMatrix_16Actions 驱动附录 D 全部 16 动作并断言落链字段与禁入明文。
func TestV7_AuditMatrix_16Actions(t *testing.T) {
	const (
		userEmail = "v@example.com"
		userPass  = "Password123!"
		newPass   = "V7NewPass456!"
	)

	h, store, auditFile := newAuditTestHandler(t)

	// —— 计费域接线（plan_bind / plan_upgrade / plan_downgrade / model_config_update）——
	stub := newQuotaStub()
	srv := httptest.NewServer(stub.handler())
	defer srv.Close()
	bh := newBillingM6TestHandler(t, srv.URL, 2*time.Second)
	bh.audit = h.audit // 同一审计链（V-7 单文件矩阵断言）
	if err := billing.InitDefaultPlans(bh.store); err != nil {
		t.Fatalf("初始化默认套餐失败: %v", err)
	}
	h.binder = bh
	h.billing = bh

	// —— Key 签发通道（fake）与模型目录（临时 ai-route）——
	h.issuer = &fakeKeyIssuer{}
	routesDir := t.TempDir()
	writeAIRouteFile(t, routesDir, "ai-route-v7",
		`{"name":"v7","pathPredicate":{"matchType":"PRE","matchValue":"/v7"},"modelPredicates":[{"matchType":"EQUAL","matchValue":"gpt-4o-mini"}],"upstreams":[{"provider":"openai","weight":100}]}`)
	h.catalog = newModelCatalogHandler(&modelCatalogSettings{routesDir: routesDir})

	// —— 下发通道（dispatch_replay 用）——
	h.dispatch = newTestDispatcher(store, &fakeDispatchApplier{})

	// ---- ①tenant_register + ⑬plan_bind：验证通过（真实 binder 绑定 free 并落链）----
	tenantID, _, rawToken := seedPendingVerify(t, store)
	w := httptest.NewRecorder()
	h.handleVerify(w, postJSON("/api/verify", `{"email":"`+userEmail+`","token":"`+rawToken+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("verify 应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ②tenant_login ----
	w = httptest.NewRecorder()
	h.handleLogin(w, postJSON("/api/login", `{"email":"`+userEmail+`","password":"`+userPass+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("login 应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ③tenant_logout（CSRF 双提交）----
	logoutReq := tenantRequest("POST", "/v1/adminext/tenant/logout", "", tenantID, "u-v7")
	logoutReq.Header.Set("X-CSRF-Token", "csrf-v7")
	logoutReq.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-v7"})
	w = httptest.NewRecorder()
	csrfCheck(h.handleLogout)(w, logoutReq)
	if w.Code != http.StatusOK {
		t.Fatalf("logout 应 200, got=%d", w.Code)
	}

	// ---- ④password_reset（申请 + 确认）----
	fm, ok := h.mailer.(*fakeMailer)
	if !ok {
		t.Fatal("审计测试 harness 应带 fakeMailer")
	}
	w = httptest.NewRecorder()
	h.handlePasswordReset(w, postJSON("/v1/tenant/password-reset", `{"email":"`+userEmail+`"}`))
	if w.Code != http.StatusAccepted {
		t.Fatalf("重置申请应 202, got=%d body=%s", w.Code, w.Body.String())
	}
	if fm.lastResetToken == "" {
		t.Fatal("未生成重置令牌")
	}
	w = httptest.NewRecorder()
	h.handlePasswordResetConfirm(w, postJSON("/v1/tenant/password-reset/confirm",
		`{"email":"`+userEmail+`","token":"`+fm.lastResetToken+`","new_password":"`+newPass+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("重置确认应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ⑤⑥⑦api_key_create / api_key_rotate / api_key_revoke ----
	w = httptest.NewRecorder()
	h.handleKeyCreate(w, tenantRequest("POST", apiKeysPath, `{"name":"v7-key"}`, tenantID, "u-v7"))
	if w.Code != http.StatusOK {
		t.Fatalf("Key 创建应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var mk map[string]any
	if err := json.NewDecoder(w.Body).Decode(&mk); err != nil {
		t.Fatalf("解析创建响应失败: %v", err)
	}
	keyID, _ := mk["id"].(string)
	plainKeyCreate, _ := mk["api_key"].(string)
	if keyID == "" || plainKeyCreate == "" {
		t.Fatalf("创建响应缺字段: %+v", mk)
	}

	rotReq := tenantRequest("POST", apiKeysPath+"/"+keyID+"/rotate", "", tenantID, "u-v7")
	rotReq.SetPathValue("id", keyID)
	w = httptest.NewRecorder()
	h.handleKeyRotate(w, rotReq)
	if w.Code != http.StatusOK {
		t.Fatalf("Key 轮换应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var rot map[string]any
	if err := json.NewDecoder(w.Body).Decode(&rot); err != nil {
		t.Fatalf("解析轮换响应失败: %v", err)
	}
	newKeyID, _ := rot["id"].(string)
	plainKeyRotate, _ := rot["api_key"].(string)
	if newKeyID == "" || newKeyID == keyID || plainKeyRotate == "" {
		t.Fatalf("轮换应返回新 Key: %+v", rot)
	}

	revReq := tenantRequest("DELETE", apiKeysPath+"/"+newKeyID, "", tenantID, "u-v7")
	revReq.SetPathValue("id", newKeyID)
	w = httptest.NewRecorder()
	h.handleKeyRevoke(w, revReq)
	if w.Code != http.StatusOK {
		t.Fatalf("Key 吊销应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ⑧policy_update（具体词不入链，仅摘要）----
	polReq := tenantRequest("PUT", tenantPolicyPath, `{"whitelist":{"entries":[{"id":"e-1","kind":"literal","value":"v7-allow-word"}]},`+
		`"blacklist":{"entries":[{"id":"e-2","kind":"regex","value":"v7-blocked[0-9]+"}]},`+
		`"category_actions":{"pii_id_card":"mask","violence":"block"}}`, tenantID, "u-v7")
	polReq.Header.Set("If-Match", "0")
	w = httptest.NewRecorder()
	h.handleTenantPolicyPut(w, polReq)
	if w.Code != http.StatusOK {
		t.Fatalf("策略保存应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ⑨policy_apply（依赖未就绪 → 503 + 审计如实登记）----
	w = httptest.NewRecorder()
	h.handleTenantPolicyApply(w, tenantRequest("POST", tenantPolicyApplyPath, "{}", tenantID, "u-v7"))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("策略生效依赖未就绪应 503, got=%d", w.Code)
	}

	// ---- ⑩model_config_update（Target=default_model）----
	mcReq := tenantRequest("PUT", tenantModelsConfigPath,
		`{"allowed_models":["gpt-4o-mini"],"default_model":"gpt-4o-mini"}`, tenantID, "u-v7")
	mcReq.Header.Set("If-Match", "0")
	w = httptest.NewRecorder()
	h.handleTenantModelsConfigPut(w, mcReq)
	if w.Code != http.StatusOK {
		t.Fatalf("模型配置应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ⑪plan_upgrade（free → pro：登记待确认单）----
	w = httptest.NewRecorder()
	h.handleTenantSubscriptionUpgrade(w, tenantRequest("POST", tenantSubscriptionPath, `{"plan_id":"pro"}`, tenantID, "u-v7"))
	if w.Code != http.StatusOK {
		t.Fatalf("升级申请应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ⑫plan_downgrade（第二租户：先绑 pro，再降 basic，次月 1 日生效）----
	tid2, _ := seedTenantUser(t, store, "v7d@example.com", userPass, tenantUserStatusActive, tenantStatusActive)
	nowNs := time.Now().UnixNano()
	if err := bh.store.Plans().Bind(billing.Subscription{
		TenantID: tid2, PlanID: "pro", EffectiveAt: nowNs, BoundBy: "v7", BoundAt: nowNs,
	}); err != nil {
		t.Fatalf("预置 pro 订阅失败: %v", err)
	}
	w = httptest.NewRecorder()
	h.handleTenantSubscriptionUpgrade(w, tenantRequest("POST", tenantSubscriptionPath, `{"plan_id":"basic"}`, tid2, "u2"))
	if w.Code != http.StatusOK {
		t.Fatalf("降级申请应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ⑬provisioning_update（active 租户高敏变更：admin 接管 + 二次确认）----
	w = httptest.NewRecorder()
	h.handleTenantProvisioningPut(w, adminTakeoverRequest("PUT", tenantProvisioningPath,
		`{"scenario":"s1","trust_tier":"trusted","confirm":true}`, tenantID, "alice"))
	if w.Code != http.StatusOK {
		t.Fatalf("开通变更应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ⑭statement_reissue（admin 批量重签；上一步已产生 provisioning 行）----
	reissueReq := httptest.NewRequest("POST", adminStatementsReissuePath, nil)
	reissueReq = reissueReq.WithContext(withClaims(reissueReq.Context(), &claims{Sub: "alice", Role: roleAdmin}))
	w = httptest.NewRecorder()
	h.handleAdminStatementsReissue(w, reissueReq)
	if w.Code != http.StatusOK {
		t.Fatalf("声明重签应 200, got=%d body=%s", w.Code, w.Body.String())
	}

	// ---- ⑮dispatch_replay（admin 接管 + reason）----
	bump(t, store, tenantID)
	w = httptest.NewRecorder()
	h.handleDispatchReplay(w, adminTakeoverRequest("POST", tenantDispatchReplayPath, `{"reason":"v7 drill"}`, tenantID, "alice"))
	if w.Code != http.StatusOK {
		t.Fatalf("下发重放应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	h.dispatch.Wait()

	// ================= 断言 =================
	events := parseAuditEvents(t, auditFile)
	raw := readAudit(t, auditFile)

	// 1) 16 动作全部落链（缺一即失败）。
	for _, action := range v7AuditActions {
		if findAuditEvent(events, action) == nil {
			t.Errorf("动作 %s 未落链（附录 D 16 动作矩阵）", action)
		}
	}

	// 2) 逐动作字段（附录 D Target / KeyFingerprint / Detail 口径）。
	if e := findAuditEvent(events, auditActionTenantRegister); e != nil {
		if e.Target != tenantID {
			t.Errorf("tenant_register Target 应为 tenant_id=%s, got=%q", tenantID, e.Target)
		}
		if want := emailFingerprint(userEmail); e.KeyFingerprint != want {
			t.Errorf("tenant_register KeyFingerprint 应为邮箱哈希前缀 %s, got=%q", want, e.KeyFingerprint)
		}
	}
	if e := findAuditEvent(events, auditActionPlanBind); e != nil {
		if e.Target != "free" {
			t.Errorf("plan_bind Target 应为 plan_id=free, got=%q", e.Target)
		}
		if e.Tenant != tenantID {
			t.Errorf("plan_bind Tenant 应为 %s, got=%q", tenantID, e.Tenant)
		}
	}
	if e := findAuditEvent(events, auditActionTenantLogin); e != nil && e.Result != "ok" {
		t.Errorf("tenant_login 成功路径 Result 应为 ok, got=%q", e.Result)
	}
	if e := findAuditEvent(events, auditActionPasswordReset); e != nil {
		if want := emailFingerprint(userEmail); e.Actor != want {
			t.Errorf("password_reset Actor 应为邮箱哈希前缀（不落明文）, got=%q", e.Actor)
		}
	}
	if e := findAuditEvent(events, auditActionAPIKeyCreate); e != nil {
		if e.Target != keyID {
			t.Errorf("api_key_create Target 应为 key_id=%s, got=%q", keyID, e.Target)
		}
		if len(e.KeyFingerprint) != 8 {
			t.Errorf("api_key_create 指纹应为 SHA-256 前 8 位, got=%q", e.KeyFingerprint)
		}
	}
	if e := findAuditEvent(events, auditActionAPIKeyRotate); e != nil {
		if e.Target != newKeyID {
			t.Errorf("api_key_rotate Target 应为新 key_id=%s, got=%q", newKeyID, e.Target)
		}
		if e.KeyFingerprint == "" || len(e.KeyFingerprint) != 8 {
			t.Errorf("api_key_rotate 指纹应为新 Key 前 8 位, got=%q", e.KeyFingerprint)
		}
	}
	if e := findAuditEvent(events, auditActionAPIKeyRevoke); e != nil {
		if e.Target != newKeyID {
			t.Errorf("api_key_revoke Target 应为 key_id=%s, got=%q", newKeyID, e.Target)
		}
		if e.KeyFingerprint == "" || len(e.KeyFingerprint) != 8 {
			t.Errorf("api_key_revoke 指纹应为旧 Key 前 8 位, got=%q", e.KeyFingerprint)
		}
	}
	if e := findAuditEvent(events, auditActionPolicyUpdate); e != nil {
		if e.Target != "policy_overlay" {
			t.Errorf("policy_update Target 应为 policy_overlay, got=%q", e.Target)
		}
		if e.Tenant != tenantID {
			t.Errorf("policy_update Tenant 应为 %s, got=%q", tenantID, e.Tenant)
		}
		if !strings.Contains(e.Detail, "wl=1") || !strings.Contains(e.Detail, "bl=1") || !strings.Contains(e.Detail, "cat=2") {
			t.Errorf("policy_update Detail 应为条目数/类目数摘要（不存具体词）, got=%q", e.Detail)
		}
	}
	if e := findAuditEvent(events, auditActionPolicyApply); e != nil {
		if e.Target != "policy_overlay" {
			t.Errorf("policy_apply Target 应为 policy_overlay, got=%q", e.Target)
		}
		if e.Detail != "unavailable" {
			t.Errorf("policy_apply Detail 应如实登记依赖未就绪, got=%q", e.Detail)
		}
	}
	if e := findAuditEvent(events, auditActionModelConfigUpdate); e != nil {
		if e.Target != "gpt-4o-mini" {
			t.Errorf("model_config_update Target 应为 default_model, got=%q", e.Target)
		}
		if !strings.Contains(e.Detail, "allowed=gpt-4o-mini") {
			t.Errorf("model_config_update Detail 应含模型 ID 列表, got=%q", e.Detail)
		}
	}
	if e := findAuditEvent(events, auditActionPlanUpgrade); e != nil {
		if e.Target != "pro" {
			t.Errorf("plan_upgrade Target 应为 plan_id=pro, got=%q", e.Target)
		}
		if !strings.Contains(e.Detail, "free->pro") {
			t.Errorf("plan_upgrade Detail 应记升档前后, got=%q", e.Detail)
		}
	}
	if e := findAuditEvent(events, auditActionPlanDowngrade); e != nil {
		if e.Target != "basic" {
			t.Errorf("plan_downgrade Target 应为 plan_id=basic, got=%q", e.Target)
		}
		if !strings.Contains(e.Detail, "pro->basic") || !strings.Contains(e.Detail, "eff=") {
			t.Errorf("plan_downgrade Detail 应记降档前后与次月生效日, got=%q", e.Detail)
		}
	}
	if e := findAuditEvent(events, auditActionProvisioningUpdate); e != nil {
		if e.Target != tenantID {
			t.Errorf("provisioning_update Target 应为 tenant_id=%s, got=%q", tenantID, e.Target)
		}
		if e.Detail == "" {
			t.Error("provisioning_update Detail 应为场景/可信域档变更摘要")
		}
	}
	if e := findAuditEvent(events, auditActionStatementReissue); e != nil {
		if e.Target == "" {
			t.Error("statement_reissue Target 应为 statement_id")
		}
		if e.Tenant != tenantID {
			t.Errorf("statement_reissue Tenant 应为 %s, got=%q", tenantID, e.Tenant)
		}
		if !strings.Contains(e.Detail, "template_version=") {
			t.Errorf("statement_reissue Detail 应记模板版本, got=%q", e.Detail)
		}
	}
	if e := findAuditEvent(events, auditActionDispatchReplay); e != nil {
		if e.Target != tenantID {
			t.Errorf("dispatch_replay Target 应为 tenant_id=%s, got=%q", tenantID, e.Target)
		}
		if !strings.Contains(e.Detail, "reason=v7 drill") || !strings.Contains(e.Detail, "config_version=") {
			t.Errorf("dispatch_replay Detail 应记原因与版本, got=%q", e.Detail)
		}
	}

	// 3) 敏感明文绝不入链（附录 D 敏感字段处理）。
	for _, secret := range []string{userPass, newPass, plainKeyCreate, plainKeyRotate, userEmail, "v7-allow-word", "v7-blocked"} {
		if secret == "" {
			continue
		}
		if strings.Contains(raw, secret) {
			t.Errorf("审计链含敏感明文 %q（附录 D 禁止）", secret)
		}
	}
}

// TestV7_AuditActionsEnum_AppendixD §6.7 过滤枚举须覆盖附录 D 全部 16 动作。
func TestV7_AuditActionsEnum_AppendixD(t *testing.T) {
	for _, action := range v7AuditActions {
		if _, ok := tenantAuditActions[action]; !ok {
			t.Errorf("§6.7 审计过滤枚举缺附录 D 动作: %s", action)
		}
	}
	// 数据面动作仍须保留。
	for _, action := range []string{"infer", "deny", "key_issue"} {
		if _, ok := tenantAuditActions[action]; !ok {
			t.Errorf("§6.7 审计过滤枚举缺数据面动作: %s", action)
		}
	}
}
