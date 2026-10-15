// Package main — N4 · 承诺边界声明单测（§4.3.4，V-S5）。
//
// 覆盖：红线校验（A 型无"端到端"、S3-b 无"整链在 TEE 内"、S2 强制"未闭环"、全局禁词）、
// 声明生成与存证（supersedes 重签链）、租户读取端点、运维批量重签发与 statement_reissue 审计。
package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// provisionForTest 直接写入开通配置（表 ⑧），供 N4 声明测试用。
func provisionForTest(t *testing.T, store *sqliteTenantStore, tid, scenario, trust string) {
	t.Helper()
	spec, ok := lookupScenario(scenario)
	if !ok {
		t.Fatalf("未知场景 %s", scenario)
	}
	chain, ver, err := renderPluginSet(scenario)
	if err != nil {
		t.Fatal(err)
	}
	pj, err := marshalPluginSet(chain)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := store.UpsertProvisioning(tx, &TenantProvisioning{
		TenantID: tid, Scenario: scenario, TrustTier: trust, AccessMode: spec.AccessMode,
		PluginSetJSON: pj, Segment1Enabled: spec.Segment1, Segment2Mode: spec.Segment2Mode,
		TemplateVersion: ver, ProviderCredRefsJSON: "[]", ProvisionedAt: 1, UpdatedAt: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// ---------- 生成与红线校验 ----------

func TestRenderStatementContent_AllScenariosRedlineClean(t *testing.T) {
	for _, scenario := range []string{scenarioS1, scenarioS2, scenarioS3a, scenarioS3b, scenarioS4} {
		t.Run(scenario, func(t *testing.T) {
			content, hash, ver, err := renderStatementContent(StatementInput{
				TenantID: "t_1", Scenario: scenario, TrustTier: trustTierTrusted, GeneratedAt: 7,
			})
			if err != nil {
				t.Fatalf("生成应通过红线校验: %v", err)
			}
			if ver != statementTemplateVersion {
				t.Errorf("模板版本应=%s, got=%s", statementTemplateVersion, ver)
			}
			if hash != sha256Hex(content) {
				t.Error("content_hash 应为 SHA-256(content)")
			}
			if strings.Contains(content, "端到端") {
				t.Errorf("A 型声明不得含“端到端”: %s", content)
			}
			if scenario == scenarioS2 && !strings.Contains(content, "未闭环") {
				t.Errorf("S2 声明必须披露未闭环: %s", content)
			}
			if scenario == scenarioS3b && strings.Contains(content, "整链在 TEE 内") {
				t.Errorf("S3-b 声明不得含“整链在 TEE 内”: %s", content)
			}
		})
	}
}

func TestCheckStatementRedlines(t *testing.T) {
	cases := []struct {
		name       string
		scenario   string
		accessMode string
		content    string
		wantErr    bool
	}{
		{"A型含端到端", scenarioS1, accessModeASegmented, "本服务端到端加密", true},
		{"S3b含整链在TEE内", scenarioS3b, accessModeASegmented, "整链在 TEE 内完成", true},
		{"S3b含整条链路在TEE内", scenarioS3b, accessModeASegmented, "整条链路在 TEE 内", true},
		{"S2缺未闭环", scenarioS2, accessModeASegmented, "分段密态，无其它说明", true},
		{"S2含未闭环合法", scenarioS2, accessModeASegmented, "证明未闭环，仅供参考", false},
		{"官方合作禁词", scenarioS1, accessModeASegmented, "某某官方合作背书", true},
		{"官方认证禁词", scenarioS1, accessModeASegmented, "获得官方认证", true},
		{"转售禁词", scenarioS1, accessModeASegmented, "允许转售", true},
		{"S3b合法", scenarioS3b, accessModeASegmented, "明文不出扩展信任域", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := checkStatementRedlines(c.scenario, c.accessMode, c.content)
			if c.wantErr && err == nil {
				t.Errorf("应红线拒绝: %q", c.content)
			}
			if !c.wantErr && err != nil {
				t.Errorf("不应拒绝: %v", err)
			}
		})
	}
}

func TestBuildStatementContent_UnknownScenario(t *testing.T) {
	if _, err := buildStatementContent(StatementInput{TenantID: "t_1", Scenario: "s9"}); err == nil {
		t.Error("未知场景应报错")
	}
}

func TestStatementDisclosures(t *testing.T) {
	s3b := strings.Join(statementDisclosures(scenarioS3b, trustTierTrusted), " ")
	if !strings.Contains(s3b, "Q-9") || strings.Contains(s3b, "整链在 TEE 内") {
		t.Errorf("S3-b 披露应含 Q-9 且不含整链承诺: %s", s3b)
	}
	untrusted := strings.Join(statementDisclosures(scenarioS4, trustTierUntrusted), " ")
	if !strings.Contains(untrusted, "TEE 化") {
		t.Errorf("非可信基础设施应披露门户 TEE 化（N10）: %s", untrusted)
	}
}

// ---------- 存证与 supersedes 链 ----------

func TestReissueStatement_SupersedesChain(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "n4a@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, store, tid, scenarioS3a, trustTierTrusted)
	h := newTenantHandler(store, testTenantCfg(), nil, nil, nil, nil, nil)

	id1, err := h.reissueStatementCore(tid, "test", 100, false, "")
	if err != nil {
		t.Fatalf("首版重签失败: %v", err)
	}
	st1, _ := store.GetCurrentStatement(tid)
	if st1 == nil || st1.StatementID != id1 || st1.SupersedesID != "" {
		t.Fatalf("首版不应有 supersedes: %+v", st1)
	}
	if st1.ContentHash != sha256Hex(st1.Content) {
		t.Error("存证 content_hash 不匹配")
	}

	id2, err := h.reissueStatementCore(tid, "test", 200, false, "")
	if err != nil {
		t.Fatalf("二次重签失败: %v", err)
	}
	st2, _ := store.GetCurrentStatement(tid)
	if st2 == nil || st2.StatementID != id2 || st2.SupersedesID != id1 {
		t.Fatalf("重签应 supersedes 前一版: %+v", st2)
	}

	all, err := store.ListStatementsByTenant(tid)
	if err != nil || len(all) != 2 {
		t.Fatalf("应存证 2 版, got=%d err=%v", len(all), err)
	}
	// L3：跨租户按 tenant_id 过滤
	if other, _ := store.GetStatement("t_other", id1); other != nil {
		t.Error("跨租户取声明应隔离（nil）")
	}
}

func TestReissueStatement_NotProvisioned(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "n4b@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	h := newTenantHandler(store, testTenantCfg(), nil, nil, nil, nil, nil)
	id, err := h.reissueStatementCore(tid, "test", 1, false, "")
	if err != nil || id != "" {
		t.Errorf("未开通不应生成声明: id=%q err=%v", id, err)
	}
}

// ---------- 租户读取端点 ----------

func TestHandleTenantStatement_Endpoint(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "n4c@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, store, tid, scenarioS3a, trustTierTrusted)

	// 未生成 → available=false
	w := httptest.NewRecorder()
	h.handleTenantStatement(w, tenantRequest("GET", tenantStatementPath, "", tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var v0 statementView
	_ = json.NewDecoder(w.Body).Decode(&v0)
	if v0.Available {
		t.Error("未生成时 available 应为 false")
	}

	// 生成后 → available=true 且返回全文
	if _, err := h.reissueStatementCore(tid, "test", 1, false, ""); err != nil {
		t.Fatal(err)
	}
	w2 := httptest.NewRecorder()
	h.handleTenantStatement(w2, tenantRequest("GET", tenantStatementPath, "", tid, "u1"))
	var v1 statementView
	if err := json.NewDecoder(w2.Body).Decode(&v1); err != nil {
		t.Fatal(err)
	}
	if !v1.Available || v1.Scenario != scenarioS3a || len(v1.Content) == 0 {
		t.Errorf("应返回当前生效声明: %+v", v1)
	}

	// 无租户作用域 → 403
	w3 := httptest.NewRecorder()
	h.handleTenantStatement(w3, httptest.NewRequest("GET", tenantStatementPath, nil))
	if w3.Code != http.StatusForbidden {
		t.Errorf("无作用域应 403, got=%d", w3.Code)
	}
}

// ---------- 运维批量重签发（触发③）----------

func TestHandleAdminStatementsReissue_Audit(t *testing.T) {
	h, store, auditFile := newAuditTestHandler(t)
	tid1, _ := seedTenantUser(t, store, "n4d1@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	tid2, _ := seedTenantUser(t, store, "n4d2@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, store, tid1, scenarioS2, trustTierTrusted)
	provisionForTest(t, store, tid2, scenarioS3b, trustTierUntrusted)

	req := httptest.NewRequest("POST", adminStatementsReissuePath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "alice", Role: roleAdmin}))
	w := httptest.NewRecorder()
	h.handleAdminStatementsReissue(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["reissued"].(float64) != 2 {
		t.Errorf("应重签 2 个租户: %+v", resp)
	}
	for _, tid := range []string{tid1, tid2} {
		if st, _ := store.GetCurrentStatement(tid); st == nil {
			t.Errorf("租户 %s 应有声明", tid)
		}
	}
	body := readAudit(t, auditFile)
	if !strings.Contains(body, auditActionStatementReissue) {
		t.Errorf("应落 %s 审计:\n%s", auditActionStatementReissue, body)
	}
	if !strings.Contains(body, "template_version=") {
		t.Errorf("审计应记录模板版本:\n%s", body)
	}
}

func TestHandleAdminStatementsReissue_Forbidden(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	cases := []struct {
		name   string
		claims *claims
	}{
		{"非 admin", &claims{Sub: "bob", Role: roleAuditor}},
		{"无会话", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", adminStatementsReissuePath, nil)
			if c.claims != nil {
				req = req.WithContext(withClaims(req.Context(), c.claims))
			}
			w := httptest.NewRecorder()
			h.handleAdminStatementsReissue(w, req)
			if w.Code != http.StatusForbidden {
				t.Errorf("应 403, got=%d", w.Code)
			}
		})
	}
}

func TestHandleAdminStatementsReissue_BadJSON(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	req := httptest.NewRequest("POST", adminStatementsReissuePath, strings.NewReader("{"))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "alice", Role: roleAdmin}))
	w := httptest.NewRecorder()
	h.handleAdminStatementsReissue(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法请求体应 400, got=%d", w.Code)
	}
}

func TestHandleAdminStatementsReissue_ReasonTooLong(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	req := httptest.NewRequest("POST", adminStatementsReissuePath,
		strings.NewReader(`{"reason":"`+strings.Repeat("x", 300)+`"}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "alice", Role: roleAdmin}))
	w := httptest.NewRecorder()
	h.handleAdminStatementsReissue(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("超长 reason 应 400, got=%d", w.Code)
	}
}

// ---------- 补充：默认值 / 错误路径 ----------

func TestStatementRedlineError_Error(t *testing.T) {
	err := &statementRedlineError{Reason: "含禁词 X"}
	if !strings.Contains(err.Error(), "红线违规") || !strings.Contains(err.Error(), "含禁词 X") {
		t.Errorf("Error() 文案不对: %q", err.Error())
	}
}

func TestBuildStatementContent_Defaults(t *testing.T) {
	c, err := buildStatementContent(StatementInput{TenantID: "t_1", Scenario: scenarioS1})
	if err != nil {
		t.Fatal(err)
	}
	if c.TrustTier != trustTierTrusted {
		t.Errorf("缺省 trust_tier 应为 trusted, got=%s", c.TrustTier)
	}
	if c.AccessMode != accessModeASegmented {
		t.Errorf("缺省 access_mode 应为 %s, got=%s", accessModeASegmented, c.AccessMode)
	}
	if c.TemplateVersion != statementTemplateVersion {
		t.Errorf("缺省模板版本应为 %s, got=%s", statementTemplateVersion, c.TemplateVersion)
	}
}

func TestRenderStatementContent_UnknownScenario(t *testing.T) {
	if _, _, _, err := renderStatementContent(StatementInput{TenantID: "t_1", Scenario: "s9"}); err == nil {
		t.Error("未知场景应报错")
	}
}

func TestReissueStatementForTenant(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "n4e@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, store, tid, scenarioS1, trustTierTrusted)
	h := newTenantHandler(store, testTenantCfg(), nil, nil, nil, nil, nil)
	if err := h.reissueStatementForTenant(tid); err != nil {
		t.Fatalf("N1 联动重签失败: %v", err)
	}
	if st, _ := store.GetCurrentStatement(tid); st == nil {
		t.Error("应生成声明")
	}
}

// ---------- 存证边界 ----------

func TestCreateStatement_Guards(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "n4f@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	// 缺 statement_id / tenant_id → 拒绝
	if err := store.CreateStatement(tx, &TenantStatement{TenantID: tid}); err == nil {
		t.Error("缺 statement_id 应拒")
	}
	if err := store.CreateStatement(tx, nil); err == nil {
		t.Error("nil 应拒")
	}
	// 正常写入
	ok := &TenantStatement{StatementID: "st-dup", TenantID: tid, Scenario: scenarioS1,
		AccessMode: accessModeASegmented, TemplateVersion: statementTemplateVersion,
		Content: "{}", ContentHash: sha256Hex("{}"), CreatedAt: 1}
	if err := store.CreateStatement(tx, ok); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	// 主键冲突 → 底层错误
	if err := store.CreateStatement(tx, ok); err == nil {
		t.Error("重复 statement_id 应报错")
	}
}

func TestGetStatement_NotFound(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "n4g@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	if st, err := store.GetStatement(tid, "st-none"); err != nil || st != nil {
		t.Errorf("不存在的声明应 nil,nil: st=%+v err=%v", st, err)
	}
}

// TestStatementStore_ClosedErrors 覆盖表 ⑨ 读路径的底层错误分支（关闭库即报错）。
func TestStatementStore_ClosedErrors(t *testing.T) {
	store := newTestStore(t)
	if err := ensureStatementsSchema(store.db); err != nil {
		t.Fatalf("未关闭库建表应成功: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("关闭库失败: %v", err)
	}
	if _, err := store.GetCurrentStatement("t_x"); err == nil {
		t.Error("关闭库 GetCurrentStatement 应报错")
	}
	if _, err := store.GetStatement("t_x", "st-x"); err == nil {
		t.Error("关闭库 GetStatement 应报错")
	}
	if _, err := store.ListStatementsByTenant("t_x"); err == nil {
		t.Error("关闭库 ListStatementsByTenant 应报错")
	}
	if _, err := store.ListProvisionedTenants(); err == nil {
		t.Error("关闭库 ListProvisionedTenants 应报错")
	}
	if err := ensureStatementsSchema(store.db); err == nil {
		t.Error("关闭库建表应报错")
	}
}

// ---------- 端点注册与错误分支 ----------

func TestRegisterStatementEndpoints(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	mux := http.NewServeMux()
	h.registerMux(mux)
	h.registerAdminStatementOps(mux, testTenantCfg())

	// 无令牌 → 401，证明路由已注册且受令牌中间件保护（fail-closed）。
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", tenantStatementPath, nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("声明读取端点无令牌应 401, got=%d", w.Code)
	}
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, httptest.NewRequest("POST", adminStatementsReissuePath, nil))
	if w2.Code != http.StatusUnauthorized {
		t.Errorf("运维重签端点无令牌应 401, got=%d", w2.Code)
	}
}

// errTenantStore 注入指定 TenantStore 方法错误以覆盖错误分支（未注入的方法透传）。
type errTenantStore struct {
	TenantStore
	provisioningErr     error
	failProvisioningFor string
	getCurrentErr       error
	beginErr            error
	createStmtErr       error
	commitErr           error
	listProvErr         error
}

func (e *errTenantStore) GetProvisioning(id string) (*TenantProvisioning, error) {
	if e.provisioningErr != nil && (e.failProvisioningFor == "" || e.failProvisioningFor == id) {
		return nil, e.provisioningErr
	}
	return e.TenantStore.GetProvisioning(id)
}

func (e *errTenantStore) GetCurrentStatement(id string) (*TenantStatement, error) {
	if e.getCurrentErr != nil {
		return nil, e.getCurrentErr
	}
	return e.TenantStore.GetCurrentStatement(id)
}

func (e *errTenantStore) Begin() (TenantTx, error) {
	if e.beginErr != nil {
		return nil, e.beginErr
	}
	tx, err := e.TenantStore.Begin()
	if err != nil || e.commitErr == nil {
		return tx, err
	}
	return &errTenantTx{TenantTx: tx, commitErr: e.commitErr}, nil
}

func (e *errTenantStore) CreateStatement(tx TenantTx, st *TenantStatement) error {
	if e.createStmtErr != nil {
		return e.createStmtErr
	}
	return e.TenantStore.CreateStatement(tx, st)
}

func (e *errTenantStore) ListProvisionedTenants() ([]string, error) {
	if e.listProvErr != nil {
		return nil, e.listProvErr
	}
	return e.TenantStore.ListProvisionedTenants()
}

// errTenantTx 注入 Commit 错误的 TenantTx（覆盖 tx.Commit 失败分支）。
type errTenantTx struct {
	TenantTx
	commitErr error
}

func (e *errTenantTx) Commit() error {
	if e.commitErr != nil {
		return e.commitErr
	}
	return e.TenantTx.Commit()
}

func TestReissueStatementCore_StoreErrors(t *testing.T) {
	base := newTestStore(t)
	tid, _ := seedTenantUser(t, base, "n4h@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, base, tid, scenarioS1, trustTierTrusted)
	boom := errors.New("boom")

	cases := []struct {
		name  string
		store TenantStore
	}{
		{"get_provisioning", &errTenantStore{TenantStore: base, provisioningErr: boom}},
		{"get_current", &errTenantStore{TenantStore: base, getCurrentErr: boom}},
		{"begin", &errTenantStore{TenantStore: base, beginErr: boom}},
		{"create", &errTenantStore{TenantStore: base, createStmtErr: boom}},
		{"commit", &errTenantStore{TenantStore: base, commitErr: boom}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := newTenantHandler(c.store, testTenantCfg(), nil, nil, nil, nil, nil)
			if _, err := h.reissueStatementCore(tid, "x", 1, false, ""); err == nil {
				t.Error("存储错误应向上传播")
			}
		})
	}
}

func TestHandleTenantStatement_StoreError(t *testing.T) {
	base := newTestStore(t)
	h := newTenantHandler(&errTenantStore{TenantStore: base, getCurrentErr: errors.New("boom")},
		testTenantCfg(), nil, nil, nil, nil, nil)
	w := httptest.NewRecorder()
	h.handleTenantStatement(w, tenantRequest("GET", tenantStatementPath, "", "t_x", "u1"))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("读取失败应 500, got=%d", w.Code)
	}
}

func TestHandleAdminStatementsReissue_StoreError(t *testing.T) {
	base := newTestStore(t)
	h := newTenantHandler(&errTenantStore{TenantStore: base, listProvErr: errors.New("boom")},
		testTenantCfg(), nil, nil, nil, nil, nil)
	req := httptest.NewRequest("POST", adminStatementsReissuePath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "alice", Role: roleAdmin}))
	w := httptest.NewRecorder()
	h.handleAdminStatementsReissue(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Errorf("枚举租户失败应 500, got=%d", w.Code)
	}
}

func TestHandleAdminStatementsReissue_PartialFailure(t *testing.T) {
	base := newTestStore(t)
	good, _ := seedTenantUser(t, base, "n4i1@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	bad, _ := seedTenantUser(t, base, "n4i2@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, base, good, scenarioS1, trustTierTrusted)
	provisionForTest(t, base, bad, scenarioS1, trustTierTrusted)
	h := newTenantHandler(&errTenantStore{TenantStore: base, provisioningErr: errors.New("boom"), failProvisioningFor: bad},
		testTenantCfg(), nil, nil, nil, nil, nil)

	req := httptest.NewRequest("POST", adminStatementsReissuePath, strings.NewReader(`{"reason":"upgrade"}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "alice", Role: roleAdmin}))
	w := httptest.NewRecorder()
	h.handleAdminStatementsReissue(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Reissued int      `json:"reissued"`
		Failed   []string `json:"failed"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Reissued != 1 || len(resp.Failed) != 1 || resp.Failed[0] != bad {
		t.Errorf("应 1 成功 1 失败(%s): %+v", bad, resp)
	}
}
