// Package main — P2-4 T-1.9（S3）共享库多集群租户隔离：跨租户/跨集群泄露负向用例。
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§T-1 ⑦：
//
//	"租户表以 tenant_id（+cluster_id 可选）复合主键/索引；所有查询强制 tenant 作用域过滤
//	 （应用层行级隔离），禁止跨租户/跨集群直读；测试覆盖跨集群泄露用例。"
//
// 覆盖：
//   - 存储层跨租户读取负向：api_key / statement / provisioning / dispatch / policy /
//     model / subscription 逐表断言"取不到他人数据"，同时断言本租户数据可读（防假阴性）；
//   - 存储层租户口径强制：GetAPIKeyByIDForTenant / RevokeAPIKeyForTenant；
//   - 跨集群共享同一物理库：两个管理面实例（各自独立连接，模拟不同集群的管理面）
//     互不可见对方租户数据；同租户数据跨实例可见（共享一致性 ≠ 泄露）；
//   - HTTP 层跨租户访问 404（不泄露资源存在性）与列表只含本租户；
//   - 索引落地断言（sqlite 实库；PG 门控变体）+ 双方言 DDL 等价性静态断言。
//
// 说明：cluster_id 列与"每租户×每集群单飞"语义由 T-3.2 引入（S3 口径为"+cluster_id 可选"）。
// 本文件锁定的跨集群隔离语义 = **共享库内不同租户的数据不得互相直读**；集群维度的
// 复合索引登记见 tenant_store.go「S3 复核结论」第三节。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------- 数据准备 ----------

// s3SeedTenant 为一个租户造全量数据（key / 声明 / 开通配置 / 下发状态 / 策略 / 模型 / 订阅）。
func s3SeedTenant(t *testing.T, s *sqliteTenantStore, tenantID, tag string) {
	t.Helper()
	now := time.Now().Unix()
	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := s.CreateTenant(tx, &Tenant{
		ID: tenantID, Name: "租户-" + tag, Status: tenantStatusActive, PlanID: "free", CreatedAt: now,
	}); err != nil {
		t.Fatalf("create tenant %s: %v", tenantID, err)
	}
	if err := s.CreateAPIKey(tx, &APIKey{
		KeyID: "k-" + tag, TenantID: tenantID, Name: "key-" + tag, JTI: "jti-" + tag,
		Fingerprint: "fp-" + tag, Status: apiKeyStatusActive, CreatedBy: "u-" + tag,
		CreatedAt: now, ExpiresAt: now + 3600,
	}); err != nil {
		t.Fatalf("create api key %s: %v", tenantID, err)
	}
	if err := s.CreateStatement(tx, &TenantStatement{
		StatementID: "st-" + tag, TenantID: tenantID, Scenario: "s1", AccessMode: "a_segmented",
		TemplateVersion: "v1", Content: "{}", ContentHash: "h-" + tag, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create statement %s: %v", tenantID, err)
	}
	if err := s.UpsertProvisioning(tx, &TenantProvisioning{
		TenantID: tenantID, Scenario: "s1", TrustTier: "trusted", AccessMode: "a_segmented",
		PluginSetJSON: "[]", Segment1Enabled: false, Segment2Mode: "none", TemplateVersion: "v1",
		ProviderCredRefsJSON: "[]", ProvisionedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("upsert provisioning %s: %v", tenantID, err)
	}
	if err := s.UpsertPolicyOverlay(tx, &PolicyOverlay{
		TenantID: tenantID, Version: 1, WhitelistJSON: `{"entries":[]}`,
		BlacklistJSON: `{"entries":[]}`, CategoryActionsJSON: `{}`, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("upsert policy overlay %s: %v", tenantID, err)
	}
	if err := s.UpsertModelConfig(tx, &ModelConfig{
		TenantID: tenantID, AllowedModelsJSON: "[]", DefaultModel: "m1", Version: 1, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("upsert model config %s: %v", tenantID, err)
	}
	if err := s.CreateSubscriptionRequest(tx, &SubscriptionRequest{
		RequestID: "req-" + tag, TenantID: tenantID, FromPlan: "free", ToPlan: "pro",
		Direction: "upgrade", Status: "pending", CreatedBy: "u-" + tag, CreatedAt: now,
	}); err != nil {
		t.Fatalf("create subscription request %s: %v", tenantID, err)
	}
	if _, err := s.BumpDispatchVersion(tx, tenantID, now); err != nil {
		t.Fatalf("bump dispatch version %s: %v", tenantID, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit seed tenant %s: %v", tenantID, err)
	}
}

// s3AssertTenantVisible 断言租户 A 的数据在 A 视角全部可读（防"全 nil"假阴性）。
func s3AssertTenantVisible(t *testing.T, s *sqliteTenantStore, tenantID, tag string) {
	t.Helper()
	key, err := s.GetAPIKeyByIDForTenant(tenantID, "k-"+tag)
	if err != nil || key == nil {
		t.Fatalf("本租户 %s 的 key 应可读: key=%v err=%v", tenantID, key, err)
	}
	stmt, err := s.GetCurrentStatement(tenantID)
	if err != nil || stmt == nil {
		t.Fatalf("本租户 %s 的当前声明应可读: stmt=%v err=%v", tenantID, stmt, err)
	}
	prov, err := s.GetProvisioning(tenantID)
	if err != nil || prov == nil {
		t.Fatalf("本租户 %s 的开通配置应可读: prov=%v err=%v", tenantID, prov, err)
	}
	disp, err := s.GetDispatchState(tenantID)
	if err != nil || disp == nil {
		t.Fatalf("本租户 %s 的下发状态应可读: disp=%v err=%v", tenantID, disp, err)
	}
	policy, err := s.GetPolicyOverlay(tenantID)
	if err != nil || policy == nil {
		t.Fatalf("本租户 %s 的策略 overlay 应可读: policy=%v err=%v", tenantID, policy, err)
	}
	model, err := s.GetModelConfig(tenantID)
	if err != nil || model == nil {
		t.Fatalf("本租户 %s 的模型配置应可读: model=%v err=%v", tenantID, model, err)
	}
	subs, err := s.ListSubscriptionRequests(tenantID, 50)
	if err != nil || len(subs) != 1 {
		t.Fatalf("本租户 %s 的订阅请求应可读: subs=%v err=%v", tenantID, subs, err)
	}
}

// s3AssertTenantInvisible 断言租户 B 视角**取不到**租户 A 的任何数据（负向核心断言）。
//
// 口径区分两类表：
//   - 每租户多行（api_keys / tenant_statements / subscription_requests）：
//     断言"按他租户的实体 id 直查为空"、"列表里不含他租户行"；
//   - 每租户一行（provisioning / policy / model / dispatch，按 tenant_id 为主键）：
//     断言读到的行的 tenant_id 是**自己**（不得是他租户的那一行），不要求为 nil。
func s3AssertTenantInvisible(t *testing.T, s *sqliteTenantStore, viewerTenant, ownerTenant, tag string) {
	t.Helper()
	// api_keys：按 id 直查（租户口径）、按名查（租户口径）、列表（租户口径）
	key, err := s.GetAPIKeyByIDForTenant(viewerTenant, "k-"+tag)
	if err != nil {
		t.Fatalf("GetAPIKeyByIDForTenant: %v", err)
	}
	if key != nil {
		t.Errorf("跨租户直查 key 应为空（租户 %s 读到租户 %s 的 key %s）", viewerTenant, ownerTenant, key.KeyID)
	}
	byName, err := s.GetActiveAPIKeyByName(viewerTenant, "key-"+tag)
	if err != nil {
		t.Fatalf("GetActiveAPIKeyByName: %v", err)
	}
	if byName != nil {
		t.Errorf("跨租户按名查 key 应为空: %+v", byName)
	}
	keys, err := s.ListAPIKeysByTenant(viewerTenant)
	if err != nil {
		t.Fatalf("ListAPIKeysByTenant: %v", err)
	}
	for _, k := range keys {
		if k.TenantID != viewerTenant {
			t.Errorf("租户 %s 的 key 列表混入了租户 %s 的 key %s", viewerTenant, k.TenantID, k.KeyID)
		}
	}
	// tenant_statements：按 id / 列表
	st, err := s.GetStatement(viewerTenant, "st-"+tag)
	if err != nil {
		t.Fatalf("GetStatement: %v", err)
	}
	if st != nil {
		t.Errorf("跨租户读声明应为空: %+v", st)
	}
	stmts, err := s.ListStatementsByTenant(viewerTenant)
	if err != nil {
		t.Fatalf("ListStatementsByTenant: %v", err)
	}
	for _, item := range stmts {
		if item.TenantID != viewerTenant {
			t.Errorf("租户 %s 的声明列表混入租户 %s 的声明 %s", viewerTenant, item.TenantID, item.StatementID)
		}
	}
	// 每租户一行的表：读到的必须是**自己**那一行
	cur, err := s.GetCurrentStatement(viewerTenant)
	if err != nil {
		t.Fatalf("GetCurrentStatement: %v", err)
	}
	if cur != nil && cur.TenantID != viewerTenant {
		t.Errorf("当前声明归属错误: want tenant=%s got=%s", viewerTenant, cur.TenantID)
	}
	prov, err := s.GetProvisioning(viewerTenant)
	if err != nil {
		t.Fatalf("GetProvisioning: %v", err)
	}
	if prov != nil && prov.TenantID != viewerTenant {
		t.Errorf("开通配置归属错误: want tenant=%s got=%s", viewerTenant, prov.TenantID)
	}
	policy, err := s.GetPolicyOverlay(viewerTenant)
	if err != nil {
		t.Fatalf("GetPolicyOverlay: %v", err)
	}
	if policy != nil && policy.TenantID != viewerTenant {
		t.Errorf("策略 overlay 归属错误: want tenant=%s got=%s", viewerTenant, policy.TenantID)
	}
	model, err := s.GetModelConfig(viewerTenant)
	if err != nil {
		t.Fatalf("GetModelConfig: %v", err)
	}
	if model != nil && model.TenantID != viewerTenant {
		t.Errorf("模型配置归属错误: want tenant=%s got=%s", viewerTenant, model.TenantID)
	}
	disp, err := s.GetDispatchState(viewerTenant)
	if err != nil {
		t.Fatalf("GetDispatchState: %v", err)
	}
	if disp != nil && disp.TenantID != viewerTenant {
		t.Errorf("下发状态归属错误: want tenant=%s got=%s", viewerTenant, disp.TenantID)
	}
	// subscription_requests
	subs, err := s.ListSubscriptionRequests(viewerTenant, 50)
	if err != nil {
		t.Fatalf("ListSubscriptionRequests: %v", err)
	}
	for _, sub := range subs {
		if sub.TenantID != viewerTenant {
			t.Errorf("租户 %s 的订阅列表混入租户 %s 的请求 %s", viewerTenant, sub.TenantID, sub.RequestID)
		}
	}
}

// ---------- 存储层负向 ----------

// TestS3_CrossTenant_StoreRead_Negative 存储层跨租户读取负向（本租户可见 + 他租户不可见）。
func TestS3_CrossTenant_StoreRead_Negative(t *testing.T) {
	s := newTestStore(t)
	s3SeedTenant(t, s, "s3_t_a", "a")
	s3SeedTenant(t, s, "s3_t_b", "b")

	s3AssertTenantVisible(t, s, "s3_t_a", "a")
	s3AssertTenantVisible(t, s, "s3_t_b", "b")

	// A 的数据在 B 视角不可见；B 的数据在 A 视角不可见。
	s3AssertTenantInvisible(t, s, "s3_t_b", "s3_t_a", "a")
	s3AssertTenantInvisible(t, s, "s3_t_a", "s3_t_b", "b")
}

// TestS3_APIKey_TenantScopedMutation_Negative 存储层租户口径强制：
// 跨租户吊销不生效、跨租户直查为空；同租户吊销生效。
func TestS3_APIKey_TenantScopedMutation_Negative(t *testing.T) {
	s := newTestStore(t)
	s3SeedTenant(t, s, "s3_t_a", "a")
	s3SeedTenant(t, s, "s3_t_b", "b")

	// 跨租户直查 → 空（与"不存在"不可区分）
	got, err := s.GetAPIKeyByIDForTenant("s3_t_b", "k-a")
	if err != nil {
		t.Fatalf("GetAPIKeyByIDForTenant: %v", err)
	}
	if got != nil {
		t.Errorf("跨租户直查 key 应为空: %+v", got)
	}

	// 跨租户吊销 → 报错且不改行
	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := s.RevokeAPIKeyForTenant(tx, "s3_t_b", "k-a", time.Now().Unix()); err == nil {
		t.Error("跨租户吊销应报错（不得改他人 key）")
	}
	_ = tx.Rollback()

	after, err := s.GetAPIKeyByIDForTenant("s3_t_a", "k-a")
	if err != nil || after == nil {
		t.Fatalf("A 的 key 应仍可读: %v %v", after, err)
	}
	if after.Status != apiKeyStatusActive || after.RevokedAt != 0 {
		t.Errorf("跨租户吊销后目标 key 状态被改: status=%s revoked_at=%d", after.Status, after.RevokedAt)
	}

	// 同租户吊销 → 生效
	tx2, err := s.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := s.RevokeAPIKeyForTenant(tx2, "s3_t_a", "k-a", time.Now().Unix()); err != nil {
		t.Fatalf("同租户吊销应成功: %v", err)
	}
	if err := tx2.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	after2, err := s.GetAPIKeyByIDForTenant("s3_t_a", "k-a")
	if err != nil || after2 == nil {
		t.Fatalf("A 的 key 应仍可读: %v %v", after2, err)
	}
	if after2.Status != apiKeyStatusRevoked || after2.RevokedAt == 0 {
		t.Errorf("同租户吊销未生效: status=%s revoked_at=%d", after2.Status, after2.RevokedAt)
	}
}

// TestS3_GlobalQuery_Boundary 管理面全局口径查询与租户口径的边界：
// 全局吊销拉取能看到全部租户的吊销记录（运维口径），但租户面视图不受影响。
func TestS3_GlobalQuery_Boundary(t *testing.T) {
	s := newTestStore(t)
	s3SeedTenant(t, s, "s3_t_a", "a")
	s3SeedTenant(t, s, "s3_t_b", "b")

	now := time.Now().Unix()
	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if err := s.RevokeAPIKey(tx, "k-a", now); err != nil { // 管理面全局口径
		t.Fatalf("全局吊销: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	revoked, err := s.ListRevokedAPIKeysSince(now - 60)
	if err != nil {
		t.Fatalf("ListRevokedAPIKeysSince: %v", err)
	}
	found := false
	for _, k := range revoked {
		if k.KeyID == "k-a" {
			found = true
		}
	}
	if !found {
		t.Error("运维全局口径应能看到吊销记录")
	}
	// 租户面视图不受全局操作影响：B 仍看不到任何 key
	keysB, err := s.ListAPIKeysByTenant("s3_t_b")
	if err != nil {
		t.Fatalf("ListAPIKeysByTenant: %v", err)
	}
	if len(keysB) != 1 {
		t.Errorf("租户 B 的 key 列表应只含自己 1 条, got=%d", len(keysB))
	}
}

// ---------- 跨集群共享库负向 ----------

// TestS3_CrossCluster_SharedDB_NoLeak 跨集群共享同一物理库：
// 两个管理面实例（各自独立连接）互不可见对方租户数据；同租户数据跨实例可见。
func TestS3_CrossCluster_SharedDB_NoLeak(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared-cluster.db")
	open := func() *sqliteTenantStore {
		t.Helper()
		ts, err := OpenTenantStore(path, false, []byte("test-pepper-12345678"))
		if err != nil {
			t.Fatalf("打开共享库失败: %v", err)
		}
		s, ok := ts.(*sqliteTenantStore)
		if !ok {
			t.Fatalf("类型断言失败: %T", ts)
		}
		return s
	}
	clusterA := open() // 集群 A 的管理面实例
	defer func() { _ = clusterA.Close() }()
	clusterB := open() // 集群 B 的管理面实例（同一物理库）
	defer func() { _ = clusterB.Close() }()

	// 集群 A 写入租户 A 的数据
	s3SeedTenant(t, clusterA, "s3_t_a", "a")

	// 集群 B：以租户 B 视角读不到租户 A 的任何数据（跨集群/跨租户泄露负向）
	s3AssertTenantInvisible(t, clusterB, "s3_t_b", "s3_t_a", "a")

	// 集群 B：以租户 A 视角可读到（共享库一致性——同一租户的数据在共享库中全局一致）
	s3AssertTenantVisible(t, clusterB, "s3_t_a", "a")

	// 集群 B 写入租户 B 的数据；集群 A 以租户 A 视角仍读不到租户 B 的数据
	s3SeedTenant(t, clusterB, "s3_t_b", "b")
	s3AssertTenantInvisible(t, clusterA, "s3_t_a", "s3_t_b", "b")
	s3AssertTenantVisible(t, clusterA, "s3_t_a", "a")
}

// ---------- HTTP 层负向 ----------

// TestS3_HTTP_CrossTenant_NotFound HTTP 层跨租户访问：不泄露存在性（404），列表只含本租户。
func TestS3_HTTP_CrossTenant_NotFound(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	created := createKey(t, h, "s3key")
	id := created["id"].(string)

	// 另一租户吊销 → 404
	req := tenantRequest("DELETE", apiKeysPath+"/"+id, "", "t_2", "u2")
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	h.handleKeyRevoke(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("跨租户吊销应 404（不泄露存在性）, got=%d", w.Code)
	}

	// 另一租户轮换 → 404
	req2 := tenantRequest("POST", apiKeysPath+"/"+id+"/rotate", "", "t_2", "u2")
	req2.SetPathValue("id", id)
	w2 := httptest.NewRecorder()
	h.handleKeyRotate(w2, req2)
	if w2.Code != http.StatusNotFound {
		t.Errorf("跨租户轮换应 404（不泄露存在性）, got=%d", w2.Code)
	}

	// 目标 key 未被跨租户操作改动
	key, err := store.GetAPIKeyByIDForTenant("t_1", id)
	if err != nil || key == nil {
		t.Fatalf("本租户 key 应可读: %v %v", key, err)
	}
	if key.Status != apiKeyStatusActive {
		t.Errorf("跨租户操作改动了目标 key: status=%s", key.Status)
	}

	// 列表：另一租户看不到该 key
	w3 := httptest.NewRecorder()
	h.handleKeyList(w3, tenantRequest("GET", apiKeysPath, "", "t_2", "u2"))
	if w3.Code != http.StatusOK {
		t.Fatalf("列表应 200, got=%d", w3.Code)
	}
	var resp struct {
		Keys []struct {
			ID       string `json:"id"`
			TenantID string `json:"tenant_id"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(w3.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析列表响应失败: %v", err)
	}
	for _, k := range resp.Keys {
		if k.ID == id {
			t.Errorf("跨租户列表泄露了他人 key %s", k.ID)
		}
		if k.TenantID != "" && k.TenantID != "t_2" {
			t.Errorf("跨租户列表混入租户 %s 的 key", k.TenantID)
		}
	}
}

// ---------- 索引落地断言 ----------

// s3RequiredIndexes T-1.9 要求落地的索引（双方言必须等价存在）。
var s3RequiredIndexes = []string{
	"idx_apikey_tenant_created",
	"idx_apikey_tenant_status",
	"idx_statements_supersedes",
	"idx_dispatch_status_updated",
}

// TestS3_Index_Registered_SQLite 索引落地断言（sqlite）+ 双方言 DDL 等价性静态断言。
func TestS3_Index_Registered_SQLite(t *testing.T) {
	s := newTestStore(t)
	for _, idx := range s3RequiredIndexes {
		var name string
		err := s.db.QueryRow(`SELECT name FROM sqlite_master WHERE type='index' AND name=?`, idx).Scan(&name)
		if err != nil {
			t.Errorf("sqlite 索引 %s 未落地: %v", idx, err)
			continue
		}
		if name != idx {
			t.Errorf("sqlite 索引名不符: want=%s got=%s", idx, name)
		}
	}
	// 双方言等价：PG DDL 必须含同样的索引（否则共享库切到 PG 后索引缺失 → 退化为跨租户全表扫描）。
	for _, idx := range s3RequiredIndexes {
		if !strings.Contains(tenantDDLSchemaPG, idx) {
			t.Errorf("PG DDL 缺少索引 %s（双方言不等价）", idx)
		}
	}
}

// TestS3_Index_Registered_PGGate PG 门控：索引在 PG 侧真实落地（ADMIN_TEST_PG_DSN 未设置则跳过）。
func TestS3_Index_Registered_PGGate(t *testing.T) {
	s := newPGTestStore(t)
	defer s.Close()
	for _, idx := range s3RequiredIndexes {
		var n int
		err := s.db.QueryRow(`SELECT COUNT(1) FROM pg_indexes WHERE schemaname = 'public' AND indexname = ?`, idx).Scan(&n)
		if err != nil {
			t.Errorf("查询 pg_indexes %s 失败: %v", idx, err)
			continue
		}
		if n != 1 {
			t.Errorf("PG 索引 %s 未落地（count=%d）", idx, n)
		}
	}
}
