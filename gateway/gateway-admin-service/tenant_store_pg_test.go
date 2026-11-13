// tenant_store_pg_test.go — P2-4 T-1.2 租户存储 PostgreSQL 门控集成测试。
//
// DSN 由环境变量 ADMIN_TEST_PG_DSN 提供（如
// postgres://<user>:<password>@host:5432/db?sslmode=disable）；未设置时 t.Skip，
// 不伪装通过。覆盖：PG DDL 等价迁移（11 张表）/ CRUD（含 RETURNING 自增、
// 乐观锁冲突、ON CONFLICT upsert、GREATEST 应用版本）/ 写事务串行。
//
// ---------- PG 门控用例总索引（P2-4 真机复验用） ----------
//
// 本包所有"只在真机 PG 上跑"的用例，统一用一条命令跑完（Go 的 -run 为非锚定
// 正则，匹配所有名字中含 "PG" 的用例）：
//
//	ADMIN_TEST_PG_DSN='postgres://<user>:<password>@host:5432/db?sslmode=disable' \
//	  go test -count=1 -v -run PG ./gateway/gateway-admin-service/...
//
// 用例清单：
//
//	TestTenantStorePG_DDLAndCRUD          租户表 PG DDL 等价迁移 + CRUD
//	TestTenantStorePG_WriteTxMutex        PG advisory xact lock 跨副本写串行
//	TestCaptchaPGGate                     captcha 限流/一次性消费的 PG 原子性
//	TestLoginGuardPGGate                  登录失败锁定的 PG 原子性
//	TestMFAIntervalPGGate                 MFA/intervalGuard 的 PG 后端
//	TestMigrate_PGPGate                   存储迁移工具 PG 侧导入/对账/序列回填
//	TestS3_Index_Registered_PGGate         S3 租户隔离索引在 PG 侧真实落地
//	TestS3_PG_CrossTenant_Negative        S3 跨租户负向（真机共享库）
//	TestS3_PG_CrossCluster_SharedDB_NoLeak S3 跨集群负向（两实例连同一 PG 库）
//	TestDispatchState_PGGate_CompositePK   T-3.2a 复合主键 (tenant_id, cluster_id) 迁移与并存
//
// 复验口径：PG 门控用例一律 **skip 即视为未复验**（本机无 PG/无 docker 时全部
// skip，不伪装通过）；真机复验后请把输出回传给 P2-4 主线。
package main

import (
	"fmt"
	"os"
	"testing"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// newPGTestStore 打开 PG 租户存储（未设置 ADMIN_TEST_PG_DSN 时跳过）。
func newPGTestStore(t *testing.T) *sqliteTenantStore {
	t.Helper()
	dsn := os.Getenv("ADMIN_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("ADMIN_TEST_PG_DSN 未设置，跳过 PG 门控用例")
	}
	ts, err := OpenTenantStoreWithDialect(sqlutil.Postgres, dsn, false, []byte("pg-test-pepper-1234"))
	if err != nil {
		t.Fatalf("open pg tenant store: %v", err)
	}
	s, ok := ts.(*sqliteTenantStore)
	if !ok {
		t.Fatalf("unexpected store type %T", ts)
	}
	return s
}

// pgWriteTx 开写事务并在失败时终止测试。
func pgWriteTx(t *testing.T, s *sqliteTenantStore) TenantTx {
	t.Helper()
	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	return tx
}

func TestTenantStorePG_DDLAndCRUD(t *testing.T) {
	s := newPGTestStore(t)
	defer s.Close()
	if !s.Dialect().IsPostgres() {
		t.Fatalf("dialect = %s, want postgres", s.Dialect())
	}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	tenantID := "pg-t-" + suffix

	// ---- 租户 + 用户（RETURNING 自增 id > 0）----
	tx := pgWriteTx(t, s)
	if err := s.CreateTenant(tx, &Tenant{ID: tenantID, Name: "pg测试租户", Status: tenantStatusActive, PlanID: "free", CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	uid, err := s.CreateUser(tx, &TenantUser{TenantID: tenantID, Email: "Pg-" + suffix + "@example.com", PasswordHash: "$2a$12$fakefakefakefakefakefakefakefakefakefakefakefakefakef", Status: tenantUserStatusActive, CreatedAt: time.Now().Unix()})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if uid <= 0 {
		t.Fatalf("PG 下用户自增 id 应 > 0，实际 %d", uid)
	}
	if u, err := s.GetUserByID(uid); err != nil || u == nil || u.TenantID != tenantID {
		t.Fatalf("get user by id: u=%v err=%v", u, err)
	}
	if tnt, err := s.GetTenantByID(tenantID); err != nil || tnt == nil || tnt.Status != tenantStatusActive {
		t.Fatalf("get tenant: %v err=%v", tnt, err)
	}

	// ---- 邮件令牌：创建 + 一次性消费 ----
	tx = pgWriteTx(t, s)
	tokenHash := fmt.Sprintf("hash-%s", suffix)
	if err := s.CreateToken(tx, &MailActionToken{TokenHash: tokenHash, TenantUserID: uid, Action: mailActionVerify, ExpiresAt: time.Now().Add(time.Hour).Unix(), ConsumedAt: 0}); err != nil {
		t.Fatalf("create token: %v", err)
	}
	if err := s.ConsumeToken(tx, tokenHash); err != nil {
		t.Fatalf("consume token: %v", err)
	}
	if err := s.ConsumeToken(tx, tokenHash); err == nil {
		t.Fatal("重复消费应失败（一次性语义）")
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// ---- API Key：创建 / 吊销 / 按 revoked_at 枚举 ----
	tx = pgWriteTx(t, s)
	now := time.Now().Unix()
	keyID := "key-" + suffix
	if err := s.CreateAPIKey(tx, &APIKey{KeyID: keyID, TenantID: tenantID, Name: "默认", JTI: "jti-" + suffix, Fingerprint: "fp-" + suffix, Status: apiKeyStatusActive, CreatedBy: "tester", CreatedAt: now, ExpiresAt: now + 86400}); err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if err := s.RevokeAPIKey(tx, keyID, now+1); err != nil {
		t.Fatalf("revoke api key: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	revoked, err := s.ListRevokedAPIKeysSince(now)
	if err != nil {
		t.Fatalf("list revoked keys: %v", err)
	}
	found := false
	for _, k := range revoked {
		if k.KeyID == keyID {
			found = true
		}
	}
	if !found {
		t.Fatal("吊销后的 key 应出现在 ListRevokedAPIKeysSince")
	}

	// ---- 策略 overlay / 模型配置：乐观锁 upsert + 版本冲突 ----
	tx = pgWriteTx(t, s)
	if err := s.UpsertPolicyOverlay(tx, &PolicyOverlay{TenantID: tenantID, Version: 0, WhitelistJSON: `{"entries":[]}`, BlacklistJSON: `{"entries":[]}`, CategoryActionsJSON: `{}`, UpdatedAt: now}); err != nil {
		t.Fatalf("upsert policy overlay: %v", err)
	}
	if err := s.UpsertModelConfig(tx, &ModelConfig{TenantID: tenantID, AllowedModelsJSON: `["gpt-a"]`, DefaultModel: "gpt-a", Version: 0, UpdatedAt: now}); err != nil {
		t.Fatalf("upsert model config: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	tx = pgWriteTx(t, s)
	if err := s.UpsertPolicyOverlay(tx, &PolicyOverlay{TenantID: tenantID, Version: 2, WhitelistJSON: `{"entries":[]}`, BlacklistJSON: `{"entries":[]}`, CategoryActionsJSON: `{}`, UpdatedAt: now}); err != errTenantVersionConflict {
		t.Fatalf("版本不匹配应返回冲突，实际 %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}

	// ---- 开通配置（ON CONFLICT upsert）----
	tx = pgWriteTx(t, s)
	if err := s.UpsertProvisioning(tx, &TenantProvisioning{TenantID: tenantID, Scenario: "s3a", TrustTier: "trusted", AccessMode: "a_segmented", PluginSetJSON: `[]`, Segment1Enabled: true, Segment2Mode: "cross_node_mtls", TemplateVersion: "tpl-1", ProviderCredRefsJSON: `[]`, ProvisionedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("upsert provisioning: %v", err)
	}
	if err := s.UpsertProvisioning(tx, &TenantProvisioning{TenantID: tenantID, Scenario: "s1", TrustTier: "untrusted", AccessMode: "a_segmented", PluginSetJSON: `[]`, Segment1Enabled: false, Segment2Mode: "none", TemplateVersion: "tpl-2", ProviderCredRefsJSON: `[]`, ProvisionedAt: now, UpdatedAt: now + 1}); err != nil {
		t.Fatalf("re-upsert provisioning: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	p, err := s.GetProvisioning(tenantID)
	if err != nil || p == nil || p.Scenario != "s1" || p.Segment1Enabled {
		t.Fatalf("get provisioning: p=%+v err=%v", p, err)
	}

	// ---- 承诺声明存证：创建 + 当前版本（tiebreak=statement_id 分支）----
	tx = pgWriteTx(t, s)
	stID := "st-" + suffix
	if err := s.CreateStatement(tx, &TenantStatement{StatementID: stID, TenantID: tenantID, Scenario: "s1", AccessMode: "a_segmented", TemplateVersion: "tpl-2", Content: `{"v":1}`, ContentHash: "abc", CreatedAt: now}); err != nil {
		t.Fatalf("create statement: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	cur, err := s.GetCurrentStatement(tenantID)
	if err != nil || cur == nil || cur.StatementID != stID {
		t.Fatalf("get current statement: %v err=%v", cur, err)
	}

	// ---- 套餐待确认单 ----
	tx = pgWriteTx(t, s)
	if err := s.CreateSubscriptionRequest(tx, &SubscriptionRequest{RequestID: "req-" + suffix, TenantID: tenantID, FromPlan: "free", ToPlan: "pro", Direction: "upgrade", Status: "pending", CreatedBy: "tester", CreatedAt: now}); err != nil {
		t.Fatalf("create subscription request: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if reqs, err := s.ListSubscriptionRequests(tenantID, 10); err != nil || len(reqs) == 0 {
		t.Fatalf("list subscription requests: n=%d err=%v", len(reqs), err)
	}

	// ---- 下发状态机：bump / applying / applied（GREATEST 分支）/ failed ----
	tx = pgWriteTx(t, s)
	v1, err := s.BumpDispatchVersion(tx, tenantID, now)
	if err != nil {
		t.Fatalf("bump dispatch: %v", err)
	}
	if err := s.MarkDispatchApplying(tx, tenantID, now); err != nil {
		t.Fatalf("mark applying: %v", err)
	}
	if err := s.MarkDispatchApplied(tx, tenantID, v1, now); err != nil {
		t.Fatalf("mark applied: %v", err)
	}
	// 乱序回退防护：更小的 applied_version 不得使 applied_version 回退。
	if err := s.MarkDispatchApplied(tx, tenantID, 0, now+1); err != nil {
		t.Fatalf("mark applied (older): %v", err)
	}
	if err := s.MarkDispatchFailed(tx, tenantID, "boom", 1, now+2); err != nil {
		t.Fatalf("mark failed: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	d, err := s.GetDispatchState(tenantID)
	if err != nil || d == nil {
		t.Fatalf("get dispatch state: %v err=%v", d, err)
	}
	if d.AppliedVersion != v1 || d.Status != dispatchStatusFailed || d.LastError != "boom" {
		t.Fatalf("dispatch state = %+v, applied_version 应保持 %d", d, v1)
	}

	// ---- 注册限流：同窗口递增 ----
	ip := "10.9.9." + suffix[len(suffix)-3:]
	c1, err := s.IncRegisterRate(ip, 3600)
	if err != nil {
		t.Fatalf("inc register rate: %v", err)
	}
	c2, err := s.IncRegisterRate(ip, 3600)
	if err != nil {
		t.Fatalf("inc register rate 2nd: %v", err)
	}
	if c2 != c1+1 {
		t.Fatalf("同窗口计数应递增：c1=%d c2=%d", c1, c2)
	}
}

// TestTenantStorePG_WriteTxMutex 验证写事务互斥：第一个事务提交前，
// 第二个 Begin（进程内 writeMu）与 PG advisory lock 路径均须串行。
func TestTenantStorePG_WriteTxMutex(t *testing.T) {
	s := newPGTestStore(t)
	defer s.Close()
	tenantID := "pg-lock-" + fmt.Sprintf("%d", time.Now().UnixNano())

	tx1, err := s.Begin()
	if err != nil {
		t.Fatalf("begin tx1: %v", err)
	}
	if err := s.CreateTenant(tx1, &Tenant{ID: tenantID, Name: "lock", Status: tenantStatusActive, PlanID: "free", CreatedAt: time.Now().Unix()}); err != nil {
		t.Fatalf("create tenant tx1: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		tx2, err := s.Begin()
		if err != nil {
			done <- err
			return
		}
		if err := s.CreateTenant(tx2, &Tenant{ID: tenantID + "-b", Name: "lock-b", Status: tenantStatusActive, PlanID: "free", CreatedAt: time.Now().Unix()}); err != nil {
			done <- err
			return
		}
		done <- tx2.Commit()
	}()
	select {
	case err := <-done:
		t.Fatalf("第二写事务在第一个提交前完成，写互斥失效: %v", err)
	case <-time.After(300 * time.Millisecond):
		// 预期：被 writeMu / advisory lock 阻塞。
	}
	if err := tx1.Commit(); err != nil {
		t.Fatalf("commit tx1: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("tx2 after tx1 commit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tx1 提交后 tx2 仍未完成")
	}
	if tnt, err := s.GetTenantByID(tenantID + "-b"); err != nil || tnt == nil {
		t.Fatalf("tx2 写入未落库: %v err=%v", tnt, err)
	}
}
