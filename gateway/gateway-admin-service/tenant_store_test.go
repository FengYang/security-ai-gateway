package main

import (
	"testing"
	"time"
)

// newTestStore 创建内存 SQLite 测试用租户存储。
func newTestStore(t *testing.T) *sqliteTenantStore {
	t.Helper()
	ts, err := OpenTenantStore(":memory:", false, []byte("test-pepper-12345678"))
	if err != nil {
		t.Fatalf("打开测试 store 失败: %v", err)
	}
	s, ok := ts.(*sqliteTenantStore)
	if !ok {
		t.Fatal("类型断言失败")
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// ---------- 租户 CRUD ----------

func TestTenantStore_CreateAndGetTenant(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()
	tenant := &Tenant{
		ID:        "t_test01",
		Name:      "测试租户",
		Status:    tenantStatusActive,
		PlanID:    "free",
		CreatedAt: now,
	}

	tx, err := s.Begin()
	if err != nil {
		t.Fatalf("Begin 失败: %v", err)
	}
	if err := s.CreateTenant(tx, tenant); err != nil {
		t.Fatalf("CreateTenant 失败: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("Commit 失败: %v", err)
	}

	got, err := s.GetTenantByID("t_test01")
	if err != nil {
		t.Fatalf("GetTenantByID 失败: %v", err)
	}
	if got == nil {
		t.Fatal("未找到租户")
	}
	if got.Name != "测试租户" {
		t.Errorf("Name 不匹配: got=%s want=测试租户", got.Name)
	}
	if got.Status != tenantStatusActive {
		t.Errorf("Status 不匹配: got=%s", got.Status)
	}

	// 不存在的租户
	missing, err := s.GetTenantByID("nonexistent")
	if err != nil {
		t.Fatalf("GetTenantByID(nonexistent) 失败: %v", err)
	}
	if missing != nil {
		t.Error("不存在的租户应返回 nil")
	}
}

func TestTenantStore_UpdateTenantStatus(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_test", Name: "n", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	tx.Commit()

	tx2, _ := s.Begin()
	defer tx2.Rollback()
	if err := s.UpdateTenantStatus(tx2, "t_test", tenantStatusDisabled); err != nil {
		t.Fatalf("UpdateTenantStatus 失败: %v", err)
	}
	tx2.Commit()
	got, _ := s.GetTenantByID("t_test")
	if got.Status != tenantStatusDisabled {
		t.Errorf("状态未更新: got=%s", got.Status)
	}
}

// ---------- 用户 CRUD ----------

func TestTenantStore_CreateAndGetUser(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_test", Name: "n", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	pwHash, _ := hashPassword("password123")
	uid, err := s.CreateUser(tx, &TenantUser{
		TenantID:     "t_test",
		Email:        "user@example.com",
		PasswordHash: pwHash,
		Status:       tenantUserStatusPending,
		CreatedAt:    now,
	})
	if err != nil {
		t.Fatalf("CreateUser 失败: %v", err)
	}
	if uid == 0 {
		t.Error("用户 ID 不应为 0")
	}
	tx.Commit()

	// 按邮箱查
	u, err := s.GetUserByEmail("user@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail 失败: %v", err)
	}
	if u == nil {
		t.Fatal("未找到用户")
	}
	if u.Email != "user@example.com" {
		t.Errorf("Email 不匹配: got=%s", u.Email)
	}
	if !verifyPassword(u.PasswordHash, "password123") {
		t.Error("密码校验失败")
	}

	// 大小写不敏感
	u2, _ := s.GetUserByEmail("USER@EXAMPLE.COM")
	if u2 == nil || u2.ID != u.ID {
		t.Error("邮箱大小写不敏感查询失败")
	}

	// 按 ID 查
	u3, _ := s.GetUserByID(uid)
	if u3 == nil || u3.Email != u.Email {
		t.Error("GetUserByID 失败")
	}
}

func TestTenantStore_DuplicateEmail(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_test", Name: "n", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	s.CreateUser(tx, &TenantUser{TenantID: "t_test", Email: "dup@example.com", PasswordHash: "h", Status: tenantUserStatusActive, CreatedAt: now})
	tx.Commit()

	tx2, _ := s.Begin()
	_, err := s.CreateUser(tx2, &TenantUser{TenantID: "t_test", Email: "dup@example.com", PasswordHash: "h2", Status: tenantUserStatusActive, CreatedAt: now})
	tx2.Rollback()
	if err == nil {
		t.Error("重复邮箱应报错")
	}
}

// ---------- 邮件令牌 ----------

func TestTenantStore_TokenLifecycle(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_test", Name: "n", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	uid, _ := s.CreateUser(tx, &TenantUser{TenantID: "t_test", Email: "u@e.com", PasswordHash: "h", Status: tenantUserStatusPending, CreatedAt: now})
	tok := &MailActionToken{
		TokenHash:    s.hashMailToken("test-token-123"),
		TenantUserID: uid,
		Action:       mailActionVerify,
		ExpiresAt:    now + 3600,
		ConsumedAt:   0,
	}
	if err := s.CreateToken(tx, tok); err != nil {
		t.Fatalf("CreateToken 失败: %v", err)
	}
	tx.Commit()

	// 查询
	hash := s.hashMailToken("test-token-123")
	got, err := s.GetToken(hash)
	if err != nil {
		t.Fatalf("GetToken 失败: %v", err)
	}
	if got == nil || got.Action != mailActionVerify {
		t.Error("令牌查询失败或类型不对")
	}

	// 消费（事务1）
	tx2, _ := s.Begin()
	defer tx2.Rollback()
	if err := s.ConsumeToken(tx2, hash); err != nil {
		t.Fatalf("ConsumeToken 失败: %v", err)
	}
	tx2.Commit()
	got2, _ := s.GetToken(hash)
	if got2.ConsumedAt == 0 {
		t.Error("令牌未标记为已消费")
	}

	// 重复消费应失败（事务2）
	tx3, _ := s.Begin()
	defer tx3.Rollback()
	if err := s.ConsumeToken(tx3, hash); err == nil {
		t.Error("重复消费应报错")
	}
	tx3.Rollback()
}

// ---------- 密码 ----------

func TestHashAndVerifyPassword(t *testing.T) {
	pw := "MySecurePass123!"
	hash, err := hashPassword(pw)
	if err != nil {
		t.Fatalf("hashPassword 失败: %v", err)
	}
	if !verifyPassword(hash, pw) {
		t.Error("正确密码校验失败")
	}
	if verifyPassword(hash, "wrong-password") {
		t.Error("错误密码不应通过")
	}
}

// ---------- 注册限流 ----------

func TestRegisterRate(t *testing.T) {
	s := newTestStore(t)

	count, err := s.IncRegisterRate("1.2.3.4", 3600)
	if err != nil {
		t.Fatalf("IncRegisterRate 失败: %v", err)
	}
	if count != 1 {
		t.Errorf("首次计数应为 1, got=%d", count)
	}

	for i := 0; i < 4; i++ {
		s.IncRegisterRate("1.2.3.4", 3600)
	}
	count6, _ := s.IncRegisterRate("1.2.3.4", 3600)
	if count6 != 6 {
		t.Errorf("第 6 次计数应为 6, got=%d", count6)
	}
}

// ---------- 事务原子性 ----------

func TestTransactionRollback(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().Unix()

	tx, _ := s.Begin()
	s.CreateTenant(tx, &Tenant{ID: "t_rollback", Name: "rb", Status: tenantStatusActive, PlanID: "free", CreatedAt: now})
	tx.Rollback()

	got, _ := s.GetTenantByID("t_rollback")
	if got != nil {
		t.Error("回滚后租户不应存在")
	}
}

// ---------- DDL 完整性：7 张表 ----------

func TestDDL_SevenTables(t *testing.T) {
	s := newTestStore(t)

	tables := []string{"tenants", "tenant_users", "mail_action_tokens", "api_keys",
		"policy_overlays", "model_configs", "register_rate"}
	for _, tbl := range tables {
		var name string
		err := s.db.QueryRow("SELECT name FROM sqlite_master WHERE type='table' AND name=?", tbl).Scan(&name)
		if err != nil {
			t.Errorf("表 %s 不存在: %v", tbl, err)
		}
	}
}
