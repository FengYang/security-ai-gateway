// Package main — 租户自助门户存储层（SQLite）。
//
// 按本体 §3.5 建立 7 张表：tenants / tenant_users / mail_action_tokens /
// api_keys / policy_overlays / model_configs / register_rate。
// 密码 bcrypt cost=12；邮件令牌哈希存储（SHA-256 + pepper）；
// 写事务走 BEGIN IMMEDIATE，与 billing store 同范式。
//
// M1 聚焦租户身份与会话所需表；api_keys / policy_overlays / model_configs
// 随后续模块补 CRUD，此处仅建表占位以保证 schema 一次到位。
package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// ---------- 常量 ----------

const (
	// bcryptCost 密码哈希代价因子（等保三级推荐 ≥12；§6.3）。
	bcryptCost = 12

	// tenantUserStatusActive / Locked 等状态常量。
	tenantUserStatusActive = "active"
	tenantUserStatusLocked = "locked"
	tenantUserStatusPending = "pending" // 未验证邮箱

	// tenantStatus* 租户状态（§3.2 状态机：pending → quota_pending → active；disabled = 停用）。
	tenantStatusPending      = "pending"       // 刚注册、邮箱未验证
	tenantStatusQuotaPending = "quota_pending" // 套餐已绑定但配额未回读确认（非 active）
	tenantStatusActive       = "active"
	tenantStatusDisabled     = "disabled"

	// mailActionVerify / PasswordReset 邮件令牌动作类型。
	mailActionVerify        = "email_verify"
	mailActionPasswordReset = "password_reset"

	// tokenTTLVerify 邮箱验证令牌有效期 24 小时（§6.3）。
	tokenTTLVerify = 24 * time.Hour
	// tokenTTLReset 密码重置令牌有效期 1 小时（§6.3）。
	tokenTTLReset = 1 * time.Hour
)

// ---------- DDL ----------

const tenantDDLSchema = `
-- 租户表
CREATE TABLE IF NOT EXISTS tenants (
  id         TEXT PRIMARY KEY,
  name       TEXT    NOT NULL,
  status     TEXT    NOT NULL DEFAULT 'active',
  plan_id    TEXT    NOT NULL DEFAULT 'free',
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- 租户用户表（一个租户可有多个用户；M1 先按 1:1 最简实现）
CREATE TABLE IF NOT EXISTS tenant_users (
  id            INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id     TEXT    NOT NULL,
  email         TEXT    NOT NULL UNIQUE,
  password_hash TEXT    NOT NULL,
  status        TEXT    NOT NULL DEFAULT 'pending',
  created_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tuser_tenant ON tenant_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tuser_status ON tenant_users(status);

-- 邮件动作令牌（注册验证 / 密码重置）
CREATE TABLE IF NOT EXISTS mail_action_tokens (
  token_hash     TEXT PRIMARY KEY,
  tenant_user_id INTEGER NOT NULL,
  action         TEXT    NOT NULL,
  expires_at     INTEGER NOT NULL,
  consumed_at    INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mtoken_user ON mail_action_tokens(tenant_user_id);
CREATE INDEX IF NOT EXISTS idx_mtoken_expires ON mail_action_tokens(expires_at);

-- API Key 表由 ensureAPIKeysSchema 负责（M3；含 M1 占位表迁移 → §3.5 结构）。

-- 策略 overlay / 模型配置表由 ensurePolicySchema 负责（M5；含 M1 占位表迁移 → §3.5 ⑤⑥）。

-- 注册频率限制（按 IP 窗口计数；C-11）
CREATE TABLE IF NOT EXISTS register_rate (
  ip           TEXT PRIMARY KEY,
  count        INTEGER NOT NULL DEFAULT 0,
  window_start INTEGER NOT NULL
);
`

// ---------- 实体 ----------

// Tenant 租户实体。
type Tenant struct {
	ID        string
	Name      string
	Status    string
	PlanID    string
	CreatedAt int64
}

// TenantUser 租户用户实体。
type TenantUser struct {
	ID           int64
	TenantID     string
	Email        string
	PasswordHash string
	Status       string
	CreatedAt    int64
}

// MailActionToken 邮件动作令牌实体。
type MailActionToken struct {
	TokenHash     string
	TenantUserID  int64
	Action        string
	ExpiresAt     int64
	ConsumedAt    int64
}

// ---------- Store 接口 ----------

// TenantStore 租户存储聚合根。
type TenantStore interface {
	// 租户
	CreateTenant(tx TenantTx, t *Tenant) error
	GetTenantByID(id string) (*Tenant, error)
	UpdateTenantStatus(tx TenantTx, id, status string) error
	// ListTenantsByStatus 按状态枚举租户（补偿任务扫描 quota_pending 用）。
	ListTenantsByStatus(status string) ([]*Tenant, error)

	// 用户
	CreateUser(tx TenantTx, u *TenantUser) (int64, error)
	GetUserByEmail(email string) (*TenantUser, error)
	GetUserByID(id int64) (*TenantUser, error)
	UpdateUserStatus(tx TenantTx, userID int64, status string) error
	UpdatePassword(tx TenantTx, userID int64, passwordHash string) error

	// 邮件令牌
	CreateToken(tx TenantTx, tok *MailActionToken) error
	GetToken(tokenHash string) (*MailActionToken, error)
	ConsumeToken(tx TenantTx, tokenHash string) error

	// API Key（M3）
	CreateAPIKey(tx TenantTx, k *APIKey) error
	GetAPIKeyByID(keyID string) (*APIKey, error)
	GetActiveAPIKeyByName(tenantID, name string) (*APIKey, error)
	ListAPIKeysByTenant(tenantID string) ([]*APIKey, error)
	RevokeAPIKey(tx TenantTx, keyID string, revokedAt int64) error
	ListRevokedAPIKeysSince(since int64) ([]*APIKey, error)

	// 策略 overlay / 模型配置（M5）
	GetPolicyOverlay(tenantID string) (*PolicyOverlay, error)
	UpsertPolicyOverlay(tx TenantTx, p *PolicyOverlay) error
	GetModelConfig(tenantID string) (*ModelConfig, error)
	UpsertModelConfig(tx TenantTx, m *ModelConfig) error

	// 开通配置（N1，§3.5 表 ⑧）
	GetProvisioning(tenantID string) (*TenantProvisioning, error)
	UpsertProvisioning(tx TenantTx, p *TenantProvisioning) error

	// 套餐升级/降级待确认单（M7）
	CreateSubscriptionRequest(tx TenantTx, r *SubscriptionRequest) error
	ListSubscriptionRequests(tenantID string, limit int) ([]*SubscriptionRequest, error)
	GetSubscriptionRequest(requestID string) (*SubscriptionRequest, error)

	// 注册限流
	IncRegisterRate(ip string, windowSec int) (int, error)

	// 事务
	Begin() (TenantTx, error)
	Close() error
}

// TenantTx 事务句柄（写路径统一入口）。
type TenantTx interface {
	Commit() error
	Rollback() error
	tx() *sql.Tx
}

// ---------- SQLite 实现 ----------

type sqliteTenantStore struct {
	db      *sql.DB
	writeMu sync.Mutex // 单写者
	pepper  []byte     // 邮件令牌 pepper（SHA-256(pepper‖token)）
}

type sqlTenantTx struct {
	t    *sql.Tx
	s    *sqliteTenantStore
	done bool
}

func (tx *sqlTenantTx) Commit() error {
	if tx.done {
		return nil
	}
	tx.done = true
	err := tx.t.Commit()
	tx.s.writeMu.Unlock()
	return err
}

func (tx *sqlTenantTx) Rollback() error {
	if tx.done {
		return nil
	}
	tx.done = true
	err := tx.t.Rollback()
	tx.s.writeMu.Unlock()
	return err
}

func (tx *sqlTenantTx) tx() *sql.Tx { return tx.t }

// OpenTenantStore 打开租户存储并执行 DDL 初始化。
// dsn: 文件路径或 ":memory:"（测试用）。
// pepper: 邮件令牌哈希加盐（§6.3）。
func OpenTenantStore(dsn string, wal bool, pepper []byte) (TenantStore, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("tenant: open sqlite: %w", err)
	}
	// 内存模式下限制单连接，避免连接池里不同连接看到不同数据库（:memory: 每连接独立）。
	if dsn == ":memory:" {
		db.SetMaxOpenConns(1)
	}
	if wal {
		if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
			db.Close()
			return nil, fmt.Errorf("tenant: enable WAL: %w", err)
		}
	}
	// 外键约束
	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("tenant: enable foreign keys: %w", err)
	}
	if _, err := db.Exec(tenantDDLSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("tenant: init schema: %w", err)
	}
	// API Key 表（M3）：对齐 §3.5（含 M1 占位表迁移）
	if err := ensureAPIKeysSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	// 策略 overlay / 模型配置表（M5）：对齐 §3.5 ⑤⑥（含 M1 占位表迁移）
	if err := ensurePolicySchema(db); err != nil {
		db.Close()
		return nil, err
	}
	// 套餐待确认单表（M7）
	if err := ensureSubscriptionSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	// 开通配置表（N1，§3.5 表 ⑧）
	if err := ensureProvisioningSchema(db); err != nil {
		db.Close()
		return nil, err
	}
	return &sqliteTenantStore{db: db, pepper: append([]byte(nil), pepper...)}, nil
}

func (s *sqliteTenantStore) Begin() (TenantTx, error) {
	s.writeMu.Lock()
	tx, err := s.db.Begin()
	if err != nil {
		s.writeMu.Unlock()
		return nil, fmt.Errorf("tenant: begin tx: %w", err)
	}
	return &sqlTenantTx{t: tx, s: s}, nil
}

func (s *sqliteTenantStore) Close() error {
	return s.db.Close()
}

// ---------- 密码辅助 ----------

// hashPassword 生成 bcrypt 哈希（cost=12）。
func hashPassword(password string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("tenant: hash password: %w", err)
	}
	return string(h), nil
}

// verifyPassword 校验 bcrypt 密码。
func verifyPassword(hash, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

// ---------- 令牌哈希辅助 ----------

// hashMailToken 计算邮件令牌哈希：SHA-256(pepper ‖ token)。
func (s *sqliteTenantStore) hashMailToken(token string) string {
	h := sha256.New()
	h.Write(s.pepper)
	h.Write([]byte(token))
	return hex.EncodeToString(h.Sum(nil))
}

// ---------- 租户 CRUD ----------

func (s *sqliteTenantStore) CreateTenant(tx TenantTx, t *Tenant) error {
	if t == nil || t.ID == "" {
		return errors.New("tenant: tenant id is required")
	}
	_, err := tx.tx().Exec(`INSERT INTO tenants (id, name, status, plan_id, created_at)
		VALUES (?, ?, ?, ?, ?)`, t.ID, t.Name, t.Status, t.PlanID, t.CreatedAt)
	if err != nil {
		return fmt.Errorf("tenant: create tenant: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) GetTenantByID(id string) (*Tenant, error) {
	var t Tenant
	err := s.db.QueryRow(`SELECT id, name, status, plan_id, created_at FROM tenants WHERE id = ?`, id).
		Scan(&t.ID, &t.Name, &t.Status, &t.PlanID, &t.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get tenant: %w", err)
	}
	return &t, nil
}

func (s *sqliteTenantStore) UpdateTenantStatus(tx TenantTx, id, status string) error {
	res, err := tx.tx().Exec(`UPDATE tenants SET status = ? WHERE id = ?`, status, id)
	if err != nil {
		return fmt.Errorf("tenant: update tenant status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("tenant: tenant %s not found", id)
	}
	return nil
}

// ListTenantsByStatus 按状态枚举租户（补偿任务扫描 quota_pending 用）。
func (s *sqliteTenantStore) ListTenantsByStatus(status string) ([]*Tenant, error) {
	rows, err := s.db.Query(`SELECT id, name, status, plan_id, created_at FROM tenants WHERE status = ?`, status)
	if err != nil {
		return nil, fmt.Errorf("tenant: list tenants by status: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.ID, &t.Name, &t.Status, &t.PlanID, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("tenant: scan tenant: %w", err)
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// ---------- 用户 CRUD ----------

func (s *sqliteTenantStore) CreateUser(tx TenantTx, u *TenantUser) (int64, error) {
	if u == nil || u.Email == "" || u.TenantID == "" {
		return 0, errors.New("tenant: user email and tenant_id are required")
	}
	res, err := tx.tx().Exec(`INSERT INTO tenant_users (tenant_id, email, password_hash, status, created_at)
		VALUES (?, ?, ?, ?, ?)`, u.TenantID, strings.ToLower(u.Email), u.PasswordHash, u.Status, u.CreatedAt)
	if err != nil {
		return 0, fmt.Errorf("tenant: create user: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

func (s *sqliteTenantStore) GetUserByEmail(email string) (*TenantUser, error) {
	var u TenantUser
	err := s.db.QueryRow(`SELECT id, tenant_id, email, password_hash, status, created_at
		FROM tenant_users WHERE email = ?`, strings.ToLower(email)).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Status, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get user by email: %w", err)
	}
	return &u, nil
}

func (s *sqliteTenantStore) GetUserByID(id int64) (*TenantUser, error) {
	var u TenantUser
	err := s.db.QueryRow(`SELECT id, tenant_id, email, password_hash, status, created_at
		FROM tenant_users WHERE id = ?`, id).
		Scan(&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Status, &u.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get user by id: %w", err)
	}
	return &u, nil
}

func (s *sqliteTenantStore) UpdateUserStatus(tx TenantTx, userID int64, status string) error {
	res, err := tx.tx().Exec(`UPDATE tenant_users SET status = ? WHERE id = ?`, status, userID)
	if err != nil {
		return fmt.Errorf("tenant: update user status: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("tenant: user %d not found", userID)
	}
	return nil
}

func (s *sqliteTenantStore) UpdatePassword(tx TenantTx, userID int64, passwordHash string) error {
	res, err := tx.tx().Exec(`UPDATE tenant_users SET password_hash = ? WHERE id = ?`, passwordHash, userID)
	if err != nil {
		return fmt.Errorf("tenant: update password: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("tenant: user %d not found", userID)
	}
	return nil
}

// ---------- 邮件令牌 CRUD ----------

func (s *sqliteTenantStore) CreateToken(tx TenantTx, tok *MailActionToken) error {
	if tok == nil || tok.TokenHash == "" {
		return errors.New("tenant: token hash is required")
	}
	_, err := tx.tx().Exec(`INSERT INTO mail_action_tokens
		(token_hash, tenant_user_id, action, expires_at, consumed_at)
		VALUES (?, ?, ?, ?, ?)`, tok.TokenHash, tok.TenantUserID, tok.Action, tok.ExpiresAt, tok.ConsumedAt)
	if err != nil {
		return fmt.Errorf("tenant: create token: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) GetToken(tokenHash string) (*MailActionToken, error) {
	var t MailActionToken
	err := s.db.QueryRow(`SELECT token_hash, tenant_user_id, action, expires_at, consumed_at
		FROM mail_action_tokens WHERE token_hash = ?`, tokenHash).
		Scan(&t.TokenHash, &t.TenantUserID, &t.Action, &t.ExpiresAt, &t.ConsumedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get token: %w", err)
	}
	return &t, nil
}

func (s *sqliteTenantStore) ConsumeToken(tx TenantTx, tokenHash string) error {
	now := time.Now().Unix()
	res, err := tx.tx().Exec(`UPDATE mail_action_tokens SET consumed_at = ? WHERE token_hash = ? AND consumed_at = 0`,
		now, tokenHash)
	if err != nil {
		return fmt.Errorf("tenant: consume token: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return errors.New("tenant: token not found or already consumed")
	}
	return nil
}

// ---------- API Key（M3，§3.5④）----------

// apiKeyStatus* API Key 状态。
const (
	apiKeyStatusActive  = "active"
	apiKeyStatusRevoked = "revoked"
)

// apiKeysDDL API Key 表结构（对齐 §3.5：key_id 主键、jti 唯一、同租户 active 名称唯一）。
const apiKeysDDL = `
CREATE TABLE IF NOT EXISTS api_keys (
  key_id       TEXT PRIMARY KEY,
  tenant_id    TEXT    NOT NULL,
  name         TEXT    NOT NULL,
  jti          TEXT    NOT NULL UNIQUE,
  fingerprint  TEXT    NOT NULL,
  status       TEXT    NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_by   TEXT    NOT NULL,
  created_at   INTEGER NOT NULL,
  last_used_at INTEGER NOT NULL DEFAULT 0,
  revoked_at   INTEGER NOT NULL DEFAULT 0,
  expires_at   INTEGER NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_key_name ON api_keys(tenant_id, name) WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_apikey_revoked ON api_keys(revoked_at) WHERE status='revoked';
CREATE INDEX IF NOT EXISTS idx_apikey_tenant ON api_keys(tenant_id);
`

// APIKey API Key 元数据（不含明文；fingerprint 为 SHA-256 全量 hex，展示取前 8 位）。
type APIKey struct {
	KeyID       string
	TenantID    string
	Name        string
	JTI         string
	Fingerprint string
	Status      string
	CreatedBy   string
	CreatedAt   int64
	LastUsedAt  int64
	RevokedAt   int64
	ExpiresAt   int64
}

// ensureAPIKeysSchema 建表；若检测到 M1 旧占位表（无 key_id 列）则重建（旧表从未写入，安全）。
func ensureAPIKeysSchema(db *sql.DB) error {
	needs, err := tableNeedsRebuild(db, "api_keys", "key_id")
	if err != nil {
		return err
	}
	if needs {
		if _, err := db.Exec(`DROP TABLE IF EXISTS api_keys`); err != nil {
			return fmt.Errorf("tenant: drop legacy api_keys: %w", err)
		}
	}
	if _, err := db.Exec(apiKeysDDL); err != nil {
		return fmt.Errorf("tenant: init api_keys schema: %w", err)
	}
	return nil
}

// tableNeedsRebuild 检测表是否为旧结构（表存在但不含 requiredCol 列）。
// table 与 requiredCol 均为代码内常量（无注入面）。
func tableNeedsRebuild(db *sql.DB, table, requiredCol string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, fmt.Errorf("tenant: inspect %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	exists, hasCol := false, false
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, fmt.Errorf("tenant: scan %s info: %w", table, err)
		}
		exists = true
		if name == requiredCol {
			hasCol = true
		}
	}
	return exists && !hasCol, rows.Err()
}

const apiKeyColumns = `key_id, tenant_id, name, jti, fingerprint, status, created_by, created_at, last_used_at, revoked_at, expires_at`

// rowScanner 行扫描抽象（*sql.Row / *sql.Rows 共用）。
type rowScanner interface{ Scan(dest ...any) error }

func scanAPIKey(sc rowScanner) (*APIKey, error) {
	var k APIKey
	if err := sc.Scan(&k.KeyID, &k.TenantID, &k.Name, &k.JTI, &k.Fingerprint, &k.Status,
		&k.CreatedBy, &k.CreatedAt, &k.LastUsedAt, &k.RevokedAt, &k.ExpiresAt); err != nil {
		return nil, err
	}
	return &k, nil
}

func (s *sqliteTenantStore) CreateAPIKey(tx TenantTx, k *APIKey) error {
	if k == nil || k.KeyID == "" || k.TenantID == "" || k.JTI == "" {
		return errors.New("tenant: api key id/tenant_id/jti are required")
	}
	_, err := tx.tx().Exec(`INSERT INTO api_keys
		(key_id, tenant_id, name, jti, fingerprint, status, created_by, created_at, last_used_at, revoked_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.KeyID, k.TenantID, k.Name, k.JTI, k.Fingerprint, k.Status, k.CreatedBy,
		k.CreatedAt, k.LastUsedAt, k.RevokedAt, k.ExpiresAt)
	if err != nil {
		return fmt.Errorf("tenant: create api key: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) GetAPIKeyByID(keyID string) (*APIKey, error) {
	k, err := scanAPIKey(s.db.QueryRow(`SELECT `+apiKeyColumns+` FROM api_keys WHERE key_id = ?`, keyID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get api key: %w", err)
	}
	return k, nil
}

func (s *sqliteTenantStore) GetActiveAPIKeyByName(tenantID, name string) (*APIKey, error) {
	k, err := scanAPIKey(s.db.QueryRow(`SELECT `+apiKeyColumns+
		` FROM api_keys WHERE tenant_id = ? AND name = ? AND status = 'active'`, tenantID, name))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get active api key by name: %w", err)
	}
	return k, nil
}

func (s *sqliteTenantStore) ListAPIKeysByTenant(tenantID string) ([]*APIKey, error) {
	return s.queryAPIKeys(`SELECT `+apiKeyColumns+
		` FROM api_keys WHERE tenant_id = ? ORDER BY created_at DESC`, tenantID)
}

func (s *sqliteTenantStore) ListRevokedAPIKeysSince(since int64) ([]*APIKey, error) {
	return s.queryAPIKeys(`SELECT `+apiKeyColumns+
		` FROM api_keys WHERE status = 'revoked' AND revoked_at > ? ORDER BY revoked_at ASC`, since)
}

func (s *sqliteTenantStore) queryAPIKeys(query string, args ...any) ([]*APIKey, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("tenant: list api keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*APIKey
	for rows.Next() {
		k, err := scanAPIKey(rows)
		if err != nil {
			return nil, fmt.Errorf("tenant: scan api key: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *sqliteTenantStore) RevokeAPIKey(tx TenantTx, keyID string, revokedAt int64) error {
	res, err := tx.tx().Exec(`UPDATE api_keys SET status = 'revoked', revoked_at = ? WHERE key_id = ? AND status = 'active'`,
		revokedAt, keyID)
	if err != nil {
		return fmt.Errorf("tenant: revoke api key: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("tenant: api key %s not found or already revoked", keyID)
	}
	return nil
}

// ---------- 策略 overlay / 模型配置（M5，§3.5⑤⑥）----------

// errTenantVersionConflict 乐观锁版本冲突（服务层映射 409）。
var errTenantVersionConflict = errors.New("tenant: version conflict")

// policyDDL 策略 overlay 与模型配置表结构（对齐 §3.5 ⑤⑥）。
const policyDDL = `
CREATE TABLE IF NOT EXISTS policy_overlays (
  tenant_id        TEXT PRIMARY KEY,
  version          INTEGER NOT NULL DEFAULT 1,
  whitelist        TEXT    NOT NULL DEFAULT '{"entries":[]}',
  blacklist        TEXT    NOT NULL DEFAULT '{"entries":[]}',
  category_actions TEXT    NOT NULL DEFAULT '{}',
  updated_at       INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS model_configs (
  tenant_id      TEXT PRIMARY KEY,
  allowed_models TEXT    NOT NULL DEFAULT '[]',
  default_model  TEXT    NOT NULL DEFAULT '',
  version        INTEGER NOT NULL DEFAULT 1,
  updated_at     INTEGER NOT NULL
);
`

// PolicyOverlay 租户策略 overlay（每租户一行）。
type PolicyOverlay struct {
	TenantID            string
	Version             int64
	WhitelistJSON       string // {"entries":[{id,kind,value,created_at}]}
	BlacklistJSON       string
	CategoryActionsJSON string // {<内置类目>: block|mask|allow}
	UpdatedAt           int64
}

// ModelConfig 租户模型配置（每租户一行）。
type ModelConfig struct {
	TenantID          string
	AllowedModelsJSON string // JSON 数组
	DefaultModel      string
	Version           int64
	UpdatedAt         int64
}

// ensurePolicySchema 建表；M1 旧占位表（无 version 列）→ 重建（旧表从未写入，安全）。
func ensurePolicySchema(db *sql.DB) error {
	for _, t := range []string{"policy_overlays", "model_configs"} {
		needs, err := tableNeedsRebuild(db, t, "version")
		if err != nil {
			return err
		}
		if needs {
			if _, err := db.Exec(`DROP TABLE IF EXISTS ` + t); err != nil {
				return fmt.Errorf("tenant: drop legacy %s: %w", t, err)
			}
		}
	}
	if _, err := db.Exec(policyDDL); err != nil {
		return fmt.Errorf("tenant: init policy schema: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) GetPolicyOverlay(tenantID string) (*PolicyOverlay, error) {
	var p PolicyOverlay
	err := s.db.QueryRow(`SELECT tenant_id, version, whitelist, blacklist, category_actions, updated_at
		FROM policy_overlays WHERE tenant_id = ?`, tenantID).
		Scan(&p.TenantID, &p.Version, &p.WhitelistJSON, &p.BlacklistJSON, &p.CategoryActionsJSON, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get policy overlay: %w", err)
	}
	return &p, nil
}

// UpsertPolicyOverlay 写入 overlay（乐观锁：WHERE version = p.Version；不存在则插入 version=1）。
// 版本不匹配 → errTenantVersionConflict。
func (s *sqliteTenantStore) UpsertPolicyOverlay(tx TenantTx, p *PolicyOverlay) error {
	res, err := tx.tx().Exec(`UPDATE policy_overlays
		SET version = version + 1, whitelist = ?, blacklist = ?, category_actions = ?, updated_at = ?
		WHERE tenant_id = ? AND version = ?`,
		p.WhitelistJSON, p.BlacklistJSON, p.CategoryActionsJSON, p.UpdatedAt, p.TenantID, p.Version)
	if err != nil {
		return fmt.Errorf("tenant: upsert policy overlay: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	if exists, err := rowExists(tx, `SELECT COUNT(1) FROM policy_overlays WHERE tenant_id = ?`, p.TenantID); err != nil {
		return err
	} else if exists {
		return errTenantVersionConflict
	}
	if _, err := tx.tx().Exec(`INSERT INTO policy_overlays
		(tenant_id, version, whitelist, blacklist, category_actions, updated_at)
		VALUES (?, 1, ?, ?, ?, ?)`,
		p.TenantID, p.WhitelistJSON, p.BlacklistJSON, p.CategoryActionsJSON, p.UpdatedAt); err != nil {
		return fmt.Errorf("tenant: insert policy overlay: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) GetModelConfig(tenantID string) (*ModelConfig, error) {
	var m ModelConfig
	err := s.db.QueryRow(`SELECT tenant_id, allowed_models, default_model, version, updated_at
		FROM model_configs WHERE tenant_id = ?`, tenantID).
		Scan(&m.TenantID, &m.AllowedModelsJSON, &m.DefaultModel, &m.Version, &m.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get model config: %w", err)
	}
	return &m, nil
}

// UpsertModelConfig 写入模型配置（乐观锁同 UpsertPolicyOverlay）。
func (s *sqliteTenantStore) UpsertModelConfig(tx TenantTx, m *ModelConfig) error {
	res, err := tx.tx().Exec(`UPDATE model_configs
		SET version = version + 1, allowed_models = ?, default_model = ?, updated_at = ?
		WHERE tenant_id = ? AND version = ?`,
		m.AllowedModelsJSON, m.DefaultModel, m.UpdatedAt, m.TenantID, m.Version)
	if err != nil {
		return fmt.Errorf("tenant: upsert model config: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	if exists, err := rowExists(tx, `SELECT COUNT(1) FROM model_configs WHERE tenant_id = ?`, m.TenantID); err != nil {
		return err
	} else if exists {
		return errTenantVersionConflict
	}
	if _, err := tx.tx().Exec(`INSERT INTO model_configs
		(tenant_id, allowed_models, default_model, version, updated_at)
		VALUES (?, ?, ?, 1, ?)`,
		m.TenantID, m.AllowedModelsJSON, m.DefaultModel, m.UpdatedAt); err != nil {
		return fmt.Errorf("tenant: insert model config: %w", err)
	}
	return nil
}

// rowExists 执行 COUNT 查询并返回是否存在（>0）。
func rowExists(tx TenantTx, query string, args ...any) (bool, error) {
	var n int
	if err := tx.tx().QueryRow(query, args...).Scan(&n); err != nil {
		return false, fmt.Errorf("tenant: count query: %w", err)
	}
	return n > 0, nil
}

// ---------- 套餐待确认单（M7，§6.8 D-9）----------

// subscriptionDDL 套餐待确认单表（D-9：租户发起 → 管理员确认复用 handleBindSubscription）。
const subscriptionDDL = `
CREATE TABLE IF NOT EXISTS subscription_requests (
  request_id TEXT PRIMARY KEY,
  tenant_id  TEXT    NOT NULL,
  from_plan  TEXT    NOT NULL,
  to_plan    TEXT    NOT NULL,
  direction  TEXT    NOT NULL,
  status     TEXT    NOT NULL DEFAULT 'pending',
  created_by TEXT    NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subreq_tenant ON subscription_requests(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_subreq_status ON subscription_requests(status);
`

// SubscriptionRequest 套餐升级/降级待确认单。
type SubscriptionRequest struct {
	RequestID string
	TenantID  string
	FromPlan  string
	ToPlan    string
	Direction string // upgrade | downgrade
	Status    string // pending | confirmed | rejected
	CreatedBy string
	CreatedAt int64
}

// ensureSubscriptionSchema 建表（M7 新表）。
func ensureSubscriptionSchema(db *sql.DB) error {
	if _, err := db.Exec(subscriptionDDL); err != nil {
		return fmt.Errorf("tenant: init subscription schema: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) CreateSubscriptionRequest(tx TenantTx, r *SubscriptionRequest) error {
	if r == nil || r.RequestID == "" || r.TenantID == "" || r.ToPlan == "" {
		return errors.New("tenant: subscription request id/tenant_id/to_plan are required")
	}
	_, err := tx.tx().Exec(`INSERT INTO subscription_requests
		(request_id, tenant_id, from_plan, to_plan, direction, status, created_by, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		r.RequestID, r.TenantID, r.FromPlan, r.ToPlan, r.Direction, r.Status, r.CreatedBy, r.CreatedAt)
	if err != nil {
		return fmt.Errorf("tenant: create subscription request: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) ListSubscriptionRequests(tenantID string, limit int) ([]*SubscriptionRequest, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Query(`SELECT request_id, tenant_id, from_plan, to_plan, direction, status, created_by, created_at
		FROM subscription_requests WHERE tenant_id = ? ORDER BY created_at DESC LIMIT ?`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("tenant: list subscription requests: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*SubscriptionRequest
	for rows.Next() {
		var r SubscriptionRequest
		if err := rows.Scan(&r.RequestID, &r.TenantID, &r.FromPlan, &r.ToPlan, &r.Direction,
			&r.Status, &r.CreatedBy, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("tenant: scan subscription request: %w", err)
		}
		out = append(out, &r)
	}
	return out, rows.Err()
}

func (s *sqliteTenantStore) GetSubscriptionRequest(requestID string) (*SubscriptionRequest, error) {
	var r SubscriptionRequest
	err := s.db.QueryRow(`SELECT request_id, tenant_id, from_plan, to_plan, direction, status, created_by, created_at
		FROM subscription_requests WHERE request_id = ?`, requestID).
		Scan(&r.RequestID, &r.TenantID, &r.FromPlan, &r.ToPlan, &r.Direction,
			&r.Status, &r.CreatedBy, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get subscription request: %w", err)
	}
	return &r, nil
}

// ---------- 注册限流 ----------

// IncRegisterRate 增加指定 IP 的注册计数，返回当前窗口计数。
// windowSec: 窗口大小（秒）；超出窗口重置为 1。
func (s *sqliteTenantStore) IncRegisterRate(ip string, windowSec int) (int, error) {
	now := time.Now().Unix()
	tx, err := s.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var count int
	var windowStart int64
	err = tx.tx().QueryRow(`SELECT count, window_start FROM register_rate WHERE ip = ?`, ip).
		Scan(&count, &windowStart)
	if err == sql.ErrNoRows {
		count = 1
		_, err = tx.tx().Exec(`INSERT INTO register_rate (ip, count, window_start) VALUES (?, 1, ?)`, ip, now)
		if err != nil {
			return 0, fmt.Errorf("tenant: insert register_rate: %w", err)
		}
	} else if err != nil {
		return 0, fmt.Errorf("tenant: get register_rate: %w", err)
	} else {
		if now-windowStart > int64(windowSec) {
			count = 1
			_, err = tx.tx().Exec(`UPDATE register_rate SET count = 1, window_start = ? WHERE ip = ?`, now, ip)
		} else {
			count++
			_, err = tx.tx().Exec(`UPDATE register_rate SET count = count + 1 WHERE ip = ?`, ip)
		}
		if err != nil {
			return 0, fmt.Errorf("tenant: update register_rate: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return count, nil
}

// ---------- 开通配置（N1，§3.5 表 ⑧）----------

// provisioningDDL 开通配置表结构（对齐 §3.5 表 ⑧；每租户一行）。
// access_mode 恒 'a_segmented'（v1.6 锁定：B 型/端到端禁选）；
// segment2_mode 对齐场景矩阵 CHECK 约束；plugin_set 为 N6 渲染后 JSON。
const provisioningDDL = `
CREATE TABLE IF NOT EXISTS tenant_provisionings (
  tenant_id          TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  scenario           TEXT    NOT NULL CHECK (scenario IN ('s1','s2','s3a','s3b','s4')),
  trust_tier         TEXT    NOT NULL CHECK (trust_tier IN ('trusted','untrusted')),
  access_mode        TEXT    NOT NULL DEFAULT 'a_segmented' CHECK (access_mode = 'a_segmented'),
  plugin_set         TEXT    NOT NULL DEFAULT '[]',
  segment1_enabled   INTEGER NOT NULL,
  segment2_mode      TEXT    NOT NULL CHECK (segment2_mode IN ('none','vendor_sdk','enclave_plaintext','cross_node_mtls','ciphertext_domain')),
  template_version   TEXT    NOT NULL,
  provider_cred_refs TEXT    NOT NULL DEFAULT '[]',
  provisioned_at     INTEGER NOT NULL,
  updated_at         INTEGER NOT NULL
);
`

// TenantProvisioning 开通配置（每租户一行）。
type TenantProvisioning struct {
	TenantID             string
	Scenario             string
	TrustTier            string // trusted | untrusted（轴 A）
	AccessMode           string // 恒 a_segmented
	PluginSetJSON        string // N6 渲染后的插件组合 JSON
	Segment1Enabled      bool   // 段① otpmask 开关（S1=0，其余=1）
	Segment2Mode         string // none/vendor_sdk/enclave_plaintext/cross_node_mtls/ciphertext_domain
	TemplateVersion      string // N6 模板版本
	ProviderCredRefsJSON string // [{name,vault_ref,updated_at}]（仅 vault 句柄 + 元数据，禁明文）
	ProvisionedAt        int64
	UpdatedAt            int64
}

// ensureProvisioningSchema 建表（N1 新表）。
func ensureProvisioningSchema(db *sql.DB) error {
	if _, err := db.Exec(provisioningDDL); err != nil {
		return fmt.Errorf("tenant: init provisioning schema: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) GetProvisioning(tenantID string) (*TenantProvisioning, error) {
	var p TenantProvisioning
	err := s.db.QueryRow(`SELECT tenant_id, scenario, trust_tier, access_mode, plugin_set,
		segment1_enabled, segment2_mode, template_version, provider_cred_refs, provisioned_at, updated_at
		FROM tenant_provisionings WHERE tenant_id = ?`, tenantID).
		Scan(&p.TenantID, &p.Scenario, &p.TrustTier, &p.AccessMode, &p.PluginSetJSON,
			&p.Segment1Enabled, &p.Segment2Mode, &p.TemplateVersion, &p.ProviderCredRefsJSON,
			&p.ProvisionedAt, &p.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get provisioning: %w", err)
	}
	return &p, nil
}

// UpsertProvisioning 写入开通配置（每租户一行；更新时保留 provisioned_at）。
func (s *sqliteTenantStore) UpsertProvisioning(tx TenantTx, p *TenantProvisioning) error {
	if p == nil || p.TenantID == "" || p.Scenario == "" {
		return errors.New("tenant: provisioning tenant_id/scenario are required")
	}
	if p.ProviderCredRefsJSON == "" {
		p.ProviderCredRefsJSON = "[]"
	}
	if p.PluginSetJSON == "" {
		p.PluginSetJSON = "[]"
	}
	_, err := tx.tx().Exec(`INSERT INTO tenant_provisionings
		(tenant_id, scenario, trust_tier, access_mode, plugin_set, segment1_enabled,
		 segment2_mode, template_version, provider_cred_refs, provisioned_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET
			scenario = excluded.scenario,
			trust_tier = excluded.trust_tier,
			access_mode = excluded.access_mode,
			plugin_set = excluded.plugin_set,
			segment1_enabled = excluded.segment1_enabled,
			segment2_mode = excluded.segment2_mode,
			template_version = excluded.template_version,
			provider_cred_refs = excluded.provider_cred_refs,
			updated_at = excluded.updated_at`,
		p.TenantID, p.Scenario, p.TrustTier, p.AccessMode, p.PluginSetJSON, p.Segment1Enabled,
		p.Segment2Mode, p.TemplateVersion, p.ProviderCredRefsJSON, p.ProvisionedAt, p.UpdatedAt)
	if err != nil {
		return fmt.Errorf("tenant: upsert provisioning: %w", err)
	}
	return nil
}
