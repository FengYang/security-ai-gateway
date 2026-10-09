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

-- 策略 overlay（M5 补 CRUD；M1 仅建表占位）
CREATE TABLE IF NOT EXISTS policy_overlays (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id  TEXT    NOT NULL,
  scope      TEXT    NOT NULL,
  action     TEXT    NOT NULL,
  pattern    TEXT    NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_policy_tenant ON policy_overlays(tenant_id);

-- 模型配置（M5 补 CRUD；M1 仅建表占位）
CREATE TABLE IF NOT EXISTS model_configs (
  tenant_id      TEXT PRIMARY KEY,
  default_model  TEXT    NOT NULL DEFAULT '',
  allowed_models TEXT    NOT NULL DEFAULT '[]',
  updated_at     INTEGER NOT NULL
);

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
	needs, err := apiKeysNeedsRebuild(db)
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

// apiKeysNeedsRebuild 检测 api_keys 是否为 M1 旧结构（存在但无 key_id 列）。
func apiKeysNeedsRebuild(db *sql.DB) (bool, error) {
	rows, err := db.Query(`PRAGMA table_info(api_keys)`)
	if err != nil {
		return false, fmt.Errorf("tenant: inspect api_keys: %w", err)
	}
	defer func() { _ = rows.Close() }()
	exists, hasKeyID := false, false
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, fmt.Errorf("tenant: scan api_keys info: %w", err)
		}
		exists = true
		if name == "key_id" {
			hasKeyID = true
		}
	}
	return exists && !hasKeyID, rows.Err()
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
