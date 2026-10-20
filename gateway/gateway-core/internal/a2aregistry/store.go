package a2aregistry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// AgentRecord 是 a2a_agents 表行的 Go 表示（§3.2 AgentRecord schema）。
type AgentRecord struct {
	Tenant              string
	Name                string
	ProviderID          string
	CardJSON            []byte
	ContentHash         string
	RawHash             string
	Revision            int
	RegistryRevision    int
	AgentVersion        string
	BackendURL          string
	Labels              map[string]string
	SignatureKid        string
	SignatureAlg        string
	SignatureVerified   bool
	SignatureVerifiedAt string
	Status              string // active|deleted
	CreatedAt           string
	UpdatedAt           string
	DeletedAt           *string
}

// ProviderKey 是 a2a_provider_keys 表行的 Go 表示（§4.2）。
type ProviderKey struct {
	TenantID   string
	ProviderID string
	Kid        string
	Alg        string
	PublicJWK  string
	Status     string // active|retired|revoked
	NotBefore  *string
	NotAfter   *string
	CreatedAt  string
	UpdatedAt  string
}

// OutboxRow 是 a2a_registry_outbox 表行。
type OutboxRow struct {
	ID        int64
	EventJSON string
	Attempts  int
}

const schemaDDL = `
CREATE TABLE IF NOT EXISTS a2a_agents (
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  card_json BLOB NOT NULL,
  content_hash TEXT NOT NULL,
  raw_hash TEXT NOT NULL,
  revision INTEGER NOT NULL,
  registry_revision INTEGER NOT NULL,
  agent_version TEXT NOT NULL,
  backend_url TEXT NOT NULL,
  labels_json TEXT,
  signature_kid TEXT NOT NULL,
  signature_alg TEXT NOT NULL,
  signature_verified INTEGER NOT NULL,
  signature_verified_at TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  deleted_at TEXT,
  PRIMARY KEY (tenant_id, name)
);
CREATE INDEX IF NOT EXISTS idx_a2a_agents_provider ON a2a_agents(tenant_id, provider_id, status);

CREATE TABLE IF NOT EXISTS a2a_provider_keys (
  tenant_id TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  kid TEXT NOT NULL,
  alg TEXT NOT NULL,
  public_jwk TEXT NOT NULL,
  status TEXT NOT NULL,
  not_before TEXT,
  not_after TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, provider_id, kid)
);

CREATE TABLE IF NOT EXISTS a2a_registry_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS a2a_idempotency (
  tenant_id TEXT NOT NULL, idem_key TEXT NOT NULL, endpoint TEXT NOT NULL,
  request_hash TEXT NOT NULL, response_json TEXT NOT NULL, expires_at TEXT NOT NULL,
  PRIMARY KEY (tenant_id, idem_key, endpoint)
);
CREATE TABLE IF NOT EXISTS a2a_registry_outbox (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  event_json TEXT NOT NULL, status TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL, last_error TEXT
);
`

const metaRegistryRevision = "registry_revision"

// schemaVersion 是本代码理解的 schema 版本（写入 PRAGMA user_version）。
// 启动时若库中 user_version > schemaVersion，说明**库比代码新**（回滚/混版），
// 按冻结 §5.1「迁移校验：schema 新于代码 → 拒绝启动」fail-closed 拒绝。
const schemaVersion = 1

// ErrSchemaTooNew 表示库 schema 版本高于本代码支持（**致命**：调用方须拒绝启动）。
var ErrSchemaTooNew = errors.New("a2aregistry: 库 schema 版本高于代码")

// errStoreUnavailable 表示存储不可用（非致命：控制面返回 503 registry_unavailable）。
var errStoreUnavailable = errors.New("a2aregistry: 存储不可用")

// Store 封装 SQLite 访问（单写者；写路径统一用 Begin 开事务，写锁保证 BEGIN IMMEDIATE 语义）。
type Store struct {
	db     *sql.DB
	writeMu sync.Mutex
}

// OpenStore 打开（或创建）A2A 注册中心 SQLite 库，设 WAL/synchronous=FULL/busy_timeout。
// dsn 形如 /var/lib/gateway-core/a2a-registry.db；测试可用 file::memory:?cache=shared。
//
// 事务语义：DSN 追加 `_txlock=immediate`（冻结 §5.1「单写者 BEGIN IMMEDIATE」），
// 使每个事务一开启即取写锁，避免 deferred 事务在升级锁时返回 SQLITE_BUSY。
//
// ⚠️ 失败语义分两类：
//   - ErrSchemaTooNew（库比代码新）→ **致命**，调用方须拒绝启动；
//   - 其余（路径不可写/磁盘故障等）→ **非致命**，调用方可用 NewUnavailable 降级为
//     registry_unavailable（控制面 503），不拖垮其它服务。
func OpenStore(dsn string) (*Store, error) {
	effDSN, err := withImmediateTxLock(dsn)
	if err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", effDSN)
	if err != nil {
		return nil, fmt.Errorf("a2aregistry: 打开数据库失败: %w", err)
	}
	pragmas := []string{
		"PRAGMA journal_mode=WAL;",
		"PRAGMA synchronous=FULL;",
		"PRAGMA busy_timeout=5000;",
		"PRAGMA foreign_keys=ON;",
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			db.Close()
			return nil, fmt.Errorf("a2aregistry: 设置 %s 失败: %w", p, err)
		}
	}
	if err := checkSchemaVersion(db); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.Exec(schemaDDL); err != nil {
		db.Close()
		return nil, fmt.Errorf("a2aregistry: 初始化 schema 失败: %w", err)
	}
	if _, err := db.Exec(fmt.Sprintf("PRAGMA user_version=%d", schemaVersion)); err != nil {
		db.Close()
		return nil, fmt.Errorf("a2aregistry: 写入 schema 版本失败: %w", err)
	}
	return &Store{db: db}, nil
}

// NewUnavailable 返回一个"存储不可用"的 Store（db 为 nil）。
// 供 New 降级路径使用：所有写/读操作返回 errStoreUnavailable（映射为 503）。
func NewUnavailable() *Store { return &Store{} }

// withImmediateTxLock 为 DSN 追加 `_txlock=immediate`（已显式指定则不覆盖）。
func withImmediateTxLock(dsn string) (string, error) {
	if dsn == "" {
		return "", fmt.Errorf("a2aregistry: DSN 为空")
	}
	if strings.Contains(dsn, "_txlock=") {
		return dsn, nil
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + "_txlock=immediate", nil
}

// checkSchemaVersion 校验库中 schema 版本不新于本代码（冻结 §5.1 迁移校验）。
func checkSchemaVersion(db *sql.DB) error {
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		return fmt.Errorf("a2aregistry: 读取 schema 版本失败: %w", err)
	}
	if v > schemaVersion {
		return fmt.Errorf("%w（库 %d > 代码 %d，拒绝启动）", ErrSchemaTooNew, v, schemaVersion)
	}
	return nil
}

// Close 关闭数据库连接。
func (s *Store) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

// Begin 开写事务（获取写锁，保证单写者 BEGIN IMMEDIATE 语义）。
// 调用方必须配对调用 Commit 或 Rollback 以释放写锁。
func (s *Store) Begin() (*sql.Tx, error) {
	s.writeMu.Lock()
	if s.db == nil {
		s.writeMu.Unlock()
		return nil, errStoreUnavailable
	}
	tx, err := s.db.BeginTx(context.Background(), &sql.TxOptions{})
	if err != nil {
		s.writeMu.Unlock()
		return nil, err
	}
	return tx, nil
}

// Commit 提交并释放写锁。
func (s *Store) Commit(tx *sql.Tx) error {
	err := tx.Commit()
	s.writeMu.Unlock()
	return err
}

// Rollback 回滚并释放写锁。
func (s *Store) Rollback(tx *sql.Tx) error {
	err := tx.Rollback()
	s.writeMu.Unlock()
	return err
}

// bumpRegistryRevision 在事务内原子递增全局 registry_revision 并返回新值。
func (s *Store) bumpRegistryRevision(tx *sql.Tx) (int, error) {
	var cur int
	if err := tx.QueryRow("SELECT COALESCE(CAST(value AS INTEGER),0) FROM a2a_registry_meta WHERE key=?", metaRegistryRevision).Scan(&cur); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}
	next := cur + 1
	if _, err := tx.Exec("INSERT INTO a2a_registry_meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value", metaRegistryRevision, itoa(next)); err != nil {
		return 0, err
	}
	return next, nil
}

// GetRegistryRevision 读取当前全局 registry_revision（无写事务时使用）。
func (s *Store) GetRegistryRevision() int {
	if s == nil || s.db == nil {
		return 0
	}
	var cur int
	_ = s.db.QueryRow("SELECT COALESCE(CAST(value AS INTEGER),0) FROM a2a_registry_meta WHERE key=?", metaRegistryRevision).Scan(&cur)
	return cur
}

// getRegistryRevisionTx 在事务内读取 registry_revision（快照构建须与记录读取同事务，
// 避免读到与记录不一致的版本号）。
func getRegistryRevisionTx(tx *sql.Tx) int {
	var cur int
	_ = tx.QueryRow("SELECT COALESCE(CAST(value AS INTEGER),0) FROM a2a_registry_meta WHERE key=?", metaRegistryRevision).Scan(&cur)
	return cur
}

// Backup 用 VACUUM INTO 生成一致性备份（冻结 §5.1 恢复：日备 VACUUM INTO + 7 天保留）。
// 目标文件已存在时返回错误（避免误覆盖备份）。
func (s *Store) Backup(dest string) error {
	if dest == "" {
		return fmt.Errorf("a2aregistry: 备份目标路径为空")
	}
	if _, err := os.Stat(dest); err == nil {
		return fmt.Errorf("a2aregistry: 备份目标已存在: %s", dest)
	}
	if _, err := s.db.Exec("VACUUM INTO ?", dest); err != nil {
		return fmt.Errorf("a2aregistry: 备份失败: %w", err)
	}
	return nil
}

// UpsertAgent 插入或全量替换 agent 记录（同事务内调用）。
func (s *Store) UpsertAgent(tx *sql.Tx, rec *AgentRecord) error {
	labels, _ := json.Marshal(rec.Labels)
	_, err := tx.Exec(`
INSERT INTO a2a_agents(tenant_id,name,provider_id,card_json,content_hash,raw_hash,revision,registry_revision,
  agent_version,backend_url,labels_json,signature_kid,signature_alg,signature_verified,signature_verified_at,status,created_at,updated_at,deleted_at)
VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(tenant_id,name) DO UPDATE SET
  provider_id=excluded.provider_id, card_json=excluded.card_json, content_hash=excluded.content_hash, raw_hash=excluded.raw_hash,
  revision=excluded.revision, registry_revision=excluded.registry_revision, agent_version=excluded.agent_version, backend_url=excluded.backend_url,
  labels_json=excluded.labels_json, signature_kid=excluded.signature_kid, signature_alg=excluded.signature_alg, signature_verified=excluded.signature_verified,
  signature_verified_at=excluded.signature_verified_at, status=excluded.status, updated_at=excluded.updated_at, deleted_at=excluded.deleted_at`,
		rec.Tenant, rec.Name, rec.ProviderID, rec.CardJSON, rec.ContentHash, rec.RawHash, rec.Revision, rec.RegistryRevision,
		rec.AgentVersion, rec.BackendURL, string(labels), rec.SignatureKid, rec.SignatureAlg, boolToInt(rec.SignatureVerified), rec.SignatureVerifiedAt, rec.Status, rec.CreatedAt, rec.UpdatedAt, rec.DeletedAt)
	if err != nil {
		return fmt.Errorf("a2aregistry: 写入 agent 失败: %w", err)
	}
	return nil
}

// GetAgent 读取单条 agent（includeDeleted 控制是否含墓碑）。
func (s *Store) GetAgent(tx *sql.Tx, tenant, name string, includeDeleted bool) (*AgentRecord, error) {
	q := `SELECT tenant_id,name,provider_id,card_json,content_hash,raw_hash,revision,registry_revision,agent_version,backend_url,labels_json,signature_kid,signature_alg,signature_verified,signature_verified_at,status,created_at,updated_at,deleted_at FROM a2a_agents WHERE tenant_id=? AND name=?`
	if !includeDeleted {
		q += ` AND status='active'`
	}
	row := tx.QueryRow(q, tenant, name)
	return scanAgent(row)
}

// ListAgents 按过滤条件列出 agent（按 name 升序）。
// tenant 为空表示跨租户列举（仅内部快照分发使用）。
//
// skill 过滤在 Go 侧做（卡 JSON 为原文，SQL LIKE 无法可靠判定 skill id）；
// limit 在过滤后生效，故过滤阶段不施加 SQL LIMIT。
func (s *Store) ListAgents(tx *sql.Tx, tenant string, namePrefix, skill, status string, includeDeleted bool, limit int, cursor string) ([]*AgentRecord, error) {
	q := `SELECT tenant_id,name,provider_id,card_json,content_hash,raw_hash,revision,registry_revision,agent_version,backend_url,labels_json,signature_kid,signature_alg,signature_verified,signature_verified_at,status,created_at,updated_at,deleted_at FROM a2a_agents`
	var args []any
	if tenant != "" {
		q += ` WHERE tenant_id=?`
		args = append(args, tenant)
	} else {
		q += ` WHERE 1=1`
	}
	if namePrefix != "" {
		q += ` AND name LIKE ? ESCAPE '\'`
		args = append(args, escapeLike(namePrefix)+"%")
	}
	if status != "" {
		q += ` AND status=?`
		args = append(args, status)
	} else if !includeDeleted {
		q += ` AND status='active'`
	}
	if cursor != "" {
		q += ` AND name > ?`
		args = append(args, cursor)
	}
	q += ` ORDER BY name ASC`
	if skill == "" && limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := tx.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*AgentRecord
	for rows.Next() {
		rec, err := scanAgentRow(rows)
		if err != nil {
			return nil, err
		}
		if skill != "" && !cardHasSkill(rec.CardJSON, skill) {
			continue
		}
		out = append(out, rec)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, rows.Err()
}

// cardHasSkill 判断卡 JSON 的 skills[].id 是否命中（冻结 §5.3 列表过滤）。
func cardHasSkill(cardJSON []byte, skill string) bool {
	var card struct {
		Skills []struct {
			ID string `json:"id"`
		} `json:"skills"`
	}
	if err := json.Unmarshal(cardJSON, &card); err != nil {
		return false
	}
	for _, s := range card.Skills {
		if s.ID == skill {
			return true
		}
	}
	return false
}

// SoftDeleteAgent 软删（写墓碑）。返回受影响行数。
func (s *Store) SoftDeleteAgent(tx *sql.Tx, tenant, name, deletedAt string) (int64, error) {
	res, err := tx.Exec(`UPDATE a2a_agents SET status='deleted', deleted_at=?, updated_at=? WHERE tenant_id=? AND name=? AND status='active'`, deletedAt, deletedAt, tenant, name)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// UpdateSignatureStatus 更新验签状态（吊销重验时）。
func (s *Store) UpdateSignatureStatus(tx *sql.Tx, tenant, name string, verified bool, at string) error {
	_, err := tx.Exec(`UPDATE a2a_agents SET signature_verified=?, signature_verified_at=?, updated_at=? WHERE tenant_id=? AND name=?`, boolToInt(verified), at, at, tenant, name)
	return err
}

// ImportProviderKey 导入 pinned 公钥（同事务）。
func (s *Store) ImportProviderKey(tx *sql.Tx, k *ProviderKey) error {
	_, err := tx.Exec(`INSERT INTO a2a_provider_keys(tenant_id,provider_id,kid,alg,public_jwk,status,not_before,not_after,created_at,updated_at)
VALUES(?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(tenant_id,provider_id,kid) DO UPDATE SET alg=excluded.alg, public_jwk=excluded.public_jwk, status=excluded.status, not_before=excluded.not_before, not_after=excluded.not_after, updated_at=excluded.updated_at`,
		k.TenantID, k.ProviderID, k.Kid, k.Alg, k.PublicJWK, k.Status, k.NotBefore, k.NotAfter, k.CreatedAt, k.UpdatedAt)
	return err
}

// GetProviderKey 读取单条 pinned 公钥；不存在返回 (nil, nil)。
func (s *Store) GetProviderKey(tx *sql.Tx, tenant, provider, kid string) (*ProviderKey, error) {
	row := tx.QueryRow(`SELECT tenant_id,provider_id,kid,alg,public_jwk,status,not_before,not_after,created_at,updated_at FROM a2a_provider_keys WHERE tenant_id=? AND provider_id=? AND kid=?`, tenant, provider, kid)
	return scanProviderKey(row)
}

// ListProviderKeys 列出 provider 的密钥（不返回私钥）。
func (s *Store) ListProviderKeys(tx *sql.Tx, tenant, provider string) ([]*ProviderKey, error) {
	rows, err := tx.Query(`SELECT tenant_id,provider_id,kid,alg,public_jwk,status,not_before,not_after,created_at,updated_at FROM a2a_provider_keys WHERE tenant_id=? AND provider_id=?`, tenant, provider)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*ProviderKey
	for rows.Next() {
		k, err := scanProviderKeyRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// SetProviderKeyStatus 更新密钥状态（revoked/retired/active）。
func (s *Store) SetProviderKeyStatus(tx *sql.Tx, tenant, provider, kid, status, at string) (int64, error) {
	res, err := tx.Exec(`UPDATE a2a_provider_keys SET status=?, updated_at=? WHERE tenant_id=? AND provider_id=? AND kid=?`, status, at, tenant, provider, kid)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// DeleteProviderKey 删除密钥（仅 revoked 或无引用）。
func (s *Store) DeleteProviderKey(tx *sql.Tx, tenant, provider, kid string) (int64, error) {
	res, err := tx.Exec(`DELETE FROM a2a_provider_keys WHERE tenant_id=? AND provider_id=? AND kid=?`, tenant, provider, kid)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// AffectedAgentsByProvider 返回某 provider 受影响（active）agent 数（吊销重验用）。
func (s *Store) AffectedAgentsByProvider(tx *sql.Tx, tenant, provider string) (int, error) {
	var n int
	err := tx.QueryRow(`SELECT COUNT(*) FROM a2a_agents WHERE tenant_id=? AND provider_id=? AND status='active'`, tenant, provider).Scan(&n)
	return n, err
}

// IdempotencyGet 读取幂等缓存响应与请求指纹；无则返回 ("", "", false)。
// 请求指纹用于判定「同 key 同 body → 同响应；同 key 不同 body → 409 idempotency_conflict」。
func (s *Store) IdempotencyGet(tx *sql.Tx, tenant, idemKey, endpoint string) (resp, reqHash string, ok bool) {
	var expires string
	err := tx.QueryRow(`SELECT response_json, request_hash, expires_at FROM a2a_idempotency WHERE tenant_id=? AND idem_key=? AND endpoint=?`, tenant, idemKey, endpoint).Scan(&resp, &reqHash, &expires)
	if err != nil {
		return "", "", false
	}
	if expires < time.Now().UTC().Format(time.RFC3339Nano) {
		return "", "", false
	}
	return resp, reqHash, true
}

// IdempotencySet 写入幂等缓存（24h）。
func (s *Store) IdempotencySet(tx *sql.Tx, tenant, idemKey, endpoint, reqHash, resp string) error {
	expires := time.Now().UTC().Add(24 * time.Hour).Format(time.RFC3339Nano)
	_, err := tx.Exec(`INSERT INTO a2a_idempotency(tenant_id,idem_key,endpoint,request_hash,response_json,expires_at)
VALUES(?,?,?,?,?,?)
ON CONFLICT(tenant_id,idem_key,endpoint) DO UPDATE SET response_json=excluded.response_json, expires_at=excluded.expires_at`,
		tenant, idemKey, endpoint, reqHash, resp, expires)
	return err
}

// InsertOutbox 写入审计 outbox（同事务）。
func (s *Store) InsertOutbox(tx *sql.Tx, eventJSON string) error {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := tx.Exec(`INSERT INTO a2a_registry_outbox(event_json,status,attempts,created_at,last_error) VALUES(?,?,0,?,NULL)`, eventJSON, "pending", now)
	return err
}

// DrainOutbox 取出待发 outbox 行（最多 limit）。
func (s *Store) DrainOutbox(limit int) ([]OutboxRow, error) {
	if s == nil || s.db == nil {
		return nil, errStoreUnavailable
	}
	rows, err := s.db.Query(`SELECT id,event_json,attempts FROM a2a_registry_outbox WHERE status='pending' ORDER BY id ASC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var r OutboxRow
		if err := rows.Scan(&r.ID, &r.EventJSON, &r.Attempts); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DeleteOutbox 删除已成功上报的 outbox 行。
func (s *Store) DeleteOutbox(id int64) error {
	if s == nil || s.db == nil {
		return errStoreUnavailable
	}
	_, err := s.db.Exec(`DELETE FROM a2a_registry_outbox WHERE id=?`, id)
	return err
}

// MarkOutboxError 标记 outbox 行上报失败（累加 attempts）。
func (s *Store) MarkOutboxError(id int64, lastErr string) error {
	if s == nil || s.db == nil {
		return errStoreUnavailable
	}
	_, err := s.db.Exec(`UPDATE a2a_registry_outbox SET attempts=attempts+1, status='pending', last_error=? WHERE id=?`, lastErr, id)
	return err
}

// --- 私有辅助 ---

func scanAgent(row *sql.Row) (*AgentRecord, error) {
	r := &AgentRecord{}
	var labels sql.NullString
	var del sql.NullString
	var verified int
	err := row.Scan(&r.Tenant, &r.Name, &r.ProviderID, &r.CardJSON, &r.ContentHash, &r.RawHash, &r.Revision, &r.RegistryRevision,
		&r.AgentVersion, &r.BackendURL, &labels, &r.SignatureKid, &r.SignatureAlg, &verified, &r.SignatureVerifiedAt, &r.Status, &r.CreatedAt, &r.UpdatedAt, &del)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	r.SignatureVerified = verified != 0
	if labels.Valid && labels.String != "" {
		_ = json.Unmarshal([]byte(labels.String), &r.Labels)
	}
	if del.Valid {
		d := del.String
		r.DeletedAt = &d
	}
	return r, nil
}

func scanAgentRow(rows *sql.Rows) (*AgentRecord, error) {
	r := &AgentRecord{}
	var labels sql.NullString
	var del sql.NullString
	var verified int
	err := rows.Scan(&r.Tenant, &r.Name, &r.ProviderID, &r.CardJSON, &r.ContentHash, &r.RawHash, &r.Revision, &r.RegistryRevision,
		&r.AgentVersion, &r.BackendURL, &labels, &r.SignatureKid, &r.SignatureAlg, &verified, &r.SignatureVerifiedAt, &r.Status, &r.CreatedAt, &r.UpdatedAt, &del)
	if err != nil {
		return nil, err
	}
	r.SignatureVerified = verified != 0
	if labels.Valid && labels.String != "" {
		_ = json.Unmarshal([]byte(labels.String), &r.Labels)
	}
	if del.Valid {
		d := del.String
		r.DeletedAt = &d
	}
	return r, nil
}

func scanProviderKey(row *sql.Row) (*ProviderKey, error) {
	k := &ProviderKey{}
	var nb, na sql.NullString
	err := row.Scan(&k.TenantID, &k.ProviderID, &k.Kid, &k.Alg, &k.PublicJWK, &k.Status, &nb, &na, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if nb.Valid {
		v := nb.String
		k.NotBefore = &v
	}
	if na.Valid {
		v := na.String
		k.NotAfter = &v
	}
	return k, nil
}

func scanProviderKeyRow(rows *sql.Rows) (*ProviderKey, error) {
	k := &ProviderKey{}
	var nb, na sql.NullString
	err := rows.Scan(&k.TenantID, &k.ProviderID, &k.Kid, &k.Alg, &k.PublicJWK, &k.Status, &nb, &na, &k.CreatedAt, &k.UpdatedAt)
	if err != nil {
		return nil, err
	}
	if nb.Valid {
		v := nb.String
		k.NotBefore = &v
	}
	if na.Valid {
		v := na.String
		k.NotAfter = &v
	}
	return k, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func itoa(i int) string {
	return fmt.Sprintf("%d", i)
}

func escapeLike(s string) string {
	return strings.NewReplacer("\\", "\\\\", "%", "\\%", "_", "\\_").Replace(s)
}
