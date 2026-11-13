// Package main — 租户自助门户存储层（SQLite / PostgreSQL 双方言）。
//
// 按本体 §3.5 建立 7 张表：tenants / tenant_users / mail_action_tokens /
// api_keys / policy_overlays / model_configs / register_rate。
// 密码 bcrypt cost=12；邮件令牌哈希存储（SHA-256 + pepper）；
// 写事务在 sqlite 下由进程内 writeMu 串行，在 PG 下另加 advisory xact lock
// （跨副本等价 BEGIN IMMEDIATE 意图，P2-4 T-1）。
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

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// boolToInt64 bool → 0/1（INTEGER 列的统一存储形态）。PG 下 pgx 不能把 Go bool
// 编码进 int4/int8 列（QA P1-1），写入参数须显式转换；读路径 Scan 进 *bool 不受影响。
func boolToInt64(b bool) int64 {
	if b {
		return 1
	}
	return 0
}

// ---------- 常量 ----------

const (
	// bcryptCost 密码哈希代价因子（等保三级推荐 ≥12；§6.3）。
	bcryptCost = 12

	// tenantUserStatusActive / Locked 等状态常量。
	tenantUserStatusActive  = "active"
	tenantUserStatusLocked  = "locked"
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

// tenantDDLSchemaPG 租户门户 PG DDL（与 sqlite 侧 tenantDDLSchema + 各 ensure*Schema 等价迁移，
// P2-4 T-1.2；PG 无 sqlite 的 PRAGMA 自检/重建逻辑，新库直建目标结构）：
//   - `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL`（新库无回填，无需 setval）；
//   - 时间戳等 INTEGER 列 → BIGINT（PG 的 INTEGER 为 4 字节，epoch 秒 2038 年溢出，
//     须与 sqlite 的 8 字节 INTEGER 等宽）；
//   - 部分唯一索引（WHERE ...）/ CHECK 约束 / ON CONFLICT 语义 PG 原生支持，逐条对齐。
const tenantDDLSchemaPG = `
CREATE TABLE IF NOT EXISTS tenants (
  id         TEXT PRIMARY KEY,
  name       TEXT   NOT NULL,
  status     TEXT   NOT NULL DEFAULT 'active',
  plan_id    TEXT   NOT NULL DEFAULT 'free',
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

CREATE TABLE IF NOT EXISTS tenant_users (
  id            BIGSERIAL PRIMARY KEY,
  tenant_id     TEXT   NOT NULL,
  email         TEXT   NOT NULL UNIQUE,
  password_hash TEXT   NOT NULL,
  status        TEXT   NOT NULL DEFAULT 'pending',
  created_at    BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_tuser_tenant ON tenant_users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_tuser_status ON tenant_users(status);

CREATE TABLE IF NOT EXISTS mail_action_tokens (
  token_hash     TEXT   PRIMARY KEY,
  tenant_user_id BIGINT NOT NULL,
  action         TEXT   NOT NULL,
  expires_at     BIGINT NOT NULL,
  consumed_at    BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_mtoken_user ON mail_action_tokens(tenant_user_id);
CREATE INDEX IF NOT EXISTS idx_mtoken_expires ON mail_action_tokens(expires_at);

CREATE TABLE IF NOT EXISTS register_rate (
  ip           TEXT    PRIMARY KEY,
  count        INTEGER NOT NULL DEFAULT 0,
  window_start BIGINT  NOT NULL
);

CREATE TABLE IF NOT EXISTS api_keys (
  key_id       TEXT PRIMARY KEY,
  tenant_id    TEXT   NOT NULL,
  name         TEXT   NOT NULL,
  jti          TEXT   NOT NULL UNIQUE,
  fingerprint  TEXT   NOT NULL,
  status       TEXT   NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  created_by   TEXT   NOT NULL,
  created_at   BIGINT NOT NULL,
  last_used_at BIGINT NOT NULL DEFAULT 0,
  revoked_at   BIGINT NOT NULL DEFAULT 0,
  expires_at   BIGINT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS uq_active_key_name ON api_keys(tenant_id, name) WHERE status='active';
CREATE INDEX IF NOT EXISTS idx_apikey_revoked ON api_keys(revoked_at) WHERE status='revoked';
CREATE INDEX IF NOT EXISTS idx_apikey_tenant ON api_keys(tenant_id);
-- P2-4 T-1.9（S3 共享库多集群租户隔离）：租户面查询一律以 tenant_id 打头，
-- 使共享库下的租户查询能按前缀裁剪、不退化为跨租户全表扫描——
-- 既是性能要求，也是"应用层行级隔离"能真正落地的存储前提。
CREATE INDEX IF NOT EXISTS idx_apikey_tenant_created ON api_keys(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_apikey_tenant_status ON api_keys(tenant_id, status);

CREATE TABLE IF NOT EXISTS policy_overlays (
  tenant_id        TEXT   PRIMARY KEY,
  version          BIGINT NOT NULL DEFAULT 1,
  whitelist        TEXT   NOT NULL DEFAULT '{"entries":[]}',
  blacklist        TEXT   NOT NULL DEFAULT '{"entries":[]}',
  category_actions TEXT   NOT NULL DEFAULT '{}',
  updated_at       BIGINT NOT NULL
);
-- P2-4 T-3.1：scope 列（策略作用域 §6.2）。PG 无 sqlite 的整表重建逻辑，存量库用
-- ADD COLUMN IF NOT EXISTS 补齐；列可空，NULL/空视作 global（存量兼容，不回填）。
ALTER TABLE policy_overlays ADD COLUMN IF NOT EXISTS scope TEXT;

CREATE TABLE IF NOT EXISTS model_configs (
  tenant_id      TEXT   PRIMARY KEY,
  allowed_models TEXT   NOT NULL DEFAULT '[]',
  default_model  TEXT   NOT NULL DEFAULT '',
  version        BIGINT NOT NULL DEFAULT 1,
  updated_at     BIGINT NOT NULL
);
ALTER TABLE model_configs ADD COLUMN IF NOT EXISTS scope TEXT;

CREATE TABLE IF NOT EXISTS subscription_requests (
  request_id TEXT PRIMARY KEY,
  tenant_id  TEXT   NOT NULL,
  from_plan  TEXT   NOT NULL,
  to_plan    TEXT   NOT NULL,
  direction  TEXT   NOT NULL,
  status     TEXT   NOT NULL DEFAULT 'pending',
  created_by TEXT   NOT NULL,
  created_at BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_subreq_tenant ON subscription_requests(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_subreq_status ON subscription_requests(status);

CREATE TABLE IF NOT EXISTS tenant_provisionings (
  tenant_id          TEXT PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
  scenario           TEXT   NOT NULL CHECK (scenario IN ('s1','s2','s3a','s3b','s4')),
  trust_tier         TEXT   NOT NULL CHECK (trust_tier IN ('trusted','untrusted')),
  access_mode        TEXT   NOT NULL DEFAULT 'a_segmented' CHECK (access_mode = 'a_segmented'),
  plugin_set         TEXT   NOT NULL DEFAULT '[]',
  segment1_enabled   INTEGER NOT NULL,
  segment2_mode      TEXT   NOT NULL CHECK (segment2_mode IN ('none','vendor_sdk','enclave_plaintext','cross_node_mtls','ciphertext_domain')),
  template_version   TEXT   NOT NULL,
  provider_cred_refs TEXT   NOT NULL DEFAULT '[]',
  provisioned_at     BIGINT NOT NULL,
  updated_at         BIGINT NOT NULL
);
ALTER TABLE tenant_provisionings ADD COLUMN IF NOT EXISTS scope TEXT;

CREATE TABLE IF NOT EXISTS tenant_statements (
  statement_id     TEXT PRIMARY KEY,
  tenant_id        TEXT   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  scenario         TEXT   NOT NULL,
  access_mode      TEXT   NOT NULL,
  template_version TEXT   NOT NULL,
  content          TEXT   NOT NULL,
  content_hash     TEXT   NOT NULL,
  supersedes_id    TEXT REFERENCES tenant_statements(statement_id),
  created_at       BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_statements_tenant ON tenant_statements(tenant_id, created_at DESC);
-- P2-4 T-1.9（S3）：GetCurrentStatement 的重签链子查询按 (tenant_id, supersedes_id) 定位，
-- 保证"取当前声明"在共享库下只扫本租户行。
CREATE INDEX IF NOT EXISTS idx_statements_supersedes ON tenant_statements(tenant_id, supersedes_id) WHERE supersedes_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS tenant_dispatch_state (
  tenant_id       TEXT   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  cluster_id      TEXT   NOT NULL DEFAULT '',
  config_version  BIGINT NOT NULL DEFAULT 0,
  status          TEXT   NOT NULL DEFAULT 'idle' CHECK (status IN ('idle','pending','applying','applied','failed')),
  applied_version BIGINT NOT NULL DEFAULT 0,
  last_error      TEXT,
  retry_count     BIGINT NOT NULL DEFAULT 0,
  updated_at      BIGINT NOT NULL,
  PRIMARY KEY (tenant_id, cluster_id)
);
-- P2-4 T-3.2a：存量库补列（幂等）。PG 无 sqlite 的整表重建，改主键走
-- DROP CONSTRAINT + ADD PRIMARY KEY（见 ensureDispatchSchemaPG）。
ALTER TABLE tenant_dispatch_state ADD COLUMN IF NOT EXISTS cluster_id TEXT NOT NULL DEFAULT '';
CREATE INDEX IF NOT EXISTS idx_dispatch_status ON tenant_dispatch_state(status);
-- P2-4 T-1.9（S3）：重启重放扫描按 status 过滤并按 updated_at 排序，
-- 复合索引避免共享库下排序退化为全表排序。
CREATE INDEX IF NOT EXISTS idx_dispatch_status_updated ON tenant_dispatch_state(status, updated_at);
-- P2-4 T-3.2a（T-1.9 交接索引清单）：集群维度索引。
CREATE INDEX IF NOT EXISTS idx_dispatch_cluster_status ON tenant_dispatch_state(cluster_id, status);
CREATE INDEX IF NOT EXISTS idx_dispatch_tenant_cluster ON tenant_dispatch_state(tenant_id, cluster_id);
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
	TokenHash    string
	TenantUserID int64
	Action       string
	ExpiresAt    int64
	ConsumedAt   int64
}

// ---------- S3 复核结论（P2-4 T-1.9） ----------
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§T-1 ⑦：
// "租户表以 tenant_id（+cluster_id 可选）复合主键/索引；所有查询强制 tenant 作用域过滤
// （应用层行级隔离），禁止跨租户/跨集群直读；测试覆盖跨集群泄露用例。"
//
// 一、租户面查询（**SQL 层强制 tenant 作用域**，共享库多集群下同样成立）：
//
//	api_keys             GetAPIKeyByIDForTenant / GetActiveAPIKeyByName / ListAPIKeysByTenant
//	policy_overlays      GetPolicyOverlay / UpsertPolicyOverlay（tenant_id 为主键）
//	model_configs        GetModelConfig / UpsertModelConfig（tenant_id 为主键）
//	tenant_provisionings GetProvisioning / UpsertProvisioning（tenant_id 为主键）
//	tenant_statements    GetCurrentStatement / GetStatement / ListStatementsByTenant
//	tenant_dispatch_state GetDispatchState / Bump·Mark*Dispatch（均按 tenant_id）
//	subscription_requests ListSubscriptionRequests（按 tenant_id）
//
// 二、管理面/后台全局口径查询（**非租户数据面路径**，刻意跨租户，逐条登记调用点与鉴权）：
//
//	ListRevokedAPIKeysSince   数据面吊销增量拉取（内部 Bearer 令牌，§6.11）
//	ListProvisionedTenants    运维批量重签发枚举（admin 端点）
//	ListDispatchStatesByStatus 重启重放扫描 pending/applying（后台 worker）
//	ListTenantsByStatus       补偿任务扫描（后台 worker）
//	GetUserByEmail/GetUserByID 登录与用户主键定位（email 全局唯一，无歧义）
//	GetToken/ConsumeToken      邮件动作令牌（token_hash 全局唯一且不可枚举）
//	IncRegisterRate            按 IP 的注册频次计数（反滥用；同 IP 跨租户共享同一计数口径）
//	GetAPIKeyByID/RevokeAPIKey 全局按 key_id（管理面/后台）——**租户面禁用**，见 ForTenant 变体
//	GetSubscriptionRequest      管理面按 request_id（当前无租户面调用点）
//
// 三、集群维度索引登记（T-3.2 落地 cluster_id 时**必须**同步追加，勿遗漏）：
//
//	tenant_dispatch_state: (cluster_id, status)、(tenant_id, cluster_id)
//	  —— **T-3.2a 已建**：idx_dispatch_cluster_status / idx_dispatch_tenant_cluster
//	     （主键同步迁移为 (tenant_id, cluster_id)）。
//	tenant_statements:    (tenant_id, cluster_id, created_at DESC)（若声明按集群分册）
//	  —— **T-3.2a 未建**：该索引以「承诺边界声明按集群分册」为前提，而 §6.2 的作用域
//	     模型只覆盖处方/路由/限流表/插件配置/工具目录，承诺边界声明仍是**租户级签名
//	     产物**（supersedes 链跨集群唯一），故不引入 cluster_id 列、不建该索引。
//	     若后续裁定声明改为按集群分册，须连带迁移 tenant_statements 并补该索引。
//
// 说明：租户表默认**尚无 cluster_id 列**——S3 口径为"+cluster_id 可选"，列本身与
// "每租户×每集群单飞"语义由 T-3.2 引入（T-3.2a 存储侧 / T-3.2b 下发侧）；
// 本清单先行登记，避免 T-3.2 漏建索引。
// 集群维度落地前，跨集群隔离由 tenant 作用域承担：共享库内不同租户的数据不得互相直读
// （负向用例见 tenant_isolation_s3_test.go）。

// ---------- Store 接口 ----------

// TenantStore 租户存储聚合根。
type TenantStore interface {
	// 租户
	CreateTenant(tx TenantTx, t *Tenant) error
	GetTenantByID(id string) (*Tenant, error)
	UpdateTenantStatus(tx TenantTx, id, status string) error
	// ListTenantsByStatus 按状态枚举租户（补偿任务扫描 quota_pending 用）。
	ListTenantsByStatus(status string) ([]*Tenant, error)
	// ListAllTenants 枚举全部租户（不限状态；P2-4 T-3.3 收敛核对枚举用）。
	ListAllTenants() ([]*Tenant, error)

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
	// GetAPIKeyByID 全局口径直查（按 key_id，**不带** tenant 作用域）：
	// 仅限管理面/后台路径；租户数据面路径必须用 GetAPIKeyByIDForTenant
	// （P2-4 T-1.9 S3：共享库多集群下禁止跨租户直读）。
	GetAPIKeyByID(keyID string) (*APIKey, error)
	// GetAPIKeyByIDForTenant 租户口径：SQL 层强制 tenant_id 过滤，跨租户返回 nil。
	GetAPIKeyByIDForTenant(tenantID, keyID string) (*APIKey, error)
	GetActiveAPIKeyByName(tenantID, name string) (*APIKey, error)
	ListAPIKeysByTenant(tenantID string) ([]*APIKey, error)
	// RevokeAPIKey 全局口径吊销（不带 tenant 作用域）：仅限管理面/后台路径。
	RevokeAPIKey(tx TenantTx, keyID string, revokedAt int64) error
	// RevokeAPIKeyForTenant 租户口径吊销：SQL 层强制 tenant_id 过滤，跨租户不生效。
	RevokeAPIKeyForTenant(tx TenantTx, tenantID, keyID string, revokedAt int64) error
	ListRevokedAPIKeysSince(since int64) ([]*APIKey, error)

	// 策略 overlay / 模型配置（M5）
	GetPolicyOverlay(tenantID string) (*PolicyOverlay, error)
	UpsertPolicyOverlay(tx TenantTx, p *PolicyOverlay) error
	GetModelConfig(tenantID string) (*ModelConfig, error)
	UpsertModelConfig(tx TenantTx, m *ModelConfig) error

	// 开通配置（N1，§3.5 表 ⑧）
	GetProvisioning(tenantID string) (*TenantProvisioning, error)
	UpsertProvisioning(tx TenantTx, p *TenantProvisioning) error

	// 承诺边界声明存证（N4，§3.5 表 ⑨）
	CreateStatement(tx TenantTx, st *TenantStatement) error
	GetCurrentStatement(tenantID string) (*TenantStatement, error)
	GetStatement(tenantID, statementID string) (*TenantStatement, error)
	ListStatementsByTenant(tenantID string) ([]*TenantStatement, error)
	// ListProvisionedTenants 列出所有已开通租户（N4 运维批量重签发枚举用）。
	ListProvisionedTenants() ([]string, error)

	// 下发状态机（N5，§3.5 表 ⑩）
	GetDispatchState(tenantID string) (*TenantDispatchState, error)
	BumpDispatchVersion(tx TenantTx, tenantID string, now int64) (int64, error)
	MarkDispatchApplying(tx TenantTx, tenantID string, now int64) error
	MarkDispatchApplied(tx TenantTx, tenantID string, appliedVersion, now int64) error
	MarkDispatchFailed(tx TenantTx, tenantID string, lastError string, retryCount, now int64) error
	// 集群维度变体（P2-4 T-3.2a：每租户×每集群一行）。clusterID = '' 即全局行，
	// 与上方无 cluster 参数的方法等价（存量语义不变）。
	GetDispatchStateForCluster(tenantID, clusterID string) (*TenantDispatchState, error)
	BumpDispatchVersionForCluster(tx TenantTx, tenantID, clusterID string, now int64) (int64, error)
	// MarkDispatchPendingForCluster 把租户级目标版本投影到集群行（**不递增**版本号）。
	MarkDispatchPendingForCluster(tx TenantTx, tenantID, clusterID string, version int64, now int64) error
	MarkDispatchApplyingForCluster(tx TenantTx, tenantID, clusterID string, now int64) error
	MarkDispatchAppliedForCluster(tx TenantTx, tenantID, clusterID string, appliedVersion, now int64) error
	MarkDispatchFailedForCluster(tx TenantTx, tenantID, clusterID, lastError string, retryCount, now int64) error
	ListDispatchStatesByStatus(statuses ...string) ([]*TenantDispatchState, error)
	// ListDispatchStatesByTenant 枚举某租户的全部下发状态行（跨集群；P2-4 T-3.3 收敛核对用）。
	ListDispatchStatesByTenant(tenantID string) ([]*TenantDispatchState, error)

	// 套餐升级/降级待确认单（M7）
	CreateSubscriptionRequest(tx TenantTx, r *SubscriptionRequest) error
	ListSubscriptionRequests(tenantID string, limit int) ([]*SubscriptionRequest, error)
	// GetSubscriptionRequest 全局口径（按 request_id，**不带** tenant 作用域）：
	// 管理面运维查询用；当前无租户面调用点（租户面统一走 ListSubscriptionRequests(tenantID)）。
	// 若后续开放租户面按 id 查，必须改用 ListSubscriptionRequests 或新增 ForTenant 变体
	// （P2-4 T-1.9 S3）。
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
	tx() sqlutil.Querier
}

// ---------- SQL 实现（sqlite / postgres 双方言） ----------

// sqliteTenantStore 租户存储的 SQL 实现。名称保留历史（既有测试/调用点），
// 实际按 db.Dialect() 适配 sqlite 或 postgres。
type sqliteTenantStore struct {
	db      *sqlutil.DB
	writeMu sync.Mutex // 进程内单写者（PG 下另有 advisory xact lock 做跨副本串行）
	pepper  []byte     // 邮件令牌 pepper（SHA-256(pepper‖token)）
}

type sqlTenantTx struct {
	t    *sqlutil.Tx
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

func (tx *sqlTenantTx) tx() sqlutil.Querier { return tx.t }

// 租户写事务的跨副本互斥键（PG advisory xact lock；固定常量即可，
// 租户库写路径本就全局串行）。
const tenantStoreLockKey int64 = 0x54454E414E54 // "TENANT"

// OpenTenantStore 打开租户存储并执行 DDL 初始化（SQLite 默认路径，签名保持兼容）。
// dsn: 文件路径或 ":memory:"（测试用）。
// pepper: 邮件令牌哈希加盐（§6.3）。
func OpenTenantStore(dsn string, wal bool, pepper []byte) (TenantStore, error) {
	return OpenTenantStoreWithDialect(sqlutil.SQLite, dsn, wal, pepper)
}

// OpenTenantStoreWithDialect 按方言打开租户存储。
// postgres 时 dsn 为 PG 连接串（如 postgres://<user>:<password>@host:5432/db?sslmode=disable）。
func OpenTenantStoreWithDialect(d sqlutil.Dialect, dsn string, wal bool, pepper []byte) (TenantStore, error) {
	if d.IsPostgres() {
		return openPostgresTenantStore(dsn, pepper)
	}
	return openSQLiteTenantStore(dsn, wal, pepper)
}

func openSQLiteTenantStore(dsn string, wal bool, pepper []byte) (TenantStore, error) {
	db, err := sqlutil.Open(sqlutil.SQLite, dsn, tenantStoreLockKey)
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
	if err := ensureAPIKeysSchema(db.DB); err != nil {
		db.Close()
		return nil, err
	}
	// 策略 overlay / 模型配置表（M5）：对齐 §3.5 ⑤⑥（含 M1 占位表迁移）
	if err := ensurePolicySchema(db.DB); err != nil {
		db.Close()
		return nil, err
	}
	// 套餐待确认单表（M7）
	if err := ensureSubscriptionSchema(db.DB); err != nil {
		db.Close()
		return nil, err
	}
	// 开通配置表（N1，§3.5 表 ⑧）
	if err := ensureProvisioningSchema(db.DB); err != nil {
		db.Close()
		return nil, err
	}
	// 承诺边界声明存证表（N4，§3.5 表 ⑨）
	if err := ensureStatementsSchema(db.DB); err != nil {
		db.Close()
		return nil, err
	}
	// 下发状态机表（N5，§3.5 表 ⑩）
	if err := ensureDispatchSchema(db.DB); err != nil {
		db.Close()
		return nil, err
	}
	// P2-4 T-3.1：策略作用域列（policy_overlays / model_configs / tenant_provisionings）。
	// 存量库补列（可空，NULL = global）；PG 侧由 DDL 内 ADD COLUMN IF NOT EXISTS 覆盖。
	if err := ensureScopeColumns(db.DB); err != nil {
		db.Close()
		return nil, err
	}
	// 注：安全计数器（A-full captcha / S1(7) 登录锁定）的 PG 化在 T-1.3/T-1.4 落地，
	// 当前仍为进程内态，此处不建表。
	return &sqliteTenantStore{db: db, pepper: append([]byte(nil), pepper...)}, nil
}

func openPostgresTenantStore(dsn string, pepper []byte) (TenantStore, error) {
	db, err := sqlutil.Open(sqlutil.Postgres, dsn, tenantStoreLockKey)
	if err != nil {
		return nil, fmt.Errorf("tenant: open postgres: %w", err)
	}
	if _, err := db.Exec(tenantDDLSchemaPG); err != nil {
		db.Close()
		return nil, fmt.Errorf("tenant: init pg schema: %w", err)
	}
	// P2-4 T-3.2a：tenant_dispatch_state 主键迁移为 (tenant_id, cluster_id)
	// （PG 走 DROP CONSTRAINT + ADD PRIMARY KEY；幂等可重入）。
	if err := ensureDispatchSchemaPG(db); err != nil {
		db.Close()
		return nil, err
	}
	// 安全计数器（captcha / 登录锁定）PG 化在 T-1.3/T-1.4 落地，此处不建表。
	return &sqliteTenantStore{db: db, pepper: append([]byte(nil), pepper...)}, nil
}

// ensureDispatchSchemaPG PG 侧下发状态机主键迁移（P2-4 T-3.2a）。
//
// PG 支持 ALTER TABLE ... ADD/DROP CONSTRAINT ⇒ 不必整表重建：
// ① 补列（幂等；DDL 内已做一次，此处兜底）；
// ② 查当前主键约束名与列序；
// ③ 已是 (tenant_id, cluster_id) 则跳过；否则 DROP CONSTRAINT + ADD PRIMARY KEY。
// 幂等可重入：重复启动不重复改主键、不重复建索引。
func ensureDispatchSchemaPG(db *sqlutil.DB) error {
	if _, err := db.Exec(`ALTER TABLE tenant_dispatch_state
		ADD COLUMN IF NOT EXISTS cluster_id TEXT NOT NULL DEFAULT ''`); err != nil {
		return fmt.Errorf("tenant: pg dispatch add cluster_id: %w", err)
	}
	conName, pkCols, err := pgPrimaryKeyInfo(db, "tenant_dispatch_state")
	if err != nil {
		return err
	}
	if len(pkCols) == 2 && pkCols[0] == "tenant_id" && pkCols[1] == "cluster_id" {
		return nil // 已是目标主键
	}
	if conName != "" {
		if _, err := db.Exec(`ALTER TABLE tenant_dispatch_state DROP CONSTRAINT ` + conName); err != nil {
			return fmt.Errorf("tenant: pg dispatch drop pk: %w", err)
		}
	}
	if _, err := db.Exec(`ALTER TABLE tenant_dispatch_state ADD PRIMARY KEY (tenant_id, cluster_id)`); err != nil {
		return fmt.Errorf("tenant: pg dispatch add pk: %w", err)
	}
	return nil
}

// pgPrimaryKeyInfo 读取 PG 表的主键约束名与列序（无主键 → 空名 + 空列）。
func pgPrimaryKeyInfo(db *sqlutil.DB, table string) (string, []string, error) {
	rows, err := db.Query(`SELECT c.conname, a.attname
		FROM pg_constraint c
		CROSS JOIN LATERAL unnest(c.conkey) WITH ORDINALITY AS k(attnum, ord)
		JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = k.attnum
		WHERE c.conrelid = to_regclass(?) AND c.contype = 'p'
		ORDER BY k.ord`, table)
	if err != nil {
		return "", nil, fmt.Errorf("tenant: pg primary key info %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	var name string
	var cols []string
	for rows.Next() {
		var col string
		if err := rows.Scan(&name, &col); err != nil {
			return "", nil, fmt.Errorf("tenant: scan pg primary key %s: %w", table, err)
		}
		cols = append(cols, col)
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	return name, cols, nil
}

// DB 返回底层方言包装（captcha/登录锁定等安全组件共用同一连接池与写锁语义）。
func (s *sqliteTenantStore) DB() *sqlutil.DB { return s.db }

// Dialect 返回存储方言。
func (s *sqliteTenantStore) Dialect() sqlutil.Dialect { return s.db.Dialect() }

// tiebreak 同时间戳的确定性排序键：sqlite 用 rowid（插入序），PG 无 rowid，
// 用主键 statement_id（同秒多条时仅影响并列顺序，不影响“最新一条”语义）。
func (s *sqliteTenantStore) tiebreak() string {
	if s.db.Dialect().IsPostgres() {
		return "statement_id"
	}
	return "rowid"
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

// ListAllTenants 枚举全部租户（不限状态；P2-4 T-3.3 收敛核对枚举用）。
func (s *sqliteTenantStore) ListAllTenants() ([]*Tenant, error) {
	rows, err := s.db.Query(`SELECT id, name, status, plan_id, created_at FROM tenants`)
	if err != nil {
		return nil, fmt.Errorf("tenant: list all tenants: %w", err)
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
	if s.db.Dialect().IsPostgres() {
		// pgx 驱动不支持 LastInsertId：PG 下经 RETURNING 直取 BIGSERIAL 自增主键。
		var id int64
		err := tx.tx().QueryRow(`INSERT INTO tenant_users (tenant_id, email, password_hash, status, created_at)
			VALUES (?, ?, ?, ?, ?) RETURNING id`,
			u.TenantID, strings.ToLower(u.Email), u.PasswordHash, u.Status, u.CreatedAt).Scan(&id)
		if err != nil {
			return 0, fmt.Errorf("tenant: create user: %w", err)
		}
		return id, nil
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
-- P2-4 T-1.9（S3 共享库多集群租户隔离）：租户面查询一律以 tenant_id 打头，
-- 使共享库下的租户查询能按前缀裁剪、不退化为跨租户全表扫描——
-- 既是性能要求，也是"应用层行级隔离"能真正落地的存储前提。
CREATE INDEX IF NOT EXISTS idx_apikey_tenant_created ON api_keys(tenant_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_apikey_tenant_status ON api_keys(tenant_id, status);
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

// GetAPIKeyByID 全局口径直查（按 key_id，不带 tenant 作用域）。
//
// P2-4 T-1.9（S3）：共享库多集群下这是**跨租户直读**的口子，仅限管理面/后台路径；
// 租户数据面路径必须用 GetAPIKeyByIDForTenant。
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

// GetAPIKeyByIDForTenant 租户口径取 Key：SQL 层强制 tenant_id 过滤。
//
// 跨租户（或不存在的 key_id）一律返回 (nil, nil)，与"不存在"不可区分——
// 不泄露 key 是否存在（P2-4 T-1.9 S3 应用层行级隔离）。
func (s *sqliteTenantStore) GetAPIKeyByIDForTenant(tenantID, keyID string) (*APIKey, error) {
	if tenantID == "" || keyID == "" {
		return nil, nil
	}
	k, err := scanAPIKey(s.db.QueryRow(`SELECT `+apiKeyColumns+
		` FROM api_keys WHERE tenant_id = ? AND key_id = ?`, tenantID, keyID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get api key for tenant: %w", err)
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

// RevokeAPIKey 全局口径吊销（按 key_id，不带 tenant 作用域）：仅限管理面/后台路径。
//
// P2-4 T-1.9（S3）：租户数据面路径必须用 RevokeAPIKeyForTenant，
// 否则共享库下存在"按 key_id 跨租户吊销"的口子。
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

// RevokeAPIKeyForTenant 租户口径吊销：SQL 层强制 tenant_id 过滤。
//
// 跨租户（或不存在/已吊销）一律返回错误且**不改任何行**，
// 保证共享库下不能凭 key_id 跨租户吊销（P2-4 T-1.9 S3）。
func (s *sqliteTenantStore) RevokeAPIKeyForTenant(tx TenantTx, tenantID, keyID string, revokedAt int64) error {
	if tenantID == "" || keyID == "" {
		return errors.New("tenant: revoke api key: tenant_id/key_id are required")
	}
	res, err := tx.tx().Exec(`UPDATE api_keys SET status = 'revoked', revoked_at = ?
		WHERE tenant_id = ? AND key_id = ? AND status = 'active'`, revokedAt, tenantID, keyID)
	if err != nil {
		return fmt.Errorf("tenant: revoke api key for tenant: %w", err)
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
//
// scope 列为 P2-4 T-3.1 策略作用域（§6.2）：可空，NULL/空视作 global（存量兼容，
// 不回填）；sqlite 无 ADD COLUMN IF NOT EXISTS，存量库由 ensureScopeColumns 补列。
const policyDDL = `
CREATE TABLE IF NOT EXISTS policy_overlays (
  tenant_id        TEXT PRIMARY KEY,
  version          INTEGER NOT NULL DEFAULT 1,
  whitelist        TEXT    NOT NULL DEFAULT '{"entries":[]}',
  blacklist        TEXT    NOT NULL DEFAULT '{"entries":[]}',
  category_actions TEXT    NOT NULL DEFAULT '{}',
  updated_at       INTEGER NOT NULL,
  scope            TEXT
);

CREATE TABLE IF NOT EXISTS model_configs (
  tenant_id      TEXT PRIMARY KEY,
  allowed_models TEXT    NOT NULL DEFAULT '[]',
  default_model  TEXT    NOT NULL DEFAULT '',
  version        INTEGER NOT NULL DEFAULT 1,
  updated_at     INTEGER NOT NULL,
  scope          TEXT
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
	// ScopeJSON 策略作用域（P2-4 T-3.1，§6.2）：{"global":true} 或 {"global":false,"clusters":[...]}；
	// 空/NULL = global（存量兼容，不回填）。
	ScopeJSON string
}

// ModelConfig 租户模型配置（每租户一行）。
type ModelConfig struct {
	TenantID          string
	AllowedModelsJSON string // JSON 数组
	DefaultModel      string
	Version           int64
	UpdatedAt         int64
	// ScopeJSON 策略作用域（P2-4 T-3.1，§6.2）；空/NULL = global。
	ScopeJSON string
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

// ensureScopeColumns 为存量 sqlite 库补齐 scope 列（P2-4 T-3.1 策略作用域）。
//
// sqlite 无 `ADD COLUMN IF NOT EXISTS`，须先 PRAGMA table_info 判存再 ALTER；
// 列可空（NULL = global，存量数据不回填），故补列不影响既有行与既有语义。
// PG 侧由 tenantDDLSchemaPG 内的 `ADD COLUMN IF NOT EXISTS` 覆盖，无需本函数。
func ensureScopeColumns(db *sql.DB) error {
	for _, t := range []string{"policy_overlays", "model_configs", "tenant_provisionings"} {
		exists, has, err := tableHasColumn(db, t, "scope")
		if err != nil {
			return err
		}
		if !exists || has {
			continue
		}
		if _, err := db.Exec(`ALTER TABLE ` + t + ` ADD COLUMN scope TEXT`); err != nil {
			return fmt.Errorf("tenant: add scope column to %s: %w", t, err)
		}
	}
	return nil
}

// tableHasColumn 判定表是否存在且是否含指定列（sqlite PRAGMA table_info）。
func tableHasColumn(db *sql.DB, table, column string) (bool, bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, false, fmt.Errorf("tenant: inspect %s: %w", table, err)
	}
	defer func() { _ = rows.Close() }()
	exists, has := false, false
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, false, fmt.Errorf("tenant: scan %s info: %w", table, err)
		}
		exists = true
		if name == column {
			has = true
		}
	}
	return exists, has, rows.Err()
}

func (s *sqliteTenantStore) GetPolicyOverlay(tenantID string) (*PolicyOverlay, error) {
	var p PolicyOverlay
	err := s.db.QueryRow(`SELECT tenant_id, version, whitelist, blacklist, category_actions, updated_at,
		COALESCE(scope, '')
		FROM policy_overlays WHERE tenant_id = ?`, tenantID).
		Scan(&p.TenantID, &p.Version, &p.WhitelistJSON, &p.BlacklistJSON, &p.CategoryActionsJSON, &p.UpdatedAt,
			&p.ScopeJSON)
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
		SET version = version + 1, whitelist = ?, blacklist = ?, category_actions = ?, updated_at = ?,
			scope = ?
		WHERE tenant_id = ? AND version = ?`,
		p.WhitelistJSON, p.BlacklistJSON, p.CategoryActionsJSON, p.UpdatedAt, p.ScopeJSON,
		p.TenantID, p.Version)
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
		(tenant_id, version, whitelist, blacklist, category_actions, updated_at, scope)
		VALUES (?, 1, ?, ?, ?, ?, ?)`,
		p.TenantID, p.WhitelistJSON, p.BlacklistJSON, p.CategoryActionsJSON, p.UpdatedAt, p.ScopeJSON); err != nil {
		return fmt.Errorf("tenant: insert policy overlay: %w", err)
	}
	return nil
}

func (s *sqliteTenantStore) GetModelConfig(tenantID string) (*ModelConfig, error) {
	var m ModelConfig
	err := s.db.QueryRow(`SELECT tenant_id, allowed_models, default_model, version, updated_at,
		COALESCE(scope, '')
		FROM model_configs WHERE tenant_id = ?`, tenantID).
		Scan(&m.TenantID, &m.AllowedModelsJSON, &m.DefaultModel, &m.Version, &m.UpdatedAt, &m.ScopeJSON)
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
		SET version = version + 1, allowed_models = ?, default_model = ?, updated_at = ?, scope = ?
		WHERE tenant_id = ? AND version = ?`,
		m.AllowedModelsJSON, m.DefaultModel, m.UpdatedAt, m.ScopeJSON, m.TenantID, m.Version)
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
		(tenant_id, allowed_models, default_model, version, updated_at, scope)
		VALUES (?, ?, ?, 1, ?, ?)`,
		m.TenantID, m.AllowedModelsJSON, m.DefaultModel, m.UpdatedAt, m.ScopeJSON); err != nil {
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
  updated_at         INTEGER NOT NULL,
  scope              TEXT
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
	// ScopeJSON 策略作用域（P2-4 T-3.1，§6.2）；空/NULL = global。
	ScopeJSON string
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
		segment1_enabled, segment2_mode, template_version, provider_cred_refs, provisioned_at, updated_at,
		COALESCE(scope, '')
		FROM tenant_provisionings WHERE tenant_id = ?`, tenantID).
		Scan(&p.TenantID, &p.Scenario, &p.TrustTier, &p.AccessMode, &p.PluginSetJSON,
			&p.Segment1Enabled, &p.Segment2Mode, &p.TemplateVersion, &p.ProviderCredRefsJSON,
			&p.ProvisionedAt, &p.UpdatedAt, &p.ScopeJSON)
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
	// Segment1Enabled 显式转 0/1（QA P1-1）：pgx 不能把 Go bool 编码进 int4 列
	// （PG 亦无 boolean→integer 隐式转换），sqlite 不受影响；统一存 0/1。
	_, err := tx.tx().Exec(`INSERT INTO tenant_provisionings
		(tenant_id, scenario, trust_tier, access_mode, plugin_set, segment1_enabled,
		 segment2_mode, template_version, provider_cred_refs, provisioned_at, updated_at, scope)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET
			scenario = excluded.scenario,
			trust_tier = excluded.trust_tier,
			access_mode = excluded.access_mode,
			plugin_set = excluded.plugin_set,
			segment1_enabled = excluded.segment1_enabled,
			segment2_mode = excluded.segment2_mode,
			template_version = excluded.template_version,
			provider_cred_refs = excluded.provider_cred_refs,
			updated_at = excluded.updated_at,
			scope = excluded.scope`,
		p.TenantID, p.Scenario, p.TrustTier, p.AccessMode, p.PluginSetJSON, boolToInt64(p.Segment1Enabled),
		p.Segment2Mode, p.TemplateVersion, p.ProviderCredRefsJSON, p.ProvisionedAt, p.UpdatedAt, p.ScopeJSON)
	if err != nil {
		return fmt.Errorf("tenant: upsert provisioning: %w", err)
	}
	return nil
}

// ---------- 承诺边界声明存证（N4，§3.5 表 ⑨）----------

// statementsDDL 承诺边界声明存证表结构（对齐 §3.5 表 ⑨）：
// content 存声明全文（防事后篡改承诺口径），supersedes_id 构成重签链。
// 说明：§3.5 表 ⑨ 写作 `REFERENCES tenants(tenant_id)`，租户表主键实为 `id`，
// 故按真实列名写 `REFERENCES tenants(id)`（与表 ⑧/⑩ FK 同法）。
const statementsDDL = `
CREATE TABLE IF NOT EXISTS tenant_statements (
  statement_id     TEXT PRIMARY KEY,
  tenant_id        TEXT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  scenario         TEXT NOT NULL,
  access_mode      TEXT NOT NULL,
  template_version TEXT NOT NULL,
  content          TEXT NOT NULL,
  content_hash     TEXT NOT NULL,
  supersedes_id    TEXT REFERENCES tenant_statements(statement_id),
  created_at       INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_statements_tenant ON tenant_statements(tenant_id, created_at DESC);
-- P2-4 T-1.9（S3）：GetCurrentStatement 的重签链子查询按 (tenant_id, supersedes_id) 定位，
-- 保证"取当前声明"在共享库下只扫本租户行。
CREATE INDEX IF NOT EXISTS idx_statements_supersedes ON tenant_statements(tenant_id, supersedes_id) WHERE supersedes_id IS NOT NULL;
`

// TenantStatement 承诺边界声明存证行（N4）。
type TenantStatement struct {
	StatementID     string
	TenantID        string
	Scenario        string // 生成时快照（防事后随配置漂移）
	AccessMode      string // 生成时快照
	TemplateVersion string // 声明模板版本（§4.3.4）
	Content         string // JSON：声明全文
	ContentHash     string // SHA-256(content) hex
	SupersedesID    string // 重签链：指向被替代版本（空 = 首版）
	CreatedAt       int64
}

// ensureStatementsSchema 建表（N4 新表）。
func ensureStatementsSchema(db *sql.DB) error {
	if _, err := db.Exec(statementsDDL); err != nil {
		return fmt.Errorf("tenant: init statements schema: %w", err)
	}
	return nil
}

const statementColumns = `statement_id, tenant_id, scenario, access_mode, template_version,
	content, content_hash, COALESCE(supersedes_id,''), created_at`

// scanStatement 行扫描（*sql.Row / *sql.Rows 共用）。
func scanStatement(sc rowScanner) (*TenantStatement, error) {
	var st TenantStatement
	if err := sc.Scan(&st.StatementID, &st.TenantID, &st.Scenario, &st.AccessMode,
		&st.TemplateVersion, &st.Content, &st.ContentHash, &st.SupersedesID,
		&st.CreatedAt); err != nil {
		return nil, err
	}
	return &st, nil
}

// CreateStatement 存证一行声明（重签时 SupersedesID 指向被替代版本，构成重签链）。
func (s *sqliteTenantStore) CreateStatement(tx TenantTx, st *TenantStatement) error {
	if st == nil || st.StatementID == "" || st.TenantID == "" {
		return errors.New("tenant: statement_id/tenant_id are required")
	}
	var supersedes any
	if st.SupersedesID != "" {
		supersedes = st.SupersedesID
	}
	_, err := tx.tx().Exec(`INSERT INTO tenant_statements
		(statement_id, tenant_id, scenario, access_mode, template_version,
		 content, content_hash, supersedes_id, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		st.StatementID, st.TenantID, st.Scenario, st.AccessMode, st.TemplateVersion,
		st.Content, st.ContentHash, supersedes, st.CreatedAt)
	if err != nil {
		return fmt.Errorf("tenant: create statement: %w", err)
	}
	return nil
}

// GetCurrentStatement 取当前生效版本（最新且未被任何行 supersede 的行；无 → nil）。
func (s *sqliteTenantStore) GetCurrentStatement(tenantID string) (*TenantStatement, error) {
	st, err := scanStatement(s.db.QueryRow(`SELECT `+statementColumns+` FROM tenant_statements
		WHERE tenant_id = ?
		  AND statement_id NOT IN (
		    SELECT supersedes_id FROM tenant_statements
		    WHERE tenant_id = ? AND supersedes_id IS NOT NULL)
		ORDER BY created_at DESC, `+s.tiebreak()+` DESC LIMIT 1`, tenantID, tenantID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get current statement: %w", err)
	}
	return st, nil
}

// GetStatement 取指定版本（历史查询，管理端；跨租户越权在此按 tenant_id 过滤，L3）。
func (s *sqliteTenantStore) GetStatement(tenantID, statementID string) (*TenantStatement, error) {
	st, err := scanStatement(s.db.QueryRow(`SELECT `+statementColumns+
		` FROM tenant_statements WHERE tenant_id = ? AND statement_id = ?`, tenantID, statementID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get statement: %w", err)
	}
	return st, nil
}

// ListStatementsByTenant 列出租户全部声明（最新在前；管理端历史视图）。
func (s *sqliteTenantStore) ListStatementsByTenant(tenantID string) ([]*TenantStatement, error) {
	rows, err := s.db.Query(`SELECT `+statementColumns+
		` FROM tenant_statements WHERE tenant_id = ? ORDER BY created_at DESC, `+s.tiebreak()+` DESC`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant: list statements: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*TenantStatement
	for rows.Next() {
		st, err := scanStatement(rows)
		if err != nil {
			return nil, fmt.Errorf("tenant: scan statement: %w", err)
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// ListProvisionedTenants 列出所有已开通租户（N4 运维批量重签发枚举用）。
func (s *sqliteTenantStore) ListProvisionedTenants() ([]string, error) {
	rows, err := s.db.Query(`SELECT tenant_id FROM tenant_provisionings ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("tenant: list provisioned tenants: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("tenant: scan provisioned tenant: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// ---------- 下发状态机（N5，§3.5 表 ⑩）----------

// dispatchStatus* 下发状态机取值（§4.3.5）。
const (
	dispatchStatusIdle     = "idle"
	dispatchStatusPending  = "pending"
	dispatchStatusApplying = "applying"
	dispatchStatusApplied  = "applied"
	dispatchStatusFailed   = "failed"
)

// TenantDispatchState 下发状态机行（每租户×每集群一行）。
type TenantDispatchState struct {
	TenantID       string
	ClusterID      string // '' = 全局（未定向）行；其余 = 具体集群 ID
	ConfigVersion  int64
	Status         string
	AppliedVersion int64
	LastError      string
	RetryCount     int64
	UpdatedAt      int64
}

// dispatchTableDDL 下发状态机**表**结构（建表；存量库已存在则不动）。
//
// 对齐 §3.5 表 ⑩；**每租户×每集群**一行，config_version 单调递增；
// P2-4 T-3.2a 起主键为 (tenant_id, cluster_id)。
//
// 说明：§3.5 表 ⑩ 写作 `REFERENCES tenants(tenant_id)`，但租户表主键实为 `id`
// （见 §3.5 tenants 表），故此处按真实列名写 `REFERENCES tenants(id)`（与表 ⑧ FK 同法），
// 否则 SQLite 开启 foreign_keys 后写入报 "foreign key mismatch"。
//
// cluster_id 语义：” = 全局（未定向）行——存量行迁移后落在该行，行为与迁移前一致；
// 其余取值 = 具体集群 ID（T-3.2b 的"每租户×每集群单飞"目标行）。
const dispatchTableDDL = `
CREATE TABLE IF NOT EXISTS tenant_dispatch_state (
  tenant_id       TEXT    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  cluster_id      TEXT    NOT NULL DEFAULT '',
  config_version  INTEGER NOT NULL DEFAULT 0,
  status          TEXT    NOT NULL DEFAULT 'idle' CHECK (status IN ('idle','pending','applying','applied','failed')),
  applied_version INTEGER NOT NULL DEFAULT 0,
  last_error      TEXT,
  retry_count     INTEGER NOT NULL DEFAULT 0,
  updated_at      INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, cluster_id)
);
`

// dispatchIndexDDL 下发状态机**索引**（须在表结构就位后建——旧表无 cluster_id 列时
// 建集群维度索引会直接报错，故与建表分离，见 ensureDispatchSchema 的执行顺序）。
const dispatchIndexDDL = `
CREATE INDEX IF NOT EXISTS idx_dispatch_status ON tenant_dispatch_state(status);
-- P2-4 T-1.9（S3）：重启重放扫描按 status 过滤并按 updated_at 排序，
-- 复合索引避免共享库下排序退化为全表排序。
CREATE INDEX IF NOT EXISTS idx_dispatch_status_updated ON tenant_dispatch_state(status, updated_at);
-- P2-4 T-3.2a（T-1.9 交接索引清单）：集群维度索引。
CREATE INDEX IF NOT EXISTS idx_dispatch_cluster_status ON tenant_dispatch_state(cluster_id, status);
CREATE INDEX IF NOT EXISTS idx_dispatch_tenant_cluster ON tenant_dispatch_state(tenant_id, cluster_id);
`

// ensureDispatchSchema 建表（N5 新表）+ T-3.2a 存量主键迁移 + 索引。
//
// 执行顺序不可调换：① 建表（新库直得目标结构）→ ② 存量主键迁移（旧库整表重建，
// 重建后才有 cluster_id 列）→ ③ 建索引（旧库缺列时建集群维度索引会报错）。
func ensureDispatchSchema(db *sql.DB) error {
	if _, err := db.Exec(dispatchTableDDL); err != nil {
		return fmt.Errorf("tenant: init dispatch schema: %w", err)
	}
	if err := migrateDispatchStatePKSQLite(db); err != nil {
		return err
	}
	if _, err := db.Exec(dispatchIndexDDL); err != nil {
		return fmt.Errorf("tenant: init dispatch indexes: %w", err)
	}
	return nil
}

// migrateDispatchStatePKSQLite 把 tenant_dispatch_state 的主键迁移为 (tenant_id, cluster_id)。
//
// sqlite 不支持 ALTER TABLE ... DROP/ADD PRIMARY KEY ⇒ **整表重建**：
// 建新表 → 拷贝存量行（cluster_id 置 ”，即"全局行"）→ 删旧表 → 改名。
// 幂等可重入：已是目标结构（列齐 + 复合主键）时直接返回，重复启动不重复重建。
func migrateDispatchStatePKSQLite(db *sql.DB) error {
	hasClusterID, need, err := dispatchStateSchemaState(db)
	if err != nil {
		return err
	}
	if !need {
		return nil
	}
	clusterExpr := "''"
	if hasClusterID {
		// 已是新列但主键不对（中间态）：按原值拷贝，不丢集群维度。
		clusterExpr = "cluster_id"
	}
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("tenant: dispatch pk migration: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	steps := []string{
		`CREATE TABLE tenant_dispatch_state_new (
  tenant_id       TEXT    NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
  cluster_id      TEXT    NOT NULL DEFAULT '',
  config_version  INTEGER NOT NULL DEFAULT 0,
  status          TEXT    NOT NULL DEFAULT 'idle' CHECK (status IN ('idle','pending','applying','applied','failed')),
  applied_version INTEGER NOT NULL DEFAULT 0,
  last_error      TEXT,
  retry_count     INTEGER NOT NULL DEFAULT 0,
  updated_at      INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, cluster_id)
)`,
		`INSERT INTO tenant_dispatch_state_new
   (tenant_id, cluster_id, config_version, status, applied_version, last_error, retry_count, updated_at)
 SELECT tenant_id, ` + clusterExpr + `, config_version, status, applied_version, last_error, retry_count, updated_at
   FROM tenant_dispatch_state`,
		`DROP TABLE tenant_dispatch_state`,
		`ALTER TABLE tenant_dispatch_state_new RENAME TO tenant_dispatch_state`,
	}
	for _, s := range steps {
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("tenant: dispatch pk migration: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("tenant: dispatch pk migration: commit: %w", err)
	}
	return nil
}

// dispatchStateSchemaState 读取 tenant_dispatch_state 的结构状态。
//
// 返回 (是否有 cluster_id 列, 是否需要重建为复合主键, error)。
// 目标结构：含 cluster_id 列，且主键为 (tenant_id, cluster_id)——sqlite 的
// PRAGMA table_info 用 pk 字段表示主键序号（1 = 第 1 列，2 = 第 2 列，0 = 非主键）。
func dispatchStateSchemaState(db *sql.DB) (bool, bool, error) {
	rows, err := db.Query(`PRAGMA table_info(tenant_dispatch_state)`)
	if err != nil {
		return false, false, fmt.Errorf("tenant: inspect dispatch state: %w", err)
	}
	defer func() { _ = rows.Close() }()
	hasClusterID := false
	pkTenant, pkCluster := 0, 0
	for rows.Next() {
		var cid, notnull, pk int
		var name, ctype string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, false, fmt.Errorf("tenant: scan dispatch state info: %w", err)
		}
		switch name {
		case "cluster_id":
			hasClusterID = true
			pkCluster = pk
		case "tenant_id":
			pkTenant = pk
		}
	}
	if err := rows.Err(); err != nil {
		return false, false, err
	}
	if !hasClusterID {
		// 旧结构（无 cluster_id 列）⇒ 须整表重建。
		return false, true, nil
	}
	return true, !(pkTenant == 1 && pkCluster == 2), nil
}

// dispatchClusterGlobal 全局（未定向）行的 cluster_id 取值。
//
// 存量行在 T-3.2a 主键迁移后落在该行（cluster_id=”），既有"每租户单行"语义
// 与行为完全不变；T-3.2b 的定向集群行使用真实集群 ID。
const dispatchClusterGlobal = ""

// dispatchColumns 下发状态机行的列投影（含 cluster_id）。
const dispatchColumns = `tenant_id, cluster_id, config_version, status, applied_version, COALESCE(last_error,''), retry_count, updated_at`

// scanDispatchState 行扫描（*sql.Row / *sql.Rows 共用）。
func scanDispatchState(sc rowScanner) (*TenantDispatchState, error) {
	var d TenantDispatchState
	if err := sc.Scan(&d.TenantID, &d.ClusterID, &d.ConfigVersion, &d.Status, &d.AppliedVersion,
		&d.LastError, &d.RetryCount, &d.UpdatedAt); err != nil {
		return nil, err
	}
	return &d, nil
}

// GetDispatchState 取**全局行**（cluster_id=”）——既有语义不变（T-3.2a 前只有这一行）。
func (s *sqliteTenantStore) GetDispatchState(tenantID string) (*TenantDispatchState, error) {
	return s.GetDispatchStateForCluster(tenantID, dispatchClusterGlobal)
}

// GetDispatchStateForCluster 取指定租户×集群的下发状态行（不存在 → nil, nil）。
func (s *sqliteTenantStore) GetDispatchStateForCluster(tenantID, clusterID string) (*TenantDispatchState, error) {
	d, err := scanDispatchState(s.db.QueryRow(`SELECT `+dispatchColumns+
		` FROM tenant_dispatch_state WHERE tenant_id = ? AND cluster_id = ?`, tenantID, clusterID))
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tenant: get dispatch state: %w", err)
	}
	return d, nil
}

// BumpDispatchVersion 同事务把**全局行**的 config_version+1、status='pending'
// （不存在则建行，config_version=1）。返回自增后的 config_version。
// 用于「配置已存、待下发」的原子性保证（§4.3.5）。
func (s *sqliteTenantStore) BumpDispatchVersion(tx TenantTx, tenantID string, now int64) (int64, error) {
	return s.BumpDispatchVersionForCluster(tx, tenantID, dispatchClusterGlobal, now)
}

// BumpDispatchVersionForCluster 同事务把指定租户×集群行的 config_version+1、
// status='pending'（不存在则建行，config_version=1）。
//
// ⚠️ 方言差异（P2-4 真机 PG 复验发现，SQLSTATE 42702）：在 ON CONFLICT DO UPDATE 中，
// 未限定的列名在**目标表与 excluded 伪表之间歧义**——PG 报
// `column reference "config_version" is ambiguous`，SQLite 则容忍。
// 故 PG 下用表名限定（tenant_dispatch_state.config_version），SQLite 保持原写法。
func (s *sqliteTenantStore) BumpDispatchVersionForCluster(tx TenantTx, tenantID, clusterID string, now int64) (int64, error) {
	bumpExpr := "config_version = config_version + 1"
	if s.db.Dialect().IsPostgres() {
		bumpExpr = "config_version = tenant_dispatch_state.config_version + 1"
	}
	_, err := tx.tx().Exec(fmt.Sprintf(`INSERT INTO tenant_dispatch_state
		(tenant_id, cluster_id, config_version, status, applied_version, last_error, retry_count, updated_at)
		VALUES (?, ?, 1, 'pending', 0, NULL, 0, ?)
		ON CONFLICT(tenant_id, cluster_id) DO UPDATE SET
			%s,
			status = 'pending',
			last_error = NULL,
			retry_count = 0,
			updated_at = excluded.updated_at`, bumpExpr),
		tenantID, clusterID, now)
	if err != nil {
		return 0, fmt.Errorf("tenant: bump dispatch version: %w", err)
	}
	var v int64
	if err := tx.tx().QueryRow(`SELECT config_version FROM tenant_dispatch_state
		WHERE tenant_id = ? AND cluster_id = ?`, tenantID, clusterID).Scan(&v); err != nil {
		return 0, fmt.Errorf("tenant: read bumped dispatch version: %w", err)
	}
	return v, nil
}

// MarkDispatchPendingForCluster 标记某租户×集群的待下发版本。
//
// 与 BumpDispatchVersionForCluster 的区别：**不递增**版本号——版本号由租户级
// 全局行承载（写路径 bump），下发时把该目标版本**投影**到集群行。
// 不存在则建行（config_version = version，status='pending'）。
func (s *sqliteTenantStore) MarkDispatchPendingForCluster(tx TenantTx, tenantID, clusterID string, version int64, now int64) error {
	_, err := tx.tx().Exec(`INSERT INTO tenant_dispatch_state
		(tenant_id, cluster_id, config_version, status, applied_version, last_error, retry_count, updated_at)
		VALUES (?, ?, ?, 'pending', 0, NULL, 0, ?)
		ON CONFLICT(tenant_id, cluster_id) DO UPDATE SET
			config_version = excluded.config_version,
			status = 'pending',
			last_error = NULL,
			retry_count = 0,
			updated_at = excluded.updated_at`, tenantID, clusterID, version, now)
	if err != nil {
		return fmt.Errorf("tenant: mark dispatch pending: %w", err)
	}
	return nil
}

// MarkDispatchApplying 置**全局行** status='applying'（不改版本）。
func (s *sqliteTenantStore) MarkDispatchApplying(tx TenantTx, tenantID string, now int64) error {
	return s.MarkDispatchApplyingForCluster(tx, tenantID, dispatchClusterGlobal, now)
}

// MarkDispatchApplyingForCluster 置指定租户×集群行 status='applying'（不改版本）。
func (s *sqliteTenantStore) MarkDispatchApplyingForCluster(tx TenantTx, tenantID, clusterID string, now int64) error {
	res, err := tx.tx().Exec(`UPDATE tenant_dispatch_state SET status = 'applying', updated_at = ?
		WHERE tenant_id = ? AND cluster_id = ?`, now, tenantID, clusterID)
	if err != nil {
		return fmt.Errorf("tenant: mark dispatch applying: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("tenant: dispatch state %s/%s not found", tenantID, clusterID)
	}
	return nil
}

// MarkDispatchApplied 置**全局行** status='applied'，applied_version 单调前进
// （MAX 语义，防乱序回退）。
func (s *sqliteTenantStore) MarkDispatchApplied(tx TenantTx, tenantID string, appliedVersion, now int64) error {
	return s.MarkDispatchAppliedForCluster(tx, tenantID, dispatchClusterGlobal, appliedVersion, now)
}

// MarkDispatchAppliedForCluster 置指定租户×集群行 status='applied'，
// applied_version 单调前进（MAX 语义，防乱序回退）。
func (s *sqliteTenantStore) MarkDispatchAppliedForCluster(tx TenantTx, tenantID, clusterID string, appliedVersion, now int64) error {
	// 标量取大：sqlite 用 MAX(a,b)，PG 的 MAX 是聚合函数，须用 GREATEST(a,b)。
	maxExpr := "MAX(applied_version, ?)"
	if s.db.Dialect().IsPostgres() {
		maxExpr = "GREATEST(applied_version, ?)"
	}
	res, err := tx.tx().Exec(`UPDATE tenant_dispatch_state
		SET status = 'applied',
		    applied_version = `+maxExpr+`,
		    last_error = NULL,
		    retry_count = 0,
		    updated_at = ?
		WHERE tenant_id = ? AND cluster_id = ?`, appliedVersion, now, tenantID, clusterID)
	if err != nil {
		return fmt.Errorf("tenant: mark dispatch applied: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("tenant: dispatch state %s/%s not found", tenantID, clusterID)
	}
	return nil
}

// MarkDispatchFailed 置**全局行** status='failed' + 脱敏 last_error + 重试计数。
func (s *sqliteTenantStore) MarkDispatchFailed(tx TenantTx, tenantID, lastError string, retryCount, now int64) error {
	return s.MarkDispatchFailedForCluster(tx, tenantID, dispatchClusterGlobal, lastError, retryCount, now)
}

// MarkDispatchFailedForCluster 置指定租户×集群行 status='failed' + 脱敏 last_error
// + 重试计数。
func (s *sqliteTenantStore) MarkDispatchFailedForCluster(tx TenantTx, tenantID, clusterID, lastError string, retryCount, now int64) error {
	res, err := tx.tx().Exec(`UPDATE tenant_dispatch_state
		SET status = 'failed', last_error = ?, retry_count = ?, updated_at = ?
		WHERE tenant_id = ? AND cluster_id = ?`, lastError, retryCount, now, tenantID, clusterID)
	if err != nil {
		return fmt.Errorf("tenant: mark dispatch failed: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return fmt.Errorf("tenant: dispatch state %s/%s not found", tenantID, clusterID)
	}
	return nil
}

// ListDispatchStatesByStatus 按状态枚举下发状态行（重启重放扫描 pending/applying，§4.3.5 item 4）。
func (s *sqliteTenantStore) ListDispatchStatesByStatus(statuses ...string) ([]*TenantDispatchState, error) {
	if len(statuses) == 0 {
		return nil, nil
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(statuses)), ",")
	args := make([]any, 0, len(statuses))
	for _, st := range statuses {
		args = append(args, st)
	}
	rows, err := s.db.Query(`SELECT `+dispatchColumns+` FROM tenant_dispatch_state WHERE status IN (`+
		placeholders+`) ORDER BY updated_at ASC`, args...)
	if err != nil {
		return nil, fmt.Errorf("tenant: list dispatch states: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*TenantDispatchState
	for rows.Next() {
		d, err := scanDispatchState(rows)
		if err != nil {
			return nil, fmt.Errorf("tenant: scan dispatch state: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ListDispatchStatesByTenant 枚举某租户的全部下发状态行（跨集群；P2-4 T-3.3 收敛核对用）。
func (s *sqliteTenantStore) ListDispatchStatesByTenant(tenantID string) ([]*TenantDispatchState, error) {
	rows, err := s.db.Query(`SELECT `+dispatchColumns+` FROM tenant_dispatch_state WHERE tenant_id = ? ORDER BY cluster_id`, tenantID)
	if err != nil {
		return nil, fmt.Errorf("tenant: list dispatch states by tenant: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []*TenantDispatchState
	for rows.Next() {
		d, err := scanDispatchState(rows)
		if err != nil {
			return nil, fmt.Errorf("tenant: scan dispatch state: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}
