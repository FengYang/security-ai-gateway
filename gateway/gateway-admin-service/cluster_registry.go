// Package main — 集群注册表（P2-4 T-2.1：registry 模型 / 存储）。
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§6.1 集群注册 API。
//
// 职责边界（**本文件只做模型与存储，不含 HTTP 端点**，端点与装配见 T-2.2）：
//   - 模型：集群身份（ID/名称/端点/形态/容量画像）、状态机、心跳与配置版本；
//   - 存储：双方言（sqlite / PostgreSQL）注册表 + 心跳明细表。
//
// 形态与拓扑（§6.4 注）：形态 ∈ {同城, 异地}，配合调度 role ∈ {primary, standby, weighted}
// 即可表达"两地三中心"（同城双中心主备/双活 + 异地灾备 standby），不另设字段。
//
// 状态机（§6.1「registry 状态机阈值」，v0.9 O2(6)）：心跳周期默认 30s；
// 连续 3 次未收到心跳 → degraded；连续 10 次（≈5min）→ unreachable；
// 恢复收到心跳 → active。阈值可被部署覆盖（ClusterHeartbeatConfig）。
//
// fail-closed 取向：已摘除（removed）/已隔离（quarantined）的集群**拒绝心跳**，
// 不允许被"复活"——摘除是受控操作（双签），不能靠一次心跳回退。
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// ---------- 枚举 ----------

// ClusterForm 集群部署形态。
type ClusterForm string

const (
	// ClusterFormSameCity 同城（与控制面同机房）。
	ClusterFormSameCity ClusterForm = "同城"
	// ClusterFormRemote 异地（灾备中心）。
	ClusterFormRemote ClusterForm = "异地"
)

// 合法形态集合。
var validClusterForms = map[ClusterForm]bool{
	ClusterFormSameCity: true,
	ClusterFormRemote:   true,
}

// ClusterStatus 集群注册状态。
type ClusterStatus string

const (
	// ClusterStatusActive 正常（心跳正常）。
	ClusterStatusActive ClusterStatus = "active"
	// ClusterStatusDegraded 降级（心跳连续缺失达 degraded 阈值）。
	ClusterStatusDegraded ClusterStatus = "degraded"
	// ClusterStatusUnreachable 不可达（心跳连续缺失达 unreachable 阈值）。
	ClusterStatusUnreachable ClusterStatus = "unreachable"
	// ClusterStatusRemoved 已摘除（受控摘除完成）。
	ClusterStatusRemoved ClusterStatus = "removed"
	// ClusterStatusQuarantined 已隔离（强制摘除路径终态）。
	ClusterStatusQuarantined ClusterStatus = "quarantined"
)

// 合法状态集合。
var validClusterStatuses = map[ClusterStatus]bool{
	ClusterStatusActive:      true,
	ClusterStatusDegraded:    true,
	ClusterStatusUnreachable: true,
	ClusterStatusRemoved:     true,
	ClusterStatusQuarantined: true,
}

// ---------- 模型 ----------

// ClusterCapacity 集群容量画像（§6.1 注册参数）。
type ClusterCapacity struct {
	RPS         int `json:"rps"`         // 额定 RPS（<=0 表示未声明）
	Concurrency int `json:"concurrency"` // 额定并发（<=0 表示未声明）
}

// ClusterRecord 集群注册记录（存储行 ↔ 模型）。
type ClusterRecord struct {
	ID       string          `json:"id"`                     // 集群 ID（唯一）
	Name     string          `json:"name"`                   // 集群名称
	Endpoint string          `json:"endpoint"`               // 数据面端点（http/https URL）
	Form     ClusterForm     `json:"form"`                   // 同城 | 异地
	Capacity ClusterCapacity `json:"capacity"`               // 容量画像
	Status   ClusterStatus   `json:"status"`                 // 注册状态
	Applied  string          `json:"applied_config_version"` // 最近上报的应用配置版本

	MissedHeartbeats int       `json:"missed_heartbeats"` // 连续缺失心跳计数
	LastHeartbeatAt  time.Time `json:"last_heartbeat_at"` // 最近心跳时间
	RegisteredAt     time.Time `json:"registered_at"`     // 注册时间
	UpdatedAt        time.Time `json:"updated_at"`        // 最近更新时间
	RemovedAt        time.Time `json:"removed_at,omitempty"`
}

// ClusterHeartbeatConfig 心跳与状态机阈值（可被部署覆盖；§6.1 默认定量值）。
type ClusterHeartbeatConfig struct {
	Period            time.Duration // 心跳周期，默认 30s
	DegradedMisses    int           // 连续缺失达该次数 → degraded，默认 3
	UnreachableMisses int           // 连续缺失达该次数 → unreachable，默认 10
}

// DefaultClusterHeartbeatConfig 返回默认阈值（30s / 3 / 10）。
func DefaultClusterHeartbeatConfig() ClusterHeartbeatConfig {
	return ClusterHeartbeatConfig{
		Period:            30 * time.Second,
		DegradedMisses:    3,
		UnreachableMisses: 10,
	}
}

// normalize 修正非法/缺省阈值，保证状态机不会因配置异常而失效。
func (c ClusterHeartbeatConfig) normalize() ClusterHeartbeatConfig {
	if c.Period <= 0 {
		c.Period = 30 * time.Second
	}
	if c.DegradedMisses <= 0 {
		c.DegradedMisses = 3
	}
	if c.UnreachableMisses <= c.DegradedMisses {
		c.UnreachableMisses = c.DegradedMisses + 7 // 默认 3 → 10
	}
	return c
}

// ---------- 存储接口 ----------

// ClusterStore 集群注册表存储（双方言同实现，SQL 由 sqlutil 自动重绑）。
type ClusterStore interface {
	// Register 注册集群（ID 冲突视为错误，幂等更新交由调用方显式决定）。
	Register(ctx context.Context, rec *ClusterRecord) error
	// Get 按 ID 取集群；不存在返回 sql.ErrNoRows。
	Get(ctx context.Context, id string) (*ClusterRecord, error)
	// List 列出全部集群（按 ID 升序）。
	List(ctx context.Context) ([]*ClusterRecord, error)
	// Heartbeat 记录一次心跳：更新最近心跳时间、清零缺失计数、记录应用配置版本，
	// 并按状态机重算状态。已摘除/已隔离集群返回错误（拒绝复活）。
	Heartbeat(ctx context.Context, id string, appliedVersion string, at time.Time) (*ClusterRecord, error)
	// RecomputeStatuses 依据当前时间重算心跳缺失状态，返回发生状态跃迁的集群。
	RecomputeStatuses(ctx context.Context, now time.Time) ([]*ClusterRecord, error)
	// SetStatus 显式设置状态（受控摘除/强制摘除路径使用）。
	SetStatus(ctx context.Context, id string, status ClusterStatus, at time.Time) error
	// Credentials 返回该注册表句柄上的集群身份凭证存储（共用同一数据库）。
	Credentials() ClusterCredentialStore
	// Close 关闭底层句柄。
	Close() error
}

// ---------- 实现 ----------

// sqlClusterStore 集群注册表的 SQL 实现（sqlite / PostgreSQL 双方言）。
type sqlClusterStore struct {
	db *sqlutil.DB
	hb ClusterHeartbeatConfig
}

// 集群注册表写事务的 advisory lock 键（PG 跨副本串行；sqlite 走进程内锁）。
const clusterStoreLockKey int64 = 0x434C555354

// OpenClusterStore 打开集群注册表并建表（双方言）。
// dsn：sqlite 为文件路径或 ":memory:"；postgres 为连接串。
func OpenClusterStore(dialect sqlutil.Dialect, dsn string) (ClusterStore, error) {
	db, err := sqlutil.Open(dialect, dsn, clusterStoreLockKey)
	if err != nil {
		return nil, fmt.Errorf("cluster_registry: open: %w", err)
	}
	st := &sqlClusterStore{db: db, hb: DefaultClusterHeartbeatConfig()}
	if err := st.ensureSchema(); err != nil {
		db.Close()
		return nil, err
	}
	return st, nil
}

// NewClusterStoreOnDB 在既有句柄上建表（供管理面与租户库共用同一 PG 连接时使用）。
func NewClusterStoreOnDB(db *sqlutil.DB, hb ClusterHeartbeatConfig) ClusterStore {
	return &sqlClusterStore{db: db, hb: hb.normalize()}
}

func (s *sqlClusterStore) Close() error { return s.db.Close() }

// ensureSchema 建表（双方言 DDL 独立维护，列宽与类型对齐）。
func (s *sqlClusterStore) ensureSchema() error {
	ddl := clusterDDLSchemaSQLite
	if s.db.Dialect().IsPostgres() {
		ddl = clusterDDLSchemaPG
	}
	if _, err := s.db.Exec(ddl); err != nil {
		return fmt.Errorf("cluster_registry: init schema: %w", err)
	}
	// 集群身份凭证表（T-2.3）：与注册表同库同句柄。
	if err := ensureClusterCredentialSchema(s.db); err != nil {
		return err
	}
	return nil
}

// Credentials 返回该注册表句柄上的集群身份凭证存储（共用同一数据库）。
func (s *sqlClusterStore) Credentials() ClusterCredentialStore {
	return NewClusterCredentialStore(s.db)
}

// clusterDDLSchemaSQLite sqlite 建表语句。
const clusterDDLSchemaSQLite = `
CREATE TABLE IF NOT EXISTS clusters (
  id                  TEXT    PRIMARY KEY,
  name                TEXT    NOT NULL,
  endpoint            TEXT    NOT NULL,
  form                TEXT    NOT NULL,
  capacity_rps        INTEGER NOT NULL DEFAULT 0,
  capacity_concurrency INTEGER NOT NULL DEFAULT 0,
  status              TEXT    NOT NULL DEFAULT 'active',
  applied_config_version TEXT NOT NULL DEFAULT '',
  missed_heartbeats   INTEGER NOT NULL DEFAULT 0,
  last_heartbeat_at   INTEGER NOT NULL DEFAULT 0,
  registered_at       INTEGER NOT NULL DEFAULT 0,
  updated_at          INTEGER NOT NULL DEFAULT 0,
  removed_at          INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_clusters_status ON clusters(status);
CREATE TABLE IF NOT EXISTS cluster_heartbeats (
  seq                   INTEGER PRIMARY KEY AUTOINCREMENT,
  cluster_id            TEXT    NOT NULL,
  received_at           INTEGER NOT NULL,
  applied_config_version TEXT   NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cluster_heartbeats_cluster ON cluster_heartbeats(cluster_id, received_at);
`

// clusterDDLSchemaPG PostgreSQL 建表语句（与 sqlite 语义等价）。
const clusterDDLSchemaPG = `
CREATE TABLE IF NOT EXISTS clusters (
  id                  TEXT    PRIMARY KEY,
  name                TEXT    NOT NULL,
  endpoint            TEXT    NOT NULL,
  form                TEXT    NOT NULL,
  capacity_rps        BIGINT  NOT NULL DEFAULT 0,
  capacity_concurrency BIGINT  NOT NULL DEFAULT 0,
  status              TEXT    NOT NULL DEFAULT 'active',
  applied_config_version TEXT NOT NULL DEFAULT '',
  missed_heartbeats   BIGINT  NOT NULL DEFAULT 0,
  last_heartbeat_at   BIGINT  NOT NULL DEFAULT 0,
  registered_at       BIGINT  NOT NULL DEFAULT 0,
  updated_at          BIGINT  NOT NULL DEFAULT 0,
  removed_at          BIGINT  NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_clusters_status ON clusters(status);
CREATE TABLE IF NOT EXISTS cluster_heartbeats (
  seq                   BIGSERIAL PRIMARY KEY,
  cluster_id            TEXT    NOT NULL,
  received_at           BIGINT  NOT NULL,
  applied_config_version TEXT   NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_cluster_heartbeats_cluster ON cluster_heartbeats(cluster_id, received_at);
`

// ---------- 模型校验 ----------

// ValidateClusterRecord 校验注册参数（fail-closed）。
func ValidateClusterRecord(rec *ClusterRecord) error {
	if rec == nil {
		return errors.New("cluster_registry: 注册记录为空")
	}
	if strings.TrimSpace(rec.ID) == "" {
		return errors.New("cluster_registry: 集群 ID 为空")
	}
	if len(rec.ID) > 64 {
		return fmt.Errorf("cluster_registry: 集群 ID 过长（%d > 64）", len(rec.ID))
	}
	if strings.TrimSpace(rec.Name) == "" {
		return fmt.Errorf("cluster_registry: 集群 %q 名称为空", rec.ID)
	}
	if err := validateClusterEndpoint(rec.Endpoint); err != nil {
		return err
	}
	if !validClusterForms[rec.Form] {
		return fmt.Errorf("cluster_registry: 集群 %q 形态非法：%q（合法值 同城|异地）", rec.ID, rec.Form)
	}
	if rec.Capacity.RPS < 0 || rec.Capacity.Concurrency < 0 {
		return fmt.Errorf("cluster_registry: 集群 %q 容量画像不得为负", rec.ID)
	}
	return nil
}

// validateClusterEndpoint 校验数据面端点（http/https 绝对 URL）。
func validateClusterEndpoint(endpoint string) error {
	if strings.TrimSpace(endpoint) == "" {
		return errors.New("cluster_registry: 数据面端点为空")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("cluster_registry: 数据面端点非法：%q（须为 http/https 绝对 URL）", endpoint)
	}
	return nil
}

// ---------- CRUD 实现 ----------

func (s *sqlClusterStore) Register(ctx context.Context, rec *ClusterRecord) error {
	if err := ValidateClusterRecord(rec); err != nil {
		return err
	}
	now := time.Now()
	if rec.RegisteredAt.IsZero() {
		rec.RegisteredAt = now
	}
	rec.UpdatedAt = now
	if rec.Status == "" {
		rec.Status = ClusterStatusActive
	}
	if !validClusterStatuses[rec.Status] {
		return fmt.Errorf("cluster_registry: 集群 %q 状态非法：%q", rec.ID, rec.Status)
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO clusters (id, name, endpoint, form, capacity_rps, capacity_concurrency, status,
                      applied_config_version, missed_heartbeats, last_heartbeat_at,
                      registered_at, updated_at, removed_at)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(id) DO UPDATE SET
  name = excluded.name,
  endpoint = excluded.endpoint,
  form = excluded.form,
  capacity_rps = excluded.capacity_rps,
  capacity_concurrency = excluded.capacity_concurrency,
  updated_at = excluded.updated_at`,
		rec.ID, rec.Name, rec.Endpoint, string(rec.Form), rec.Capacity.RPS, rec.Capacity.Concurrency,
		string(rec.Status), rec.Applied, rec.MissedHeartbeats, rec.LastHeartbeatAt.Unix(),
		rec.RegisteredAt.Unix(), rec.UpdatedAt.Unix(), rec.RemovedAt.Unix())
	if err != nil {
		return fmt.Errorf("cluster_registry: 注册集群 %q: %w", rec.ID, err)
	}
	return nil
}

func (s *sqlClusterStore) Get(ctx context.Context, id string) (*ClusterRecord, error) {
	row := s.db.QueryRowContext(ctx, clusterSelect+` WHERE id = ?`, id)
	rec, err := scanCluster(row)
	if err != nil {
		return nil, err
	}
	return rec, nil
}

func (s *sqlClusterStore) List(ctx context.Context) ([]*ClusterRecord, error) {
	rows, err := s.db.QueryContext(ctx, clusterSelect+` ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("cluster_registry: 列出集群: %w", err)
	}
	defer rows.Close()
	out := make([]*ClusterRecord, 0, 8)
	for rows.Next() {
		rec, err := scanCluster(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cluster_registry: 遍历集群: %w", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// clusterSelect 统一的列清单（避免各处漂移）。
const clusterSelect = `SELECT id, name, endpoint, form, capacity_rps, capacity_concurrency,
       status, applied_config_version, missed_heartbeats, last_heartbeat_at,
       registered_at, updated_at, removed_at FROM clusters`

// clusterRowScanner 行扫描接口（sql.Row / sql.Rows 通用）。
type clusterRowScanner interface {
	Scan(dest ...any) error
}

func scanCluster(sc clusterRowScanner) (*ClusterRecord, error) {
	var (
		rec        ClusterRecord
		form       string
		status     string
		lastHb     int64
		registered int64
		updated    int64
		removed    int64
	)
	err := sc.Scan(&rec.ID, &rec.Name, &rec.Endpoint, &form, &rec.Capacity.RPS, &rec.Capacity.Concurrency,
		&status, &rec.Applied, &rec.MissedHeartbeats, &lastHb, &registered, &updated, &removed)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, sql.ErrNoRows
		}
		return nil, fmt.Errorf("cluster_registry: 扫描集群行: %w", err)
	}
	rec.Form = ClusterForm(form)
	rec.Status = ClusterStatus(status)
	rec.LastHeartbeatAt = unixToTime(lastHb)
	rec.RegisteredAt = unixToTime(registered)
	rec.UpdatedAt = unixToTime(updated)
	rec.RemovedAt = unixToTime(removed)
	return &rec, nil
}

func (s *sqlClusterStore) Heartbeat(ctx context.Context, id string, appliedVersion string, at time.Time) (*ClusterRecord, error) {
	if at.IsZero() {
		at = time.Now()
	}
	// 单语句完成：更新最近心跳、清零缺失计数、写入配置版本、按状态机重算状态。
	// removed / quarantined 不在可恢复之列 ⇒ 条件不命中即拒绝（fail-closed，不复活）。
	res, err := s.db.ExecContext(ctx, `
UPDATE clusters SET
  last_heartbeat_at = ?,
  missed_heartbeats = 0,
  applied_config_version = CASE WHEN ? = '' THEN applied_config_version ELSE ? END,
  status = CASE WHEN status IN ('removed','quarantined') THEN status ELSE 'active' END,
  updated_at = ?
WHERE id = ? AND status NOT IN ('removed','quarantined')`,
		at.Unix(), appliedVersion, appliedVersion, at.Unix(), id)
	if err != nil {
		return nil, fmt.Errorf("cluster_registry: 记录心跳 %q: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("cluster_registry: 记录心跳 %q: %w", id, err)
	}
	if n == 0 {
		return nil, fmt.Errorf("cluster_registry: 集群 %q 不存在或已摘除（拒绝心跳）", id)
	}
	// 心跳明细（供审计与排障；写失败不回滚主状态——明细是辅助证据）。
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO cluster_heartbeats (cluster_id, received_at, applied_config_version) VALUES (?,?,?)`,
		id, at.Unix(), appliedVersion); err != nil {
		return nil, fmt.Errorf("cluster_registry: 写心跳明细 %q: %w", id, err)
	}
	return s.Get(ctx, id)
}

func (s *sqlClusterStore) RecomputeStatuses(ctx context.Context, now time.Time) ([]*ClusterRecord, error) {
	if now.IsZero() {
		now = time.Now()
	}
	recs, err := s.List(ctx)
	if err != nil {
		return nil, err
	}
	var changed []*ClusterRecord
	for _, rec := range recs {
		next := EvaluateClusterStatus(rec, now, s.hb)
		if next == rec.Status {
			continue
		}
		if err := s.SetStatus(ctx, rec.ID, next, now); err != nil {
			return nil, err
		}
		rec.Status = next
		rec.UpdatedAt = now
		changed = append(changed, rec)
	}
	return changed, nil
}

func (s *sqlClusterStore) SetStatus(ctx context.Context, id string, status ClusterStatus, at time.Time) error {
	if !validClusterStatuses[status] {
		return fmt.Errorf("cluster_registry: 状态非法：%q", status)
	}
	if at.IsZero() {
		at = time.Now()
	}
	removedAt := int64(0)
	if status == ClusterStatusRemoved || status == ClusterStatusQuarantined {
		removedAt = at.Unix()
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE clusters SET status = ?, updated_at = ?, removed_at = ? WHERE id = ?`,
		string(status), at.Unix(), removedAt, id)
	if err != nil {
		return fmt.Errorf("cluster_registry: 设置集群 %q 状态: %w", id, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("cluster_registry: 设置集群 %q 状态: %w", id, err)
	}
	if n == 0 {
		return fmt.Errorf("cluster_registry: 集群 %q 不存在", id)
	}
	return nil
}

// ---------- 状态机 ----------

// EvaluateClusterStatus 依据心跳缺失情况计算目标状态（纯函数，便于单测）。
//
// 规则：
//   - removed / quarantined 为终态，任何情况下不自动迁出；
//   - 距最近心跳的缺失周期数 = floor((now - last)/period)（从未心跳按注册时刻起算）；
//   - 缺失 ≥ unreachableMisses → unreachable；≥ degradedMisses → degraded；
//   - 否则 → active（恢复）。
func EvaluateClusterStatus(rec *ClusterRecord, now time.Time, cfg ClusterHeartbeatConfig) ClusterStatus {
	if rec == nil {
		return ClusterStatusUnreachable
	}
	switch rec.Status {
	case ClusterStatusRemoved, ClusterStatusQuarantined:
		return rec.Status
	}
	cfg = cfg.normalize()
	base := rec.LastHeartbeatAt
	if base.IsZero() {
		base = rec.RegisteredAt
	}
	if base.IsZero() {
		return ClusterStatusUnreachable
	}
	if now.Before(base) {
		// 时钟回拨：保守按不可达处理（fail-closed）。
		return ClusterStatusUnreachable
	}
	missed := int(now.Sub(base) / cfg.Period)
	switch {
	case missed >= cfg.UnreachableMisses:
		return ClusterStatusUnreachable
	case missed >= cfg.DegradedMisses:
		return ClusterStatusDegraded
	default:
		return ClusterStatusActive
	}
}

// unixToTime 将 unix 秒还原为时间（0 → 零值时间）。
func unixToTime(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}
