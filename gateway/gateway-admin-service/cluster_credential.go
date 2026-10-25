// Package main — 集群身份凭证（P2-4 T-2.3）。
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§6.1「集群身份凭证」与「凭证生命周期」。
//
// 定位：集群注册/心跳/摘除三类操作除 RBAC 外，**还要叠加集群身份根信任**——
// 即"调用方确实是这个集群（或管理面代它操作）"，凭证缺失/过期/不匹配一律拒绝（fail-closed）。
//
// 本期形态：**短期轮换令牌**（随机串，库内只存哈希）。
// mTLS 客户端证书属部署侧通道信任（T-4.3），不在本文件实现。
//
// 生命周期（§6.1 v0.8 补）：
//   - 签发：注册时签发（明文只在签发瞬间返回一次，库内仅存 SHA-256 哈希）；
//   - 轮换：签发新令牌即作废旧令牌（旧令牌立即失效），默认 TTL ≤ 24h；
//   - 吊销：集群摘除时同步吊销其全部凭证（吊销动作入审计，落链见 T-2.5）；
//   - 异常态：集群处于 degraded/unreachable 期间凭证**仍然有效**——心跳失联已由注册表状态机
//     观测（R-1 自治前提），不得因凭证之外的故障额外阻断恢复通道。
//
// 安全细节：哈希输入绑定 clusterID（"clusterID|secret"），使 A 集群的令牌无法在 B 集群处通过校验；
// 比对使用常量时间（subtle.ConstantTimeCompare）；令牌不出现在错误信息与日志中。
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// CredentialStatus 集群身份凭证状态。
type CredentialStatus string

const (
	// CredentialActive 有效（可用于注册/心跳/摘除）。
	CredentialActive CredentialStatus = "active"
	// CredentialRotated 已被轮换作废。
	CredentialRotated CredentialStatus = "rotated"
	// CredentialRevoked 已被吊销（集群摘除时同步吊销）。
	CredentialRevoked CredentialStatus = "revoked"
)

// DefaultClusterCredentialTTL 凭证默认有效期（§6.1 建议 ≤24h；超过即拒绝，按上限收敛）。
const DefaultClusterCredentialTTL = 24 * time.Hour

// ClusterCredential 集群身份凭证记录（存储行 ↔ 模型）。
type ClusterCredential struct {
	ID        string           `json:"id"`         // 凭证 ID
	ClusterID string           `json:"cluster_id"` // 绑定集群 ID
	Status    CredentialStatus `json:"status"`     // active | rotated | revoked
	IssuedAt  time.Time        `json:"issued_at"`
	ExpiresAt time.Time        `json:"expires_at"`
	ClosedAt  time.Time        `json:"closed_at,omitempty"` // 轮换/吊销时刻
}

// ClusterCredentialStore 集群身份凭证存储。
type ClusterCredentialStore interface {
	// Issue 为集群签发凭证；**同时作废该集群既有的 active 凭证**（保证同一集群至多一条 active）。
	// 返回明文令牌（**只在此刻可见**）与凭证记录。
	Issue(ctx context.Context, clusterID string, ttl time.Duration, now time.Time) (string, *ClusterCredential, error)
	// Verify 校验令牌：缺失/过期/已吊销/不匹配一律报错（fail-closed）。
	Verify(ctx context.Context, clusterID string, token string, now time.Time) (*ClusterCredential, error)
	// Rotate 轮换凭证：作废该集群现有凭证并签发新凭证，返回新明文令牌。
	Rotate(ctx context.Context, clusterID string, ttl time.Duration, now time.Time) (string, *ClusterCredential, error)
	// RevokeAll 吊销该集群全部凭证（摘除时调用），返回受影响的凭证数。
	RevokeAll(ctx context.Context, clusterID string, now time.Time) (int, error)
}

// sqlClusterCredentialStore 凭证存储的 SQL 实现（双方言）。
type sqlClusterCredentialStore struct {
	db *sqlutil.DB
}

// NewClusterCredentialStore 在既有注册表句柄上构造凭证存储。
func NewClusterCredentialStore(db *sqlutil.DB) ClusterCredentialStore {
	return &sqlClusterCredentialStore{db: db}
}

// clusterCredentialSelect 统一列清单（含哈希，比对时一次取回）。
const clusterCredentialSelect = `SELECT id, cluster_id, status, issued_at, expires_at, closed_at, secret_hash FROM cluster_credentials`

// Issue 签发凭证（并作废该集群既有 active 凭证）。
func (s *sqlClusterCredentialStore) Issue(ctx context.Context, clusterID string, ttl time.Duration, now time.Time) (string, *ClusterCredential, error) {
	if clusterID == "" {
		return "", nil, errors.New("cluster_credential: 集群 ID 为空")
	}
	if ttl <= 0 || ttl > DefaultClusterCredentialTTL {
		// 轮换周期上限（§6.1 建议 ≤24h）：超限收敛到上限，避免被配成长期有效。
		ttl = DefaultClusterCredentialTTL
	}
	if now.IsZero() {
		now = time.Now()
	}
	// 先作废旧凭证（同一集群至多一条 active）。
	if _, err := s.db.ExecContext(ctx,
		`UPDATE cluster_credentials SET status = ?, closed_at = ? WHERE cluster_id = ? AND status = ?`,
		string(CredentialRotated), now.Unix(), clusterID, string(CredentialActive)); err != nil {
		return "", nil, fmt.Errorf("cluster_credential: 作废旧凭证: %w", err)
	}
	secret, err := randomTokenSecret()
	if err != nil {
		return "", nil, fmt.Errorf("cluster_credential: 生成令牌失败: %w", err)
	}
	id, err := randomTokenSecret()
	if err != nil {
		return "", nil, fmt.Errorf("cluster_credential: 生成凭证 ID 失败: %w", err)
	}
	rec := &ClusterCredential{
		ID:        id,
		ClusterID: clusterID,
		Status:    CredentialActive,
		IssuedAt:  now,
		ExpiresAt: now.Add(ttl),
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO cluster_credentials (id, cluster_id, secret_hash, status, issued_at, expires_at, closed_at)
		 VALUES (?,?,?,?,?,?,0)`,
		rec.ID, rec.ClusterID, hashClusterSecret(clusterID, secret), string(rec.Status),
		rec.IssuedAt.Unix(), rec.ExpiresAt.Unix()); err != nil {
		return "", nil, fmt.Errorf("cluster_credential: 写入凭证: %w", err)
	}
	return secret, rec, nil
}

// Verify 校验令牌（fail-closed）。
func (s *sqlClusterCredentialStore) Verify(ctx context.Context, clusterID string, token string, now time.Time) (*ClusterCredential, error) {
	if clusterID == "" || token == "" {
		return nil, errors.New("cluster_credential: 凭证缺失（集群 ID 或令牌为空）")
	}
	if now.IsZero() {
		now = time.Now()
	}
	rows, err := s.db.QueryContext(ctx,
		clusterCredentialSelect+` WHERE cluster_id = ? AND status = ? ORDER BY issued_at DESC`,
		clusterID, string(CredentialActive))
	if err != nil {
		return nil, fmt.Errorf("cluster_credential: 查询凭证: %w", err)
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var (
			rec       ClusterCredential
			status    string
			issuedAt  int64
			expiresAt int64
			closedAt  int64
			hash      string
		)
		if err := rows.Scan(&rec.ID, &rec.ClusterID, &status, &issuedAt, &expiresAt, &closedAt, &hash); err != nil {
			return nil, fmt.Errorf("cluster_credential: 扫描凭证: %w", err)
		}
		rec.Status = CredentialStatus(status)
		rec.IssuedAt = unixToTime(issuedAt)
		rec.ExpiresAt = unixToTime(expiresAt)
		rec.ClosedAt = unixToTime(closedAt)
		found = true
		// 过期即失效（fail-closed）。
		if now.After(rec.ExpiresAt) {
			return nil, fmt.Errorf("cluster_credential: 集群 %q 凭证已过期（%s）", clusterID, rec.ID)
		}
		// 常量时间比对哈希。
		if subtle.ConstantTimeCompare([]byte(hash), []byte(hashClusterSecret(clusterID, token))) == 1 {
			return &rec, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cluster_credential: 遍历凭证: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("cluster_credential: 集群 %q 无有效凭证", clusterID)
	}
	return nil, fmt.Errorf("cluster_credential: 集群 %q 凭证不匹配", clusterID)
}

// Rotate 轮换凭证：作废旧凭证 + 签发新凭证。
func (s *sqlClusterCredentialStore) Rotate(ctx context.Context, clusterID string, ttl time.Duration, now time.Time) (string, *ClusterCredential, error) {
	return s.Issue(ctx, clusterID, ttl, now)
}

// RevokeAll 吊销该集群全部凭证（摘除时同步吊销）。
func (s *sqlClusterCredentialStore) RevokeAll(ctx context.Context, clusterID string, now time.Time) (int, error) {
	if clusterID == "" {
		return 0, errors.New("cluster_credential: 集群 ID 为空")
	}
	if now.IsZero() {
		now = time.Now()
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE cluster_credentials SET status = ?, closed_at = ? WHERE cluster_id = ? AND status <> ?`,
		string(CredentialRevoked), now.Unix(), clusterID, string(CredentialRevoked))
	if err != nil {
		return 0, fmt.Errorf("cluster_credential: 吊销凭证: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cluster_credential: 吊销凭证: %w", err)
	}
	return int(n), nil
}

// randomTokenSecret 生成随机令牌（base64url 编码的 32 字节熵）。
func randomTokenSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashClusterSecret 计算令牌哈希（绑定集群 ID，A 集群令牌无法在 B 集群通过）。
func hashClusterSecret(clusterID, secret string) string {
	sum := sha256.Sum256([]byte(clusterID + "|" + secret))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ensureClusterCredentialSchema 建表（双方言；幂等，可重复调用）。
func ensureClusterCredentialSchema(db *sqlutil.DB) error {
	ddl := `
CREATE TABLE IF NOT EXISTS cluster_credentials (
  id          TEXT    PRIMARY KEY,
  cluster_id  TEXT    NOT NULL,
  secret_hash TEXT    NOT NULL,
  status      TEXT    NOT NULL DEFAULT 'active',
  issued_at   INTEGER NOT NULL DEFAULT 0,
  expires_at  INTEGER NOT NULL DEFAULT 0,
  closed_at   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cluster_credentials_cluster ON cluster_credentials(cluster_id, status);
`
	if db.Dialect().IsPostgres() {
		ddl = `
CREATE TABLE IF NOT EXISTS cluster_credentials (
  id          TEXT    PRIMARY KEY,
  cluster_id  TEXT    NOT NULL,
  secret_hash TEXT    NOT NULL,
  status      TEXT    NOT NULL DEFAULT 'active',
  issued_at   BIGINT  NOT NULL DEFAULT 0,
  expires_at  BIGINT  NOT NULL DEFAULT 0,
  closed_at   BIGINT  NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_cluster_credentials_cluster ON cluster_credentials(cluster_id, status);
`
	}
	if _, err := db.Exec(ddl); err != nil {
		return fmt.Errorf("cluster_credential: init schema: %w", err)
	}
	return nil
}

// 编译期断言：凭证存储实现满足接口。
var _ ClusterCredentialStore = (*sqlClusterCredentialStore)(nil)
