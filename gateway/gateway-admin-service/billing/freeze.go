package billing

import (
	"database/sql"
	"fmt"
)

// ---------- 冻结类型与存储（T8，§4.1.7 / §5.7） ----------

// FreezeRecord 冻结行。
type FreezeRecord struct {
	TenantID string
	Reason   string // spike|reconcile_diff|pricing_missing|manual
	Severity string // warning|critical
	FrozenAt int64
	Until    int64 // 0 = 无限（人工解除）
	By       string
}

// FreezeStore 冻结状态持久化接口。
type FreezeStore interface {
	Put(f FreezeRecord) error
	Get(tenant string) (*FreezeRecord, error)
	// List 返回全部冻结记录（供自动解冻枚举，B-6.10-2）。
	List() ([]FreezeRecord, error)
	Delete(tenant string) error
}

// ensureFreezeSchema 确保 freezes 表存在。
func ensureFreezeSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS freezes (
  tenant_id  TEXT PRIMARY KEY,
  reason     TEXT NOT NULL,
  severity   TEXT NOT NULL,
  frozen_at  INTEGER NOT NULL,
  until      INTEGER NOT NULL DEFAULT 0,
  by         TEXT NOT NULL
);`)
	return err
}

type sqliteFreezeStore struct {
	db *sql.DB
}

func (s *sqliteFreezeStore) Put(f FreezeRecord) error {
	if f.TenantID == "" {
		return fmt.Errorf("billing: freeze tenant_id is required")
	}
	_, err := s.db.Exec(`INSERT INTO freezes (tenant_id, reason, severity, frozen_at, until, by)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET
			reason = excluded.reason,
			severity = excluded.severity,
			frozen_at = excluded.frozen_at,
			until = excluded.until,
			by = excluded.by`,
		f.TenantID, f.Reason, f.Severity, f.FrozenAt, f.Until, f.By)
	if err != nil {
		return fmt.Errorf("billing: put freeze: %w", err)
	}
	return nil
}

func (s *sqliteFreezeStore) Get(tenant string) (*FreezeRecord, error) {
	var f FreezeRecord
	err := s.db.QueryRow(`SELECT tenant_id, reason, severity, frozen_at, until, by
		FROM freezes WHERE tenant_id = ?`, tenant).Scan(
		&f.TenantID, &f.Reason, &f.Severity, &f.FrozenAt, &f.Until, &f.By)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("billing: get freeze: %w", err)
	}
	return &f, nil
}

func (s *sqliteFreezeStore) Delete(tenant string) error {
	_, err := s.db.Exec(`DELETE FROM freezes WHERE tenant_id = ?`, tenant)
	if err != nil {
		return fmt.Errorf("billing: delete freeze: %w", err)
	}
	return nil
}

// List 返回全部冻结记录（按 tenant_id 升序）。
func (s *sqliteFreezeStore) List() ([]FreezeRecord, error) {
	rows, err := s.db.Query(`SELECT tenant_id, reason, severity, frozen_at, until, by
		FROM freezes ORDER BY tenant_id`)
	if err != nil {
		return nil, fmt.Errorf("billing: list freezes: %w", err)
	}
	defer rows.Close()
	var out []FreezeRecord
	for rows.Next() {
		var f FreezeRecord
		if err := rows.Scan(&f.TenantID, &f.Reason, &f.Severity, &f.FrozenAt, &f.Until, &f.By); err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
