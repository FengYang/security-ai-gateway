package billing

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

// ---------- BillStore SQLite 实现（T5，§5.3） ----------

type sqliteBillStore struct {
	db *sql.DB
}

// ensureBillSchema 确保 bills/bill_items 表存在。
func ensureBillSchema(db *sql.DB) error {
	ddl := `
CREATE TABLE IF NOT EXISTS bills (
  id            TEXT PRIMARY KEY,
  tenant_id     TEXT NOT NULL,
  kind          TEXT NOT NULL,
  period        TEXT NOT NULL,
  -- cluster_id：计费打标（R-4/A5(6)，P2-4 T-1.8）。空串 = 单集群/未打标/跨集群混合。
  -- ★ 证据/维度列，不入账单签名域（canonicalBill 已冻结，§7.2/§7.6）。
  cluster_id    TEXT NOT NULL DEFAULT '',
  total         INTEGER NOT NULL,
  currency      TEXT NOT NULL DEFAULT 'CNY',
  price_version TEXT NOT NULL DEFAULT '',
  status        TEXT NOT NULL,
  sig           TEXT NOT NULL DEFAULT '',
  ledger_head   TEXT NOT NULL,
  audit_head    TEXT NOT NULL,
  generated_at  INTEGER NOT NULL,
  UNIQUE(tenant_id, kind, period)
);
CREATE INDEX IF NOT EXISTS idx_bills_tenant ON bills(tenant_id, generated_at DESC);
-- 按集群过滤/汇总的索引见 ensureBillClusterIndexes（须在 ALTER 补列之后建）

CREATE TABLE IF NOT EXISTS bill_items (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  bill_id         TEXT NOT NULL,
  model_key       TEXT NOT NULL,
  standard_tokens INTEGER NOT NULL,
  tokens_in       INTEGER NOT NULL,
  tokens_out      INTEGER NOT NULL,
  retry_toks      INTEGER NOT NULL,
  amount          INTEGER NOT NULL,
  tier_breakdown  TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_bill_items_bill ON bill_items(bill_id);
	`
	_, err := db.Exec(ddl)
	return err
}

// ensureBillClusterIDColumn 为既有库补 `cluster_id` 列（P2-4 T-1.8：R-4/A5(6) 计费打标维度）。
// 同款幂等写法：新库由 DDL 建列 ⇒ 此处必报 "duplicate column name"（吞掉）。
// 必须在 ensureBillSchema 之后调用（表不存在时 ALTER 会真的报错）。
//
// ★ 只加列，不改签名域 ⇒ 既有账单的 sig 仍然可验。
func ensureBillClusterIDColumn(db *sql.DB) error {
	_, err := db.Exec(`ALTER TABLE bills ADD COLUMN cluster_id TEXT NOT NULL DEFAULT ''`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("billing: migrate bills cluster_id: %w", err)
	}
	// ★ 索引后于补列：老库在 ALTER 之前建该索引会报 "no such column: cluster_id"。
	if err := ensureBillClusterIndexes(db); err != nil {
		return err
	}
	return nil
}

// ensureBillClusterIndexes 建 bills.cluster_id 索引（同 ensureLedgerClusterIndexes 的原因，
// 不能放进 ensureBillSchema 的 DDL）。
func ensureBillClusterIndexes(db *sql.DB) error {
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_bills_cluster ON bills(cluster_id, generated_at DESC)`); err != nil {
		return fmt.Errorf("billing: create bills cluster index: %w", err)
	}
	return nil
}

func (s *sqliteBillStore) Put(b *Bill) error {
	if b == nil || b.ID == "" {
		return fmt.Errorf("billing: bill id is required")
	}
	if b.Currency == "" {
		b.Currency = "CNY"
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("billing: bill tx: %w", err)
	}
	defer func() {
		if err != nil {
			tx.Rollback()
		}
	}()

	// 幂等由 UNIQUE(tenant,kind,period) 保证
	_, err = tx.Exec(`INSERT INTO bills
		(id, tenant_id, kind, period, cluster_id, total, currency, price_version, status, sig,
		 ledger_head, audit_head, generated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		b.ID, b.TenantID, b.Kind, b.Period, b.ClusterID, int64(b.Total), b.Currency,
		b.PriceVersion, b.Status, b.Sig, b.LedgerHead, b.AuditHead, b.GeneratedAt)
	if err != nil {
		return fmt.Errorf("billing: insert bill: %w", err)
	}

	for _, it := range b.Items {
		tb, _ := json.Marshal(it.TierBreakdown)
		_, err = tx.Exec(`INSERT INTO bill_items
			(bill_id, model_key, standard_tokens, tokens_in, tokens_out, retry_toks, amount, tier_breakdown)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			b.ID, it.ModelKey, it.StandardTokens, it.TokensIn, it.TokensOut,
			it.RetryToks, int64(it.Amount), string(tb))
		if err != nil {
			return fmt.Errorf("billing: insert bill item: %w", err)
		}
	}

	return tx.Commit()
}

func (s *sqliteBillStore) Get(billID string) (*Bill, error) {
	var b Bill
	var total int64
	err := s.db.QueryRow(`SELECT id, tenant_id, kind, period, cluster_id, total, currency, price_version,
		status, sig, ledger_head, audit_head, generated_at
		FROM bills WHERE id = ?`, billID).Scan(
		&b.ID, &b.TenantID, &b.Kind, &b.Period, &b.ClusterID, &total, &b.Currency, &b.PriceVersion,
		&b.Status, &b.Sig, &b.LedgerHead, &b.AuditHead, &b.GeneratedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("billing: get bill: %w", err)
	}
	b.Total = Amount(total)

	items, err := s.itemsOf(billID)
	if err != nil {
		return nil, err
	}
	b.Items = items
	return &b, nil
}

func (s *sqliteBillStore) itemsOf(billID string) ([]BillItem, error) {
	rows, err := s.db.Query(`SELECT model_key, standard_tokens, tokens_in, tokens_out,
		retry_toks, amount, tier_breakdown FROM bill_items WHERE bill_id = ? ORDER BY id`, billID)
	if err != nil {
		return nil, fmt.Errorf("billing: query bill items: %w", err)
	}
	defer rows.Close()
	var items []BillItem
	for rows.Next() {
		var it BillItem
		var amount int64
		var tbJSON string
		if err := rows.Scan(&it.ModelKey, &it.StandardTokens, &it.TokensIn, &it.TokensOut,
			&it.RetryToks, &amount, &tbJSON); err != nil {
			return nil, err
		}
		it.Amount = Amount(amount)
		if tbJSON != "" && tbJSON != "[]" {
			json.Unmarshal([]byte(tbJSON), &it.TierBreakdown)
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

func (s *sqliteBillStore) List(q BillQuery) ([]*Bill, error) {
	query := `SELECT id, tenant_id, kind, period, cluster_id, total, currency, price_version,
		status, sig, ledger_head, audit_head, generated_at FROM bills WHERE 1=1`
	var args []interface{}
	if q.TenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, q.TenantID)
	}
	// 集群过滤（R-4/A5(6)）：ClusterUnset 优先，命中"仅未打标"语义。
	if q.ClusterUnset {
		query += ` AND cluster_id = ''`
	} else if q.ClusterID != "" {
		query += ` AND cluster_id = ?`
		args = append(args, q.ClusterID)
	}
	if q.Kind != "" {
		query += ` AND kind = ?`
		args = append(args, q.Kind)
	}
	if q.From != "" {
		query += ` AND period >= ?`
		args = append(args, q.From)
	}
	if q.To != "" {
		query += ` AND period <= ?`
		args = append(args, q.To)
	}
	query += ` ORDER BY generated_at DESC`
	if q.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, q.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("billing: list bills: %w", err)
	}
	defer rows.Close()
	var bills []*Bill
	for rows.Next() {
		var b Bill
		var total int64
		if err := rows.Scan(&b.ID, &b.TenantID, &b.Kind, &b.Period, &b.ClusterID, &total, &b.Currency,
			&b.PriceVersion, &b.Status, &b.Sig, &b.LedgerHead, &b.AuditHead, &b.GeneratedAt); err != nil {
			return nil, err
		}
		b.Total = Amount(total)
		bills = append(bills, &b)
	}
	return bills, rows.Err()
}

func (s *sqliteBillStore) UpdateStatus(billID, status string) error {
	_, err := s.db.Exec(`UPDATE bills SET status = ? WHERE id = ?`, status, billID)
	if err != nil {
		return fmt.Errorf("billing: update bill status: %w", err)
	}
	return nil
}
