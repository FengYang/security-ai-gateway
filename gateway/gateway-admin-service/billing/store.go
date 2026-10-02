package billing

import (
	"database/sql"
	"fmt"
	"sync"

	_ "modernc.org/sqlite"
)

// ---------- 事务与存储聚合根（§4.1.8） ----------

// Tx 事务句柄（单写事务 BEGIN IMMEDIATE；§7.1.1 并发安全前提）。
type Tx interface {
	Commit() error
	Rollback() error
	// tx 返回底层 sql.Tx（包内使用，不对外暴露）。
	tx() *sql.Tx
}

// sqlTx 是 Tx 的 SQLite 实现。携带 store 引用以便在 Commit/Rollback 后释放写锁。
type sqlTx struct {
	t    *sql.Tx
	s    *sqliteStore
	done bool
}

func (s *sqlTx) Commit() error {
	if s.done {
		return nil
	}
	s.done = true
	err := s.t.Commit()
	s.s.writeMu.Unlock()
	return err
}

func (s *sqlTx) Rollback() error {
	if s.done {
		return nil
	}
	s.done = true
	err := s.t.Rollback()
	s.s.writeMu.Unlock()
	return err
}

func (s *sqlTx) tx() *sql.Tx { return s.t }

// Store 账务域存储聚合根：提供事务与各子存储的 accessor。
// 实现必须并发安全；Ledger().Append 在单写事务内串行化（§7.1.1）。
type Store interface {
	Begin() (Tx, error)           // 开事务（写路径统一入口）
	Ledger() LedgerStore          // §4.1.1
	Bills() BillStore             // 账单子存储
	Plans() PlanStore             // §4.1.2
	Freezes() FreezeStore         // 冻结子存储
	QuotaAlerts() QuotaAlertStore // 余额告警去重（S-7，§6.11）
	Close() error                 // 优雅关闭（§6.15）
}

// ---------- DDL ----------

const ddlSchema = `
-- 账本表（追加式，仅 INSERT；§5.1）
CREATE TABLE IF NOT EXISTS billing_ledger (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT    NOT NULL,
  model_key   TEXT    NOT NULL,
  day         TEXT    NOT NULL,
  tokens_in   INTEGER NOT NULL DEFAULT 0,
  tokens_out  INTEGER NOT NULL DEFAULT 0,
  requests    INTEGER NOT NULL DEFAULT 0,
  retry_toks  INTEGER NOT NULL DEFAULT 0,
  std_in      INTEGER NOT NULL DEFAULT 0,
  std_out     INTEGER NOT NULL DEFAULT 0,
  source      TEXT    NOT NULL,
  price_ver   TEXT    NOT NULL DEFAULT '',
  event_key   TEXT    NOT NULL,
  prev_hash   TEXT    NOT NULL,
  entry_hash  TEXT    NOT NULL,
  created_at  INTEGER NOT NULL,
  UNIQUE(event_key)
);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant_day ON billing_ledger(tenant_id, day);

-- 不可变保障：禁止 UPDATE/DELETE 绕过应用层（§7.5）
DROP TRIGGER IF EXISTS trig_ledger_no_update;
DROP TRIGGER IF EXISTS trig_ledger_no_delete;
CREATE TRIGGER trig_ledger_no_update
BEFORE UPDATE ON billing_ledger
BEGIN
  SELECT RAISE(ABORT, 'billing_ledger is append-only (UPDATE forbidden)');
END;
CREATE TRIGGER trig_ledger_no_delete
BEFORE DELETE ON billing_ledger
BEGIN
  SELECT RAISE(ABORT, 'billing_ledger is append-only (DELETE forbidden)');
END;

-- 账本链尾单例（供 Head() 快速查询，避免每次扫全表）
CREATE TABLE IF NOT EXISTS billing_ledger_head (
  id          INTEGER PRIMARY KEY CHECK (id = 1),
  seq         INTEGER NOT NULL DEFAULT 0,
  entry_hash  TEXT    NOT NULL DEFAULT '',
  updated_at  INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO billing_ledger_head (id, seq, entry_hash, updated_at) VALUES (1, 0, '', 0);
`

// ---------- SQLite Store 实现 ----------

type sqliteStore struct {
	db          *sql.DB
	ledger      *sqliteLedgerStore
	bills       *sqliteBillStore
	plans       *sqlitePlanStore
	freezes     *sqliteFreezeStore
	quotaAlerts *sqliteQuotaAlertStore
	// 写锁：保证同一时刻只有一个写事务（SQLite 单写者模型）。
	writeMu sync.Mutex
}

// OpenSQLiteStore 打开 SQLite 存储并执行 DDL 初始化。
// dsn: 文件路径或 ":memory:"（测试用）。
func OpenSQLiteStore(dsn string, wal bool) (Store, error) {
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("billing: open sqlite: %w", err)
	}
	if wal {
		if _, err := db.Exec("PRAGMA journal_mode=WAL;"); err != nil {
			db.Close()
			return nil, fmt.Errorf("billing: enable WAL: %w", err)
		}
	}
	// 执行 DDL
	if _, err := db.Exec(ddlSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("billing: init schema: %w", err)
	}
	// 初始化 plans/subscriptions 表
	if err := ensurePlanSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("billing: init plan schema: %w", err)
	}
	// 初始化 bills/bill_items 表
	if err := ensureBillSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("billing: init bill schema: %w", err)
	}
	// 初始化 freezes 表
	if err := ensureFreezeSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("billing: init freeze schema: %w", err)
	}
	// 初始化 quota_alerts 表（S-7 余额告警去重）
	if err := ensureQuotaAlertSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("billing: init quota alert schema: %w", err)
	}
	s := &sqliteStore{db: db}
	s.ledger = &sqliteLedgerStore{db: db, s: s}
	s.bills = &sqliteBillStore{db: db}
	s.plans = &sqlitePlanStore{db: db}
	s.freezes = &sqliteFreezeStore{db: db}
	s.quotaAlerts = &sqliteQuotaAlertStore{db: db}
	return s, nil
}

func (s *sqliteStore) Begin() (Tx, error) {
	s.writeMu.Lock()
	t, err := s.db.Begin()
	if err != nil {
		s.writeMu.Unlock()
		return nil, fmt.Errorf("billing: begin tx: %w", err)
	}
	return &sqlTx{t: t, s: s}, nil
}

func (s *sqliteStore) Ledger() LedgerStore          { return s.ledger }
func (s *sqliteStore) Bills() BillStore             { return s.bills }
func (s *sqliteStore) Plans() PlanStore             { return s.plans }
func (s *sqliteStore) Freezes() FreezeStore         { return s.freezes }
func (s *sqliteStore) QuotaAlerts() QuotaAlertStore { return s.quotaAlerts }

func (s *sqliteStore) Close() error {
	return s.db.Close()
}
