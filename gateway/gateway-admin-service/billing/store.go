package billing

import (
	"database/sql"
	"fmt"
	"strings"
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
	Begin() (Tx, error)     // 开事务（写路径统一入口）
	Ledger() LedgerStore    // §4.1.1
	Bills() BillStore       // 账单子存储
	Plans() PlanStore       // §4.1.2
	Freezes() FreezeStore   // 冻结子存储
	AlertDedup() AlertStore // 告警去重（S-7 余额 / S-9 到期）
	Close() error           // 优雅关闭（§6.15）
}

// ---------- DDL ----------

const ddlSchema = `
-- 账本表（追加式，仅 INSERT；§5.1）
CREATE TABLE IF NOT EXISTS billing_ledger (
  seq         INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id   TEXT    NOT NULL,
  model_key   TEXT    NOT NULL,
  day         TEXT    NOT NULL,
  -- cluster_id：计费打标（R-4/A5(6)，P2-4 T-1.8）。空串 = 单集群/未打标（既有数据默认值）。
  -- ★ 证据/维度列，不入哈希域（ComputeEntryHash 规范载荷已冻结，§7.6 破坏性升级）。
  cluster_id  TEXT    NOT NULL DEFAULT '',
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
  hash_alg    TEXT    NOT NULL DEFAULT '',
  created_at  INTEGER NOT NULL,
  UNIQUE(event_key)
);
CREATE INDEX IF NOT EXISTS idx_ledger_tenant_day ON billing_ledger(tenant_id, day);
-- 按集群过滤/聚合的索引见 ensureLedgerClusterIndexes（须在 ALTER 补列之后建）

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
  updated_at  INTEGER NOT NULL DEFAULT 0,
  poll_end_ns INTEGER NOT NULL DEFAULT 0
);
INSERT OR IGNORE INTO billing_ledger_head (id, seq, entry_hash, updated_at) VALUES (1, 0, '', 0);
`

// ---------- SQLite Store 实现 ----------

// ensureLedgerHashAlgColumn 为既有库补 `hash_alg` 列（P0-4 §5.4.3 B-5.4-1：持久化哈希须带算法标识）。
// SQLite 无 `ADD COLUMN IF NOT EXISTS` ⇒ 幂等捕获 "duplicate column name"（新库由 DDL 建列，此处必报该错）。
func ensureLedgerHashAlgColumn(db *sql.DB) error {
	_, err := db.Exec(`ALTER TABLE billing_ledger ADD COLUMN hash_alg TEXT NOT NULL DEFAULT ''`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("billing: migrate ledger hash_alg: %w", err)
	}
	return nil
}

// ensureLedgerClusterIDColumn 为既有库补 `cluster_id` 列（P2-4 T-1.8：R-4/A5(6) 计费打标维度）。
// 与 hash_alg 同款幂等写法：新库由 DDL 建列 ⇒ 此处必报 "duplicate column name"（吞掉）。
//
// ★ 只加**列**，不改哈希域：既有条目的 entry_hash 不变 ⇒ 账本链与 Verify() 不受影响。
func ensureLedgerClusterIDColumn(db *sql.DB) error {
	_, err := db.Exec(`ALTER TABLE billing_ledger ADD COLUMN cluster_id TEXT NOT NULL DEFAULT ''`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("billing: migrate ledger cluster_id: %w", err)
	}
	// ★ 索引必须**后于**补列：老库在 ALTER 之前建该索引会报
	// "no such column: cluster_id"，直接让 OpenSQLiteStore 失败（升级即不可用）。
	if err := ensureLedgerClusterIndexes(db); err != nil {
		return fmt.Errorf("billing: migrate ledger cluster_id: %w", err)
	}
	return nil
}

// ensureLedgerClusterIndexes 建 cluster_id 相关索引（跨集群过滤/聚合，R-4/A5(6)）。
//
// 特意**不放进 ddlSchema**：ddlSchema 在补列迁移之前执行，老库建索引时列还不存在。
func ensureLedgerClusterIndexes(db *sql.DB) error {
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_ledger_cluster_day ON billing_ledger(cluster_id, day)`); err != nil {
		return fmt.Errorf("billing: create ledger cluster index: %w", err)
	}
	return nil
}

// ensurePollWatermarkColumn 为既有库补 `poll_end_ns` 列（★ BUG-001：拉取水位持久化）。
// 新库由 DDL 建列 ⇒ 此处必报 "duplicate column name"（幂等吞掉）。
func ensurePollWatermarkColumn(db *sql.DB) error {
	_, err := db.Exec(`ALTER TABLE billing_ledger_head ADD COLUMN poll_end_ns INTEGER NOT NULL DEFAULT 0`)
	if err != nil && !strings.Contains(err.Error(), "duplicate column name") {
		return fmt.Errorf("billing: migrate poll_end_ns: %w", err)
	}
	return nil
}

type sqliteStore struct {
	db         *sql.DB
	ledger     *sqliteLedgerStore
	bills      *sqliteBillStore
	plans      *sqlitePlanStore
	freezes    *sqliteFreezeStore
	alertDedup *sqliteAlertStore
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
	// 迁移：为既有库补 `hash_alg` 列（P0-4 §5.4.3 B-5.4-1）
	if err := ensureLedgerHashAlgColumn(db); err != nil {
		db.Close()
		return nil, err
	}
	// 迁移：为既有库补 `poll_end_ns` 列（★ BUG-001：拉取水位持久化）
	if err := ensurePollWatermarkColumn(db); err != nil {
		db.Close()
		return nil, err
	}
	// 迁移：为既有库补 `cluster_id` 列（P2-4 T-1.8：R-4/A5(6) 计费打标维度）
	if err := ensureLedgerClusterIDColumn(db); err != nil {
		db.Close()
		return nil, err
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
	// 迁移：为既有库补 bills.`cluster_id` 列（P2-4 T-1.8：R-4/A5(6) 计费打标维度）
	if err := ensureBillClusterIDColumn(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("billing: migrate bill cluster_id: %w", err)
	}
	// 初始化 freezes 表
	if err := ensureFreezeSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("billing: init freeze schema: %w", err)
	}
	// 初始化 alert_dedup 表（S-7 余额告警 / S-9 到期提醒去重）
	if err := ensureAlertSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("billing: init alert dedup schema: %w", err)
	}
	s := &sqliteStore{db: db}
	s.ledger = &sqliteLedgerStore{db: db, s: s}
	s.bills = &sqliteBillStore{db: db}
	s.plans = &sqlitePlanStore{db: db}
	s.freezes = &sqliteFreezeStore{db: db}
	s.alertDedup = &sqliteAlertStore{db: db}
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

func (s *sqliteStore) Ledger() LedgerStore    { return s.ledger }
func (s *sqliteStore) Bills() BillStore       { return s.bills }
func (s *sqliteStore) Plans() PlanStore       { return s.plans }
func (s *sqliteStore) Freezes() FreezeStore   { return s.freezes }
func (s *sqliteStore) AlertDedup() AlertStore { return s.alertDedup }

func (s *sqliteStore) Close() error {
	return s.db.Close()
}
