package sqlutil

import (
	"context"
	"database/sql"
	"os"
	"sync"
	"testing"
	"time"
)

func TestRebindPostgres(t *testing.T) {
	cases := []struct{ in, want string }{
		{"SELECT * FROM t WHERE a = ? AND b = ?", "SELECT * FROM t WHERE a = $1 AND b = $2"},
		{"SELECT '?' AS q, x FROM t WHERE y = ?", "SELECT '?' AS q, x FROM t WHERE y = $1"},
		{"SELECT 'it''s ?' FROM t WHERE z = ?", "SELECT 'it''s ?' FROM t WHERE z = $1"},
		{`SELECT "col?" FROM t WHERE a = ?`, `SELECT "col?" FROM t WHERE a = $1`},
		{"-- what? no\nSELECT ?", "-- what? no\nSELECT $1"},
		{"/* a ? b */ SELECT ?", "/* a ? b */ SELECT $1"},
		{"UPDATE t SET a = a + 1 WHERE id = ?", "UPDATE t SET a = a + 1 WHERE id = $1"},
		// 非注释语境下的 - 与 / 不应误判为注释起始。
		{"SELECT a-b, a/b, ? FROM t", "SELECT a-b, a/b, $1 FROM t"},
		// 未闭合字符串按字面处理（后续 ? 不转换——PG 侧本就是语法错误，重绑不得改变 SQL 形态）。
		{"SELECT 'unclosed, ? kept", "SELECT 'unclosed, ? kept"},
	}
	for _, c := range cases {
		if got := Postgres.Rebind(c.in); got != c.want {
			t.Errorf("Rebind(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	if got := SQLite.Rebind("SELECT ?"); got != "SELECT ?" {
		t.Errorf("sqlite rebind should be identity, got %q", got)
	}
}

// TestRebindConcurrent 重绑为纯函数，须并发安全（-race 下验证）。
func TestRebindConcurrent(t *testing.T) {
	const q = `SELECT * FROM t WHERE a = ? AND b IN (?, ?) -- x ? y`
	const want = `SELECT * FROM t WHERE a = $1 AND b IN ($2, $3) -- x ? y`
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				if got := Postgres.Rebind(q); got != want {
					t.Errorf("Rebind concurrent got %q, want %q", got, want)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestDBTxSQLite(t *testing.T) {
	db, err := Open(SQLite, ":memory:", 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(`CREATE TABLE k (id INTEGER PRIMARY KEY, v TEXT NOT NULL)`); err != nil {
		t.Fatalf("create: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO k (v) VALUES (?)`, "a"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}

	var v string
	if err := db.QueryRow(`SELECT v FROM k WHERE id = ?`, 1).Scan(&v); err != nil {
		t.Fatalf("query: %v", err)
	}
	if v != "a" {
		t.Fatalf("v = %q", v)
	}

	tx2, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("begin2: %v", err)
	}
	if _, err := tx2.Exec(`INSERT INTO k (v) VALUES (?)`, "b"); err != nil {
		t.Fatalf("insert2: %v", err)
	}
	if err := tx2.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM k`).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	if n != 1 {
		t.Fatalf("rows = %d after rollback, want 1", n)
	}
}

// TestPostgresTxAdvisoryLockGate PG 门控集成测试（ADMIN_TEST_PG_DSN 未设置时跳过）：
// 覆盖建表 / 写事务 / advisory xact lock 互斥 / 回滚。
func TestPostgresTxAdvisoryLockGate(t *testing.T) {
	dsn := os.Getenv("ADMIN_TEST_PG_DSN")
	if dsn == "" {
		t.Skip("ADMIN_TEST_PG_DSN 未设置，跳过 PG 门控用例")
	}
	db, err := Open(Postgres, dsn, 0x53514C55 /*"SQLU"*/)
	if err != nil {
		t.Fatalf("open pg: %v", err)
	}
	defer db.Close()

	// 建表（多语句 DDL；无参 Exec 走 pgx 简单协议，支持批量）。
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS sqlutil_gate (
		id BIGSERIAL PRIMARY KEY, v TEXT NOT NULL)`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM sqlutil_gate`); err != nil {
		t.Fatalf("clean table: %v", err)
	}

	// 写事务（BeginTx 内自动取 advisory xact lock）。
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	if _, err := tx.Exec(`INSERT INTO sqlutil_gate (v) VALUES (?)`, "a"); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var v string
	if err := db.QueryRow(`SELECT v FROM sqlutil_gate WHERE v = 'a'`).Scan(&v); err != nil || v != "a" {
		t.Fatalf("query after commit: v=%q err=%v", v, err)
	}

	// advisory lock 互斥：txA 持锁期间，txB 的 Begin 应阻塞（等价 BEGIN IMMEDIATE 意图）。
	txA, err := db.Begin()
	if err != nil {
		t.Fatalf("begin txA: %v", err)
	}
	if _, err := txA.Exec(`INSERT INTO sqlutil_gate (v) VALUES (?)`, "held"); err != nil {
		t.Fatalf("insert txA: %v", err)
	}
	bDone := make(chan error, 1)
	go func() {
		txB, err := db.Begin()
		if err != nil {
			bDone <- err
			return
		}
		if _, err := txB.Exec(`INSERT INTO sqlutil_gate (v) VALUES (?)`, "b"); err != nil {
			bDone <- err
			return
		}
		bDone <- txB.Commit()
	}()
	select {
	case err := <-bDone:
		t.Fatalf("txB 在 txA 提交前完成，advisory lock 未互斥: %v", err)
	case <-time.After(300 * time.Millisecond):
		// 预期：txB 被 advisory lock 阻塞。
	}
	if err := txA.Commit(); err != nil {
		t.Fatalf("commit txA: %v", err)
	}
	select {
	case err := <-bDone:
		if err != nil {
			t.Fatalf("txB after txA commit: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("txA 提交后 txB 仍未完成")
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlutil_gate`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("count = %d err=%v, want 3", n, err)
	}

	// 回滚路径。
	tx2, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx2: %v", err)
	}
	if _, err := tx2.Exec(`INSERT INTO sqlutil_gate (v) VALUES (?)`, "c"); err != nil {
		t.Fatalf("insert tx2: %v", err)
	}
	if err := tx2.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlutil_gate`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("count after rollback = %d err=%v, want 3", n, err)
	}
}

func TestQuerierInterface(t *testing.T) {
	var _ Querier = (*sql.Tx)(nil)
	var _ Querier = (*Tx)(nil)
}
