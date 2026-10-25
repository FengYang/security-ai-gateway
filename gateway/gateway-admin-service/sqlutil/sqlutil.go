// Package sqlutil 提供 sqlite/postgres 双方言的最小适配层。
//
// 设计目标（P2-4 T-1.1）：
//   - 同一套 SQL 文本（`?` 占位符）经 Rebind 转成 PG 的 `$n`；
//   - 写事务在 PG 下用 `pg_advisory_xact_lock` 等价 SQLite `BEGIN IMMEDIATE` 的跨副本互斥；
//   - 不改动既有调用点的 SQL 形态，降低双库改造的回归风险。
package sqlutil

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // 注册 "pgx" 驱动
	_ "modernc.org/sqlite"             // 注册 "sqlite" 驱动
)

// Dialect 数据库方言。
type Dialect string

const (
	// SQLite SQLite 方言（默认；既有部署行为不变）。
	SQLite Dialect = "sqlite"
	// Postgres PostgreSQL 方言（共享库多副本）。
	Postgres Dialect = "postgres"
)

// ParseDialect 解析驱动名（空串/未知按 sqlite，保持向后兼容）。
func ParseDialect(s string) Dialect {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "postgres", "postgresql", "pg", "pgx":
		return Postgres
	default:
		return SQLite
	}
}

// DriverName 返回 database/sql 驱动名。
func (d Dialect) DriverName() string {
	if d == Postgres {
		return "pgx"
	}
	return "sqlite"
}

// IsPostgres 是否 PG 方言。
func (d Dialect) IsPostgres() bool { return d == Postgres }

// Rebind 把 `?` 占位符转换为方言占位符（PG `$1..$n`；SQLite 原样）。
// 单引号字符串、双引号标识符、`--`/`/* */` 注释内的 `?` 不转换。
func (d Dialect) Rebind(query string) string {
	if d != Postgres || !strings.Contains(query, "?") {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 8)
	n := 1
	inSingle, inDouble, inLine, inBlock := false, false, false, false
	for i := 0; i < len(query); i++ {
		c := query[i]
		if inLine {
			b.WriteByte(c)
			if c == '\n' {
				inLine = false
			}
			continue
		}
		if inBlock {
			b.WriteByte(c)
			if c == '*' && i+1 < len(query) && query[i+1] == '/' {
				b.WriteByte('/')
				i++
				inBlock = false
			}
			continue
		}
		if inSingle {
			b.WriteByte(c)
			if c == '\'' {
				// 处理 '' 转义：连续两个单引号仍处于字符串内。
				if i+1 < len(query) && query[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				inSingle = false
			}
			continue
		}
		if inDouble {
			b.WriteByte(c)
			if c == '"' {
				inDouble = false
			}
			continue
		}
		switch c {
		case '\'':
			inSingle = true
			b.WriteByte(c)
		case '"':
			inDouble = true
			b.WriteByte(c)
		case '-':
			b.WriteByte(c)
			if i+1 < len(query) && query[i+1] == '-' {
				b.WriteByte('-')
				i++
				inLine = true
			}
		case '/':
			b.WriteByte(c)
			if i+1 < len(query) && query[i+1] == '*' {
				b.WriteByte('*')
				i++
				inBlock = true
			}
		case '?':
			fmt.Fprintf(&b, "$%d", n)
			n++
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// DB 方言感知的 *sql.DB 包装。
type DB struct {
	*sql.DB
	dialect Dialect
	lockKey int64
}

// Wrap 包装既有 *sql.DB。
func Wrap(db *sql.DB, d Dialect, lockKey int64) *DB {
	return &DB{DB: db, dialect: d, lockKey: lockKey}
}

// Open 打开数据库（driver 为方言的驱动名；由调用方保证 DSN 格式）。
func Open(d Dialect, dsn string, lockKey int64) (*DB, error) {
	db, err := sql.Open(d.DriverName(), dsn)
	if err != nil {
		return nil, fmt.Errorf("sqlutil: open %s: %w", d, err)
	}
	return Wrap(db, d, lockKey), nil
}

// Dialect 返回方言。
func (db *DB) Dialect() Dialect { return db.dialect }

// Rebind 暴露方言重绑（少量直接拼 SQL 的场景）。
func (db *DB) Rebind(q string) string { return db.dialect.Rebind(q) }

// Exec 执行语句。
func (db *DB) Exec(query string, args ...any) (sql.Result, error) {
	return db.DB.Exec(db.dialect.Rebind(query), args...)
}

// ExecContext 执行语句。
func (db *DB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return db.DB.ExecContext(ctx, db.dialect.Rebind(query), args...)
}

// Query 查询。
func (db *DB) Query(query string, args ...any) (*sql.Rows, error) {
	return db.DB.Query(db.dialect.Rebind(query), args...)
}

// QueryContext 查询。
func (db *DB) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return db.DB.QueryContext(ctx, db.dialect.Rebind(query), args...)
}

// QueryRow 单行查询。
func (db *DB) QueryRow(query string, args ...any) *sql.Row {
	return db.DB.QueryRow(db.dialect.Rebind(query), args...)
}

// QueryRowContext 单行查询。
func (db *DB) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return db.DB.QueryRowContext(ctx, db.dialect.Rebind(query), args...)
}

// Begin 开写事务：进程内互斥由调用方的 writeMu 保证；PG 下额外取事务级
// advisory lock，使跨副本写路径同样串行（等价 SQLite BEGIN IMMEDIATE 的意图）。
func (db *DB) Begin() (*Tx, error) {
	return db.BeginTx(context.Background(), nil)
}

// BeginTx 开写事务（opts 透传）。
func (db *DB) BeginTx(ctx context.Context, opts *sql.TxOptions) (*Tx, error) {
	raw, err := db.DB.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	tx := &Tx{Tx: raw, dialect: db.dialect}
	if db.dialect.IsPostgres() && db.lockKey != 0 {
		if _, err := raw.ExecContext(ctx, "SELECT pg_advisory_xact_lock($1)", db.lockKey); err != nil {
			_ = raw.Rollback()
			return nil, fmt.Errorf("sqlutil: acquire advisory lock: %w", err)
		}
	}
	return tx, nil
}

// Tx 方言感知的 *sql.Tx 包装。
type Tx struct {
	*sql.Tx
	dialect Dialect
}

// Dialect 返回方言。
func (tx *Tx) Dialect() Dialect { return tx.dialect }

// Exec 执行语句。
func (tx *Tx) Exec(query string, args ...any) (sql.Result, error) {
	return tx.Tx.Exec(tx.dialect.Rebind(query), args...)
}

// ExecContext 执行语句。
func (tx *Tx) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return tx.Tx.ExecContext(ctx, tx.dialect.Rebind(query), args...)
}

// Query 查询。
func (tx *Tx) Query(query string, args ...any) (*sql.Rows, error) {
	return tx.Tx.Query(tx.dialect.Rebind(query), args...)
}

// QueryContext 查询。
func (tx *Tx) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return tx.Tx.QueryContext(ctx, tx.dialect.Rebind(query), args...)
}

// QueryRow 单行查询。
func (tx *Tx) QueryRow(query string, args ...any) *sql.Row {
	return tx.Tx.QueryRow(tx.dialect.Rebind(query), args...)
}

// QueryRowContext 单行查询。
func (tx *Tx) QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row {
	return tx.Tx.QueryRowContext(ctx, tx.dialect.Rebind(query), args...)
}

// Querier 事务内的最小执行面（TenantTx/billing.Tx 的 tx() 返回它）。
type Querier interface {
	Exec(query string, args ...any) (sql.Result, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

var _ Querier = (*sql.Tx)(nil)
var _ Querier = (*Tx)(nil)
