package billing

import (
	"context"
	"database/sql"
	"fmt"
)

// ---------- LedgerStore 接口（§4.1.1） ----------

// LedgerStore 账本存储（唯一写入入口；实现必须并发安全 + 事务）。
type LedgerStore interface {
	// Append 追加一批条目（EventKey 去重；返回实际新增数与新链尾）。
	// 幂等：重复 EventKey 静默跳过（不报错），保证"拉取重叠窗口"可安全重放。
	Append(tx Tx, entries []LedgerEntry) (added int, head LedgerHead, err error)
	// Range 只读查询（按日/租户；金额计算在读取侧，账本只存用量）。
	Range(q LedgerQuery) ([]LedgerEntry, error)
	// CountSource 统计某租户某来源在 [fromNs,toNs] 创建时间区间内的条目数（P2-5 job 对账）。
	CountSource(ctx context.Context, tenant, source string, fromNs, toNs int64) (int64, error)
	// Verify 校验哈希链完整性；返回首个断链 Seq（-1 = 完好）。
	Verify() (brokenAt int64, err error)
	// Head 链尾摘要。
	Head() (LedgerHead, error)
	// ReproduceHead 重放 period 内条目，判定链尾 == want（账单锚定校验，§7.3）。
	ReproduceHead(tenant, period, want string) bool
	// PollWatermark 返回拉取水位（上轮成功窗口的结束时刻，UTC ns；0 = 未初始化）。
	// ★ BUG-001：供进程重启后恢复**非重叠**拉取游标（避免回溯 lookback 造成重复入账）。
	PollWatermark() (int64, error)
	// SetPollWatermark 持久化拉取水位（每成功拉取一段即推进）。
	SetPollWatermark(ns int64) error
}

// ---------- SQLite 实现 ----------

type sqliteLedgerStore struct {
	db *sql.DB
	s  *sqliteStore
}

// Append 追加条目（事务内执行；幂等去重 + 哈希链维护）。
func (s *sqliteLedgerStore) Append(tx Tx, entries []LedgerEntry) (int, LedgerHead, error) {
	if len(entries) == 0 {
		head, _ := s.headFromTx(tx)
		return 0, head, nil
	}
	sqlTx := tx.tx()

	// 1. 获取当前链尾
	var headSeq int64
	var headHash string
	var headUpdated int64
	err := sqlTx.QueryRow(`SELECT seq, entry_hash, updated_at FROM billing_ledger_head WHERE id = 1`).
		Scan(&headSeq, &headHash, &headUpdated)
	if err != nil {
		return 0, LedgerHead{}, fmt.Errorf("billing: get ledger head: %w", err)
	}

	// 2. 逐条插入（跳过重复 event_key），维护链
	prevHash := headHash
	curSeq := uint64(headSeq)
	added := 0

	stmt, err := sqlTx.Prepare(`
		INSERT OR IGNORE INTO billing_ledger
		(tenant_id, model_key, day, cluster_id, tokens_in, tokens_out, requests, retry_toks,
		 std_in, std_out, source, price_ver, event_key, prev_hash, entry_hash, hash_alg, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		return 0, LedgerHead{}, fmt.Errorf("billing: prepare insert: %w", err)
	}
	defer stmt.Close()

	// ★ BUG-006：记录**实际新增**的最后一条 created_at（而非输入切片末条），
	// 用于链尾 updated_at 与返回值（输入含重复被忽略时二者可能不同）。
	var lastCreatedAt int64

	for _, e := range entries {
		// 设置链序号与前序哈希
		curSeq++
		e.Seq = curSeq
		e.PrevHash = prevHash
		// B-5.4-1：写入端如实标注哈希算法（intl → ""（缺省 = SHA-256），sm-* → "sm3"）。
		if e.HashAlg == "" {
			e.HashAlg = hashAlgTag()
		}
		h, herr := ComputeEntryHash(e)
		if herr != nil {
			return added, LedgerHead{}, herr
		}
		e.EntryHash = h

		res, err := stmt.Exec(
			e.TenantID, e.ModelKey, e.Day, e.ClusterID,
			e.TokensIn, e.TokensOut, e.Requests, e.RetryToks,
			e.StdIn, e.StdOut, e.Source, e.PriceVer,
			e.EventKey, e.PrevHash, e.EntryHash, e.HashAlg, e.CreatedAt,
		)
		if err != nil {
			return added, LedgerHead{}, fmt.Errorf("billing: insert ledger seq=%d: %w", curSeq, err)
		}
		ra, _ := res.RowsAffected()
		if ra > 0 {
			prevHash = e.EntryHash
			lastCreatedAt = e.CreatedAt
			added++
		} else {
			// 重复：回退 curSeq（下次插入重新用），prevHash 不变
			curSeq--
		}
	}

	// 3. 更新链尾表（仅当有新增）
	if added > 0 {
		now := lastCreatedAt // ★ BUG-006：实际新增末条
		_, err := sqlTx.Exec(`UPDATE billing_ledger_head SET seq = ?, entry_hash = ?, updated_at = ? WHERE id = 1`,
			int64(curSeq), prevHash, now)
		if err != nil {
			return added, LedgerHead{}, fmt.Errorf("billing: update ledger head: %w", err)
		}
		headUpdated = now // ★ BUG-006：返回值反映已写入的 updated_at（此前为更新前旧值）
		// 指标 #2/#3（§9.1.1 唯一生产者）
		IncLedgerEntries(added)
		SetLedgerHeadSeq(curSeq)
	}

	return added, LedgerHead{Seq: curSeq, EntryHash: prevHash, UpdatedAt: headUpdated}, nil
}

func (s *sqliteLedgerStore) headFromTx(tx Tx) (LedgerHead, error) {
	var head LedgerHead
	err := tx.tx().QueryRow(`SELECT seq, entry_hash, updated_at FROM billing_ledger_head WHERE id = 1`).
		Scan(&head.Seq, &head.EntryHash, &head.UpdatedAt)
	return head, err
}

// Range 按条件查询账本条目。
func (s *sqliteLedgerStore) Range(q LedgerQuery) ([]LedgerEntry, error) {
	query := `SELECT seq, tenant_id, model_key, day, cluster_id, tokens_in, tokens_out, requests,
		retry_toks, std_in, std_out, source, price_ver, event_key, prev_hash, entry_hash, created_at, hash_alg
		FROM billing_ledger WHERE 1=1`
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
	if q.DayFrom != "" {
		query += ` AND day >= ?`
		args = append(args, q.DayFrom)
	}
	if q.DayTo != "" {
		query += ` AND day <= ?`
		args = append(args, q.DayTo)
	}
	query += ` ORDER BY seq ASC`
	if q.Limit > 0 {
		query += ` LIMIT ?`
		args = append(args, q.Limit)
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("billing: query ledger: %w", err)
	}
	defer rows.Close()

	var entries []LedgerEntry
	for rows.Next() {
		var e LedgerEntry
		err := rows.Scan(&e.Seq, &e.TenantID, &e.ModelKey, &e.Day, &e.ClusterID,
			&e.TokensIn, &e.TokensOut, &e.Requests, &e.RetryToks,
			&e.StdIn, &e.StdOut, &e.Source, &e.PriceVer,
			&e.EventKey, &e.PrevHash, &e.EntryHash, &e.CreatedAt, &e.HashAlg)
		if err != nil {
			return nil, fmt.Errorf("billing: scan ledger: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// Verify 全量校验哈希链完整性。返回首个断链的 seq（-1 = 完好）。
//
// 注：本查询**不读** cluster_id——它是证据/维度列、不入哈希域（§7.6），
// 故打标与否不影响链校验结果（参见 TestClusterID_ChainIntegrityPreserved）。
func (s *sqliteLedgerStore) Verify() (int64, error) {
	rows, err := s.db.Query(`SELECT seq, prev_hash, entry_hash, tenant_id, model_key, day, tokens_in, tokens_out,
		requests, retry_toks, std_in, std_out, source, price_ver, event_key, created_at, hash_alg
		FROM billing_ledger ORDER BY seq ASC`)
	if err != nil {
		return -1, fmt.Errorf("billing: verify query: %w", err)
	}
	defer rows.Close()

	var prevHash string
	var prevSeq uint64
	for rows.Next() {
		var e LedgerEntry
		err := rows.Scan(&e.Seq, &e.PrevHash, &e.EntryHash, &e.TenantID, &e.ModelKey, &e.Day,
			&e.TokensIn, &e.TokensOut, &e.Requests, &e.RetryToks,
			&e.StdIn, &e.StdOut, &e.Source, &e.PriceVer, &e.EventKey, &e.CreatedAt, &e.HashAlg)
		if err != nil {
			return -1, fmt.Errorf("billing: verify scan: %w", err)
		}
		// 序号连续性检查
		if e.Seq != prevSeq+1 {
			return int64(e.Seq), nil
		}
		// 前序哈希一致性
		if e.PrevHash != prevHash {
			return int64(e.Seq), nil
		}
		// 本条哈希正确性（按条目自述 hash_alg 分派复算 ⇒ 迁移后旧条目仍可验，B-5.4-1）
		computed, herr := ComputeEntryHash(e)
		if herr != nil {
			return -1, fmt.Errorf("billing: 账本条目 seq=%d 哈希算法非法: %w", e.Seq, herr)
		}
		if computed != e.EntryHash {
			return int64(e.Seq), nil
		}
		prevHash = e.EntryHash
		prevSeq = e.Seq
	}
	if rows.Err() != nil {
		return -1, rows.Err()
	}
	return -1, nil
}

// Head 返回链尾摘要。
func (s *sqliteLedgerStore) Head() (LedgerHead, error) {
	var head LedgerHead
	err := s.db.QueryRow(`SELECT seq, entry_hash, updated_at FROM billing_ledger_head WHERE id = 1`).
		Scan(&head.Seq, &head.EntryHash, &head.UpdatedAt)
	if err != nil {
		return LedgerHead{}, fmt.Errorf("billing: get head: %w", err)
	}
	return head, nil
}

// ReproduceHead 重放某租户某周期条目，校验链尾是否等于 want。
// period: "2006-01-02"（日）或 "2006-01"（月，用 day LIKE 'YYYY-MM%'）。
func (s *sqliteLedgerStore) ReproduceHead(tenant, period, want string) bool {
	if tenant == "" || period == "" || want == "" {
		return false
	}
	var dayCond string
	var args []interface{}
	args = append(args, tenant)
	if len(period) == 7 { // YYYY-MM
		dayCond = ` AND day LIKE ?`
		args = append(args, period+"%")
	} else {
		dayCond = ` AND day = ?`
		args = append(args, period)
	}
	rows, err := s.db.Query(
		`SELECT seq, tenant_id, model_key, day, tokens_in, tokens_out, requests,
		 retry_toks, std_in, std_out, source, price_ver, event_key, prev_hash, entry_hash, created_at
		 FROM billing_ledger WHERE tenant_id = ?`+dayCond+` ORDER BY seq ASC`,
		args...)
	if err != nil {
		return false
	}
	defer rows.Close()

	var lastHash string
	var lastSeq uint64
	for rows.Next() {
		var e LedgerEntry
		rows.Scan(&e.Seq, &e.TenantID, &e.ModelKey, &e.Day,
			&e.TokensIn, &e.TokensOut, &e.Requests, &e.RetryToks,
			&e.StdIn, &e.StdOut, &e.Source, &e.PriceVer,
			&e.EventKey, &e.PrevHash, &e.EntryHash, &e.CreatedAt)
		lastHash = e.EntryHash
		lastSeq = e.Seq
	}
	_ = lastSeq
	return lastHash == want
}

// PollWatermark 读取拉取水位（★ BUG-001）。
func (s *sqliteLedgerStore) PollWatermark() (int64, error) {
	var ns int64
	if err := s.db.QueryRow(`SELECT poll_end_ns FROM billing_ledger_head WHERE id = 1`).Scan(&ns); err != nil {
		return 0, fmt.Errorf("billing: get poll watermark: %w", err)
	}
	return ns, nil
}

// SetPollWatermark 持久化拉取水位（★ BUG-001：成功入账后推进，供重启恢复游标）。
func (s *sqliteLedgerStore) SetPollWatermark(ns int64) error {
	if _, err := s.db.Exec(`UPDATE billing_ledger_head SET poll_end_ns = ? WHERE id = 1`, ns); err != nil {
		return fmt.Errorf("billing: set poll watermark: %w", err)
	}
	return nil
}

// CountSource 统计某租户某来源在 [fromNs,toNs] 创建时间区间内的条目数（P2-5 job 对账）。
func (s *sqliteLedgerStore) CountSource(ctx context.Context, tenant, source string, fromNs, toNs int64) (int64, error) {
	if tenant == "" || source == "" {
		return 0, fmt.Errorf("billing: CountSource requires tenant and source")
	}
	q := `SELECT COUNT(*) FROM billing_ledger WHERE tenant_id = ? AND source = ? AND created_at >= ? AND created_at <= ?`
	var n int64
	if err := s.db.QueryRowContext(ctx, q, tenant, source, fromNs, toNs).Scan(&n); err != nil {
		return 0, fmt.Errorf("billing: count source: %w", err)
	}
	return n, nil
}
