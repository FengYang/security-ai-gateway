package billing

import (
	"fmt"
)

// ---------- 账本折叠与月累计（T4/T5 数据源，A-32/A-39） ----------

// FoldByModel 把账本条目按模型折叠为 UsageAgg（std 用账本锁定值，A-39）。
// dayFrom/dayTo: 闭区间（含）；空 = 不限。
func (s *sqliteLedgerStore) FoldByModel(tenant, dayFrom, dayTo string) (*UsageAgg, error) {
	q := LedgerQuery{TenantID: tenant, DayFrom: dayFrom, DayTo: dayTo}
	entries, err := s.Range(q)
	if err != nil {
		return nil, err
	}
	agg := &UsageAgg{TenantID: tenant, ByModel: map[string]*ModelStd{}}
	if dayFrom == dayTo {
		agg.Period = dayFrom // 日结算
	} else {
		agg.Period = dayFrom[:minInt(len(dayFrom), 7)] // 月结算（YYYY-MM）
	}
	for _, e := range entries {
		mu := agg.ByModel[e.ModelKey]
		if mu == nil {
			mu = &ModelStd{}
			agg.ByModel[e.ModelKey] = mu
		}
		mu.StdIn += e.StdIn
		mu.StdOut += e.StdOut
		mu.TokensIn += e.TokensIn
		mu.TokensOut += e.TokensOut
		mu.Requests += e.Requests
		mu.RetryToks += e.RetryToks
	}
	return agg, nil
}

// MonthStdBefore 实现 MonthStdProvider：读账本锁定 std 求「当月初至 period 起点前」累计（分轴，A-26）。
//   - period = "YYYY-MM"（月结）→ 起点即月初 → 返回 (0,0)
//   - period = "YYYY-MM-DD"（日结）→ 累计 [月初, period)
func (s *sqliteLedgerStore) MonthStdBefore(tenant, modelKey, period string) (int64, int64) {
	if len(period) < 7 {
		return 0, 0
	}
	month := period[:7]
	if len(period) == 7 {
		return 0, 0 // 月结：起点即月初
	}
	monthStart := month + "-01"
	if period <= monthStart {
		return 0, 0
	}
	var stdIn, stdOut int64
	err := s.db.QueryRow(`SELECT COALESCE(SUM(std_in),0), COALESCE(SUM(std_out),0)
		FROM billing_ledger
		WHERE tenant_id = ? AND model_key = ? AND day >= ? AND day < ?`,
		tenant, modelKey, monthStart, period).Scan(&stdIn, &stdOut)
	if err != nil {
		// 读失败按 0 处理（保守：计价起点归零；不阻断出账）
		return 0, 0
	}
	return stdIn, stdOut
}

// ---------- 净量查询（L2 对账用） ----------

// NetTotals 账本净量合计（tokens_in/tokens_out 剔除 retry，与审计链净量三元组同口径 A-42）。
type NetTotals struct {
	TokensIn  int64
	TokensOut int64
	RetryToks int64
	Requests  int64
}

// SumNet 汇总某租户某区间（闭区间）的账本净量。
func (s *sqliteLedgerStore) SumNet(tenant, dayFrom, dayTo string) (NetTotals, error) {
	query := `SELECT COALESCE(SUM(tokens_in),0), COALESCE(SUM(tokens_out),0),
		COALESCE(SUM(retry_toks),0), COALESCE(SUM(requests),0)
		FROM billing_ledger WHERE tenant_id = ?`
	args := []interface{}{tenant}
	if dayFrom != "" {
		query += ` AND day >= ?`
		args = append(args, dayFrom)
	}
	if dayTo != "" {
		query += ` AND day <= ?`
		args = append(args, dayTo)
	}
	var t NetTotals
	if err := s.db.QueryRow(query, args...).Scan(&t.TokensIn, &t.TokensOut, &t.RetryToks, &t.Requests); err != nil {
		return NetTotals{}, fmt.Errorf("billing: sum net: %w", err)
	}
	return t, nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DailyStdTotals 按日汇总某租户的标准 token 合计（std_in+std_out），供 spike 检测。
// 返回 map[day]total（仅含有条目的日）。
func (s *sqliteLedgerStore) DailyStdTotals(tenant, dayFrom, dayTo string) (map[string]int64, error) {
	query := `SELECT day, COALESCE(SUM(std_in),0) + COALESCE(SUM(std_out),0) AS total
		FROM billing_ledger WHERE tenant_id = ?`
	args := []interface{}{tenant}
	if dayFrom != "" {
		query += ` AND day >= ?`
		args = append(args, dayFrom)
	}
	if dayTo != "" {
		query += ` AND day <= ?`
		args = append(args, dayTo)
	}
	query += ` GROUP BY day`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("billing: daily std totals: %w", err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var day string
		var total int64
		if err := rows.Scan(&day, &total); err != nil {
			return nil, err
		}
		out[day] = total
	}
	return out, rows.Err()
}
