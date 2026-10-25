package billing

import (
	"fmt"
	"sort"
)

// ---------- 集群维度 cluster_id（R-4 / A5(6)，P2-4 T-1.8）----------
//
// # 口径（务必遵守，违反即破坏性升级 §7.6）
//
// cluster_id 是**证据列 / 聚合维度**，用于跨集群对账与中央可观测：
//   - 它**不进**账本哈希域（ComputeEntryHash 的规范载荷字段顺序已冻结）；
//   - 它**不进**账单签名域（canonicalBill 已冻结，§7.2）。
//
// 因此：给既有条目"补打标"或"去掉标"，既有 entry_hash 与账单 sig **保持不变**，
// 账本链 Verify() 与账单验签均不受影响（与审计链 dual_approval_ids 同款做法）。
//
// 空串 "" 是合法取值：单集群部署 / 计量侧未上报 / 跨集群混合账单。
// 聚合时未打标数据归入 "" 一组，**不丢不重**。

// retryModelKey 重试聚合行的模型键（平台成本，无计价需求；计价路径须排除）。
const retryModelKey = "__retry__"

// ClusterUsage 单集群维度的用量/金额聚合（跨集群对账、中央可观测）。
//
// Amount 由 BillingService.ClusterUsageReport 填充（逐集群独立计价）；
// 直接调用 LedgerStore.SumByCluster 时 Amount 恒为 0（存储层不做计价）。
type ClusterUsage struct {
	ClusterID string               `json:"cluster_id"` // "" = 未打标组
	TokensIn  int64                `json:"tokens_in"`
	TokensOut int64                `json:"tokens_out"`
	Requests  int64                `json:"requests"`
	RetryToks int64                `json:"retry_toks"` // 平台成本，不计用户金额（M9）
	StdIn     int64                `json:"std_in"`
	StdOut    int64                `json:"std_out"`
	Entries   int64                `json:"entries"` // 账本条目数
	Amount    Amount               `json:"amount"`  // 分（计价后；未计价为 0）
	ByModel   map[string]*ModelStd `json:"by_model,omitempty"`
}

// ClusterBillTotal 单集群维度的账单金额汇总（R-4/A5(6)）。
type ClusterBillTotal struct {
	ClusterID string `json:"cluster_id"` // "" = 未打标组
	Bills     int64  `json:"bills"`      // 账单数
	Total     Amount `json:"total"`      // 金额合计（分）
}

// ---------- 账本侧：按 cluster_id 折叠与汇总 ----------

// foldEntriesByCluster 把账本条目按 cluster_id × model_key 折叠为 UsageAgg（纯函数，便于单测）。
//
// 未打标条目（ClusterID == ""）归入 "" 一组；所有条目均被计入 ⇒ 不丢不重。
func foldEntriesByCluster(entries []LedgerEntry, tenant, dayFrom, dayTo string) map[string]*UsageAgg {
	out := make(map[string]*UsageAgg)
	period := dayFrom
	if dayFrom != dayTo {
		// 与 FoldByModel 同口径：跨日区间 → 月粒度 "YYYY-MM"
		period = dayFrom[:minInt(len(dayFrom), 7)]
	}
	for i := range entries {
		e := &entries[i]
		agg := out[e.ClusterID]
		if agg == nil {
			agg = &UsageAgg{TenantID: tenant, Period: period, ByModel: map[string]*ModelStd{}}
			out[e.ClusterID] = agg
		}
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
	return out
}

// FoldByCluster 按 cluster_id 折叠某租户区间内的账本条目（每集群一个 UsageAgg）。
// tenant 为空 = 所有租户；dayFrom/dayTo 为闭区间（空 = 不限）。
func (s *sqliteLedgerStore) FoldByCluster(tenant, dayFrom, dayTo string) (map[string]*UsageAgg, error) {
	entries, err := s.Range(LedgerQuery{TenantID: tenant, DayFrom: dayFrom, DayTo: dayTo})
	if err != nil {
		return nil, err
	}
	return foldEntriesByCluster(entries, tenant, dayFrom, dayTo), nil
}

// SumByCluster 按 cluster_id 汇总某租户区间内的账本用量（只读，不计价）。
//
// 返回按 ClusterID 升序（确定性输出，便于断言与对账）；未打标组为 ""。
// Amount 恒为 0——存储层不做计价，需金额请用 BillingService.ClusterUsageReport。
func (s *sqliteLedgerStore) SumByCluster(tenant, dayFrom, dayTo string) ([]ClusterUsage, error) {
	q := LedgerQuery{TenantID: tenant, DayFrom: dayFrom, DayTo: dayTo}
	entries, err := s.Range(q)
	if err != nil {
		return nil, err
	}
	byCluster := foldEntriesByCluster(entries, tenant, dayFrom, dayTo)
	counts := make(map[string]int64, len(byCluster))
	for i := range entries {
		counts[entries[i].ClusterID]++
	}

	out := make([]ClusterUsage, 0, len(byCluster))
	for cid, agg := range byCluster {
		cu := ClusterUsage{ClusterID: cid, Entries: counts[cid], ByModel: agg.ByModel}
		for _, mu := range agg.ByModel {
			cu.TokensIn += mu.TokensIn
			cu.TokensOut += mu.TokensOut
			cu.Requests += mu.Requests
			cu.RetryToks += mu.RetryToks
			cu.StdIn += mu.StdIn
			cu.StdOut += mu.StdOut
		}
		out = append(out, cu)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ClusterID < out[j].ClusterID })
	return out, nil
}

// ClustersInRange 返回某租户区间内出现过的 cluster_id（去重升序；"" 代表未打标）。
// 供出账时推导账单的集群标签（便宜：走 idx_ledger_cluster_day 的 DISTINCT）。
func (s *sqliteLedgerStore) ClustersInRange(tenant, dayFrom, dayTo string) ([]string, error) {
	query := `SELECT DISTINCT cluster_id FROM billing_ledger WHERE 1=1`
	var args []interface{}
	if tenant != "" {
		query += ` AND tenant_id = ?`
		args = append(args, tenant)
	}
	if dayFrom != "" {
		query += ` AND day >= ?`
		args = append(args, dayFrom)
	}
	if dayTo != "" {
		query += ` AND day <= ?`
		args = append(args, dayTo)
	}
	query += ` ORDER BY cluster_id`
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("billing: clusters in range: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cid string
		if err := rows.Scan(&cid); err != nil {
			return nil, err
		}
		out = append(out, cid)
	}
	return out, rows.Err()
}

// ---------- 账单侧：按 cluster_id 汇总金额 ----------

// SumByCluster 按 cluster_id 汇总账单金额（只读）。
// 返回按 ClusterID 升序；未打标/混合账单归入 "" 组。
func (s *sqliteBillStore) SumByCluster(q BillQuery) ([]ClusterBillTotal, error) {
	query := `SELECT cluster_id, COUNT(*), COALESCE(SUM(total),0) FROM bills WHERE 1=1`
	var args []interface{}
	if q.TenantID != "" {
		query += ` AND tenant_id = ?`
		args = append(args, q.TenantID)
	}
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
	query += ` GROUP BY cluster_id ORDER BY cluster_id`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("billing: sum bills by cluster: %w", err)
	}
	defer rows.Close()
	var out []ClusterBillTotal
	for rows.Next() {
		var ct ClusterBillTotal
		var total int64
		if err := rows.Scan(&ct.ClusterID, &ct.Bills, &total); err != nil {
			return nil, err
		}
		ct.Total = Amount(total)
		out = append(out, ct)
	}
	return out, rows.Err()
}

// ---------- 服务层入口（供跨集群对账 / 中央可观测调用）----------

// clusterLedger 账本集群聚合能力（可选接口探测，避免破坏 LedgerStore 可替换性）。
type clusterLedger interface {
	FoldByCluster(tenant, dayFrom, dayTo string) (map[string]*UsageAgg, error)
	SumByCluster(tenant, dayFrom, dayTo string) ([]ClusterUsage, error)
	ClustersInRange(tenant, dayFrom, dayTo string) ([]string, error)
}

// clusterBillSummer 账单集群汇总能力（可选接口探测）。
type clusterBillSummer interface {
	SumByCluster(q BillQuery) ([]ClusterBillTotal, error)
}

// ClusterUsageReport 按 cluster_id 维度汇总某租户区间内的**用量与金额**（R-4/A5(6)）。
//
// 口径：
//   - 未打标条目归入 "" 一组，不丢不重（各组 TokensIn 之和 = 全量 SumNet 之和）；
//   - 金额按各集群自身的 UsageAgg **独立计价**（月累计起点由计价引擎按 period 决定）；
//     重试聚合行 `__retry__` 无计价需求，计价时排除（与入账路径同口径）；
//   - 只读：不写账本、不触发链校验、不改变任何既有状态。
//
// 未配置计价引擎或价格表时，仅返回用量维度（Amount 保持 0）。
func (s *BillingService) ClusterUsageReport(tenant, dayFrom, dayTo string) ([]ClusterUsage, error) {
	ls, ok := s.store.Ledger().(clusterLedger)
	if !ok {
		return nil, fmt.Errorf("billing: ledger store does not support cluster aggregation")
	}
	out, err := ls.SumByCluster(tenant, dayFrom, dayTo)
	if err != nil {
		return nil, err
	}
	if s.rating == nil || s.prices == nil {
		return out, nil
	}
	tbl := s.prices.Current()
	if tbl == nil {
		return out, nil
	}
	folds, err := ls.FoldByCluster(tenant, dayFrom, dayTo)
	if err != nil {
		return nil, err
	}
	for i := range out {
		agg := folds[out[i].ClusterID]
		if agg == nil {
			continue
		}
		rateable := rateableClusterAgg(agg)
		if rateable == nil {
			continue // 仅重试行（平台成本）或无用量 ⇒ 金额 0
		}
		amt, err := s.rating.Rate(rateable, tbl)
		if err != nil {
			return nil, fmt.Errorf("billing: cluster %q 计价失败: %w", out[i].ClusterID, err)
		}
		out[i].Amount = amt
	}
	return out, nil
}

// ClusterBillTotals 按 cluster_id 维度汇总账单金额（R-4/A5(6)）。
func (s *BillingService) ClusterBillTotals(q BillQuery) ([]ClusterBillTotal, error) {
	bs, ok := s.store.Bills().(clusterBillSummer)
	if !ok {
		return nil, fmt.Errorf("billing: bill store does not support cluster aggregation")
	}
	return bs.SumByCluster(q)
}

// rateableClusterAgg 构造可计价的集群子聚合：剔除 `__retry__`（平台成本，无计价需求）。
// 全部为重试行或无模型维度时返回 nil（金额按 0 处理）。
func rateableClusterAgg(agg *UsageAgg) *UsageAgg {
	if agg == nil || len(agg.ByModel) == 0 {
		return nil
	}
	sub := &UsageAgg{TenantID: agg.TenantID, Period: agg.Period, ByModel: map[string]*ModelStd{}}
	for mk, mu := range agg.ByModel {
		if mk == retryModelKey {
			continue
		}
		sub.ByModel[mk] = mu
	}
	if len(sub.ByModel) == 0 {
		return nil
	}
	return sub
}

// clusterOfPeriod 推导某租户某周期账单的集群标签（出账时打标）。
//
// 规则：周期内该租户账本条目**唯一**集群标签才打标；
// 未打标（全空）、跨集群混合或无条目 ⇒ ""（混合场景须用 ClusterUsageReport 拆分）。
func (s *BillingService) clusterOfPeriod(tenant, dayFrom, dayTo string) string {
	ls, ok := s.store.Ledger().(clusterLedger)
	if !ok {
		return ""
	}
	ids, err := ls.ClustersInRange(tenant, dayFrom, dayTo)
	if err != nil || len(ids) != 1 {
		return ""
	}
	return ids[0]
}
