package billing

import (
	"fmt"
	"log"
	"time"
)

// ---------- 异常检测（T8，§6.9） ----------

// AnomalyKind 异常类型（A-17 枚举）。
type AnomalyKind string

const (
	KindSpike          AnomalyKind = "spike"           // 单日用量突增
	KindReconcileDiff  AnomalyKind = "reconcile_diff"  // L2 差异
	KindQuotaWarn      AnomalyKind = "quota_warn"      // 配额预警
	KindPricingMissing AnomalyKind = "pricing_missing" // 缺单价
	KindPlanExpired    AnomalyKind = "plan_expired"    // 套餐到期（S-9）
)

// Severity 严重级。
type Severity string

const (
	SeverityWarning  Severity = "warning"
	SeverityCritical Severity = "critical"
)

// Anomaly 单条异常。
type Anomaly struct {
	Tenant   string      `json:"tenant"`
	Kind     AnomalyKind `json:"kind"`
	Severity Severity    `json:"severity"`
	Day      string      `json:"day,omitempty"`
	Ratio    float64     `json:"ratio,omitempty"`
	Detail   string      `json:"detail,omitempty"`
}

// FreezeLinker 冻结联动接口（§6.10；由 *FreezeController 实现）。
type FreezeLinker interface {
	Frozen(tenant string) (bool, error)
	Freeze(tenant, reason, severity, by string) error
	Unfreeze(tenant, by string) error
	// ListFrozen 返回当前生效的冻结记录（供自动解冻枚举，B-6.10-2）。
	ListFrozen() ([]FreezeRecord, error)
}

// AnomalyDetector 异常检测器（S-5，§6.9）。
type AnomalyDetector struct {
	ledger *sqliteLedgerStore
	cfg    AnomalyConfig

	// 可选依赖：nil 时跳过对应规则（① spike 仅需 ledger）。
	plans      PlanStore          // ③ 配额预警
	prices     PriceTableProvider // ④ 单价缺失
	reconciler *Reconciler        // ② L2 对账差异（L2 未接入时 nil）
	now        func() int64       // 套餐解析时间（默认 time.Now）
	freeze     FreezeLinker       // 冻结联动（§6.10.1；nil = 不联动）
}

// SetFreezeLinker 注入冻结联动执行者（§6.10.1）。
func (d *AnomalyDetector) SetFreezeLinker(f FreezeLinker) { d.freeze = f }

// withDefaults 补齐各阈值缺省值（与配置默认一致，§4.2）。
func (d *AnomalyDetector) withDefaults() *AnomalyDetector {
	if d.cfg.DailySpikeRatio <= 0 {
		d.cfg.DailySpikeRatio = 3.0
	}
	if d.cfg.SpikeCriticalRatio <= 0 {
		d.cfg.SpikeCriticalRatio = 10.0
	}
	if d.cfg.ReconcileAlertRatio <= 0 {
		d.cfg.ReconcileAlertRatio = 0.001
	}
	if d.cfg.QuotaWarnRatio <= 0 {
		d.cfg.QuotaWarnRatio = 0.2
	}
	if d.now == nil {
		d.now = func() int64 { return time.Now().UnixNano() }
	}
	return d
}

// NewAnomalyDetector 构造仅含账本的检测器（① spike；②/③/④ 跳过）。
func NewAnomalyDetector(ledger *sqliteLedgerStore, cfg AnomalyConfig) *AnomalyDetector {
	return (&AnomalyDetector{ledger: ledger, cfg: cfg}).withDefaults()
}

// NewAnomalyDetectorForStore 构造绑定 Store 的检测器（供 S-5 调度接线，§6.9.1 四类规则）。
//
// prices 为单价表提供器（nil = 跳过 ④）；rec 为 L2 对账器（nil = 跳过 ②，L2 未接入时）。
func NewAnomalyDetectorForStore(store Store, prices PriceTableProvider, rec *Reconciler,
	cfg AnomalyConfig, now func() int64) *AnomalyDetector {
	d := &AnomalyDetector{prices: prices, reconciler: rec, now: now}
	if store != nil {
		if l, ok := store.Ledger().(*sqliteLedgerStore); ok {
			d.ledger = l
		}
		d.plans = store.Plans()
	}
	return d.withDefaults()
}

// Tenants 返回账本中出现过的租户（供 S-5 任务枚举，§6.16）。
func (d *AnomalyDetector) Tenants() ([]string, error) {
	if d.ledger == nil {
		return nil, nil
	}
	return d.ledger.Tenants()
}

// Scan 执行 §6.9.1 四类异常检测（S-5）。
//
//	① spike：当日 > 前 7 日均值 × spike_ratio（A-36 样本 <3 天不判）
//	② reconcile_diff：L2 差异率 > 0（依赖 reconciler）
//	③ quota_warn：剩余比 < quota_warn_ratio（依赖 plans；并回填指标 #12）
//	④ pricing_missing：当日出现过单价表未知的 modelKey（依赖 prices）
//
// 指标 #10 anomaly_total 的**唯一生产者**＝本方法返回点（逐条发射，★ O-8）。
func (d *AnomalyDetector) Scan(tenants []string, day string) []Anomaly {
	var out []Anomaly
	for _, t := range tenants {
		if a, err := d.ScanSpike(t, day); err == nil && a != nil {
			out = append(out, *a)
		}
		if a := d.scanReconcile(t, day); a != nil {
			out = append(out, *a)
		}
		if a := d.scanQuota(t, day); a != nil {
			out = append(out, *a)
		}
		out = append(out, d.scanPricingMissing(t, day)...)
	}
	for _, a := range out {
		IncAnomaly(string(a.Kind), string(a.Severity)) // 指标 #10（统一出口）
	}
	return out
}

// ApplyFreezes 对 critical 异常执行冻结联动（§6.10.1）：
// kind ∈ {spike, reconcile_diff, pricing_missing} 且 severity=critical → 冻结（by="system"）。
// 已冻结者跳过（保留首次 reason，B-6.10-1）；`plan_expired` 不冻结（§6.4.2 不自动降级）。
// 返回本次新冻结的租户数。未注入 FreezeLinker 时 no-op。
func (d *AnomalyDetector) ApplyFreezes(anomalies []Anomaly) int {
	if d.freeze == nil {
		return 0
	}
	n := 0
	for _, a := range anomalies {
		if a.Severity != SeverityCritical || !freezeTriggerKind(a.Kind) {
			continue
		}
		already, err := d.freeze.Frozen(a.Tenant)
		if err != nil {
			log.Printf("[billing] 冻结联动判定失败 tenant=%s: %v", a.Tenant, err)
			continue
		}
		if already {
			continue // 已冻结 → 不重复冻结（保留首次原因，B-6.10-1）
		}
		if err := d.freeze.Freeze(a.Tenant, string(a.Kind), string(SeverityCritical), "system"); err != nil {
			log.Printf("[billing] 冻结联动失败 tenant=%s kind=%s: %v", a.Tenant, a.Kind, err)
			continue
		}
		n++
	}
	return n
}

// freezeTriggerKind 触发自动冻结的异常类型（§6.10.1）。
func freezeTriggerKind(k AnomalyKind) bool {
	switch k {
	case KindSpike, KindReconcileDiff, KindPricingMissing:
		return true
	}
	return false
}

// SyncFrozenGauge 以冻结存储为准回填 gateway_admin_billing_frozen（#24）。
//
// 进程重启后 gauge 归零（且历史冻结仍在 DB），本方法在每个扫描周期把「当前生效冻结」重新置 1；
// 解冻路径（FreezeController.Unfreeze）已置 0。未注入 FreezeLinker 时 no-op。
func (d *AnomalyDetector) SyncFrozenGauge() {
	if d.freeze == nil {
		return
	}
	recs, err := d.freeze.ListFrozen()
	if err != nil {
		return
	}
	for _, r := range recs {
		SetFrozen(r.TenantID, true)
	}
}

// AutoUnfreeze 对「由 reconcile_diff 触发」且对账已恢复（L2 Pass）的冻结执行自动解冻（B-6.10-2）。
//
// 仅 `reconcile_diff` 触发者可自动解冻；`manual`/`pricing_missing` 等**不**自动解冻（须人工）。
// 返回本次解冻的租户数。未注入 FreezeLinker 或 reconciler 时 no-op。
func (d *AnomalyDetector) AutoUnfreeze(day string) int {
	if d.freeze == nil || d.reconciler == nil {
		return 0
	}
	recs, err := d.freeze.ListFrozen()
	if err != nil {
		log.Printf("[billing] 自动解冻：枚举冻结失败：%v", err)
		return 0
	}
	n := 0
	for _, r := range recs {
		if r.Reason != string(KindReconcileDiff) {
			continue // 仅 reconcile_diff 触发者可自动解冻（B-6.10-2）
		}
		res, err := d.reconciler.L2(r.TenantID, day, day)
		if err != nil {
			log.Printf("[billing] 自动解冻：对账读取失败 tenant=%s: %v", r.TenantID, err)
			continue
		}
		if !res.Pass {
			continue // 对账仍未恢复 → 保持冻结
		}
		if err := d.freeze.Unfreeze(r.TenantID, "system"); err != nil {
			log.Printf("[billing] 自动解冻失败 tenant=%s: %v", r.TenantID, err)
			continue
		}
		n++
	}
	return n
}

// scanReconcile ② L2 对账差异（§6.9.1 ②）。
func (d *AnomalyDetector) scanReconcile(tenant, day string) *Anomaly {
	if d.reconciler == nil {
		return nil
	}
	res, err := d.reconciler.L2(tenant, day, day)
	if err != nil || res.Ratio <= 0 {
		return nil
	}
	return &Anomaly{Tenant: tenant, Kind: KindReconcileDiff,
		Severity: severityOf(res.Ratio, d.cfg.ReconcileAlertRatio),
		Day:      day, Ratio: res.Ratio,
		Detail: fmt.Sprintf("diff=%d ratio=%.6f", res.Diff, res.Ratio)}
}

// scanQuota ③ 配额预警（§6.9.1 ③）；回填指标 #12 quota_remaining_ratio（不限于低于阈值）。
func (d *AnomalyDetector) scanQuota(tenant, day string) *Anomaly {
	ratio, ok := d.QuotaRemaining(tenant, day)
	if !ok {
		return nil
	}
	SetQuotaRemainingRatio(tenant, ratio) // 指标 #12（O-8 唯一生产者）
	return d.quotaWarnAnomaly(tenant, day, ratio)
}

// QuotaRemaining 某租户当月（截至 day）配额剩余比；无套餐/不限量 → ok=false（B-6.11-3）。
// 供 S-5 规则③ 与 S-7 余额告警复用。
func (d *AnomalyDetector) QuotaRemaining(tenant, day string) (float64, bool) {
	if d.plans == nil || d.ledger == nil || len(day) < 7 {
		return 0, false
	}
	plan, err := d.plans.Resolve(tenant, d.now())
	if err != nil || plan == nil || plan.MonthlyTokens <= 0 {
		return 0, false // 无套餐 / 不限量 → 不告警（B-6.11-3）
	}
	used, err := d.monthStdUsed(tenant, day)
	if err != nil {
		return 0, false
	}
	remaining := plan.MonthlyTokens - used
	if remaining < 0 {
		remaining = 0
	}
	return float64(remaining) / float64(plan.MonthlyTokens), true
}

// QuotaWarnThreshold 配额告警阈值（quota_warn_ratio，R-21；供 S-7 复用）。
func (d *AnomalyDetector) QuotaWarnThreshold() float64 { return d.cfg.QuotaWarnRatio }

// quotaWarnAnomaly 按剩余比生成配额预警：≥ 阈值 → nil；已耗尽（rem=0）→ critical（B-6.11-2）。
func (d *AnomalyDetector) quotaWarnAnomaly(tenant, day string, ratio float64) *Anomaly {
	if ratio >= d.cfg.QuotaWarnRatio {
		return nil
	}
	sev := SeverityWarning
	if ratio <= 0 {
		sev = SeverityCritical // B-6.11-2：已耗尽 → critical
	}
	return &Anomaly{Tenant: tenant, Kind: KindQuotaWarn, Severity: sev,
		Day: day, Ratio: ratio,
		Detail: fmt.Sprintf("remaining_ratio=%.3f", ratio)}
}

// scanPricingMissing ④ 单价缺失（§6.9.1 ④）。
func (d *AnomalyDetector) scanPricingMissing(tenant, day string) []Anomaly {
	if d.prices == nil || d.ledger == nil {
		return nil
	}
	tbl := d.prices.Current()
	if tbl == nil {
		return nil
	}
	entries, err := d.ledger.Range(LedgerQuery{TenantID: tenant, DayFrom: day, DayTo: day})
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []Anomaly
	for _, e := range entries {
		if e.ModelKey == "__retry__" || seen[e.ModelKey] {
			continue // retry 聚合行无计价需求
		}
		seen[e.ModelKey] = true
		if _, ok := tbl.ModelPriceOf(e.ModelKey); !ok {
			out = append(out, PricingMissing(tenant, e.ModelKey))
		}
	}
	return out
}

// monthStdUsed 某租户当月（自然月）截至 day（含）的标准 token 合计（std_in+std_out）。
func (d *AnomalyDetector) monthStdUsed(tenant, day string) (int64, error) {
	totals, err := d.ledger.DailyStdTotals(tenant, day[:7]+"-01", day)
	if err != nil {
		return 0, err
	}
	var sum int64
	for _, v := range totals {
		sum += v
	}
	return sum, nil
}

// severityOf 按临界阈值分级：> threshold → critical；否则 warning（A-25 同维度阈值）。
func severityOf(ratio, criticalThreshold float64) Severity {
	if ratio > criticalThreshold {
		return SeverityCritical
	}
	return SeverityWarning
}

// ScanSpike 单日用量突增检测（§6.9.1 ①）。
//
// 规则（A-36/B-6.9-5）：
//   - 比较基准 = 前 7 日日均（不含当日）
//   - 有效基准日数 < 3 → 不告警（新租户保护）
//   - ratio > spike_critical_ratio → critical（可冻结，A-25）
//   - ratio > daily_spike_ratio → warning（不冻结）
func (d *AnomalyDetector) ScanSpike(tenant, day string) (*Anomaly, error) {
	t, err := time.Parse(dayLayout, day)
	if err != nil {
		return nil, fmt.Errorf("billing: scan spike: bad day %q: %w", day, err)
	}
	from := t.AddDate(0, 0, -7).Format(dayLayout)
	totals, err := d.ledger.DailyStdTotals(tenant, from, day)
	if err != nil {
		return nil, err
	}
	today := totals[day]
	if today <= 0 {
		return nil, nil // 当日无用量 → 不告警
	}
	// 前 7 日（不含当日）
	var sum int64
	var n int
	for i := 1; i <= 7; i++ {
		pd := t.AddDate(0, 0, -i).Format(dayLayout)
		if v, ok := totals[pd]; ok && v > 0 {
			sum += v
			n++
		}
	}
	if n < 3 {
		return nil, nil // 有效基准日 < 3 → 新租户保护，不告警
	}
	avg := float64(sum) / float64(n)
	if avg <= 0 {
		return nil, nil // 除零保护
	}
	ratio := float64(today) / avg
	if ratio > d.cfg.SpikeCriticalRatio {
		return &Anomaly{Tenant: tenant, Kind: KindSpike, Severity: SeverityCritical,
			Day: day, Ratio: ratio,
			Detail: fmt.Sprintf("today=%d avg=%.0f ratio=%.2f", today, avg, ratio)}, nil
	}
	if ratio > d.cfg.DailySpikeRatio {
		return &Anomaly{Tenant: tenant, Kind: KindSpike, Severity: SeverityWarning,
			Day: day, Ratio: ratio,
			Detail: fmt.Sprintf("today=%d avg=%.0f ratio=%.2f", today, avg, ratio)}, nil
	}
	return nil, nil
}

// ScanQuotaWarn 配额预警（§6.9.1 ③）：剩余比例 < quota_warn_ratio → 告警
// （已耗尽 rem=0 → critical，B-6.11-2）。
func (d *AnomalyDetector) ScanQuotaWarn(tenant, day string, used, limit int64) *Anomaly {
	if limit <= 0 {
		return nil
	}
	remaining := limit - used
	if remaining < 0 {
		remaining = 0
	}
	return d.quotaWarnAnomaly(tenant, day, float64(remaining)/float64(limit))
}

// PricingMissing 缺单价异常（供 Rate 失败时构造）。
func PricingMissing(tenant, modelKey string) Anomaly {
	return Anomaly{Tenant: tenant, Kind: KindPricingMissing, Severity: SeverityCritical,
		Detail: fmt.Sprintf("model=%s", modelKey)}
}
