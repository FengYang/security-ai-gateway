package billing

import (
	"fmt"
	"time"
)

// ---------- 异常检测（T8，§6.9） ----------

// AnomalyKind 异常类型（A-17 枚举）。
type AnomalyKind string

const (
	KindSpike           AnomalyKind = "spike"            // 单日用量突增
	KindReconcileDiff   AnomalyKind = "reconcile_diff"   // L2 差异
	KindQuotaWarn       AnomalyKind = "quota_warn"       // 配额预警
	KindPricingMissing  AnomalyKind = "pricing_missing"  // 缺单价
	KindPlanExpired     AnomalyKind = "plan_expired"     // 套餐到期（S-9）
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

// AnomalyDetector 异常检测器（S-5）。
type AnomalyDetector struct {
	ledger *sqliteLedgerStore
	cfg    AnomalyConfig
}

// NewAnomalyDetector 构造检测器。
func NewAnomalyDetector(ledger *sqliteLedgerStore, cfg AnomalyConfig) *AnomalyDetector {
	if cfg.DailySpikeRatio <= 0 {
		cfg.DailySpikeRatio = 3.0
	}
	if cfg.SpikeCriticalRatio <= 0 {
		cfg.SpikeCriticalRatio = 10.0
	}
	return &AnomalyDetector{ledger: ledger, cfg: cfg}
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
		IncAnomaly(string(KindSpike), string(SeverityCritical)) // 指标 #10
		return &Anomaly{Tenant: tenant, Kind: KindSpike, Severity: SeverityCritical,
			Day: day, Ratio: ratio,
			Detail: fmt.Sprintf("today=%d avg=%.0f ratio=%.2f", today, avg, ratio)}, nil
	}
	if ratio > d.cfg.DailySpikeRatio {
		IncAnomaly(string(KindSpike), string(SeverityWarning)) // 指标 #10
		return &Anomaly{Tenant: tenant, Kind: KindSpike, Severity: SeverityWarning,
			Day: day, Ratio: ratio,
			Detail: fmt.Sprintf("today=%d avg=%.0f ratio=%.2f", today, avg, ratio)}, nil
	}
	return nil, nil
}

// ScanQuotaWarn 配额预警（§6.9.1 ③）：剩余比例 < quota_warn_ratio → warning。
func (d *AnomalyDetector) ScanQuotaWarn(tenant, day string, used, limit int64) *Anomaly {
	if limit <= 0 {
		return nil
	}
	remaining := limit - used
	if remaining < 0 {
		remaining = 0
	}
	ratio := float64(remaining) / float64(limit)
	if ratio < d.cfg.QuotaWarnRatio {
		return &Anomaly{Tenant: tenant, Kind: KindQuotaWarn, Severity: SeverityWarning,
			Day: day, Ratio: ratio,
			Detail: fmt.Sprintf("remaining_ratio=%.3f", ratio)}
	}
	return nil
}

// PricingMissing 缺单价异常（供 Rate 失败时构造）。
func PricingMissing(tenant, modelKey string) Anomaly {
	return Anomaly{Tenant: tenant, Kind: KindPricingMissing, Severity: SeverityCritical,
		Detail: fmt.Sprintf("model=%s", modelKey)}
}
