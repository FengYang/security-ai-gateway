// notify.go — P0-3 Token 计费体系：余额告警通知（S-7，§6.11）。
//
// 通知器以 `periodKey` 幂等（B-6.11-1：同租户同周期只告警一次），去重状态**持久化**
// （重启后不重复告警）。实际交付（邮件/Webhook）经可选 sink；未配置 sink 时仅本地日志
// ——外部告警由 Prometheus 规则 `BillingQuotaLow` 依指标 #12 触发（§9.3）。
package billing

import (
	"database/sql"
	"fmt"
	"log"
)

// Notifier 计费域通知器（§4.1.x / §6.11）。
type Notifier interface {
	// WarnQuotaLow 配额剩余过低告警；periodKey 幂等（同键仅发送一次）。
	WarnQuotaLow(tenant string, rem float64, periodKey string) error
}

// QuotaAlertStore 配额告警去重存储（periodKey 幂等，B-6.11-1）。
type QuotaAlertStore interface {
	// MarkIfNew 标记 (tenant, periodKey) 已告警；返回 true 表示首次（应发送）。
	MarkIfNew(tenant, periodKey string, at int64) (bool, error)
}

// ensureQuotaAlertSchema 确保 quota_alerts 表存在。
func ensureQuotaAlertSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS quota_alerts (
  tenant_id  TEXT NOT NULL,
  period_key TEXT NOT NULL,
  alerted_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, period_key)
);`)
	return err
}

type sqliteQuotaAlertStore struct {
	db *sql.DB
}

// MarkIfNew 首次插入成功 → true；已存在（本周期已告警）→ false。
func (s *sqliteQuotaAlertStore) MarkIfNew(tenant, periodKey string, at int64) (bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO quota_alerts (tenant_id, period_key, alerted_at)
		VALUES (?, ?, ?)`, tenant, periodKey, at)
	if err != nil {
		return false, fmt.Errorf("billing: quota alert mark: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// QuotaNotifier 默认通知器：去重（QuotaAlertStore）后经 sink 交付；sink=nil 仅本地日志。
type QuotaNotifier struct {
	store QuotaAlertStore
	sink  func(tenant string, rem float64, periodKey string) // 可选：邮件/Webhook 交付
	now   func() int64
}

// NewQuotaNotifier 构造通知器。sink 可为 nil（仅日志）。
func NewQuotaNotifier(store QuotaAlertStore,
	sink func(tenant string, rem float64, periodKey string), now func() int64) *QuotaNotifier {
	if now == nil {
		now = func() int64 { return 0 }
	}
	return &QuotaNotifier{store: store, sink: sink, now: now}
}

// WarnQuotaLow 实现 Notifier：同 (tenant, periodKey) 仅发送一次（B-6.11-1）。
func (n *QuotaNotifier) WarnQuotaLow(tenant string, rem float64, periodKey string) error {
	if n.store != nil {
		first, err := n.store.MarkIfNew(tenant, periodKey, n.now())
		if err != nil {
			return err
		}
		if !first {
			return nil // 本周期已告警 → 幂等跳过
		}
	}
	log.Printf("[billing] 余额告警 tenant=%s period=%s remaining=%.3f", tenant, periodKey, rem)
	if n.sink != nil {
		n.sink(tenant, rem, periodKey)
	}
	return nil
}
