// notify.go — P0-3 Token 计费体系：余额告警通知（S-7，§6.11）。
//
// 通知器以 `periodKey` 幂等（B-6.11-1：同租户同周期只告警一次），去重状态**持久化**
// （重启后不重复告警）。实际交付（邮件/Webhook）经可选 sink；未配置 sink 时仅本地日志
// ——外部告警由 Prometheus 规则 `BillingQuotaLow` 依指标 #12 触发（§9.3）。
package billing

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// Notifier 计费域通知器（§4.1.x / §6.11）。
type Notifier interface {
	// WarnQuotaLow 配额剩余过低告警；periodKey 幂等（同键仅发送一次）。
	WarnQuotaLow(tenant string, rem float64, periodKey string) error
}

// AlertStore 告警去重存储（(tenant, key) 幂等）。
// 供 S-7 余额告警（key=月周期 "YYYY-MM"）与 S-9 到期提醒（key=expiry:<到期时间>:<阈值>）复用。
type AlertStore interface {
	// MarkIfNew 标记 (tenant, key) 已告警；返回 true 表示首次（应发送）。
	MarkIfNew(tenant, key string, at int64) (bool, error)
}

// ensureAlertSchema 确保 alert_dedup 表存在（通用告警去重）。
func ensureAlertSchema(db *sql.DB) error {
	_, err := db.Exec(`
CREATE TABLE IF NOT EXISTS alert_dedup (
  tenant_id  TEXT NOT NULL,
  dedup_key  TEXT NOT NULL,
  alerted_at INTEGER NOT NULL,
  PRIMARY KEY (tenant_id, dedup_key)
);`)
	return err
}

type sqliteAlertStore struct {
	db *sql.DB
}

// MarkIfNew 首次插入成功 → true；已存在（同键已告警）→ false。
func (s *sqliteAlertStore) MarkIfNew(tenant, key string, at int64) (bool, error) {
	res, err := s.db.Exec(`INSERT OR IGNORE INTO alert_dedup (tenant_id, dedup_key, alerted_at)
		VALUES (?, ?, ?)`, tenant, key, at)
	if err != nil {
		return false, fmt.Errorf("billing: alert mark: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// AlertEvent 告警事件（外部交付载荷，§6.11 / §6.4.2）。
type AlertEvent struct {
	Kind           string  `json:"kind"` // quota_low | plan_expiring
	Tenant         string  `json:"tenant"`
	Severity       string  `json:"severity,omitempty"`
	RemainingRatio float64 `json:"remaining_ratio,omitempty"` // quota_low
	Period         string  `json:"period,omitempty"`          // quota_low: 月周期；plan_expiring: 到期日（UTC+8）
	Days           int     `json:"days,omitempty"`            // plan_expiring: 30|7|0
}

// AlertSink 告警外部交付器（nil = 仅本地日志 + Prometheus 规则）。
type AlertSink func(event AlertEvent)

// QuotaNotifier 默认通知器：去重（AlertStore）后经 sink 交付；sink=nil 仅本地日志。
type QuotaNotifier struct {
	store AlertStore
	sink  AlertSink // 可选：邮件/Webhook 交付
	now   func() int64
}

// NewQuotaNotifier 构造通知器。sink 可为 nil（仅日志）。
func NewQuotaNotifier(store AlertStore, sink AlertSink, now func() int64) *QuotaNotifier {
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
		sev := string(SeverityWarning)
		if rem <= 0 {
			sev = string(SeverityCritical) // B-6.11-2：已耗尽 → critical
		}
		n.sink(AlertEvent{Kind: "quota_low", Tenant: tenant, RemainingRatio: rem, Period: periodKey, Severity: sev})
	}
	return nil
}

// ---------- 外部交付 sink（Webhook，§6.11 / §6.4.2） ----------

// webhookAlertSink 把告警事件 POST 到外部 Webhook（JSON）。
type webhookAlertSink struct {
	url    string
	client *http.Client
}

// NewWebhookAlertSink 构造 Webhook 交付 sink（供配额告警与到期提醒共用）。
//
// url 为空 → 返回 nil（调用方按"无外部交付"处理：仅本地日志 + Prometheus 规则）。
// 交付失败仅记日志、不向上返回错误（fire-and-forget；可靠性由 Prometheus 规则侧兜底）。
func NewWebhookAlertSink(url string, timeout time.Duration) AlertSink {
	if url == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	s := &webhookAlertSink{url: url, client: &http.Client{Timeout: timeout}}
	return s.deliver
}

func (s *webhookAlertSink) deliver(event AlertEvent) {
	body, err := json.Marshal(event)
	if err != nil {
		log.Printf("[billing] 告警 Webhook 序列化失败 tenant=%s: %v", event.Tenant, err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.client.Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(body))
	if err != nil {
		log.Printf("[billing] 告警 Webhook 构造失败 tenant=%s: %v", event.Tenant, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		log.Printf("[billing] 告警 Webhook 投递失败 tenant=%s: %v", event.Tenant, err)
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body) // 排空以复用连接
	if resp.StatusCode >= 300 {
		log.Printf("[billing] 告警 Webhook 返回 %d tenant=%s", resp.StatusCode, event.Tenant)
	}
}
