package billing

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ---------- PlanStore SQLite 实现（T1，§4.1.2 / §5.2） ----------

// sqlitePlanStore 套餐与订阅的 SQLite 存储。
type sqlitePlanStore struct {
	db *sql.DB
}

// ensurePlanSchema 确保 plans/subscriptions 表存在（由 OpenSQLiteStore 调用）。
func ensurePlanSchema(db *sql.DB) error {
	ddl := `
CREATE TABLE IF NOT EXISTS plans (
  id             TEXT PRIMARY KEY,
  name           TEXT NOT NULL,
  monthly_tokens INTEGER NOT NULL DEFAULT 0,
  concurrency    INTEGER NOT NULL DEFAULT 0,
  cache_tier     TEXT NOT NULL DEFAULT 'none',
  model_scopes   TEXT NOT NULL DEFAULT '[]',
  over_quota     TEXT NOT NULL DEFAULT 'reject',
  price_id       TEXT NOT NULL DEFAULT '',
  extra_limits   TEXT NOT NULL DEFAULT '[]',
  pay_mode       TEXT NOT NULL DEFAULT 'postpaid',
  version        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS subscriptions (
  id           INTEGER PRIMARY KEY AUTOINCREMENT,
  tenant_id    TEXT NOT NULL,
  plan_id      TEXT NOT NULL,
  effective_at INTEGER NOT NULL,
  expires_at   INTEGER NOT NULL DEFAULT 0,
  bound_by     TEXT NOT NULL,
  bound_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sub_tenant_eff ON subscriptions(tenant_id, effective_at DESC);
CREATE INDEX IF NOT EXISTS idx_sub_expires ON subscriptions(expires_at) WHERE expires_at > 0;
	`
	_, err := db.Exec(ddl)
	return err
}

func (s *sqlitePlanStore) GetPlan(planID string) (*Plan, error) {
	var p Plan
	var modelScopesJSON, extraLimitsJSON string
	err := s.db.QueryRow(`SELECT id, name, monthly_tokens, concurrency, cache_tier,
		model_scopes, over_quota, price_id, extra_limits, pay_mode, version
		FROM plans WHERE id = ?`, planID).Scan(
		&p.ID, &p.Name, &p.MonthlyTokens, &p.Concurrency, &p.CacheTier,
		&modelScopesJSON, &p.OverQuota, &p.PriceID, &extraLimitsJSON, &p.PayMode, &p.Version)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("billing: get plan: %w", err)
	}
	json.Unmarshal([]byte(modelScopesJSON), &p.ModelScopes)
	json.Unmarshal([]byte(extraLimitsJSON), &p.ExtraLimits)
	return &p, nil
}

func (s *sqlitePlanStore) PutPlan(p *Plan) error {
	if p == nil || p.ID == "" {
		return fmt.Errorf("billing: plan id is required")
	}
	modelScopesJSON, _ := json.Marshal(p.ModelScopes)
	extraLimitsJSON, _ := json.Marshal(p.ExtraLimits)
	if p.ModelScopes == nil {
		modelScopesJSON = []byte("[]")
	}
	if p.ExtraLimits == nil {
		extraLimitsJSON = []byte("[]")
	}
	if p.PayMode == "" {
		p.PayMode = "postpaid"
	}
	if p.CacheTier == "" {
		p.CacheTier = "none"
	}
	if p.OverQuota == "" {
		p.OverQuota = "reject"
	}
	if p.Version <= 0 {
		p.Version = 1
	}

	_, err := s.db.Exec(`INSERT INTO plans
		(id, name, monthly_tokens, concurrency, cache_tier, model_scopes, over_quota,
		 price_id, extra_limits, pay_mode, version)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			monthly_tokens = excluded.monthly_tokens,
			concurrency = excluded.concurrency,
			cache_tier = excluded.cache_tier,
			model_scopes = excluded.model_scopes,
			over_quota = excluded.over_quota,
			price_id = excluded.price_id,
			extra_limits = excluded.extra_limits,
			pay_mode = excluded.pay_mode,
			version = plans.version + 1`,
		p.ID, p.Name, p.MonthlyTokens, p.Concurrency, p.CacheTier,
		string(modelScopesJSON), p.OverQuota, p.PriceID, string(extraLimitsJSON),
		p.PayMode, p.Version)
	if err != nil {
		return fmt.Errorf("billing: put plan: %w", err)
	}
	return nil
}

func (s *sqlitePlanStore) ListPlans() ([]Plan, error) {
	rows, err := s.db.Query(`SELECT id, name, monthly_tokens, concurrency, cache_tier,
		model_scopes, over_quota, price_id, extra_limits, pay_mode, version FROM plans ORDER BY id`)
	if err != nil {
		return nil, fmt.Errorf("billing: list plans: %w", err)
	}
	defer rows.Close()
	var plans []Plan
	for rows.Next() {
		var p Plan
		var modelScopesJSON, extraLimitsJSON string
		err := rows.Scan(&p.ID, &p.Name, &p.MonthlyTokens, &p.Concurrency, &p.CacheTier,
			&modelScopesJSON, &p.OverQuota, &p.PriceID, &extraLimitsJSON, &p.PayMode, &p.Version)
		if err != nil {
			return nil, err
		}
		json.Unmarshal([]byte(modelScopesJSON), &p.ModelScopes)
		json.Unmarshal([]byte(extraLimitsJSON), &p.ExtraLimits)
		plans = append(plans, p)
	}
	return plans, rows.Err()
}

func (s *sqlitePlanStore) Bind(sub Subscription) error {
	if sub.TenantID == "" || sub.PlanID == "" {
		return fmt.Errorf("billing: subscription tenant_id and plan_id are required")
	}
	if sub.EffectiveAt <= 0 {
		sub.EffectiveAt = time.Now().UnixNano()
	}
	if sub.BoundAt <= 0 {
		sub.BoundAt = time.Now().UnixNano()
	}
	_, err := s.db.Exec(`INSERT INTO subscriptions
		(tenant_id, plan_id, effective_at, expires_at, bound_by, bound_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		sub.TenantID, sub.PlanID, sub.EffectiveAt, sub.ExpiresAt,
		sub.BoundBy, sub.BoundAt)
	if err != nil {
		return fmt.Errorf("billing: bind subscription: %w", err)
	}
	return nil
}

func (s *sqlitePlanStore) Resolve(tenant string, now int64) (*Plan, error) {
	if tenant == "" {
		return nil, fmt.Errorf("billing: tenant is required")
	}
	// 找 effective_at <= now 的最新一条订阅，且未过期（expires_at=0 或 expires_at > now）
	var planID string
	err := s.db.QueryRow(`SELECT plan_id FROM subscriptions
		WHERE tenant_id = ? AND effective_at <= ?
		AND (expires_at = 0 OR expires_at > ?)
		ORDER BY effective_at DESC LIMIT 1`,
		tenant, now, now).Scan(&planID)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("billing: resolve subscription: %w", err)
	}
	return s.GetPlan(planID)
}

// ListSubscriptions 返回 effective_at <= now 的全部订阅（按 effective_at 升序）。
// 供到期扫描（S-9）：Resolve 会滤除已过期项，无法用于到期检测，故需此枚举。
func (s *sqlitePlanStore) ListSubscriptions(now int64) ([]Subscription, error) {
	rows, err := s.db.Query(`SELECT tenant_id, plan_id, effective_at, expires_at, bound_by, bound_at
		FROM subscriptions WHERE effective_at <= ? ORDER BY effective_at ASC`, now)
	if err != nil {
		return nil, fmt.Errorf("billing: list subscriptions: %w", err)
	}
	defer rows.Close()
	var out []Subscription
	for rows.Next() {
		var sub Subscription
		if err := rows.Scan(&sub.TenantID, &sub.PlanID, &sub.EffectiveAt, &sub.ExpiresAt,
			&sub.BoundBy, &sub.BoundAt); err != nil {
			return nil, err
		}
		out = append(out, sub)
	}
	return out, rows.Err()
}

// ---------- 默认套餐（4 档，§4.1.3） ----------

// DefaultPlans 返回 4 档默认套餐定义（初始化时写入 DB）。
func DefaultPlans() []Plan {
	return []Plan{
		{
			ID:            "free",
			Name:          "免费版",
			MonthlyTokens: 5000000, // 5M 标准 token / 月
			Concurrency:   2,
			CacheTier:     "none",
			OverQuota:     "reject",
			PayMode:       "postpaid",
			ExtraLimits: []QuotaLimit{
				{Window: "minute", MaxTokens: 100000},
				{Window: "day", MaxTokens: 500000},
			},
		},
		{
			ID:            "basic",
			Name:          "基础版",
			MonthlyTokens: 50000000, // 50M / 月
			Concurrency:   10,
			CacheTier:     "exact",
			OverQuota:     "degrade",
			PayMode:       "postpaid",
			ExtraLimits: []QuotaLimit{
				{Window: "minute", MaxTokens: 500000},
				{Window: "day", MaxTokens: 5000000},
			},
		},
		{
			ID:            "pro",
			Name:          "专业版",
			MonthlyTokens: 500000000, // 500M / 月
			Concurrency:   50,
			CacheTier:     "semantic",
			OverQuota:     "charge",
			PayMode:       "postpaid",
			ExtraLimits: []QuotaLimit{
				{Window: "minute", MaxTokens: 2000000},
				{Window: "day", MaxTokens: 30000000},
			},
		},
		{
			ID:            "enterprise",
			Name:          "企业版",
			MonthlyTokens: 0, // 不限量（定制）
			Concurrency:   200,
			CacheTier:     "semantic",
			OverQuota:     "charge",
			PayMode:       "postpaid",
		},
	}
}

// InitDefaultPlans 将默认套餐写入 DB（幂等：已存在则跳过）。
func InitDefaultPlans(s Store) error {
	for _, p := range DefaultPlans() {
		existing, err := s.Plans().GetPlan(p.ID)
		if err != nil {
			return err
		}
		if existing != nil {
			continue // 已存在则跳过
		}
		pp := p
		if err := s.Plans().PutPlan(&pp); err != nil {
			return fmt.Errorf("init default plan %s: %w", p.ID, err)
		}
	}
	return nil
}

// ---------- 套餐校验 ----------

// ValidatePlan 校验套餐参数合法性。
func ValidatePlan(p *Plan) error {
	if p == nil {
		return fmt.Errorf("plan is nil")
	}
	if p.ID == "" {
		return fmt.Errorf("plan id is required")
	}
	if strings.ContainsAny(p.ID, " \t\n/") {
		return fmt.Errorf("plan id contains invalid characters")
	}
	if p.Name == "" {
		return fmt.Errorf("plan name is required")
	}
	if p.MonthlyTokens < 0 {
		return fmt.Errorf("monthly_tokens must be >= 0 (0 = unlimited)")
	}
	if p.Concurrency < 0 {
		return fmt.Errorf("concurrency must be >= 0")
	}
	switch p.CacheTier {
	case "none", "exact", "semantic":
	default:
		return fmt.Errorf("cache_tier must be 'none', 'exact', or 'semantic'")
	}
	switch p.OverQuota {
	case "reject", "degrade", "charge":
	default:
		return fmt.Errorf("over_quota must be 'reject', 'degrade', or 'charge'")
	}
	switch p.PayMode {
	case "postpaid":
	default:
		return fmt.Errorf("pay_mode must be 'postpaid' (P0)")
	}
	return nil
}
