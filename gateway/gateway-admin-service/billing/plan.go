package billing

// ---------- 套餐类型（T1，§4.1.2） ----------

// Plan 套餐定义。
type Plan struct {
	ID            string       `json:"id"`
	Name          string       `json:"name"`
	MonthlyTokens int64        `json:"monthly_tokens"` // 标准 token 月配额（<=0 = 不限/定制）
	Concurrency   int          `json:"concurrency"`
	CacheTier     string       `json:"cache_tier"`   // none | exact | semantic
	ModelScopes   []string     `json:"model_scopes"` // 允许模型白名单（空 = 全部）
	OverQuota     string       `json:"over_quota"`   // reject | degrade | charge
	PriceID       string       `json:"price_id"`
	ExtraLimits   []QuotaLimit `json:"extra_limits,omitempty"`
	PayMode       string       `json:"pay_mode"` // postpaid（P0 仅此值）
	Version       int64        `json:"version"`
}

// QuotaLimit 单维度配额（复用 ratelimit 语义，window 同口径：""=累计 / "minute" / "day" / "month"）。
type QuotaLimit struct {
	Window    string `json:"window,omitempty"`
	MaxTokens int64  `json:"max_tokens"`
}

// Subscription 租户套餐绑定。
type Subscription struct {
	TenantID    string `json:"tenant"`
	PlanID      string `json:"plan_id"`
	EffectiveAt int64  `json:"effective_at"` // UTC 纳秒
	ExpiresAt   int64  `json:"expires_at"`   // 0 = 不过期
	BoundBy     string `json:"bound_by"`
	BoundAt     int64  `json:"bound_at"`
}

// PlanStore 套餐与订阅存储接口。
type PlanStore interface {
	GetPlan(planID string) (*Plan, error)
	PutPlan(p *Plan) error
	ListPlans() ([]Plan, error)
	Bind(s Subscription) error
	Resolve(tenant string, now int64) (*Plan, error)
	// ListSubscriptions 返回 effective_at <= now 的全部订阅（按 effective_at 升序）。
	// 供到期扫描（S-9）：Resolve 会滤除已过期项，无法用于到期检测，故需此枚举。
	ListSubscriptions(now int64) ([]Subscription, error)
}
