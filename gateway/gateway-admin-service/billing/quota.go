package billing

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"time"
)

// ---------- 配额编译（T2，§6.4） ----------
//
// 说明：gateway-core/internal/ratelimit 为 internal 包，跨目录不可导入
// （Go internal 可见性规则：仅 gateway-core 子树可导入）。故本包定义**结构等价**
// 的配额类型，JSON 线格式与 tee-infer quotaRequest / ratelimit.QuotaUpdate 一致，
// 保证下发契约不漂移。

// QuotaUpdate 配额更新（与 tee-infer quotaRequest / ratelimit.QuotaUpdate 线格式对齐）。
type QuotaUpdate struct {
	Tenant string       `json:"tenant"`
	Limits []QuotaLimit `json:"limits"`
}

// QuotaCompiler 套餐 → 配额更新编译器。
type QuotaCompiler interface {
	// Compile 把租户套餐编译为 tee-infer 配额更新（含 month 窗口主配额 + extra_limits）。
	Compile(tenant string, p *Plan) ([]QuotaUpdate, error)
}

type quotaCompiler struct{}

// NewQuotaCompiler 构造配额编译器。
func NewQuotaCompiler() QuotaCompiler { return &quotaCompiler{} }

// Compile 编译套餐为配额更新。
//
// 规则（§6.4.2 / A-33）：
//   - MonthlyTokens > 0 → 一条 window="month" 的配额（单位 = 标准 token，与计费同口径）
//   - ExtraLimits（minute/day 等）逐条附加
//   - 维度顺序规范化：""（累计）< minute < day < month（与 ratelimit windowRank 风格一致）
func (c *quotaCompiler) Compile(tenant string, p *Plan) ([]QuotaUpdate, error) {
	if tenant == "" {
		return nil, fmt.Errorf("billing: quota compile: tenant is required")
	}
	if p == nil {
		return nil, fmt.Errorf("billing: quota compile: plan is nil")
	}

	limits := make([]QuotaLimit, 0, len(p.ExtraLimits)+1)
	// 主配额：月（标准 token）；MonthlyTokens=0 表示不限量，不发月配额
	if p.MonthlyTokens > 0 {
		limits = append(limits, QuotaLimit{Window: "month", MaxTokens: p.MonthlyTokens})
	}
	// 附加维度
	for _, l := range p.ExtraLimits {
		if l.MaxTokens > 0 {
			limits = append(limits, QuotaLimit{Window: normalizeWindow(l.Window), MaxTokens: l.MaxTokens})
		}
	}

	// 规范化排序（同租户同策略集 → 同 limits 顺序，便于断言与排障）
	sort.SliceStable(limits, func(i, j int) bool {
		return windowRank(limits[i].Window) < windowRank(limits[j].Window)
	})

	return []QuotaUpdate{{Tenant: tenant, Limits: limits}}, nil
}

// windowRank 维度规范化顺序：累计 < minute < day < month。
func windowRank(window string) int {
	switch window {
	case "minute":
		return 1
	case "day":
		return 2
	case "month":
		return 3
	default: // ""（累计）
		return 0
	}
}

// normalizeWindow 归一化窗口名（空 = 累计）。
func normalizeWindow(w string) string {
	switch w {
	case "minute", "day", "month":
		return w
	default:
		return ""
	}
}

// ---------- 配额下发（T2） ----------

// QuotaApplier 配额下发器（把编译结果送到 tee-infer）。
type QuotaApplier interface {
	ApplyQuota(ctx context.Context, updates []QuotaUpdate) error
}

// httpQuotaApplier 通过 HTTP POST {base}/usage/quota 下发（管理头 X-Admin-Token）。
type httpQuotaApplier struct {
	baseURL string
	token   string
	client  *http.Client
}

// NewHTTPQuotaApplier 构造 HTTP 配额下发器；baseURL 为空返回 nil（未配置 = 不下发）。
func NewHTTPQuotaApplier(baseURL, token string, timeout time.Duration) QuotaApplier {
	if baseURL == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &httpQuotaApplier{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: timeout},
	}
}

func (a *httpQuotaApplier) ApplyQuota(ctx context.Context, updates []QuotaUpdate) error {
	for _, u := range updates {
		body, err := json.Marshal(u)
		if err != nil {
			return fmt.Errorf("billing: marshal quota: %w", err)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			a.baseURL+"/usage/quota", bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("billing: build quota req: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		if a.token != "" {
			req.Header.Set("X-Admin-Token", a.token)
		}
		resp, err := a.client.Do(req)
		if err != nil {
			return fmt.Errorf("billing: apply quota http: %w", err)
		}
		// 读取并关闭 body（连接复用）
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("billing: apply quota status %d for tenant %s", resp.StatusCode, u.Tenant)
		}
	}
	return nil
}

// ---------- 配额回读确认（P-1/M6，§6.4.1 2c） ----------

// QuotaReader 配额回读器：读 tee-infer 当前**已生效**限额（window → max_tokens）。
type QuotaReader interface {
	GetQuota(ctx context.Context, tenant string) ([]QuotaLimit, error)
}

// GetQuota 回读实现：GET {base}/usage/quota?tenant=X（§6.4.1 2c 的唯一判据来源）。
func (a *httpQuotaApplier) GetQuota(ctx context.Context, tenant string) ([]QuotaLimit, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		a.baseURL+"/usage/quota?tenant="+url.QueryEscape(tenant), nil)
	if err != nil {
		return nil, fmt.Errorf("billing: build quota readback req: %w", err)
	}
	if a.token != "" {
		req.Header.Set("X-Admin-Token", a.token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("billing: quota readback http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("billing: quota readback status %d", resp.StatusCode)
	}
	var out struct {
		Limits []QuotaLimit `json:"limits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("billing: quota readback decode: %w", err)
	}
	return out.Limits, nil
}

// ConfirmQuotaApplied 回读确认（P-1/M6）：轮询至"已生效限额 ⊇ 期望"，≤ within 返回 nil。
//
// POST /usage/quota 返回 2xx **不等于**已生效；M6 判据以本回读为唯一构造点（§6.4.1 2c）。
// 比对口径：期望集合中每条 (window,max_tokens) 均已在生效集合中（顺序无关）；期望为空视为已确认。
func ConfirmQuotaApplied(ctx context.Context, rd QuotaReader, tenant string, want []QuotaUpdate,
	within, poll time.Duration) error {
	if rd == nil {
		return fmt.Errorf("billing: confirm quota: reader is nil")
	}
	if poll <= 0 {
		poll = time.Second
	}
	var wantLimits []QuotaLimit
	for _, u := range want {
		wantLimits = append(wantLimits, u.Limits...)
	}
	deadline := time.Now().Add(within)
	var last []QuotaLimit
	for {
		got, err := rd.GetQuota(ctx, tenant)
		if err == nil {
			last = got
			if quotaLimitsCovered(wantLimits, got) {
				return nil
			}
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf("billing: quota not confirmed within %s (want=%v got=%v)", within, wantLimits, last)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(poll):
		}
	}
}

// quotaLimitsCovered 期望限额均已生效（顺序无关）。
func quotaLimitsCovered(want, got []QuotaLimit) bool {
	if len(want) == 0 {
		return true
	}
	set := make(map[QuotaLimit]bool, len(got))
	for _, l := range got {
		set[l] = true
	}
	for _, w := range want {
		if !set[w] {
			return false
		}
	}
	return true
}
