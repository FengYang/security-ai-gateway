package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ---------- 拉取源（T3b · pull，§6.3.1） ----------

// PullSource 从 tee-infer 拉取增量计量的源接口。
type PullSource interface {
	// Pull 拉取 [fromNs, toNs) 区间的计量增量（左闭右开，UTC 纳秒）。
	Pull(ctx context.Context, fromNs, toNs int64) (*UsageWindow, error)
}

// teeInferPullSource 调用 tee-infer GET /usage?from=&to= 的实现。
type teeInferPullSource struct {
	baseURL   string
	token     string // Admin-Token（独立计量令牌，§6.3.1）
	client    *http.Client
}

// NewTEEPullSource 构造 tee-infer 拉取源。
func NewTEEPullSource(baseURL, token string, timeout time.Duration) PullSource {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &teeInferPullSource{
		baseURL: baseURL,
		token:   token,
		client:  &http.Client{Timeout: timeout},
	}
}

// pullUsageResp tee-infer /usage?from=&to= 的 JSON 响应。
type pullUsageResp struct {
	From    string                       `json:"from"`
	To      string                       `json:"to"`
	Tenants map[string]*billingIncTee    `json:"tenants"`
}

// billingIncTee 兼容 tee-infer billingIncrement 结构（int + 字段名映射）。
type billingIncTee struct {
	TokensIn  int                `json:"tokens_in"`
	TokensOut int                `json:"tokens_out"`
	Requests  int                `json:"requests"`
	ByModel   map[string]*modelUsageTee `json:"by_model"`
}

type modelUsageTee struct {
	TokensIn  int `json:"tokens_in"`
	TokensOut int `json:"tokens_out"`
	Requests  int `json:"requests"`
}

func (s *teeInferPullSource) Pull(ctx context.Context, fromNs, toNs int64) (*UsageWindow, error) {
	// Unix 秒精度（与 tee-infer parseBillingTime 兼容）
	fromSec := fromNs / int64(time.Second)
	toSec := toNs / int64(time.Second)
	if toSec <= fromSec {
		toSec = fromSec + 1 // 保证区间非空
	}

	url := fmt.Sprintf("%s/usage?from=%d&to=%d", s.baseURL, fromSec, toSec)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("billing pull: build req: %w", err)
	}
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("billing pull: http: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("billing pull: status %d: %s", resp.StatusCode, string(body))
	}

	var raw pullUsageResp
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("billing pull: decode: %w", err)
	}

	// 转换为内部 TenantAgg 结构（int → int64，按模型维度保留）
	tenants := make(map[string]*TenantAgg, len(raw.Tenants))
	for tenant, inc := range raw.Tenants {
		ta := &TenantAgg{
			TokensIn:  int64(inc.TokensIn),
			TokensOut: int64(inc.TokensOut),
			Requests:  int64(inc.Requests),
			ByModel:   make(map[string]*ModelAgg, len(inc.ByModel)),
		}
		for mk, mu := range inc.ByModel {
			ta.ByModel[mk] = &ModelAgg{
				TokensIn:  int64(mu.TokensIn),
				TokensOut: int64(mu.TokensOut),
				Requests:  int64(mu.Requests),
			}
		}
		tenants[tenant] = ta
	}

	// event_key = "pull-{fromSec}-{toSec}"（同窗口幂等）
	eventKey := fmt.Sprintf("pull-%d-%d", fromSec, toSec)

	return &UsageWindow{
		FromNs:   fromNs,
		ToNs:     toNs,
		Tenants:  tenants,
		Source:   "pull",
		EventKey: eventKey,
	}, nil
}
