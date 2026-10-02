package billing

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

// ---------- 拉取源（T3b · pull，§6.3.1） ----------

// PullSource 从 tee-infer 拉取增量计量的源接口。
type PullSource interface {
	// Pull 拉取 [fromNs, toNs) 区间的计量增量（左闭右开，UTC 纳秒）。
	Pull(ctx context.Context, fromNs, toNs int64) (*UsageWindow, error)
}

// SetMeteringSource 注入增量拉取源与参数（S-1，§6.1.1）。
// lookback: 重叠回补窗口（R-7）；syncMode: 账本单写者（A-12/R-30）。
func (s *BillingService) SetMeteringSource(src PullSource, lookback time.Duration, syncMode string) {
	s.source = src
	s.pullLookback = lookback
	s.syncMode = syncMode
}

// pullOnce 单次增量拉取 [now-lookback, now) 并入账（S-1，§6.1.1）。
//
// 时钟回拨（B-6.1-3）：`now < 上次轮询时刻` → 记指标 #17 并跳过本轮（防"负区间"）。
// 拉取/入账失败 → 记指标 #5 `error`；**游标为滑动窗口 `now-lookback`，不因失败而丢失数据**
// （下轮重拉同区间，`event_key` 幂等去重 B-6.1-8）。成功入账的 #5 `ok` 由 `IngestWindow` 发射。
func (s *BillingService) pullOnce(ctx context.Context) {
	if s.source == nil {
		return
	}
	now := s.now()
	if now < s.lastPollNs {
		IncClockSkew() // 指标 #17（唯一生产者）
		s.lastPollNs = now
		return
	}
	s.lastPollNs = now

	win, err := s.source.Pull(ctx, now-int64(s.pullLookback), now)
	if err != nil {
		IncPull("error") // 不推进游标（下轮重拉，幂等）
		log.Printf("[billing] S-1 拉取失败：%v", err)
		return
	}
	if win == nil {
		IncPull("ok")
		return
	}
	if _, err := s.IngestWindow(ctx, win, s.syncMode); err != nil {
		IncPull("error")
		log.Printf("[billing] S-1 入账失败：%v", err)
		return
	}
	IncPull("ok") // 指标 #5（本方法为该指标唯一生产者）
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
//
// GA-计费 P0-3（A-27/A-35）：新增 `_net` 净量与 `retry_tokens` 单列字段；
// 拉取侧**消费 `_net` 字段入账**（tokens 与 retry 不重叠，M9 与 M1 同保）。
type billingIncTee struct {
	TokensIn     int                      `json:"tokens_in"`
	TokensOut    int                      `json:"tokens_out"`
	Requests     int                      `json:"requests"`
	TokensInNet  int                      `json:"tokens_in_net"`
	TokensOutNet int                      `json:"tokens_out_net"`
	RetryTokens  int                      `json:"retry_tokens"`
	ByModel      map[string]*modelUsageTee `json:"by_model"`
}

type modelUsageTee struct {
	TokensIn     int `json:"tokens_in"`
	TokensOut    int `json:"tokens_out"`
	Requests     int `json:"requests"`
	TokensInNet  int `json:"tokens_in_net"`
	TokensOutNet int `json:"tokens_out_net"`
	RetryTokens  int `json:"retry_tokens"`
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
		// tee-infer 计量端点鉴权头为 `X-Admin-Token`（checkMetering，accepts 管理令牌或只读计量令牌）——
		// **不是** `Authorization: Bearer`（后者由 tee-infer 忽略 → 受保护实例下恒 401；E2E-1 实测暴露）。
		req.Header.Set("X-Admin-Token", s.token)
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

	// 转换为内部 TenantAgg 结构（int → int64，按模型维度保留）。
	//
	// A-27/A-35：入账消费**净量**（tokens_in_net/tokens_out_net），retry 归 RetryToks（平台成本）。
	// 兼容降级：若对端为旧版（未提供 _net 字段，全 0）而 tokens 非 0 → 视为无 retry 的净量
	// （保持可加性；retry 归因为 0，与旧行为一致）。
	tenants := make(map[string]*TenantAgg, len(raw.Tenants))
	for tenant, inc := range raw.Tenants {
		inNet, outNet, retry := inc.TokensInNet, inc.TokensOutNet, inc.RetryTokens
		if inNet == 0 && outNet == 0 && retry == 0 && (inc.TokensIn != 0 || inc.TokensOut != 0) {
			inNet, outNet = inc.TokensIn, inc.TokensOut // 旧版对端：_net 缺省 = 全量净量
		}
		ta := &TenantAgg{
			TokensIn:  int64(inNet),
			TokensOut: int64(outNet),
			Requests:  int64(inc.Requests),
			RetryToks: int64(retry),
			ByModel:   make(map[string]*ModelAgg, len(inc.ByModel)),
		}
		for mk, mu := range inc.ByModel {
			mInNet, mOutNet, mRetry := mu.TokensInNet, mu.TokensOutNet, mu.RetryTokens
			if mInNet == 0 && mOutNet == 0 && mRetry == 0 && (mu.TokensIn != 0 || mu.TokensOut != 0) {
				mInNet, mOutNet = mu.TokensIn, mu.TokensOut
			}
			ta.ByModel[mk] = &ModelAgg{
				TokensIn:  int64(mInNet),
				TokensOut: int64(mOutNet),
				Requests:  int64(mu.Requests),
				RetryToks: int64(mRetry),
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
