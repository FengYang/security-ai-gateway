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

// daySeg 一个 UTC+8 自然日切分段（左闭右开）。
type daySeg struct {
	day  string
	from int64
	to   int64
}

// daySegments 把 [from, to) 按 UTC+8 自然日切分为**非重叠**段（★ BUG-007）。
// 每段归属其自然日，使账本归日与 tee-infer /usage 的按日查询同口径。
// 解析失败时不切分（保守单段），归属日回退为窗口结束日。
func daySegments(from, to int64) []daySeg {
	if to <= from {
		return nil
	}
	var segs []daySeg
	cur := from
	for cur < to {
		day := dayOfNs(cur)
		_, nextStart, err := dayRangeNs(day, day) // [dayStart, nextDayStart)
		if err != nil {
			return []daySeg{{day: dayOfNs(to), from: from, to: to}}
		}
		segTo := nextStart
		if segTo > to {
			segTo = to
		}
		segs = append(segs, daySeg{day: day, from: cur, to: segTo})
		cur = segTo
	}
	return segs
}

// pullRange 拉取并入账 [from, to)（★ BUG-001 非重叠 + ★ BUG-007 按日切分）。
//
// 逐日段：独立 Pull → 标注归属日 → IngestWindow（单写者门控/幂等不变）；
// 段成功即推进内存游标与持久化水位；任一段失败即返回错误（**不越过失败段**，无丢账）。
func (s *BillingService) pullRange(ctx context.Context, from, to int64) error {
	for _, seg := range daySegments(from, to) {
		win, err := s.source.Pull(ctx, seg.from, seg.to)
		if err != nil {
			return err
		}
		if win != nil {
			win.Day = seg.day // ★ BUG-007：显式归属日
			if _, err := s.IngestWindow(ctx, win, s.syncMode); err != nil {
				return err
			}
		}
		s.lastPollNs = seg.to
		if err := s.store.Ledger().SetPollWatermark(seg.to); err != nil {
			log.Printf("[billing] 拉取水位持久化失败（内存游标已推进至 %d）：%v", seg.to, err)
		}
	}
	return nil
}

// pullOnce 单次增量拉取并入账（S-1，§6.1.1）。
//
// ★ BUG-001 修复：改为**游标式非重叠窗口** [cursor, now)，彻底消除“滑动窗口重叠 → 重复入账”。
//   - 游标三级回退：内存 lastPollNs → 持久化水位 PollWatermark → now-lookback（仅首次部署）；
//   - 仅当拉取**且**入账成功（或空窗口）才推进游标；失败不推进（下轮覆盖同区间，无丢账无重复）；
//   - 时钟回拨（B-6.1-3）：`now < cursor` → 记 #17 并重同步游标、跳过本轮。
func (s *BillingService) pullOnce(ctx context.Context) {
	if s.source == nil {
		return
	}
	s.pollMu.Lock()
	defer s.pollMu.Unlock()

	now := s.now()
	if now < s.lastPollNs { // 时钟回拨（B-6.1-3）
		IncClockSkew() // 指标 #17（唯一生产者）
		s.lastPollNs = now
		return
	}
	from := s.lastPollNs
	if from <= 0 { // 重启恢复：持久化水位（= 上轮成功窗口结束，天然无重叠）
		if ns, err := s.store.Ledger().PollWatermark(); err == nil {
			from = ns
		}
	}
	if from <= 0 { // 首次部署：一次性回溯 lookback
		from = now - int64(s.pullLookback)
	}
	if from >= now { // 保证半开区间 [from,now) 非空
		from = now - int64(time.Second)
	}
	if err := s.pullRange(ctx, from, now); err != nil {
		IncPull("error") // ★ 不越过失败段（游标保持）
		log.Printf("[billing] S-1 拉取/入账失败（游标保持）：%v", err)
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
