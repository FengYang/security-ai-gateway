package billing

import (
	"fmt"
	"sort"
	"time"
)

// ---------- 入账核心逻辑（T3b · 聚合→账本条目，§6.3.3） ----------

// dayLayout UTC+8 自然日格式（与 Period.Timezone=UTC+8 对应，P0 硬编码）。
const dayLayout = "2006-01-02"

// utc8Offset UTC+8 偏移（秒）。
const utc8Offset = 8 * 3600

// dayOfNs 把 UTC 纳秒时间戳转为 UTC+8 自然日字符串。
func dayOfNs(ns int64) string {
	sec := ns / int64(time.Second)
	utc8Sec := sec + utc8Offset
	t := time.Unix(utc8Sec, 0).UTC()
	return t.Format(dayLayout)
}

// clockOfNs 把 UTC 纳秒时间戳转为 UTC+8 的 "HH:MM"（供 S-3 月结按时刻触发）。
func clockOfNs(ns int64) string {
	sec := ns/int64(time.Second) + utc8Offset
	return time.Unix(sec, 0).UTC().Format("15:04")
}

// dayOfMonthOfNs 返回 UTC+8 自然日的"日"（1..31；供 S-3 月结按日触发）。
func dayOfMonthOfNs(ns int64) int {
	sec := ns/int64(time.Second) + utc8Offset
	return time.Unix(sec, 0).UTC().Day()
}

// AggToEntries 将一次拉取/推送的聚合窗口转为账本条目列表。
//
// 拆分规则（§6.3.3）：
//  1. 按租户 × 模型维度 拆分为条目（与 ledger 表 model_key 对齐）
//  2. 同一窗口内按窗口结束时间算日（UTC+8）—— 一次窗口可能跨日，需按日拆分
//     （P0 简化：窗口 ≤ 1 天则取窗口结束日；超 1 天由调用方分批拉取）
//  3. event_key 保证幂等："{source}-{windowEventKey}-{tenant}-{model}"
//  4. 入账时由 RatingEngine 计算 std_in/std_out/price_ver 并锁定（A-32）
//
// ★ M9 / A-42：TokensIn/TokensOut 为净量（剔除 retry）；RetryToks 归平台成本。
func AggToEntries(win *UsageWindow) []LedgerEntry {
	if win == nil || len(win.Tenants) == 0 {
		return nil
	}

	// ★ BUG-007：优先使用窗口**显式标注**的归属日（拉取已按 UTC+8 自然日切分）；
	// 未标注时回退“窗口结束日”（push 事件级窗口 / 兼容旧调用；窗口 ≤ 24h 时成立）。
	day := win.Day
	if day == "" {
		day = dayOfNs(win.ToNs)
	}
	nowNs := time.Now().UnixNano()

	var entries []LedgerEntry

	// 按租户名排序 → 按模型名排序 → 确定性输出（便于测试与对账）
	tenants := make([]string, 0, len(win.Tenants))
	for t := range win.Tenants {
		tenants = append(tenants, t)
	}
	sort.Strings(tenants)

	for _, tenant := range tenants {
		agg := win.Tenants[tenant]
		if agg == nil {
			continue
		}

		if len(agg.ByModel) == 0 {
			// 无模型维度 → 合并到一条 model_key=""（不应出现，保险）
			if agg.TokensIn == 0 && agg.TokensOut == 0 && agg.Requests == 0 && agg.RetryToks == 0 {
				continue
			}
			entries = append(entries, LedgerEntry{
				TenantID:  tenant,
				ModelKey:  "",
				Day:       day,
				ClusterID: win.ClusterID, // 计费打标（证据列，不入哈希域）
				TokensIn:  agg.TokensIn,
				TokensOut: agg.TokensOut,
				Requests:  agg.Requests,
				RetryToks: agg.RetryToks,
				Source:    win.Source,
				EventKey:  fmt.Sprintf("%s-%s-%s-__all__", win.Source, win.EventKey, tenant),
				CreatedAt: nowNs,
			})
			continue
		}

		// 有模型维度 → 按模型拆分
		models := make([]string, 0, len(agg.ByModel))
		for m := range agg.ByModel {
			models = append(models, m)
		}
		sort.Strings(models)

		var totalRetry int64
		for _, mk := range models {
			mu := agg.ByModel[mk]
			if mu == nil {
				continue
			}
			// 跳过完全无数据的模型（tokens_in/out/requests/retry 全 0）
			if mu.TokensIn == 0 && mu.TokensOut == 0 && mu.Requests == 0 && mu.RetryToks == 0 {
				continue
			}
			entries = append(entries, LedgerEntry{
				TenantID:  tenant,
				ModelKey:  mk,
				Day:       day,
				ClusterID: win.ClusterID, // 计费打标（证据列，不入哈希域）
				TokensIn:  mu.TokensIn,
				TokensOut: mu.TokensOut,
				Requests:  mu.Requests,
				RetryToks: mu.RetryToks,
				Source:    win.Source,
				EventKey:  fmt.Sprintf("%s-%s-%s-%s", win.Source, win.EventKey, tenant, mk),
				CreatedAt: nowNs,
			})
			totalRetry += mu.RetryToks
		}
		// 顶层 RetryToks 若有（推送可能直接带总量），差额补到 "__retry__" 模型
		if agg.RetryToks > totalRetry {
			entries = append(entries, LedgerEntry{
				TenantID:  tenant,
				ModelKey:  "__retry__",
				Day:       day,
				ClusterID: win.ClusterID, // 计费打标（证据列，不入哈希域）
				Requests:  0,
				RetryToks: agg.RetryToks - totalRetry,
				Source:    win.Source,
				EventKey:  fmt.Sprintf("%s-%s-%s-__retry__", win.Source, win.EventKey, tenant),
				CreatedAt: nowNs,
			})
		}
	}

	return entries
}

// ---------- 推送接收（T3b · push，§4.1.5 / §6.3.1/§6.3.2） ----------

// PushEvent 推送单条计费事件（§4.1.5：与 tee-infer `billingEventPayload` 对齐 + `is_retry`）。
//
// 事件级载荷（单租户/单模型/单次推理），非窗口聚合——与 pull 的窗口级载荷不同粒度（§6.3.2）。
type PushEvent struct {
	EventID    string `json:"event_id"`
	TenantID   string `json:"tenant"`
	RequestID  string `json:"request_id"`
	EngineType string `json:"engine_type"`
	Model      string `json:"model"`
	TokensIn   int    `json:"tokens_in"`
	TokensOut  int    `json:"tokens_out"`
	Result     string `json:"result"` // ok | engine_error
	IsRetry    bool   `json:"is_retry,omitempty"`
	TS         string `json:"ts"` // RFC3339（与审计 timestamp 同源）
	// ClusterID 计费打标：产生该事件的集群（R-4/A5(6)，P2-4 T-1.8）。
	// 空串 = 未上报（默认 ⇒ 既有推送行为不变）；非空则透传到账本 cluster_id 证据列。
	ClusterID string `json:"cluster_id,omitempty"`
}

// 已知 result 取值（B-6.3-3：未知值按 ok 兜底落账，仅指标单记 `unknown_result`）。
const (
	pushResultOK          = "ok"
	pushResultEngineError = "engine_error"
)

// pushEventToWindow 推送事件 → UsageWindow（事件级：单租户单模型）。
//
// 返回 nil = 该事件**不落账**：关键字段缺失 / 负 token（B-6.3-4）/ `ts` 非法（无法归日）。
// event_key：AggToEntries 拼为 `push-{event_id}-{tenant}-{model}`（§6.3.4 事件级幂等）。
// is_retry=true → retry_toks 归因，`tokens_in/out` 置零（§6.3.4 路①，M9）。
func pushEventToWindow(ev PushEvent) *UsageWindow {
	if ev.TenantID == "" || ev.Model == "" || ev.EventID == "" {
		return nil
	}
	if ev.TokensIn < 0 || ev.TokensOut < 0 {
		return nil // B-6.3-4：负 token（-1）忽略，不落账、不计负
	}
	t, err := time.Parse(time.RFC3339Nano, ev.TS)
	if err != nil {
		return nil // ts 非法 → 无法归日，不落账
	}
	in, out, retry := int64(ev.TokensIn), int64(ev.TokensOut), int64(0)
	if ev.IsRetry {
		retry = in + out
		in, out = 0, 0
	}
	return &UsageWindow{
		FromNs: t.UnixNano(), ToNs: t.UnixNano(),
		Source:    "push",
		EventKey:  ev.EventID,
		ClusterID: ev.ClusterID, // 计费打标透传（R-4/A5(6)）
		Tenants: map[string]*TenantAgg{
			ev.TenantID: {
				TokensIn: in, TokensOut: out, Requests: 1, RetryToks: retry,
				ByModel: map[string]*ModelAgg{
					ev.Model: {TokensIn: in, TokensOut: out, Requests: 1, RetryToks: retry},
				},
			},
		},
	}
}

// ---------- 单写者门控（A-12 / R-30） ----------

// CanWrite 判断当前 sync_mode 下某来源是否允许写账本。
//
// 规则（§6.3.2/R-30）：
//   - sync_mode=pull → 只有 pull 来源写账；push 仅更新实时视图（不写账）
//   - sync_mode=push → 只有 push 来源写账；pull 仅供 L2 对账（不写账）
func CanWrite(syncMode, source string) bool {
	switch syncMode {
	case SyncModePull:
		return source == "pull" || source == "manual"
	case SyncModePush:
		return source == "push" || source == "manual"
	default:
		return false
	}
}
