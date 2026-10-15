package main

// ttftfetch.go — P1-6 M2.6：TTFT 统计周期拉取（控制面 → 数据面，§6.3 / D-6 / TT2-12）。
//
// 职责：
//   - 周期 tick 批量拉取 `GET /routes/ttft/stats?tenant=<t>`（每请求 = 该租户全量批量）；
//   - 租户集合 = 已建引擎（routingEngines）的 tenant 去重集合（字典序）；
//   - **round-robin 分片**（§6.3/R-6/TT2-12）：每 tick ≤ TTFTStatsMaxTenantsPerTick 个租户请求，
//     租户数 ≤ 上限时每 tick 全量刷新；超出时每个端点的统计更新周期 ≤ ceil(N/上限) 个 tick
//     （对齐 §6.3 估算式：interval × ceil(总批次数/每 tick 批次数)，批 = 租户）；
//     **禁止**逐条（逐 endpoint/stats 条目）循环 GET；
//   - 解析后写 `EndpointState.TTFT`（含 `valid`/`updated_at` 过期判定——数据面侧写时定版）；
//   - 404 = 控制面无该租户统计（M3.5 如实 404，含 reset 后/冷启动）→ **失效旧画像**（D-8 回退）；
//     网络错/5xx/非契约载荷 → 标记通道不可达（R2-19 序 1，回退原因 `_unreachable`）。
//
// 边界（C-3/TT2-19）：本文件仅被 tick 驱动，请求路径零调用、零分配；读路径无锁（值语义
// TTFTStat + Valid 位），写路径经 Engine 显式加锁接缝（SetEndpointTTFT / SetTTFTStatsUnreachable）。
// cache 维度契约未落地（P0-2/D-10/M2.7）：当前仅写 cache="miss" 条目，其余维度忽略。

import (
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/higress-group/wasm-go/pkg/wrapper"
	"github.com/tidwall/gjson"

	"security-ai-gateway/gateway/wasm/otpmask-plugin/routeengine"
)

// TTFTStatsMaxTenantsPerTick 每 tick 租户请求上限（§6.3："每 tick 总批次数设上限（如 ≤4）"）。
const TTFTStatsMaxTenantsPerTick = 4

// ttftFetchDispatch 单租户统计拉取入口（wasm 运行态 = fetchTenant；单测替换以跳过网络）。
var ttftFetchDispatch = func(rt *ttftRuntimeState, tenant string, nowSec int64) {
	rt.fetchTenant(tenant, nowSec)
}

// ttftFetchTick 统计拉取周期任务（wrapper.RegisterTickFunc 回调）。
func ttftFetchTick() {
	ttftFetchTickAt(time.Now().Unix())
}

// ttftFetchTickAt 拉取 tick 主流程（nowSec 注入可测）：
// 单飞门（陈旧自愈）→ 租户集合 round-robin 分片 → 逐租户发起批量拉取（≤上限）。
func ttftFetchTickAt(nowSec int64) {
	rt := &ttftRuntime
	if !rt.enabled {
		return
	}
	// 单飞：上一批仍在飞则不重叠；若在飞标记已超过 2×周期（回调被丢弃——环境终止/热更新），
	// 视为陈旧并自愈（否则拉取将永久停摆）。
	if rt.fetchInflight > 0 {
		if nowSec-rt.fetchStartSec <= 2*rt.intervalMs/1000 {
			return
		}
		rt.fetchInflight = 0
	}
	sel := rt.selectTenants(ttftFetchTenants(), TTFTStatsMaxTenantsPerTick)
	if len(sel) == 0 {
		return // 无已建引擎租户（如路由未启用）→ 零网络
	}
	rt.fetchStartSec = nowSec
	for _, tenant := range sel {
		ttftFetchDispatch(rt, tenant, nowSec)
	}
}

// selectTenants 按 round-robin 游标从字典序租户列表取 ≤max 个（更新游标）。
// 列表每 tick 重算（引擎集只增不删）；游标对当前长度取模。
func (rt *ttftRuntimeState) selectTenants(all []string, max int) []string {
	if len(all) == 0 || max <= 0 {
		return nil
	}
	n := max
	if n > len(all) {
		n = len(all)
	}
	start := rt.fetchCursor % len(all)
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, all[(start+i)%len(all)])
	}
	rt.fetchCursor = (start + n) % len(all)
	return out
}

// ttftFetchTenants 返回已建引擎的 tenant 去重集合（字典序；确定性 round-robin 顺序）。
func ttftFetchTenants() []string {
	routingEngines.mu.Lock()
	seen := make(map[string]struct{}, len(routingEngines.entries))
	for k := range routingEngines.entries {
		t, _, _ := strings.Cut(k, "\x00")
		seen[t] = struct{}{}
	}
	routingEngines.mu.Unlock()
	out := make([]string, 0, len(seen))
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out
}

// fetchTenant 发起单租户批量拉取（GET，异步回调应用）。
func (rt *ttftRuntimeState) fetchTenant(tenant string, nowSec int64) {
	cli := wrapper.NewClusterClient(wrapper.FQDNCluster{FQDN: rt.service, Port: rt.port})
	headers := make([][2]string, 0, 1)
	token := rt.token
	if v := runtimeCoreChannelToken(); v != "" { // 运行态通道令牌优先（C 项；回退静态配置）
		token = v
	}
	if token != "" {
		headers = append(headers, [2]string{"Authorization", "Bearer " + token})
	}
	rt.fetchInflight++
	err := cli.Get("/routes/ttft/stats?tenant="+url.QueryEscape(tenant), headers,
		func(statusCode int, _ http.Header, respBody []byte) {
			rt.fetchDone()
			metricTTFTStatsFetchCb.incr()
			_, rejected := ttftApplyStatsResponse(tenant, statusCode, respBody, nowSec)
			if rejected > 0 {
				metricTTFTStatsFetchReject.incr()
				ttftLogWarnf("otpmask-plugin: TTFT 统计拉取被拒 tenant=%q status=%d body=%s",
					tenant, statusCode, ttftTruncate(respBody))
				return
			}
			metricTTFTStatsFetchOK.incr()
		})
	if err != nil {
		rt.fetchDone()
		metricTTFTStatsFetchReject.incr()
		ttftMarkTenantStatsUnreachable(tenant, true)
		ttftLogWarnf("otpmask-plugin: TTFT 统计拉取触发失败 tenant=%q: %v", tenant, err)
	}
}

// fetchDone 在飞计数递减（下限 0；防陈旧自愈重置后旧回调复减为负）。
func (rt *ttftRuntimeState) fetchDone() {
	if rt.fetchInflight > 0 {
		rt.fetchInflight--
	}
}

// ttftApplyStatsResponse 应用统计响应（纯逻辑可测；返回写入条数与拒绝标志）。
//
// 分支语义（对齐 §6.3 与 M3.5 实现）：
//   - 200 + stats 数组：通道可达；逐条写入（结构非法条目跳过）；
//   - 200 + 非契约载荷：不动存量统计、不判不可达（服务端版本错配/中间件页），仅拒绝计数；
//   - 404：控制面无该租户统计（冷启动/reset 后）→ 通道可达，但数据面旧画像不再有控制面背书
//     → 失效（逐端点置零 valid=false，"无统计" 走 D-8 回退）；
//   - 400：请求非法（本端构造，不应发生）→ 通道可达、存量保留，仅拒绝计数；
//   - 其余（503 source_unavailable / 5xx / 异常状态）：通道不可达 → R2-19 序 1 标记。
func ttftApplyStatsResponse(tenant string, statusCode int, respBody []byte, nowSec int64) (applied, rejected int) {
	switch {
	case statusCode == http.StatusOK:
		stats := gjson.GetBytes(respBody, "stats")
		if !stats.IsArray() {
			return 0, 1
		}
		ttftMarkTenantStatsUnreachable(tenant, false)
		stats.ForEach(func(_, v gjson.Result) bool {
			applied += ttftApplyStatEntry(tenant, v, nowSec)
			return true
		})
		return applied, 0
	case statusCode == http.StatusNotFound:
		ttftMarkTenantStatsUnreachable(tenant, false)
		ttftInvalidateTenantStats(tenant)
		return 0, 0
	case statusCode == http.StatusBadRequest:
		ttftMarkTenantStatsUnreachable(tenant, false)
		return 0, 1
	default:
		ttftMarkTenantStatsUnreachable(tenant, true)
		return 0, 1
	}
}

// ttftApplyStatEntry 写入单条 stats 条目（返回 1 = 已写入；0 = 跳过）。
//   - tenant 缺省按请求租户兜底（契约要求每条带 tenant）；
//   - 未知 (tenant,model) 引擎 / 未知端点 → 跳过（如引擎尚未建、或路由已下线）；
//   - cache 维度：契约未落地（M2.7）仅接受 "miss"（缺省按 miss），其余维度忽略；
//   - 范围钳制：p95_ms ≤ 0 视为结构非法跳过（上钳 max_ttft_ms 由读路径 latencyRefMs 完成）；
//   - 过期判定（§6.3/D-8）：服务端 valid=true 但 now-updated_at > stale_sec（引擎延迟配置）→
//     写时置 Valid=false（latencyEligible 信任该位）。
func ttftApplyStatEntry(tenant string, v gjson.Result, nowSec int64) int {
	t := v.Get("tenant").String()
	if t == "" {
		t = tenant
	}
	model := v.Get("model").String()
	endpoint := v.Get("endpoint").String()
	if t == "" || model == "" || endpoint == "" {
		return 0
	}
	engine := ttftEngineLookup(t, model)
	if engine == nil {
		return 0
	}
	cache := v.Get("cache").String()
	if cache == "" {
		cache = "miss"
	}
	if cache != "miss" {
		return 0 // cache 维度契约未落地（P0-2/D-10/M2.7）
	}
	st := routeengine.TTFTStat{
		P50Ms:     v.Get("p50_ms").Int(),
		P95Ms:     v.Get("p95_ms").Int(),
		Samples:   v.Get("samples").Int(),
		Valid:     v.Get("valid").Bool(),
		UpdatedAt: v.Get("updated_at").Int(),
		Cache:     cache,
	}
	if st.P95Ms <= 0 {
		return 0 // 结构非法（范围钳制；上钳由读路径完成）
	}
	if st.Valid {
		if stale := engine.LatencyConfigOf().StaleSec; stale > 0 && nowSec-st.UpdatedAt > int64(stale) {
			st.Valid = false // 数据面侧过期判定（写时定版）
		}
	}
	if engine.SetEndpointTTFT(endpoint, st) {
		return 1
	}
	return 0
}

// ttftEngineLookup 按 (tenant, model) 取已建引擎（不创建；未建 → nil）。
func ttftEngineLookup(tenant, model string) *routeengine.Engine {
	routingEngines.mu.Lock()
	defer routingEngines.mu.Unlock()
	if e := routingEngines.entries[tenant+"\x00"+model]; e != nil {
		return e.engine
	}
	return nil
}

// ttftTenantEngines 取该租户的全部已建引擎（含所有 model）。
func ttftTenantEngines(tenant string) []*routeengine.Engine {
	routingEngines.mu.Lock()
	out := make([]*routeengine.Engine, 0, 4)
	for k, e := range routingEngines.entries {
		if t, _, ok := strings.Cut(k, "\x00"); ok && t == tenant {
			out = append(out, e.engine)
		}
	}
	routingEngines.mu.Unlock()
	return out
}

// ttftMarkTenantStatsUnreachable 置该租户全部引擎的统计通道不可达标志（R2-19 序 1）。
func ttftMarkTenantStatsUnreachable(tenant string, v bool) {
	for _, e := range ttftTenantEngines(tenant) {
		e.SetTTFTStatsUnreachable(v)
	}
}

// ttftInvalidateTenantStats 失效该租户全部引擎的端点统计（逐端点置零值 = valid=false）。
// 语义：404 = 控制面无该租户统计 → 数据面旧画像必须退出（D-8「无统计」回退）。
func ttftInvalidateTenantStats(tenant string) {
	for _, e := range ttftTenantEngines(tenant) {
		for _, name := range e.EndpointNames() {
			e.SetEndpointTTFT(name, routeengine.TTFTStat{})
		}
	}
}
