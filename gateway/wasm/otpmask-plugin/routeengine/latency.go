// Package routeengine — P1-6 TTFT 严格性能择优：统计结构与延迟配置（M1.1）。
//
// 设计依据：《GA-AI网关能力补齐方案--P1--TTFT严格性能择优.md》v1.5
//
//	§4.1 M1.1：TTFTStat + LatencyConfig（纯数据结构，无 Mode，模式由 Strategy 决定）
//	§6.1：latency 段字段表（JSON 标签逐字段一致；默认值/范围见字段注释）
//	§6.3：stats 下发条目字段（p50_ms / p95_ms / samples / valid / updated_at / cache）
//
// 边界（对齐本体附录 B 职责划分）：本文件仅定义数据结构与参数归一化，
// 不含采样、上报、网络调用；读路径无锁、值语义（C-3）。
package routeengine

import "math"

// ============================================================
// TTFT 统计结构（写入 EndpointState.TTFT）
// ============================================================

// TTFTStat 端点首 token 延迟（TTFT）统计快照（值语义、读路径无锁）。
//
// 由数据面周期拉取（M2.6，ttftfetch.go）自控制面 `GET /routes/ttft/stats`（§6.3）
// 取得并写入 `EndpointState.TTFT`；选路时仅作只读使用，不就地改写（C-3）。
// JSON 标签与 §6.3 stats 条目逐字段一致。
type TTFTStat struct {
	P50Ms     int64  `json:"p50_ms"`     // P50 分位（毫秒）
	P95Ms     int64  `json:"p95_ms"`     // P95 分位（毫秒；默认参考分位，见 LatencyConfig.Quantile）
	Samples   int64  `json:"samples"`    // 窗口内样本数
	Valid     bool   `json:"valid"`      // 统计是否有效（样本充足且未过期，D-8）
	UpdatedAt int64  `json:"updated_at"` // 统计更新时间（Unix 秒）
	Cache     string `json:"cache"`      // cache 分层标识："hit"/"miss"（D-10；契约未落地前恒 "miss"）
}

// ============================================================
// 延迟配置（路由表 latency 段，§6.1）
// ============================================================

// LatencyConfig 延迟择优参数（自路由表 `latency` 段解析，M4.5）。
//
// 设计要点（§6.1）：
//   - **无 Mode 字段**：选路模式由 `Config.Strategy` 唯一决定
//     （latency-aware / latency-fastest / hybrid）；
//   - 缺省值：window_sec=300 / quantile=p95 / gamma=1.0 / min_weight=0.05 /
//     explore_ratio=0.05 / min_samples=20 / stale_sec=75 / cache_partition=true /
//     max_ttft_ms=30000；
//   - `gamma=0` 与 `explore_ratio=0` 均为**合法显式取值**（§3.5 关键性质：
//     γ=0 且 explore_ratio=1 退化为均匀随机），故缺省填充必须在 schema 解析层
//     **按字段存在性**完成（M4.5）；本层 normalized() 只做越界钳制，
//     不把合法 0 值改写为缺省；
//   - `cache_partition` 的缺省 true 同样由 M4.5 依 JSON 字段存在性填充
//     （Go 零值为 false，本层无法区分「显式 false」与「未提供」）。
type LatencyConfig struct {
	WindowSec      int     `json:"window_sec"`      // 滑窗长度（秒），默认 300，范围 60–3600（分片数 N=ceil(window_sec/25)，§3.3）
	Quantile       string  `json:"quantile"`        // 参考延迟分位："p50"/"p95"，默认 "p95"
	Gamma          float64 `json:"gamma"`           // 倒数幂指数 γ，默认 1.0，范围 0–5（D-3）
	MinWeight      float64 `json:"min_weight"`      // 归一化前相对权重下界，默认 0.05，范围 0–0.5（D-4）
	ExploreRatio   float64 `json:"explore_ratio"`   // 探索概率，默认 0.05，范围 0–1（D-4）
	MinSamples     int     `json:"min_samples"`     // 样本不足判无效，默认 20，≥1（D-8）
	StaleSec       int     `json:"stale_sec"`       // 统计过期阈值（秒），默认 75，≥25 且 ≥2×上报周期（D-8）
	CachePartition bool    `json:"cache_partition"` // 按 cache 分层统计，默认 true（D-10）
	MaxTTFTMs      int64   `json:"max_ttft_ms"`     // 采样上限（毫秒），默认 30000，≥1000（超时按上限归桶，抑制离群）
}

// 越界钳制的安全缺省（对齐 §6.1 默认值列与范围约束）。
const (
	defaultLatencyWindowSec    = 300
	minLatencyWindowSec        = 60
	maxLatencyWindowSec        = 3600
	defaultLatencyQuantile     = "p95"
	defaultLatencyGamma        = 1.0
	maxLatencyGamma            = 5.0
	defaultLatencyMinWeight    = 0.05
	maxLatencyMinWeight        = 0.5
	defaultLatencyExploreRatio = 0.05
	defaultLatencyMinSamples   = 20
	defaultLatencyStaleSec     = 75
	minLatencyStaleSec         = 25
	defaultLatencyMaxTTFTMs    = 30000
	minLatencyMaxTTFTMs        = 1000
)

// normalized 返回越界字段被钳制回安全缺省后的副本（不修改接收者）。
//
// 语义边界：仅处理**越界**值；合法显式值（含 gamma=0 / explore_ratio=0 /
// min_weight=0 / quantile="p50"）原样保留。字段**缺省填充**（未提供时取默认）
// 由 schema 解析层按存在性完成（M4.5），不在本层处理。
func (c LatencyConfig) normalized() LatencyConfig {
	if c.WindowSec < minLatencyWindowSec || c.WindowSec > maxLatencyWindowSec {
		c.WindowSec = defaultLatencyWindowSec
	}
	if c.Quantile != "p50" && c.Quantile != "p95" {
		c.Quantile = defaultLatencyQuantile
	}
	if c.Gamma < 0 || c.Gamma > maxLatencyGamma {
		c.Gamma = defaultLatencyGamma
	}
	if c.MinWeight < 0 || c.MinWeight > maxLatencyMinWeight {
		c.MinWeight = defaultLatencyMinWeight
	}
	if c.ExploreRatio < 0 || c.ExploreRatio > 1 {
		c.ExploreRatio = defaultLatencyExploreRatio
	}
	if c.MinSamples < 1 {
		c.MinSamples = defaultLatencyMinSamples
	}
	if c.StaleSec < minLatencyStaleSec {
		c.StaleSec = defaultLatencyStaleSec
	}
	if c.MaxTTFTMs < minLatencyMaxTTFTMs {
		c.MaxTTFTMs = defaultLatencyMaxTTFTMs
	}
	return c
}

// ============================================================
// 权函数（M1.2）：无量纲倒数幂 + 相对下界（§3.5；D-3/D-4）
//
// 全部为请求内临时量：不改写 EndpointState.Weight、不分配切片（C-3），
// 扫描均直接遍历 state map（对齐 pickByWeight 的无分配手法）。
// ============================================================

// latencyRefMs 取端点参考延迟 t_i（毫秒）：按 cfg.Quantile 选 p50/p95，
// 并钳制到 [1ms, cfg.MaxTTFTMs]：
//   - 下钳 1ms：防除零（保证 t_min ≥ 1ms、r_i ∈ (0,1]）；
//   - 上钳 max_ttft_ms：抑制离群（§3.5 / TT2-07）。
//
// 前置：cfg 已经 normalized()（MaxTTFTMs ≥ 1000）。
func latencyRefMs(st TTFTStat, cfg LatencyConfig) int64 {
	t := st.P95Ms
	if cfg.Quantile == "p50" {
		t = st.P50Ms
	}
	if t < 1 {
		t = 1
	}
	if t > cfg.MaxTTFTMs {
		t = cfg.MaxTTFTMs
	}
	return t
}

// latencyBaseOf 计算 base_i = (t_min / t_i)^γ（无量纲，§3.5 量纲与下界 D-3）。
// 调用方保证 tMinMs / tMs 均已钳制 ≥ 1ms（r ∈ (0,1]，分母分子均非零）。
func latencyBaseOf(tMinMs, tMs int64, gamma float64) float64 {
	return math.Pow(float64(tMinMs)/float64(tMs), gamma)
}

// latencyEligible 端点是否参与延迟加权：可用（IsUsable，沿用 P0-1）且 TTFT 统计有效。
// §6.3：valid=false 或 updated_at 过期 → 该端点退出版本内 TTFT 权（仅用其余有效端点）。
// 过期判定由数据面拉取侧完成（M2.6 写入时置 Valid=false），本层信任 Valid 位。
func latencyEligible(ep *EndpointState) bool {
	return ep.IsUsable() && ep.TTFT.Valid
}

// latencyGroupScan 最高优先级组扫描（一次遍历、零分配）：
//   - minPrio：组优先级（数字越小越高）；
//   - usable ：组内可用端点数（IsUsable，含 TTFT 无效者）；
//   - single ：usable==1 时该端点（§3.5 单端点优化 TT2-07：直接返回，跳过权计算）；
//   - ok     ：是否存在可用端点。
func latencyGroupScan(state map[string]*EndpointState) (minPrio, usable int, single *EndpointState, ok bool) {
	minPrio = math.MaxInt
	for _, ep := range state {
		if !ep.IsUsable() {
			continue
		}
		if ep.Priority < minPrio {
			minPrio, usable, single = ep.Priority, 1, ep
		} else if ep.Priority == minPrio {
			usable++
			single = nil
		}
	}
	return minPrio, usable, single, minPrio != math.MaxInt
}

// latencyGroupTMin 组内**有效**端点的参考延迟最小值 t_min 与有效端点数：
// t_min = min_{j∈E} max(1ms, t_j)（§3.5，保证 ≥ 1ms）。eligible=0 时 tMinMs=0。
func latencyGroupTMin(state map[string]*EndpointState, minPrio int, cfg LatencyConfig) (tMinMs int64, eligible int) {
	tMinMs = math.MaxInt64
	for _, ep := range state {
		if ep.Priority != minPrio || !latencyEligible(ep) {
			continue
		}
		if t := latencyRefMs(ep.TTFT, cfg); t < tMinMs {
			tMinMs = t
		}
		eligible++
	}
	if eligible == 0 {
		tMinMs = 0
	}
	return tMinMs, eligible
}

// latencyGroupMaxBase 组内最大 base：max_{j∈E} (t_min / t_j)^γ（§3.5 floor 定义用）。
// 组内至少 1 个有效端点时其值恒为 1（取到 t_j=t_min 者）；此处如实计算不假设，
// 以保持与公式逐字一致（field 后续演进时稳健）。
func latencyGroupMaxBase(state map[string]*EndpointState, minPrio int, tMinMs int64, cfg LatencyConfig) float64 {
	maxBase := 0.0
	for _, ep := range state {
		if ep.Priority != minPrio || !latencyEligible(ep) {
			continue
		}
		if b := latencyBaseOf(tMinMs, latencyRefMs(ep.TTFT, cfg), cfg.Gamma); b > maxBase {
			maxBase = b
		}
	}
	return maxBase
}

// latencyGroupWeightOf 单端点权 w_i = max(base_i, floor)（§3.5；floor 在此之前由调用方
// 以 min_weight × max_j(base_j) 计算）。latency-aware 与 hybrid 第①步共用。
func latencyGroupWeightOf(ep *EndpointState, tMinMs int64, floor float64, cfg LatencyConfig) float64 {
	w := latencyBaseOf(tMinMs, latencyRefMs(ep.TTFT, cfg), cfg.Gamma)
	if w < floor {
		w = floor
	}
	return w
}

// latencyGroupTotalWeight 组内 Σ w_j（w_j = max(base_j, floor)）——归一化分母。
func latencyGroupTotalWeight(state map[string]*EndpointState, minPrio int, tMinMs int64, floor float64, cfg LatencyConfig) float64 {
	total := 0.0
	for _, ep := range state {
		if ep.Priority != minPrio || !latencyEligible(ep) {
			continue
		}
		total += latencyGroupWeightOf(ep, tMinMs, floor, cfg)
	}
	return total
}

// ============================================================
// latency-aware 抽样与确定性回退（M1.3；§3.5 / R2-16 / R2-19）
// ============================================================

// 回退原因（与 otpmask_route_ttft_fallback_total 拆名一一对应，§6.5；M5.2 接线）。
const (
	fallbackUnreachable = "unreachable" // R2-19 序 1：控制面不可达 / 聚合器 503
	fallbackStale       = "stale"       // R2-19 序 2：组内统计全部陈旧
	fallbackLowSamples  = "low_samples" // R2-19 序 3/4：样本不足（含 E==1 等价单端点）
	fallbackNoSamples   = "no_samples"  // R2-19 序 3：全无样本（非流式流量常态）
	fallbackNoRand      = "no_rand"     // R2-19 序 5：随机源不可用 → 确定性回退
)

// latencyFallbackObserver 包级回退观测接缝（M5.2 由插件注入 → fallback_total 拆名
// Counter）。未注入时 no-op；请求路径不写日志/不发网络（C-4），仅回调计数。
var latencyFallbackObserver func(reason string)

// SetLatencyFallbackObserver 注入回退观测回调（仅装配期调用一次）。
func SetLatencyFallbackObserver(fn func(reason string)) { latencyFallbackObserver = fn }

// reportLatencyFallback 记录一次延迟策略回退（无回调时静默）。
func reportLatencyFallback(reason string) {
	if latencyFallbackObserver != nil {
		latencyFallbackObserver(reason)
	}
}

// latencyFastestOf 组内**有效**端点 argmin t_i（确定性：并列按 name 字典序；
// 禁止依赖 map 遍历序，TT2-02）。§3.5 no_rand 确定性回退与 latency-fastest 共用。
func latencyFastestOf(state map[string]*EndpointState, minPrio int, cfg LatencyConfig) (*EndpointState, bool) {
	var best *EndpointState
	var bestT int64
	for _, ep := range state {
		if ep.Priority != minPrio || !latencyEligible(ep) {
			continue
		}
		t := latencyRefMs(ep.TTFT, cfg)
		if best == nil || t < bestT || (t == bestT && ep.Name < best.Name) {
			best, bestT = ep, t
		}
	}
	return best, best != nil
}

// pickByLatency latency-aware：探索 + 倒数幂加权随机（§3.5；R2-19 回退索引）。
// 调用方持锁（pickByStrategy 内部）。Decision.Strategy 恒为本次生效的
// config.Strategy（R2-10：回退不改写策略标签，回退以 fallback_total{reason} 表达）。
func (e *Engine) pickByLatency() Decision {
	cfg := e.config.Latency.normalized()
	minPrio, usable, single, hasUsable := latencyGroupScan(e.state)
	if !hasUsable {
		return Decision{Reason: "no_usable_endpoints"}
	}
	if usable == 1 {
		// §3.5 单端点优化（TT2-07）：跳过权计算与探索，等价 latency-fastest。
		return e.latencyDecisionOf(single, "latency_single")
	}

	tMin, eligible := latencyGroupTMin(e.state, minPrio, cfg)
	switch {
	case eligible == 0:
		// R2-19 序 1-3：全局回退 failure-aware（行为 = pickByWeight）。
		return e.latencyGlobalFallback(e.classifyNoStats(minPrio, cfg))
	case eligible == 1:
		// R2-19 序 4：等价退单端点（确定性），计 _low_samples。
		if sole, ok := latencyFastestOf(e.state, minPrio, cfg); ok {
			reportLatencyFallback(fallbackLowSamples)
			return e.latencyDecisionOf(sole, "latency_single_eligible")
		}
		return e.latencyGlobalFallback(fallbackLowSamples) // 理论不可达
	}

	maxBase := latencyGroupMaxBase(e.state, minPrio, tMin, cfg)
	floor := cfg.MinWeight * maxBase
	totalW := latencyGroupTotalWeight(e.state, minPrio, tMin, floor, cfg)
	if totalW <= 0 {
		// 数值退化（理论不可达：≥2 个有效端点 ⇒ 每端点 w > 0）→ 确定性回退。
		return e.latencyFallbackFastest(minPrio, cfg, "")
	}

	// 抽样 1：探索判定（R2-16：两次抽样分别取随机，任一步 ok=false 即确定性回退）。
	rv1, ok1 := randFloat64()
	if !ok1 {
		return e.latencyFallbackFastest(minPrio, cfg, fallbackNoRand)
	}
	if rv1 < cfg.ExploreRatio {
		// 探索：在**可用**集合 U 内均匀随机（§3.5；含 TTFT 无效端点——探索为其提供
		// 刷新统计样本的机会，避免「无效→永无流量→永远无效」的饿死闭环）。
		rv2, ok2 := randFloat64()
		if !ok2 {
			return e.latencyFallbackFastest(minPrio, cfg, fallbackNoRand)
		}
		idx := int(rv2 * float64(usable))
		if idx >= usable {
			idx = usable - 1
		}
		i := 0
		for _, ep := range e.state {
			if ep.Priority != minPrio || !ep.IsUsable() {
				continue
			}
			if i == idx {
				return e.latencyDecisionOf(ep, "latency_explore")
			}
			i++
		}
		return e.latencyFallbackFastest(minPrio, cfg, "") // 理论不可达
	}

	// 利用：按 w_i 加权随机（抽样 2），失败 → 确定性回退（R2-16）。
	rv2, ok2 := randFloat64()
	if !ok2 {
		return e.latencyFallbackFastest(minPrio, cfg, fallbackNoRand)
	}
	r := rv2 * totalW
	var cum float64
	for _, ep := range e.state {
		if ep.Priority != minPrio || !latencyEligible(ep) {
			continue
		}
		cum += latencyGroupWeightOf(ep, tMin, floor, cfg)
		if r < cum {
			return e.latencyDecisionOf(ep, "latency_weighted")
		}
	}
	// 浮点误差兜底（r 逼近 totalW 尾部）：确定性回退，不依赖 map 遍历序。
	return e.latencyFallbackFastest(minPrio, cfg, "")
}

// latencyDecisionOf 构造选中结果：Strategy 恒回填本次生效的 config.Strategy（R2-10）。
func (e *Engine) latencyDecisionOf(ep *EndpointState, reason string) Decision {
	return Decision{
		EndpointName: ep.Name,
		EndpointURL:  ep.URL,
		Strategy:     e.config.Strategy,
		Reason:       reason,
	}
}

// latencyFallbackFastest 确定性回退：取组内最快有效端点（§3.5；reason 非空时计数）。
func (e *Engine) latencyFallbackFastest(minPrio int, cfg LatencyConfig, reason string) Decision {
	if reason != "" {
		reportLatencyFallback(reason)
	}
	if best, ok := latencyFastestOf(e.state, minPrio, cfg); ok {
		return e.latencyDecisionOf(best, "latency_fallback_fastest")
	}
	// 不应发生（调用点保证 ≥2 个有效端点）；保底走全局回退。
	return e.latencyGlobalFallback(fallbackLowSamples)
}

// latencyGlobalFallback R2-19 序 1-3：全局回退既有 failure-aware 加权
// （行为 = pickByWeight），计数后仍回填 config.Strategy（R2-10：回退不改写策略标签）。
func (e *Engine) latencyGlobalFallback(reason string) Decision {
	reportLatencyFallback(reason)
	d := e.pickByWeight()
	d.Strategy = e.config.Strategy
	d.Reason = "latency_fallback_" + reason
	return d
}

// classifyNoStats R2-19 序 1-3 归因（组内有效端点 E==0 时）：
// 序 1 unreachable（拉取侧置位）→ 序 3 no_samples / low_samples → 序 2 stale。
//
// 口径说明：陈旧（stale）的**时间**判定由数据面拉取侧完成（M2.6 按时钟判 updated_at
// 过期并置 valid=false），保持本包无 wall-clock 依赖（纯逻辑、可离线单测）；本层以
// 「样本充足但仍无效」归因 stale（此时唯一剩余成因即过期淘汰，见 §6.3）。
func (e *Engine) classifyNoStats(minPrio int, cfg LatencyConfig) string {
	if e.ttftUnreachable {
		return fallbackUnreachable
	}
	anySamples := false
	allBelowMin := true
	for _, ep := range e.state {
		if ep.Priority != minPrio || !ep.IsUsable() {
			continue
		}
		if ep.TTFT.Samples > 0 {
			anySamples = true
		}
		if ep.TTFT.Samples >= int64(cfg.MinSamples) {
			allBelowMin = false
		}
	}
	if !anySamples {
		return fallbackNoSamples
	}
	if allBelowMin {
		return fallbackLowSamples
	}
	return fallbackStale
}
