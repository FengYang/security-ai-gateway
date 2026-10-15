package route

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"security-ai-gateway/gateway/cryptop"
)

// cryptoProvider 路由表签名/验签所用 Provider（P0-4 §5.4.4 组⑫）：
// profile 取自 `CRYPTO_PROFILE`（§12.3；默认 intl，与现役 HMAC-SHA256 逐字节等价）。
var cryptoProvider = newCryptoProvider()

func newCryptoProvider() cryptop.Provider {
	profile := os.Getenv("CRYPTO_PROFILE")
	if profile == "" {
		profile = string(cryptop.ProfileIntl)
	}
	p, err := cryptop.New(cryptop.Profile(profile))
	if err != nil {
		panic("route: 初始化 cryptop provider 失败（CRYPTO_PROFILE=" + profile + "）: " + err.Error())
	}
	return p
}

// EndpointAuth 端点凭证配置（方案 §9.2）。
// P0 支持 km:// / file:// / env:// 三种 secret_ref scheme。
type EndpointAuth struct {
	Type      string `json:"type,omitempty"`       // 认证类型：bearer / apikey / none
	SecretRef string `json:"secret_ref,omitempty"` // 密钥引用：km://<path> / file://<path> / env://<name>
}

// TableEndpoint 路由表中的端点配置（P0-1 多端点权重路由）。
// 向后兼容：TableRoute 保留 DefaultEngine/FallbackEngine（v1 二元模式），
// Endpoints 为 v2 多端点增强字段。当 Endpoints 非空时优先使用多端点模式。
type TableEndpoint struct {
	Name     string       `json:"name"`               // 端点名称（唯一标识）
	URL      string       `json:"url,omitempty"`      // 端点地址
	Weight   float64      `json:"weight,omitempty"`   // 权重（0-1），同优先级内按比例分配
	Priority int          `json:"priority,omitempty"` // 优先级（数字越小越高，1=主，2=备1...）
	Enabled  bool         `json:"enabled,omitempty"`  // 是否启用（缺省 true）
	Auth     EndpointAuth `json:"auth,omitempty"`     // P0 端点凭证配置
}

// RouteCanary 灰度切流配置（方案 §7.5）。
// 零值 = 未启用灰度。
type RouteCanary struct {
	Enabled            bool     `json:"enabled,omitempty"`
	TargetEndpoint     string   `json:"target_endpoint,omitempty"`
	TargetWeight       float64  `json:"target_weight,omitempty"`
	RampStep           float64  `json:"ramp_step,omitempty"`
	RampIntervalMs     int64    `json:"ramp_interval_ms,omitempty"`
	RollbackThreshold  float64  `json:"rollback_threshold,omitempty"`
	RollbackMinSamples int64    `json:"rollback_min_samples,omitempty"`
	AllowedTenants     []string `json:"allowed_tenants,omitempty"`
}

// RouteLatency 延迟择优配置段（P1-6 M4.1，本体 v1.5 §6.1 字段表；JSON 严格对齐）。
//
// 字段存在性（关键：C-5 签名一致性 + 缺省填充口径，M4.5）：
//   - `gamma` / `min_weight` / `explore_ratio` / `cache_partition` 的**显式零值合法**
//     （γ=0 退化为均匀、min_weight=0 无下界、explore_ratio=0 纯利用、
//     cache_partition=false 不分层），以指针类型区分「未配置（M4.5 填缺省）」与「显式零值」；
//   - `window_sec` / `min_samples` / `stale_sec` / `max_ttft_ms` / `quantile` 的零值
//     非法（M4.3 Validate 拒绝），值类型即可区分缺省（M4.5 按零值填默认）。
//
// 本结构在 gateway-core `internal/route` 与 routecache **两侧同构**（签名逐字节一致，C-5）。
type RouteLatency struct {
	WindowSec      int      `json:"window_sec,omitempty"`      // 滑窗长度（秒），默认 300，范围 60–3600（T 固定 25s，N=ceil(window_sec/25)，R2-08）
	Quantile       string   `json:"quantile,omitempty"`        // 参考延迟分位："p50"/"p95"，默认 "p95"
	Gamma          *float64 `json:"gamma,omitempty"`           // 倒数幂指数 γ，默认 1.0，范围 0–5（D-3；0 合法）
	MinWeight      *float64 `json:"min_weight,omitempty"`      // 归一化前相对权重下界，默认 0.05，范围 0–0.5（D-4；0 合法）
	ExploreRatio   *float64 `json:"explore_ratio,omitempty"`   // 探索概率，默认 0.05，范围 0–1（D-4；0 合法）
	MinSamples     int      `json:"min_samples,omitempty"`     // 样本不足判无效，默认 20，≥1（D-8）
	StaleSec       int      `json:"stale_sec,omitempty"`       // 统计过期阈值（秒），默认 75，≥25 且 ≥2×上报周期（D-8）
	CachePartition *bool    `json:"cache_partition,omitempty"` // 按 cache 分层统计，默认 true（D-10；false 合法）
	MaxTTFTMs      int64    `json:"max_ttft_ms,omitempty"`     // 采样上限（毫秒），默认 30000，≥1000（超时按上限归桶，抑制离群）
}

// TableRoute 默认路由表的一条记录：tenant+model → 目标引擎与端点（拉路径 L2 兜底）。
// 向后兼容：DefaultEngine / FallbackEngine 为 v1 二元模式字段，保留不动；
// Endpoints 为 v2 多端点权重路由新增字段。两端通过 CanonicalBytes 保证签名一致。
type TableRoute struct {
	Tenant         string          `json:"tenant"`
	Model          string          `json:"model"`
	DefaultEngine  string          `json:"default_engine"`
	FallbackEngine string          `json:"fallback_engine,omitempty"`
	Target         string          `json:"target,omitempty"`    // 可选：显式目标端点（缺省用引擎默认）
	Endpoints      []TableEndpoint `json:"endpoints,omitempty"` // P0-1 新增：多端点权重配置
	// P0-1 新增：多端点路由策略（priority 主备 / weighted 权重 / failure-aware 失败率感知）。
	// 空 = priority（缺省，与既有行为一致）。仅在 Endpoints 非空时生效。
	Strategy string       `json:"strategy,omitempty"`
	Canary   *RouteCanary `json:"canary,omitempty"` // P0-1 新增：灰度切流配置（§7.5）
	// P1-6 新增：延迟择优配置段（omitempty：旧表序列化逐字节不变，C-5）。
	// strategy 为 latency-aware / latency-fastest / hybrid 时必须携带本段（M4.3 Validate 校验）。
	Latency *RouteLatency `json:"latency,omitempty"`
}

// RouteTable 默认路由表（gateway-core 为事实源，签名后经 GET /routes 下发）。
type RouteTable struct {
	Version   int          `json:"version"`
	UpdatedAt int64        `json:"updated_at"`
	Routes    []TableRoute `json:"routes"`
	Signature []byte       `json:"signature"` // HMAC over canonical(version||updatedAt||routes)
}

// CanonicalBytes 生成不含签名的规范字节序列，用于签发/验签。
// 字段顺序固定，保证 gateway-core 与插件两侧 marshal 一致。
func (t *RouteTable) CanonicalBytes() ([]byte, error) {
	payload := struct {
		Version   int          `json:"version"`
		UpdatedAt int64        `json:"updated_at"`
		Routes    []TableRoute `json:"routes"`
	}{t.Version, t.UpdatedAt, t.Routes}
	return json.Marshal(payload)
}

// SignTable 对路由表签名并写入 Signature 字段。同一 Signer（K_rx）。
func (s *Signer) SignTable(t *RouteTable) error {
	canon, err := t.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("route: 路由表编码失败: %w", err)
	}
	// MAC 经 cryptop（intl=HMAC-SHA256；sm=HMAC-SM3；§5.4.4 组⑫）。
	t.Signature = cryptoProvider.HMAC(s.key, canon)
	return nil
}

// VerifyTable 校验路由表签名，返回是否有效。
func (s *Signer) VerifyTable(t *RouteTable) bool {
	canon, err := t.CanonicalBytes()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(t.Signature, cryptoProvider.HMAC(s.key, canon)) == 1
}

// Lookup 在路由表中按 tenant+model 精确查找；未命中返回 nil。
func (t *RouteTable) Lookup(tenant, model string) *TableRoute {
	for i := range t.Routes {
		r := &t.Routes[i]
		if r.Tenant == tenant && r.Model == model {
			return r
		}
	}
	return nil
}

// NewRouteTable 构造路由表并返回空实例（routing 由调用方填充）。
func NewRouteTable(version int, nowUnix int64) *RouteTable {
	return &RouteTable{Version: version, UpdatedAt: nowUnix, Routes: []TableRoute{}}
}

// ============================================================
// Validate：Schema + 逻辑校验（方案 §7.5.7 + §4.1.3）
// ============================================================

// Validate 校验路由表合法性（逐条路由 + 端点 + 灰度配置）。
// 空表合法（version=0, routes=[]）。
func (t *RouteTable) Validate() error {
	seen := make(map[string]bool)
	for i := range t.Routes {
		r := &t.Routes[i]
		key := r.Tenant + "\x00" + r.Model
		if seen[key] {
			return fmt.Errorf("route: 重复路由 tenant=%q model=%q", r.Tenant, r.Model)
		}
		seen[key] = true
		if err := r.Validate(); err != nil {
			return fmt.Errorf("route[%d] tenant=%q model=%q: %w", i, r.Tenant, r.Model, err)
		}
	}
	return nil
}

// Validate 校验单条路由配置的合法性。
func (r *TableRoute) Validate() error {
	if r.Tenant == "" {
		return fmt.Errorf("tenant 不能为空")
	}
	if r.Model == "" {
		return fmt.Errorf("model 不能为空")
	}
	// 多端点模式校验
	if len(r.Endpoints) > 0 {
		names := make(map[string]bool)
		for j, ep := range r.Endpoints {
			if ep.Name == "" {
				return fmt.Errorf("endpoints[%d].name 不能为空", j)
			}
			if names[ep.Name] {
				return fmt.Errorf("endpoints[%d].name 重复: %s", j, ep.Name)
			}
			names[ep.Name] = true
			if ep.URL == "" && ep.Enabled {
				return fmt.Errorf("endpoints[%d].url 不能为空（启用的端点必须有地址）", j)
			}
			if ep.Weight < 0 || ep.Weight > 1 {
				return fmt.Errorf("endpoints[%d].weight 须在 [0,1] 范围内，got %f", j, ep.Weight)
			}
			if ep.Priority < 0 {
				return fmt.Errorf("endpoints[%d].priority 须为非负整数，got %d", j, ep.Priority)
			}
			// auth.secret_ref scheme 校验（P0: km:// / file:// / env://）
			if ep.Auth.SecretRef != "" {
				if err := validateSecretRef(ep.Auth.SecretRef); err != nil {
					return fmt.Errorf("endpoints[%d].auth.secret_ref 无效: %w", j, err)
				}
			}
		}
		// 策略枚举校验（P1-6 M4.3：扩展延迟择优三策略，§6.1）
		switch r.Strategy {
		case "", "priority", "weighted", "failure-rate-aware",
			"latency-aware", "latency-fastest", "hybrid":
			// 合法
		default:
			return fmt.Errorf("strategy 不合法: %q（支持 priority/weighted/failure-rate-aware/latency-aware/latency-fastest/hybrid）", r.Strategy)
		}
		// strategy 与 latency 段一致性 + latency 段范围校验（P1-6 M4.3；§6.1）
		latencyStrategy := r.Strategy == "latency-aware" || r.Strategy == "latency-fastest" || r.Strategy == "hybrid"
		if latencyStrategy && r.Latency == nil {
			return fmt.Errorf("strategy %q 必须携带 latency 段（§6.1）", r.Strategy)
		}
		if r.Latency != nil {
			if !latencyStrategy {
				return fmt.Errorf("latency 段仅适用于 latency-aware/latency-fastest/hybrid（当前 strategy=%q）", r.Strategy)
			}
			if err := r.Latency.validate(); err != nil {
				return fmt.Errorf("latency 配置无效: %w", err)
			}
		}
		// 灰度配置校验（启用才校验）
		if r.Canary != nil && r.Canary.Enabled {
			if err := r.Canary.validate(r.Endpoints); err != nil {
				return fmt.Errorf("canary 配置无效: %w", err)
			}
		}
	}
	return nil
}

// validateSecretRef 校验 secret_ref 的 scheme（P0 支持 km:// / file:// / env://）。
func validateSecretRef(ref string) error {
	if len(ref) < 5 { // "km://" 最短 5，实际还需 path
		return fmt.Errorf("格式错误（须为 km://<path> / file://<path> / env://<name>）")
	}
	switch {
	case len(ref) >= 5 && ref[:5] == "km://":
		if len(ref) == 5 {
			return fmt.Errorf("km:// 后路径不能为空")
		}
	case len(ref) >= 7 && ref[:7] == "file://":
		if len(ref) == 7 {
			return fmt.Errorf("file:// 后路径不能为空")
		}
	case len(ref) >= 6 && ref[:6] == "env://":
		if len(ref) == 6 {
			return fmt.Errorf("env:// 后变量名不能为空")
		}
	default:
		return fmt.Errorf("不支持的 scheme（P0 仅支持 km:// / file:// / env://）")
	}
	return nil
}

// validate 校验灰度配置（方案 §7.5.7 核心规则）。
func (c *RouteCanary) validate(endpoints []TableEndpoint) error {
	if c.TargetEndpoint == "" {
		return fmt.Errorf("target_endpoint 不能为空")
	}
	// 目标端点必须存在
	found := false
	for _, ep := range endpoints {
		if ep.Name == c.TargetEndpoint {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("target_endpoint %q 不在端点列表中", c.TargetEndpoint)
	}
	if c.TargetWeight <= 0 || c.TargetWeight > 1 {
		return fmt.Errorf("target_weight 须在 (0,1] 范围内，got %f", c.TargetWeight)
	}
	if c.RampStep <= 0 || c.RampStep > 1 {
		return fmt.Errorf("ramp_step 须在 (0,1] 范围内，got %f", c.RampStep)
	}
	if c.RampIntervalMs <= 0 {
		return fmt.Errorf("ramp_interval_ms 须为正整数，got %d", c.RampIntervalMs)
	}
	if c.RollbackThreshold <= 0 || c.RollbackThreshold > 1 {
		return fmt.Errorf("rollback_threshold 须在 (0,1] 范围内，got %f", c.RollbackThreshold)
	}
	if c.RollbackMinSamples < 0 {
		return fmt.Errorf("rollback_min_samples 须为非负整数，got %d", c.RollbackMinSamples)
	}
	return nil
}

// validate 校验 latency 段的取值范围（P1-6 M4.3；§6.1 字段表约束）。
// 零值/指针 nil 表示「未配置」（缺省填充在 M4.5 buildEngineConfig），不参与范围校验；
// 显式零值合法字段（gamma / min_weight / explore_ratio / cache_partition）如实校验。
func (l *RouteLatency) validate() error {
	if l.WindowSec != 0 && (l.WindowSec < 60 || l.WindowSec > 3600) {
		return fmt.Errorf("window_sec 须在 [60,3600]，got %d", l.WindowSec)
	}
	switch l.Quantile {
	case "", "p50", "p95":
		// 合法（"" = 缺省 p95）
	default:
		return fmt.Errorf("quantile 须为 p50/p95，got %q", l.Quantile)
	}
	if l.Gamma != nil && (*l.Gamma < 0 || *l.Gamma > 5) {
		return fmt.Errorf("gamma 须在 [0,5]，got %v", *l.Gamma)
	}
	if l.MinWeight != nil && (*l.MinWeight < 0 || *l.MinWeight > 0.5) {
		return fmt.Errorf("min_weight 须在 [0,0.5]，got %v", *l.MinWeight)
	}
	if l.ExploreRatio != nil && (*l.ExploreRatio < 0 || *l.ExploreRatio > 1) {
		return fmt.Errorf("explore_ratio 须在 [0,1]，got %v", *l.ExploreRatio)
	}
	if l.MinSamples < 0 {
		return fmt.Errorf("min_samples 须为非负整数（0=缺省 20），got %d", l.MinSamples)
	}
	if l.StaleSec != 0 && l.StaleSec < 25 {
		return fmt.Errorf("stale_sec 须 ≥25（且 ≥2×上报周期），got %d", l.StaleSec)
	}
	if l.MaxTTFTMs != 0 && l.MaxTTFTMs < 1000 {
		return fmt.Errorf("max_ttft_ms 须 ≥1000，got %d", l.MaxTTFTMs)
	}
	return nil
}

// ============================================================
// Clone：深拷贝
// ============================================================

// Clone 返回路由表的深拷贝（含签名）。
func (t *RouteTable) Clone() *RouteTable {
	if t == nil {
		return nil
	}
	routes := make([]TableRoute, len(t.Routes))
	for i, r := range t.Routes {
		eps := make([]TableEndpoint, len(r.Endpoints))
		copy(eps, r.Endpoints)
		routes[i] = r
		routes[i].Endpoints = eps
		if r.Canary != nil {
			canary := *r.Canary
			tenants := make([]string, len(r.Canary.AllowedTenants))
			copy(tenants, r.Canary.AllowedTenants)
			canary.AllowedTenants = tenants
			routes[i].Canary = &canary
		}
		if r.Latency != nil {
			routes[i].Latency = cloneRouteLatency(r.Latency)
		}
	}
	sig := make([]byte, len(t.Signature))
	copy(sig, t.Signature)
	return &RouteTable{
		Version:   t.Version,
		UpdatedAt: t.UpdatedAt,
		Routes:    routes,
		Signature: sig,
	}
}

// cloneRouteLatency 深拷贝 latency 段（含指针字段，P1-6 M4.1）。
func cloneRouteLatency(l *RouteLatency) *RouteLatency {
	if l == nil {
		return nil
	}
	cp := *l
	if l.Gamma != nil {
		v := *l.Gamma
		cp.Gamma = &v
	}
	if l.MinWeight != nil {
		v := *l.MinWeight
		cp.MinWeight = &v
	}
	if l.ExploreRatio != nil {
		v := *l.ExploreRatio
		cp.ExploreRatio = &v
	}
	if l.CachePartition != nil {
		v := *l.CachePartition
		cp.CachePartition = &v
	}
	return &cp
}

// ============================================================
// Diff：差异比较（用于审计链记录）
// ============================================================

// RouteChange 单条路由变更记录。
type RouteChange struct {
	Tenant string `json:"tenant"`
	Model  string `json:"model"`
	Change string `json:"change"` // add / remove / modify
	Field  string `json:"field,omitempty"`
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
}

// DiffRoutes 比较两张路由表的差异（逐条路由粒度）。
// 仅比较业务字段（不含 version/updated_at/signature）。
func DiffRoutes(a, b *RouteTable) []RouteChange {
	var changes []RouteChange
	aMap := make(map[string]*TableRoute)
	if a != nil {
		for i := range a.Routes {
			key := a.Routes[i].Tenant + "\x00" + a.Routes[i].Model
			aMap[key] = &a.Routes[i]
		}
	}
	bMap := make(map[string]*TableRoute)
	if b != nil {
		for i := range b.Routes {
			key := b.Routes[i].Tenant + "\x00" + b.Routes[i].Model
			bMap[key] = &b.Routes[i]
		}
	}
	// 新增 + 修改
	for key, br := range bMap {
		ar, ok := aMap[key]
		if !ok {
			changes = append(changes, RouteChange{
				Tenant: br.Tenant, Model: br.Model, Change: "add",
			})
			continue
		}
		diffs := diffRouteFields(ar, br)
		changes = append(changes, diffs...)
	}
	// 删除
	for key, ar := range aMap {
		if _, ok := bMap[key]; !ok {
			changes = append(changes, RouteChange{
				Tenant: ar.Tenant, Model: ar.Model, Change: "remove",
			})
		}
	}
	return changes
}

// diffRouteFields 逐条比较两条路由的字段差异。
func diffRouteFields(a, b *TableRoute) []RouteChange {
	var changes []RouteChange
	key := a.Tenant + "\x00" + a.Model
	_ = key
	if a.DefaultEngine != b.DefaultEngine {
		changes = append(changes, RouteChange{
			Tenant: a.Tenant, Model: a.Model, Change: "modify",
			Field: "default_engine", Old: a.DefaultEngine, New: b.DefaultEngine,
		})
	}
	if a.FallbackEngine != b.FallbackEngine {
		changes = append(changes, RouteChange{
			Tenant: a.Tenant, Model: a.Model, Change: "modify",
			Field: "fallback_engine", Old: a.FallbackEngine, New: b.FallbackEngine,
		})
	}
	if a.Strategy != b.Strategy {
		changes = append(changes, RouteChange{
			Tenant: a.Tenant, Model: a.Model, Change: "modify",
			Field: "strategy", Old: a.Strategy, New: b.Strategy,
		})
	}
	// 端点列表：简化比较（端点数量/名称集合变化即记一条）
	if !endpointsEqual(a.Endpoints, b.Endpoints) {
		oldSummary := fmt.Sprintf("%d endpoints", len(a.Endpoints))
		newSummary := fmt.Sprintf("%d endpoints", len(b.Endpoints))
		changes = append(changes, RouteChange{
			Tenant: a.Tenant, Model: a.Model, Change: "modify",
			Field: "endpoints", Old: oldSummary, New: newSummary,
		})
	}
	// 灰度配置：启用状态变化即记一条
	aCanaryEnabled := a.Canary != nil && a.Canary.Enabled
	bCanaryEnabled := b.Canary != nil && b.Canary.Enabled
	if aCanaryEnabled != bCanaryEnabled {
		changes = append(changes, RouteChange{
			Tenant: a.Tenant, Model: a.Model, Change: "modify",
			Field: "canary.enabled",
			Old:   fmt.Sprintf("%v", aCanaryEnabled),
			New:   fmt.Sprintf("%v", bCanaryEnabled),
		})
	}
	// latency 段（P1-6 M4.1）：按子字段记录（latency.<字段>；nil 段 ≡ 全缺省）
	changes = append(changes, diffLatencyFields(a, b)...)
	return changes
}

// latencyFieldNames latency 段子字段名（按 §6.1 顺序；与 latencyFields 一一对应）。
var latencyFieldNames = [...]string{
	"window_sec", "quantile", "gamma", "min_weight", "explore_ratio",
	"min_samples", "stale_sec", "cache_partition", "max_ttft_ms",
}

// diffLatencyFields 比较 latency 段（nil 段 ≡ 全缺省/空段），按子字段记录变更
// （Field 形如 "latency.gamma"，对齐 canary.enabled 既有粒度，P1-6 M4.1）。
// 显式零值（指针非 nil）与缺省可区分：如 gamma=0 显式配置记录 "(缺省)" → "0"。
func diffLatencyFields(a, b *TableRoute) []RouteChange {
	af := latencyFields(a.Latency)
	bf := latencyFields(b.Latency)
	var changes []RouteChange
	for i, name := range latencyFieldNames {
		if af[i] == bf[i] {
			continue
		}
		changes = append(changes, RouteChange{
			Tenant: a.Tenant, Model: a.Model, Change: "modify",
			Field: "latency." + name, Old: af[i], New: bf[i],
		})
	}
	return changes
}

// latencyFields 返回 latency 段按 §6.1 顺序的子字段显示值（审计 diff 用）。
// nil 段 → 全 "(缺省)"；值类型零值 → "(缺省)"（零值非法或即缺省，M4.3）；
// 指针字段非 nil 时如实显示（含显式零值，如 gamma=0 / cache_partition=false）。
func latencyFields(l *RouteLatency) [9]string {
	const def = "(缺省)"
	if l == nil {
		return [9]string{def, def, def, def, def, def, def, def, def}
	}
	s := func(v string) string {
		if v == "" {
			return def
		}
		return v
	}
	i := func(v int) string {
		if v == 0 {
			return def
		}
		return strconv.Itoa(v)
	}
	i64 := func(v int64) string {
		if v == 0 {
			return def
		}
		return strconv.FormatInt(v, 10)
	}
	f := func(p *float64) string {
		if p == nil {
			return def
		}
		return strconv.FormatFloat(*p, 'g', -1, 64)
	}
	bl := func(p *bool) string {
		if p == nil {
			return def
		}
		return strconv.FormatBool(*p)
	}
	return [9]string{
		i(l.WindowSec), s(l.Quantile), f(l.Gamma), f(l.MinWeight), f(l.ExploreRatio),
		i(l.MinSamples), i(l.StaleSec), bl(l.CachePartition), i64(l.MaxTTFTMs),
	}
}

// endpointsEqual 两个端点列表是否相等（逐字段比较）。
func endpointsEqual(a, b []TableEndpoint) bool {
	if len(a) != len(b) {
		return false
	}
	bMap := make(map[string]TableEndpoint)
	for _, ep := range b {
		bMap[ep.Name] = ep
	}
	for _, ep := range a {
		bep, ok := bMap[ep.Name]
		if !ok {
			return false
		}
		if ep.URL != bep.URL || ep.Weight != bep.Weight ||
			ep.Priority != bep.Priority || ep.Enabled != bep.Enabled ||
			ep.Auth.Type != bep.Auth.Type || ep.Auth.SecretRef != bep.Auth.SecretRef {
			return false
		}
	}
	return true
}
