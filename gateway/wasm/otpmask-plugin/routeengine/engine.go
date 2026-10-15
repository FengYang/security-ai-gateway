// Package routeengine — Wasm 数据面的多模型智能路由引擎（P0-1 核心模块）。
//
// 职责：
//   - 根据路由配置（来自 routecache 的 TableRoute.Endpoints）选择目标端点
//   - 维护端点运行时状态（健康度 / 失败率 / 熔断状态）
//   - 支持多策略：主备（priority）、权重（weight）、失败率感知（failure-rate-aware）
//
// 设计原则（极简优先）：
//   - 纯逻辑包，无 envoy/wasm hostcall 依赖，可独立单测
//   - 读路径无锁（状态更新异步，请求路径只做原子读）
//   - 向后兼容：Endpoints 为空时回退到 v1 二元模式（DefaultEngine/FallbackEngine）
//
// 分层：
//
//	routecache.Decide() → routeengine.Engine.PickEndpoint() → 端点选择结果
//	          ↑                      ↑
//	   (已有，复用)          (本包，P0-1 新增)
package routeengine

import (
	"math"
	"sort"
	"sync"
)

// ============================================================
// 端点状态
// ============================================================

// HealthStatus 端点健康状态。
type HealthStatus int

const (
	HealthUnknown   HealthStatus = iota // 初始状态，未探测过
	HealthHealthy                       // 健康
	HealthUnhealthy                     // 不健康
)

// CircuitState 熔断器状态。
type CircuitState int

const (
	CircuitClosed   CircuitState = iota // 正常，流量通过
	CircuitOpen                         // 熔断，流量拒绝
	CircuitHalfOpen                     // 半开，探测中
)

// EndpointState 端点运行时状态（Wasm 侧内存态）。
//
// 设计依据：方案 §5.1.1 EndpointRuntime 四层结构
//   - Config 层：从路由表加载（热更新时整体替换）
//   - Failure 层：EWMA 失败率统计（写路径 CAS，读路径无锁）
//   - CircuitBreaker 层：熔断器三状态机
//   - 流量层：CurrentWeight（被失败率动态调整后）
//
// 并发安全：Wasm 单线程，读写均在同一线程，无需原子操作。
// 配置热更新通过整 map 替换实现原子切换。
type EndpointState struct {
	// —— 配置层（从路由表加载）——
	Name       string  // 端点名称（唯一标识）
	URL        string  // 端点地址
	Priority   int     // 优先级（数字越小越高）
	Enabled    bool    // 是否启用
	BaseWeight float64 // 配置的基础权重（0-1，同优先级组内和为1）

	// —— 失败率统计层（EWMA，方案 §6.2）——
	Failure EWMARate

	// —— 熔断器层（三状态机，方案 §6.3）——
	CircuitBreaker CircuitBreaker

	// —— 流量层（动态权重，被失败率/熔断影响后）——
	Weight float64 // 当前实际权重（0-1，同优先级组内归一化后使用）

	// —— P1-6 延迟统计层（TTFT 快照，值语义、读路径无锁）——
	// 由数据面周期拉取（ttftfetch.go，M2.6）写入；选路时只读，不就地改写（C-3）。
	TTFT TTFTStat
}

// IsUsable 返回端点是否可以被选中（启用 + 非熔断打开 + 权重 > 0）。
// 健康状态通过 EWMA 失败率推导，不单独维护 HealthStatus 字段。
func (e *EndpointState) IsUsable() bool {
	return e.Enabled &&
		e.CircuitBreaker.State != CircuitOpen &&
		e.Weight > 0
}

// ============================================================
// 路由引擎
// ============================================================

// Strategy 路由策略类型。
type Strategy string

const (
	StrategyPriority     Strategy = "priority"      // 主备模式（按优先级）
	StrategyWeighted     Strategy = "weighted"      // 权重模式（同优先级按比例）
	StrategyFailureAware Strategy = "failure-aware" // 失败率感知（动态权重调整）

	// —— P1-6 延迟择优（M1.3；本体 §6.1 strategy 枚举扩展）——
	StrategyLatencyAware   Strategy = "latency-aware"   // TTFT 倒数加权随机（D-3/D-4）
	StrategyLatencyFastest Strategy = "latency-fastest" // 最快优先（确定性；γ→∞ 极限形式）
	StrategyHybrid         Strategy = "hybrid"          // 失败率 × TTFT 三步合并（M1.5）
)

// CanaryConfig 灰度切流配置（方案 §7.5）。
// Enabled=false 或 TargetEndpoint 为空时，灰度功能关闭，Engine 行为不变。
type CanaryConfig struct {
	Enabled            bool     // 是否启用灰度
	TargetEndpoint     string   // 灰度目标端点名称
	TargetWeight       float64  // 目标灰度权重（0-1）
	RampStep           float64  // 每次放量进度步长（0-1）
	RampIntervalMs     int64    // 放量间隔（毫秒）
	RollbackThreshold  float64  // 自动回滚失败率阈值（0-1）
	RollbackMinSamples int64    // 回滚最小样本数
	AllowedTenants     []string // 租户白名单（空=所有租户均参与灰度）
}

// Config 引擎配置（来自路由表的一条 TableRoute 解析结果）。
type Config struct {
	Strategy  Strategy
	Endpoints []EndpointConfig

	// 失败率感知（EWMA）配置
	EWMAAlpha          float64 // 平滑系数，默认 0.1
	EWMAMinSamples     int64   // 最小样本数，默认 10
	EWMADecayHalfLifeS int64   // 时间衰减半衰期（秒），默认 60

	// 动态权重调整配置
	WeightAdjustStep    float64 // 每次调整步长，默认 0.1
	WeightMin           float64 // 最小权重，默认 0.05
	WeightFailureThresh float64 // 失败率降权阈值，默认 0.5
	WeightRecoveryRatio float64 // 恢复阈值比例，默认 0.5

	// 熔断器配置
	CircuitFailureThresh float64 // 熔断失败率阈值，默认 0.5
	CircuitMinSamples    int64   // 熔断最小样本数，默认 10
	CircuitCooldownMs    int64   // 熔断冷却时间（毫秒），默认 30000

	// 灰度切流配置（方案 §7.5，可选）
	Canary CanaryConfig

	// P1-6 延迟择优配置（strategy 为 latency-*/hybrid 时生效；§6.1）
	Latency LatencyConfig
}

// EndpointConfig 端点配置（来自 TableRoute.Endpoints）。
type EndpointConfig struct {
	Name     string
	URL      string
	Weight   float64 // 基础权重 0-1
	Priority int     // 优先级
	Enabled  bool
}

// Decision 一次端点选择的结果。
type Decision struct {
	EndpointName string // 选中的端点名称
	EndpointURL  string // 选中的端点地址
	Strategy     Strategy
	Reason       string // 选择原因（用于日志/审计）
	CanaryGroup  string // 灰度分组：whitelist / treatment / control / ""（无灰度）
}

// BillingNotifier 计费通知接口（P0-1 W4-5 接口预留，方案附录 D）。
//
// P0-1 侧仅定义接口 + 调用点，不做具体实现。
// 实际计费逻辑由 P0-3 计费模块注入实现（如通过 gRPC/HTTP 上报计费服务）。
//
// 设计要点：
//   - RecordUsage 在 RecordResult 之后调用（不阻塞请求路径核心逻辑）
//   - IsRetry 标记本次请求是否为重试（重试不计费，方案 §D.2）
//   - 接口方法应快速返回（异步上报由实现方内部处理）
type BillingNotifier interface {
	// RecordUsage 记录一次端点请求的用量。
	// tenant/model/endpoint：路由维度
	// inputTokens/outputTokens：token 用量（-1 表示未知，如非流式响应尚未统计）
	// isRetry：是否为重试请求（重试不计费）
	// success：请求是否成功（失败是否计费由计费侧策略决定）
	RecordUsage(tenant, model, endpoint string, inputTokens, outputTokens int, isRetry bool, success bool)
}

// SetBillingHook 注册计费通知器（nil = 取消通知）。
// 线程安全：由调用方保证在无请求时设置（如初始化或配置热更新时）。
func (e *Engine) SetBillingHook(hook BillingNotifier) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.billingHook = hook
}

// SetTTFTStatsUnreachable 标记 TTFT 统计通道不可达（R2-19 序 1）。
// 由数据面拉取 tick（M2.6）在控制面不可达 / 聚合器 503 时调用；请求路径只读该标志。
func (e *Engine) SetTTFTStatsUnreachable(v bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.ttftUnreachable = v
}

// SetEndpointTTFT 写入端点 TTFT 统计（M1.6 写入接缝；M2.6 周期拉取 tick 调用）。
//
// 数据面把控制面 stats 下发结果（§6.3；含 valid / updated_at 过期判定后的最终值）
// 写入运行态；未知名返回 false（调用方决定是否计数）。统计值不参与路由表签名
// （D-6）；请求路径只读该字段，写路径显式加锁（engine 锁保护）。
func (e *Engine) SetEndpointTTFT(name string, stat TTFTStat) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	ep, ok := e.state[name]
	if !ok {
		return false
	}
	ep.TTFT = stat
	return true
}

// LatencyConfigOf 返回延迟配置副本（P1-6 M2.6：统计写入侧读取 stale_sec 做过期判定；读路径加锁）。
func (e *Engine) LatencyConfigOf() LatencyConfig {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.config.Latency
}

// TTFTStatsUnreachable 返回统计通道不可达标志（R2-19 序 1；诊断与测试读取）。
func (e *Engine) TTFTStatsUnreachable() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.ttftUnreachable
}

// Engine 路由引擎实例。
//
// 用法：
//  1. NewEngine(config) 创建引擎
//  2. PickEndpoint() / PickEndpointForTenant() 在请求路径调用（快速）
//  3. RecordResult() 记录请求结果（更新 EWMA + 权重 + 熔断器）
//  4. Tick() 周期调用（推进灰度放量 + 自动回滚检测）
//  5. UpdateConfig() / UpdateConfigSmooth() 热更新配置
//  6. SetBillingHook() 注册计费通知器（P0-1 W4-5 接口预留）
type Engine struct {
	mu          sync.RWMutex
	config      Config
	state       map[string]*EndpointState // name -> state
	canary      *CanaryManager            // 灰度管理器（nil = 未启用灰度）
	billingHook BillingNotifier           // 计费通知器（nil = 不通知）

	// P1-6：R2-19 序 1 的控制面不可达标志（数据面拉取 tick 维护；请求路径只读）
	ttftUnreachable bool
}

// NewEngine 创建路由引擎。
// config.Endpoints 为空时引擎仍可工作（PickEndpoint 返回空 Decision），
// 由调用方决定回退逻辑（如走 v1 二元模式 DefaultEngine）。
func NewEngine(config Config) *Engine {
	e := &Engine{
		config: config,
		state:  make(map[string]*EndpointState),
	}
	e.setDefaults()
	e.initState()
	e.initCanary()
	return e
}

// setDefaults 为配置中的零值字段设置默认值（与方案 §4.3 Schema 默认值对齐）。
func (e *Engine) setDefaults() {
	if e.config.EWMAAlpha <= 0 || e.config.EWMAAlpha > 1 {
		e.config.EWMAAlpha = 0.1
	}
	if e.config.EWMAMinSamples <= 0 {
		e.config.EWMAMinSamples = 10
	}
	if e.config.EWMADecayHalfLifeS < 0 {
		e.config.EWMADecayHalfLifeS = 60
	}
	if e.config.WeightAdjustStep <= 0 {
		e.config.WeightAdjustStep = 0.1
	}
	if e.config.WeightMin <= 0 {
		e.config.WeightMin = 0.05
	}
	if e.config.WeightFailureThresh <= 0 {
		e.config.WeightFailureThresh = 0.5
	}
	if e.config.WeightRecoveryRatio <= 0 {
		e.config.WeightRecoveryRatio = 0.5
	}
	if e.config.CircuitFailureThresh <= 0 {
		e.config.CircuitFailureThresh = 0.5
	}
	if e.config.CircuitMinSamples <= 0 {
		e.config.CircuitMinSamples = 10
	}
	if e.config.CircuitCooldownMs <= 0 {
		e.config.CircuitCooldownMs = 30000
	}
}

// initState 从配置初始化端点状态。
func (e *Engine) initState() {
	for _, ep := range e.config.Endpoints {
		baseW := ep.Weight
		if baseW <= 0 {
			baseW = 1.0
		}
		e.state[ep.Name] = &EndpointState{
			Name:       ep.Name,
			URL:        ep.URL,
			Priority:   ep.Priority,
			Enabled:    ep.Enabled,
			BaseWeight: baseW,
			Weight:     baseW,
			Failure: EWMARate{
				Alpha:          e.config.EWMAAlpha,
				MinSamples:     e.config.EWMAMinSamples,
				DecayHalfLifeS: e.config.EWMADecayHalfLifeS,
			},
			CircuitBreaker: CircuitBreaker{
				FailureThreshold: e.config.CircuitFailureThresh,
				MinSamples:       e.config.CircuitMinSamples,
				CooldownMs:       e.config.CircuitCooldownMs,
			},
		}
	}
	// 同优先级组内权重归一化
	e.normalizeAllGroups()
}

// initCanary 初始化灰度管理器（如果配置了灰度）。
// 通过 failureRateFn / setWeightFn 两个回调与 Engine 解耦（方案 §7.5.6）。
func (e *Engine) initCanary() {
	if !e.config.Canary.Enabled || e.config.Canary.TargetEndpoint == "" {
		e.canary = nil
		return
	}
	// 灰度目标端点必须存在
	if _, ok := e.state[e.config.Canary.TargetEndpoint]; !ok {
		e.canary = nil
		return
	}
	targetName := e.config.Canary.TargetEndpoint
	e.canary = NewCanaryManager(
		CanaryEndpointConfig{
			Name:               targetName,
			TargetWeight:       e.config.Canary.TargetWeight,
			RampStep:           e.config.Canary.RampStep,
			RampIntervalMs:     e.config.Canary.RampIntervalMs,
			RollbackThreshold:  e.config.Canary.RollbackThreshold,
			RollbackMinSamples: e.config.Canary.RollbackMinSamples,
			AllowedTenants:     e.config.Canary.AllowedTenants,
		},
		// failureRateFn：从 Engine 状态中取灰度端点的失败率
		func() (float64, bool) {
			ep, ok := e.state[targetName]
			if !ok {
				return 0, false
			}
			return ep.Failure.GetRate(), ep.Failure.Valid()
		},
		// setWeightFn：设置灰度端点的权重（会触发同组归一化）
		func(w float64) {
			ep, ok := e.state[targetName]
			if !ok {
				return
			}
			ep.Weight = w
			e.normalizeGroupByPriority(ep.Priority)
		},
	)
}

// UpdateConfig 热更新配置（原子替换内部状态，RWMutex 写保护）。
// 旧状态的失败率等运行时数据不迁移（配置变更视为重新开始）。
func (e *Engine) UpdateConfig(config Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.config = config
	e.state = make(map[string]*EndpointState, len(config.Endpoints))
	e.initState()
	e.initCanary()
}

// UpdateConfigSmooth 热更新配置（平滑迁移）。
//
// 与 UpdateConfig 的区别：
//   - UpdateConfig：全部重置（旧状态全部丢弃）
//   - UpdateConfigSmooth：同名端点保留 EWMA 失败率和熔断器状态（平滑迁移）
//
// 迁移规则：
//   - 新配置中有、旧状态中也有的端点 → 保留失败率和熔断器状态，更新配置层（权重/优先级/启用）；
//     其中 TTFT 统计（P1-6，TT2-04）：URL 未变保留，URL 变更重置 valid=false
//   - 新配置中有、旧状态中没有的端点 → 全新初始化（TTFT 零值 = valid=false）
//   - 旧状态中有、新配置中没有的端点 → 丢弃（TTFT 随 EndpointState 一并清理）
//   - 配置层变更（如基础权重、优先级）立即生效，失败率统计保留
//
// 设计依据：方案 §4.1 配置热更新（平滑迁移，避免配置变更导致统计丢失、瞬时雪崩）
func (e *Engine) UpdateConfigSmooth(config Config) {
	e.mu.Lock()
	defer e.mu.Unlock()

	oldState := e.state
	e.config = config
	e.setDefaults()
	e.state = make(map[string]*EndpointState, len(config.Endpoints))

	for _, epCfg := range config.Endpoints {
		baseW := epCfg.Weight
		if baseW <= 0 {
			baseW = 1.0
		}

		if oldEp, ok := oldState[epCfg.Name]; ok {
			// 同名端点：保留失败率和熔断器状态，更新配置层
			// TT2-04：URL 变更 → TTFT 重置无效（避免旧地址画像污染新端点）
			if oldEp.URL != epCfg.URL {
				oldEp.TTFT = TTFTStat{}
			}
			oldEp.Name = epCfg.Name
			oldEp.URL = epCfg.URL
			oldEp.Priority = epCfg.Priority
			oldEp.Enabled = epCfg.Enabled
			oldEp.BaseWeight = baseW
			// 权重保留当前动态值，但不超过新的 BaseWeight
			if oldEp.Weight > baseW {
				oldEp.Weight = baseW
			}
			// 更新 EWMA 和熔断器的配置参数（如果新配置指定了不同的参数）
			oldEp.Failure.Alpha = e.config.EWMAAlpha
			oldEp.Failure.MinSamples = e.config.EWMAMinSamples
			oldEp.Failure.DecayHalfLifeS = e.config.EWMADecayHalfLifeS
			oldEp.CircuitBreaker.FailureThreshold = e.config.CircuitFailureThresh
			oldEp.CircuitBreaker.MinSamples = e.config.CircuitMinSamples
			oldEp.CircuitBreaker.CooldownMs = e.config.CircuitCooldownMs

			e.state[epCfg.Name] = oldEp
		} else {
			// 新端点：全新初始化（TTFT 零值 = valid=false，TT2-04）
			e.state[epCfg.Name] = &EndpointState{
				Name:       epCfg.Name,
				URL:        epCfg.URL,
				Priority:   epCfg.Priority,
				Enabled:    epCfg.Enabled,
				BaseWeight: baseW,
				Weight:     baseW,
				Failure: EWMARate{
					Alpha:          e.config.EWMAAlpha,
					MinSamples:     e.config.EWMAMinSamples,
					DecayHalfLifeS: e.config.EWMADecayHalfLifeS,
				},
				CircuitBreaker: CircuitBreaker{
					FailureThreshold: e.config.CircuitFailureThresh,
					MinSamples:       e.config.CircuitMinSamples,
					CooldownMs:       e.config.CircuitCooldownMs,
				},
			}
		}
	}
	// 同优先级组内权重归一化
	e.normalizeAllGroups()
	e.initCanary()
}

// PickEndpoint 根据当前策略选择一个端点。
// 返回空 Decision 表示没有可用端点（调用方应走降级逻辑）。
// 无租户信息时调用此方法；有租户信息时优先用 PickEndpointForTenant。
//
// 并发安全：读路径仅持 RLock，保证请求路径延迟可控。
func (e *Engine) PickEndpoint() Decision {
	return e.PickEndpointForTenant("")
}

// PickEndpointForTenant 带租户灰度判定的端点选择（方案 §7.5.5 租户白名单）。
//
// 灰度逻辑：
//   - 无灰度（canary=nil）→ 直接按策略选，CanaryGroup 为空
//   - 白名单租户 → 强制走灰度端点（若可用），CanaryGroup = "whitelist"
//   - 非白名单 → 按当前权重随机分配，命中灰度端点则 CanaryGroup = "treatment"，否则 "control"
func (e *Engine) PickEndpointForTenant(tenant string) Decision {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if len(e.state) == 0 {
		return Decision{Reason: "no_usable_endpoints"}
	}

	// 无灰度：直接选
	if e.canary == nil {
		return e.pickByStrategy()
	}

	canaryEpName := e.config.Canary.TargetEndpoint
	canaryEp, canaryUsable := e.state[canaryEpName]
	canaryIsUsable := canaryUsable && canaryEp.IsUsable()

	// 白名单租户：强制走灰度端点（若可用）
	if e.canary.IsTenantAllowed(tenant) && canaryIsUsable &&
		e.canary.State().State != CanaryIdle && e.canary.State().State != CanaryRolledBack {
		return Decision{
			EndpointName: canaryEp.Name,
			EndpointURL:  canaryEp.URL,
			Strategy:     e.config.Strategy,
			Reason:       "canary_whitelist",
			CanaryGroup:  "whitelist",
		}
	}

	// 非白名单 / 灰度未启动：按权重策略选择
	decision := e.pickByStrategy()
	if decision.EndpointName == canaryEpName && canaryIsUsable &&
		e.canary.State().State != CanaryIdle && e.canary.State().State != CanaryRolledBack {
		decision.CanaryGroup = "treatment"
	} else if e.canary.State().State != CanaryIdle && e.canary.State().State != CanaryRolledBack {
		decision.CanaryGroup = "control"
	}
	return decision
}

// strategyUnknownObserver 包级未映射策略观测接缝（P1-6 M4.4；R2-17/TT2-11）。
//
// pickByStrategy() 的 default 分支在**每次请求路径命中时**回调（运行时持续可观测，
// 区别于配置加载期的一次性信号）；由插件装配期注入 →
// otpmask_route_strategy_unknown_total + 错误日志。回退动作保持 priority
// （不改既有运行语义）；新增策略须同步登记此处 switch 与插件 routeStrategy()。
var strategyUnknownObserver func(strategy string)

// SetStrategyUnknownObserver 注入未映射策略观测回调（仅装配期调用，单线程语义）。
func SetStrategyUnknownObserver(fn func(strategy string)) { strategyUnknownObserver = fn }

// pickByStrategy 按配置的策略选择端点（内部辅助，调用方持锁）。
// 直接遍历 e.state，零堆分配。
// P1-6（M1.6/M4.4）：latency-aware / latency-fastest / hybrid 分发至 latency.go 实现；
// default = 显式信号（R2-17/TT2-11）：观测回调计数 + 回退 priority（运行语义不变），
// 不再静默。
func (e *Engine) pickByStrategy() Decision {
	switch e.config.Strategy {
	case StrategyPriority:
		return e.pickByPriority()
	case StrategyWeighted, StrategyFailureAware:
		return e.pickByWeight()
	case StrategyLatencyAware:
		return e.pickByLatency()
	case StrategyLatencyFastest:
		return e.pickByLatencyFastest()
	case StrategyHybrid:
		return e.pickByHybrid()
	default:
		if strategyUnknownObserver != nil {
			strategyUnknownObserver(string(e.config.Strategy))
		}
		return e.pickByPriority()
	}
}

// filterUsable 过滤出可用端点（启用 + 非熔断 open + 权重 > 0）。
// 注意：每次调用分配新 slice，仅用于对外 API（UsableEndpointNames）。
// 请求路径的 PickEndpoint 不经过此处，以避免分配。
func (e *Engine) filterUsable() []*EndpointState {
	result := make([]*EndpointState, 0, len(e.state))
	for _, ep := range e.state {
		if ep.IsUsable() {
			result = append(result, ep)
		}
	}
	return result
}

// pickByPriority 按优先级选择：选最高优先级组里第一个可用端点。
// 一次遍历搞定，零分配。
func (e *Engine) pickByPriority() Decision {
	var best *EndpointState
	for _, ep := range e.state {
		if !ep.IsUsable() {
			continue
		}
		if best == nil || ep.Priority < best.Priority {
			best = ep
		}
	}
	if best == nil {
		return Decision{Reason: "no_usable_endpoints"}
	}
	return Decision{
		EndpointName: best.Name,
		EndpointURL:  best.URL,
		Strategy:     StrategyPriority,
		Reason:       "priority",
	}
}

// pickByWeight 按权重随机选择（同优先级内按比例分配）。
// 两遍遍历：第一遍找最高优先级 + 算总权重，第二遍加权随机。
// 零堆分配。
func (e *Engine) pickByWeight() Decision {
	// 第一遍：找最高优先级 + 算该组总权重
	minPrio := math.MaxInt
	var totalWeight float64
	hasUsable := false
	for _, ep := range e.state {
		if !ep.IsUsable() {
			continue
		}
		hasUsable = true
		if ep.Priority < minPrio {
			minPrio = ep.Priority
			totalWeight = ep.Weight
		} else if ep.Priority == minPrio {
			totalWeight += ep.Weight
		}
	}
	if !hasUsable {
		return Decision{Reason: "no_usable_endpoints"}
	}
	if totalWeight <= 0 {
		return Decision{Reason: "no_available_in_priority_group"}
	}

	// 第二遍：加权随机选择。随机源经 §4.7 注入接缝取得（本包不 import 密码）；
	// 随机源未注入/暂不可用 → 确定性取组内第一个（不阻塞请求路径）。
	if rv, ok := randFloat64(); ok {
		r := rv * totalWeight
		var cum float64
		for _, ep := range e.state {
			if !ep.IsUsable() || ep.Priority != minPrio {
				continue
			}
			cum += ep.Weight
			if r < cum {
				return Decision{
					EndpointName: ep.Name,
					EndpointURL:  ep.URL,
					Strategy:     StrategyWeighted,
					Reason:       "weighted_random",
				}
			}
		}
	}
	// 兜底：返回组内第一个（随机源不可用 / 浮点误差防护）
	for _, ep := range e.state {
		if ep.IsUsable() && ep.Priority == minPrio {
			return Decision{
				EndpointName: ep.Name,
				EndpointURL:  ep.URL,
				Strategy:     StrategyWeighted,
				Reason:       "weighted_fallback",
			}
		}
	}
	return Decision{Reason: "no_available_in_priority_group"}
}

// RecordResult 记录一次请求结果（成功/失败），更新 EWMA 失败率、熔断器状态和动态权重。
//
// 处理流程（方案 §6.2 失败率感知 + §6.3 熔断器 + §6.2.3 动态权重）：
//  1. 更新 EWMA 失败率
//  2. 检查熔断器状态机（状态可能变更：Closed↔Open↔HalfOpen）
//  3. 失败率感知策略下，根据新失败率调整端点权重
//  4. 同优先级组内权重归一化
//  5. 计费钩子通知（若注册了 BillingNotifier，方案附录 D）
func (e *Engine) RecordResult(endpointName string, success bool) {
	e.mu.Lock()
	ep, ok := e.state[endpointName]
	if !ok {
		e.mu.Unlock()
		return
	}

	now := nowMs()

	// 1. 更新 EWMA 失败率
	ep.Failure.Record(success, now)

	// 2. 熔断器状态机
	cbChanged := ep.CircuitBreaker.OnResult(success, ep.Failure.GetRate(), ep.Failure.Valid(), now)

	// 3. 失败率感知策略下调整权重
	weightChanged := false
	if e.config.Strategy == StrategyFailureAware && ep.CircuitBreaker.State == CircuitClosed {
		newW, changed := AdjustWeight(
			ep.Weight,
			ep.Failure.GetRate(),
			ep.Failure.Valid(),
			WeightAdjustConfig{
				BaseWeight:       ep.BaseWeight,
				MinWeight:        e.config.WeightMin,
				AdjustStep:       e.config.WeightAdjustStep,
				FailureThreshold: e.config.WeightFailureThresh,
				RecoveryRatio:    e.config.WeightRecoveryRatio,
			},
		)
		if changed {
			ep.Weight = newW
			weightChanged = true
		}
	}

	// 4. 熔断器从 Open 变 HalfOpen 时重置权重到基础值的一半
	//    （熔断恢复期从低权重开始，逐步恢复）
	if cbChanged && ep.CircuitBreaker.State == CircuitHalfOpen {
		ep.Weight = ep.BaseWeight * 0.5
		weightChanged = true
	}

	// 5. 同优先级组内权重归一化
	if weightChanged {
		e.normalizeGroupByPriority(ep.Priority)
	}

	// 计费钩子（在锁外调用，避免持锁时执行可能阻塞的外部调用）
	hook := e.billingHook
	e.mu.Unlock()

	if hook != nil {
		// P0 预留：token 用量未知（-1），非重试（false）
		// 实际 token 计数和重试标记由调用方通过 NotifyUsage 补充
		hook.RecordUsage("", "", endpointName, -1, -1, false, success)
	}
}

// normalizeAllGroups 对所有优先级组做权重归一化。
func (e *Engine) normalizeAllGroups() {
	// 按优先级分组
	prioGroups := make(map[int][]*EndpointState)
	for _, ep := range e.state {
		prioGroups[ep.Priority] = append(prioGroups[ep.Priority], ep)
	}
	for _, group := range prioGroups {
		NormalizeWeights(group)
	}
}

// normalizeGroupByPriority 对指定优先级组做权重归一化。
func (e *Engine) normalizeGroupByPriority(priority int) {
	var group []*EndpointState
	for _, ep := range e.state {
		if ep.Priority == priority {
			group = append(group, ep)
		}
	}
	NormalizeWeights(group)
}

// GetEndpointFailureRate 获取指定端点的当前失败率（用于测试和监控）。
func (e *Engine) GetEndpointFailureRate(endpointName string) (float64, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ep, ok := e.state[endpointName]
	if !ok {
		return 0, false
	}
	return ep.Failure.GetRate(), ep.Failure.Valid()
}

// GetEndpointCircuitState 获取指定端点的熔断器状态（用于测试）。
func (e *Engine) GetEndpointCircuitState(endpointName string) (CircuitState, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ep, ok := e.state[endpointName]
	if !ok {
		return CircuitClosed, false
	}
	return ep.CircuitBreaker.State, true
}

// GetEndpointWeight 获取指定端点的当前权重（用于测试）。
func (e *Engine) GetEndpointWeight(endpointName string) (float64, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ep, ok := e.state[endpointName]
	if !ok {
		return 0, false
	}
	return ep.Weight, true
}

// EndpointCount 返回当前端点数量（用于测试和监控）。
func (e *Engine) EndpointCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.state)
}

// EndpointPriority 返回指定端点的优先级（供降级恢复计数等消费者读取）。
func (e *Engine) EndpointPriority(endpointName string) (int, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ep, ok := e.state[endpointName]
	if !ok {
		return 0, false
	}
	return ep.Priority, true
}

// Tick 周期推进：灰度放量 + 自动回滚检测（方案 §7.5.3 / §7.5.4）。
//
// 由 onTick 事件驱动调用（推荐 10s 间隔），调用方负责时间精度。
// 返回：灰度状态是否变化了（供日志/告警判断）。
// 无灰度时返回 false，零开销。
func (e *Engine) Tick(nowMs int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.canary == nil {
		return false
	}
	return e.canary.Tick(nowMs)
}

// StartCanary 手动启动灰度（从 Idle/RolledBack → RampingUp）。
// 返回 false 表示当前状态不允许启动（如已在放量中）。
func (e *Engine) StartCanary(nowMs int64) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.canary == nil {
		return false
	}
	return e.canary.Start(nowMs)
}

// RollbackCanary 手动触发灰度回滚。
func (e *Engine) RollbackCanary(reason string, nowMs int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.canary == nil {
		return
	}
	e.canary.Rollback(reason, nowMs)
}

// CanarySnapshot 返回灰度状态快照（无灰度返回零值 + false）。
func (e *Engine) CanarySnapshot() (CanaryStateSnapshot, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.canary == nil {
		return CanaryStateSnapshot{}, false
	}
	return e.canary.State(), true
}

// EndpointNames 返回所有端点名称（用于测试和监控）。
func (e *Engine) EndpointNames() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.state))
	for name := range e.state {
		names = append(names, name)
	}
	return names
}

// UsableEndpointNames 返回可用端点名称（启用 + 熔断非 open + 权重 > 0），按名称升序。
// 供非流式重试（方案 §6.5.4 NextEndpoint）筛选重试候选端点：
// 熔断打开的端点天然不在结果内，等价于 §6.8「熔断打开时禁止重试该端点」的硬约束。
func (e *Engine) UsableEndpointNames() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	names := make([]string, 0, len(e.state))
	for _, ep := range e.state {
		if ep.IsUsable() {
			names = append(names, ep.Name)
		}
	}
	sort.Strings(names)
	return names
}

// EndpointURL 返回指定端点的 URL（供重试时向新端点重新派发）。
func (e *Engine) EndpointURL(name string) (string, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	ep, ok := e.state[name]
	if !ok {
		return "", false
	}
	return ep.URL, true
}

// EndpointStates 返回端点状态的独立副本（供降级评估等内部消费者读取）。
// 返回副本而非内部指针，避免调用方在锁外读到并发修改的字段。
func (e *Engine) EndpointStates() []*EndpointState {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*EndpointState, 0, len(e.state))
	for _, ep := range e.state {
		cp := *ep
		out = append(out, &cp)
	}
	return out
}

// ============================================================
// 无状态端点选择（纯函数，W2 接线用）
// ============================================================

// Endpoint 端点配置（无状态选择用，最小字段集）。
type Endpoint struct {
	Name     string
	URL      string
	Weight   float64 // 0-1
	Priority int     // 数字越小优先级越高
	Enabled  bool
}

// PickEndpoint 无状态端点选择（纯函数，不依赖任何运行时状态）。
// 适用于 W2 接线阶段：每次请求从路由表读出 Endpoints，直接调用此函数选择。
// 后续失败率感知/熔断等有状态逻辑由 Engine 类型承载。
//
// strategy: "priority"（主备）或 "weighted"（权重）。空值 = priority。
// 返回空 Decision 表示无可用端点。
func PickEndpoint(endpoints []Endpoint, strategy Strategy) Decision {
	usable := filterEndpoints(endpoints)
	if len(usable) == 0 {
		return Decision{Reason: "no_usable_endpoints"}
	}
	switch strategy {
	case StrategyWeighted:
		return pickByWeightStateless(usable)
	default:
		return pickByPriorityStateless(usable)
	}
}

// filterEndpoints 过滤出启用的端点。
func filterEndpoints(eps []Endpoint) []Endpoint {
	result := make([]Endpoint, 0, len(eps))
	for _, ep := range eps {
		if ep.Enabled && ep.Weight > 0 {
			result = append(result, ep)
		}
	}
	return result
}

// pickByPriorityStateless 按优先级选：最高优先级组第一个。
func pickByPriorityStateless(usable []Endpoint) Decision {
	best := usable[0]
	for _, ep := range usable[1:] {
		if ep.Priority < best.Priority {
			best = ep
		}
	}
	return Decision{
		EndpointName: best.Name,
		EndpointURL:  best.URL,
		Strategy:     StrategyPriority,
		Reason:       "priority",
	}
}

// pickByWeightStateless 按权重随机选择（同优先级组内加权随机）。
func pickByWeightStateless(usable []Endpoint) Decision {
	if len(usable) == 0 {
		return Decision{Reason: "no_usable_endpoints"}
	}
	// 找出最高优先级
	minPrio := int(^uint(0) >> 1) // MaxInt
	for _, ep := range usable {
		if ep.Priority < minPrio {
			minPrio = ep.Priority
		}
	}
	// 收集最高优先级组
	var group []Endpoint
	var totalWeight float64
	for _, ep := range usable {
		if ep.Priority == minPrio {
			group = append(group, ep)
			totalWeight += ep.Weight
		}
	}
	if len(group) == 0 || totalWeight <= 0 {
		return Decision{Reason: "no_available_in_priority_group"}
	}
	// 加权随机（随机源经 §4.7 注入；不可用 → 确定性取组内第一个）
	if rv, ok := randFloat64(); ok {
		r := rv * totalWeight
		var cum float64
		for _, ep := range group {
			cum += ep.Weight
			if r < cum {
				return Decision{
					EndpointName: ep.Name,
					EndpointURL:  ep.URL,
					Strategy:     StrategyWeighted,
					Reason:       "weighted_random",
				}
			}
		}
	}
	return Decision{
		EndpointName: group[0].Name,
		EndpointURL:  group[0].URL,
		Strategy:     StrategyWeighted,
		Reason:       "weighted_fallback",
	}
}

// ============================================================
// 随机源接缝（§4.7 分层：本包不 import 密码/hostcall）
// ============================================================

// RandSource 加权选择的随机源接缝：由插件在装配期注入经 cryptop sidecar `/v1/rand`
// （B-4.6-2）的实现；单测注入**同步**实现即可令 CPS 调用同步完成（同 cryptoseam_test.go 手法）。
type RandSource interface {
	// Float64 返回 [0,1) 均匀随机数；随机源暂不可用时返回 ok=false
	// （调用方按确定性主备回退，不阻塞请求路径、不回退插件内密码运算）。
	Float64() (v float64, ok bool)
}

// randSource 进程级随机源（wasm 单线程：装配期写入、请求期只读）。
var randSource RandSource

// SetRandSource 注入随机源（nil = 未注入 → 加权选择回退确定性主备）。
func SetRandSource(rs RandSource) { randSource = rs }

// randFloat64 取一个 [0,1) 随机数；随机源未注入/暂不可用返回 (0,false)。
func randFloat64() (float64, bool) {
	if randSource == nil {
		return 0, false
	}
	return randSource.Float64()
}
