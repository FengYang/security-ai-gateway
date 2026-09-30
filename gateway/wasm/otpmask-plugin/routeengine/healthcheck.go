package routeengine

import (
	"time"
)

// HealthCheckMode 健康检查模式
type HealthCheckMode int

const (
	// HealthCheckPassive 纯被动模式：仅依赖真实流量的失败统计
	HealthCheckPassive HealthCheckMode = iota
	// HealthCheckActive 纯主动模式：仅依赖主动探测结果
	HealthCheckActive
	// HealthCheckMixed 混合模式（推荐）：低流量端点主动探测，高流量端点被动统计
	HealthCheckMixed
)

func (m HealthCheckMode) String() string {
	switch m {
	case HealthCheckPassive:
		return "PASSIVE"
	case HealthCheckActive:
		return "ACTIVE"
	case HealthCheckMixed:
		return "MIXED"
	default:
		return "UNKNOWN"
	}
}

// HealthCheckConfig 健康检查配置
type HealthCheckConfig struct {
	// 模式：PASSIVE / ACTIVE / MIXED
	Mode HealthCheckMode
	// 主动检查间隔（毫秒）
	IntervalMs int
	// 低流量阈值：每秒请求数低于此值视为低流量（MIXED 模式下触发主动检查）
	LowTrafficRPS float64
	// 每次主动检查的请求超时（毫秒，仅作记录用，实际超时由调用方控制）
	TimeoutMs int
	// 连续成功 N 次后将熔断端点恢复（与被动恢复并行）
	SuccessThreshold int
	// 连续失败 N 次后标记不健康（主动模式下）
	FailureThreshold int
}

// 默认健康检查配置
func defaultHealthCheckConfig() HealthCheckConfig {
	return HealthCheckConfig{
		Mode:             HealthCheckPassive,
		IntervalMs:       5000,
		LowTrafficRPS:    1.0,
		TimeoutMs:        3000,
		SuccessThreshold: 3,
		FailureThreshold: 3,
	}
}

// HealthChecker 主动健康检查管理器
//
// 职责：
//   - 跟踪每个端点的最近流量，判断是否需要主动检查
//   - 调度检查时机（按间隔）
//   - 处理主动检查结果（通过 Engine.RecordResult 回写）
//
// 设计原则：
//   - Engine 层不感知 HTTP，仅提供接口
//   - 实际探测由插件层（onTick → HTTP callout）完成
//   - HealthChecker 只负责调度决策和结果聚合
type HealthChecker struct {
	config HealthCheckConfig

	// 端点主动检查状态（按端点名索引）
	// 注：与 Engine.state 解耦，HealthChecker 通过回调读写 Engine 状态
	epState map[string]*healthEpState

	// 回调：获取端点最近的请求速率（RPS）
	getRPSFn func(endpointName string) (float64, bool)
	// 回调：记录一次主动检查结果（成功/失败）
	recordResultFn func(endpointName string, success bool)
	// 回调：获取端点当前是否熔断（用于跳过已熔断端点的检查频率控制）
	isCircuitOpenFn func(endpointName string) bool

	// 当前时间（毫秒），支持测试注入
	nowMs      int64
	nowInjected bool
}

// healthEpState 单个端点的主动检查状态
type healthEpState struct {
	Name              string
	LastCheckMs       int64  // 上次检查时间
	ConsecutiveSuccess int   // 连续成功次数
	ConsecutiveFail   int   // 连续失败次数
	ActiveUnhealthy   bool  // 主动检查判定为不健康
	InCheckFlight     bool  // 有检查进行中（防止并发重复检查）
}

// NewHealthChecker 创建健康检查管理器
func NewHealthChecker(
	config HealthCheckConfig,
	getRPSFn func(endpointName string) (float64, bool),
	recordResultFn func(endpointName string, success bool),
	isCircuitOpenFn func(endpointName string) bool,
) *HealthChecker {
	if config.IntervalMs <= 0 {
		config.IntervalMs = defaultHealthCheckConfig().IntervalMs
	}
	if config.SuccessThreshold <= 0 {
		config.SuccessThreshold = defaultHealthCheckConfig().SuccessThreshold
	}
	if config.FailureThreshold <= 0 {
		config.FailureThreshold = defaultHealthCheckConfig().FailureThreshold
	}
	if config.LowTrafficRPS <= 0 {
		config.LowTrafficRPS = defaultHealthCheckConfig().LowTrafficRPS
	}
	return &HealthChecker{
		config:          config,
		epState:         make(map[string]*healthEpState),
		getRPSFn:        getRPSFn,
		recordResultFn:  recordResultFn,
		isCircuitOpenFn: isCircuitOpenFn,
	}
}

// SetNow 注入当前时间（测试用）
func (h *HealthChecker) SetNow(nowMs int64) {
	h.nowMs = nowMs
	h.nowInjected = true
}

func (h *HealthChecker) now() int64 {
	if h.nowInjected {
		return h.nowMs
	}
	return time.Now().UnixMilli()
}

// lastCheckNever 表示端点尚未探测过（哨兵值，区别于"探测发生在 t=0"）。
const lastCheckNever int64 = -1

// RegisterEndpoint 注册需要主动检查的端点
func (h *HealthChecker) RegisterEndpoint(name string) {
	if _, ok := h.epState[name]; ok {
		return
	}
	h.epState[name] = &healthEpState{
		Name:        name,
		LastCheckMs: lastCheckNever,
	}
}

// UnregisterEndpoint 注销端点
func (h *HealthChecker) UnregisterEndpoint(name string) {
	delete(h.epState, name)
}

// ShouldCheck 判断某个端点现在是否需要发起主动健康检查。
//
// 返回值：
//   - true：应该发起检查
//   - false：不需要（高流量 / 间隔未到 / 检查中 / 被动模式）
//
// 调用方若返回 true，应立即发起探测，并在探测完成后调用 RecordCheckResult。
func (h *HealthChecker) ShouldCheck(endpointName string) bool {
	if h.config.Mode == HealthCheckPassive {
		return false
	}

	ep, ok := h.epState[endpointName]
	if !ok {
		return false
	}

	now := h.now()

	// 间隔未到（首次未探测过 → 立即探测，满足 §2.1 "故障检测 < 10s" 指标）
	if ep.LastCheckMs != lastCheckNever && now-ep.LastCheckMs < int64(h.config.IntervalMs) {
		return false
	}

	// 有检查在飞
	if ep.InCheckFlight {
		return false
	}

	// MIXED 模式：仅低流量端点触发主动检查
	if h.config.Mode == HealthCheckMixed {
		if h.getRPSFn != nil {
			rps, valid := h.getRPSFn(endpointName)
			if valid && rps >= h.config.LowTrafficRPS {
				// 高流量，被动模式足以，跳过主动检查
				return false
			}
		}
	}

	// 标记检查在飞
	ep.InCheckFlight = true
	ep.LastCheckMs = now
	return true
}

// RecordCheckResult 记录一次主动健康检查的结果。
//
// 结果同时写入：
//   1. 主动检查自身的连续成功/失败计数（用于主动模式下判定健康状态）
//   2. 通过 recordResultFn 回写到 Engine 的失败率统计（被动模式也能受益）
func (h *HealthChecker) RecordCheckResult(endpointName string, success bool) {
	ep, ok := h.epState[endpointName]
	if !ok {
		return
	}
	ep.InCheckFlight = false

	if success {
		ep.ConsecutiveSuccess++
		ep.ConsecutiveFail = 0
		// 连续成功达到阈值 → 主动判定为健康
		if ep.ConsecutiveSuccess >= h.config.SuccessThreshold {
			ep.ActiveUnhealthy = false
		}
	} else {
		ep.ConsecutiveFail++
		ep.ConsecutiveSuccess = 0
		// 连续失败达到阈值 → 主动判定为不健康
		if ep.ConsecutiveFail >= h.config.FailureThreshold {
			ep.ActiveUnhealthy = true
		}
	}

	// 回写到 Engine 失败率统计（被动统计也受益于主动探测结果）
	if h.recordResultFn != nil {
		h.recordResultFn(endpointName, success)
	}
}

// IsActivelyUnhealthy 查询端点是否被主动检查判定为不健康。
//
// 仅 ACTIVE 模式下此状态直接决定可用性；
// MIXED 模式下此状态作为被动熔断的补充信号。
func (h *HealthChecker) IsActivelyUnhealthy(endpointName string) bool {
	if h.config.Mode == HealthCheckPassive {
		return false
	}
	ep, ok := h.epState[endpointName]
	if !ok {
		return false
	}
	return ep.ActiveUnhealthy
}

// GetCheckState 获取端点的主动检查状态（用于可观测性）
type HealthCheckEpState struct {
	Name               string
	LastCheckMs        int64
	ConsecutiveSuccess int
	ConsecutiveFail    int
	ActiveUnhealthy    bool
	InCheckFlight      bool
	Mode               string
}

// GetEndpointState 获取指定端点的主动检查状态
func (h *HealthChecker) GetEndpointState(endpointName string) (HealthCheckEpState, bool) {
	ep, ok := h.epState[endpointName]
	if !ok {
		return HealthCheckEpState{}, false
	}
	return HealthCheckEpState{
		Name:               ep.Name,
		LastCheckMs:        ep.LastCheckMs,
		ConsecutiveSuccess: ep.ConsecutiveSuccess,
		ConsecutiveFail:    ep.ConsecutiveFail,
		ActiveUnhealthy:    ep.ActiveUnhealthy,
		InCheckFlight:      ep.InCheckFlight,
		Mode:               h.config.Mode.String(),
	}, true
}

// TickEndpoints 返回本次 tick 需要发起主动检查的端点列表。
//
// 插件在 onTick 中调用此方法，对返回的每个端点发起 HTTP 探测，
// 探测完成后调用 RecordCheckResult 回写结果。
func (h *HealthChecker) TickEndpoints() []string {
	var needCheck []string
	for name := range h.epState {
		if h.ShouldCheck(name) {
			needCheck = append(needCheck, name)
		}
	}
	return needCheck
}
