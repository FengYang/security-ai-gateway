package routeengine

// ============================================================
// CanaryManager：灰度切流管理器
// 设计依据：方案 §4.3 灰度切流（金丝雀发布）+ §7.4 灰度切流与租户白名单
//
// 核心能力：
//  1. 渐进式放量：按 step 逐步提高 canary 权重，间隔 rampIntervalMs
//  2. 自动回滚：canary 端点失败率 > rollbackThreshold → 立即回滚到 0
//  3. 租户白名单：只有白名单内的租户才会被分配到 canary 端点
//  4. 状态机：Idle → RampingUp → Stable → RollingBack → RolledBack
//
// 使用方式：
//   - 灰度端点的 BaseWeight 设为目标权重（如 0.1）
//   - 非灰度端点（基线）的 BaseWeight 保持原值
//   - CanaryManager 控制灰度端点的 CanaryWeight（0→目标权重）
//   - PickEndpoint 时使用 CurrentWeight = BaseWeight * CanaryProgress
// ============================================================

// CanaryState 灰度发布状态。
type CanaryState int

const (
	CanaryIdle       CanaryState = iota // 未开始
	CanaryRampingUp                     // 渐进放量中
	CanaryStable                        // 稳定运行（已达目标权重）
	CanaryRollingBack                   // 回滚中
	CanaryRolledBack                    // 已回滚（灰度关闭）
)

// CanaryEndpointConfig 单个端点的灰度配置。
type CanaryEndpointConfig struct {
	Name               string  // 端点名称
	TargetWeight       float64 // 目标权重（0-1，稳定状态下达到的权重）
	RampStep           float64 // 每次放量步长（如 0.05 = 5%）
	RampIntervalMs     int64   // 放量间隔（毫秒）
	RollbackThreshold  float64 // 自动回滚失败率阈值（如 0.1 = 10%）
	RollbackMinSamples int64   // 回滚最小样本数
	AllowedTenants     []string // 租户白名单（空 = 所有租户）
}

// CanaryStateSnapshot 灰度状态快照。
type CanaryStateSnapshot struct {
	State           CanaryState // 当前状态
	CurrentProgress float64     // 当前放量进度（0-1，1 = 达到目标权重）
	CurrentWeight   float64     // 当前实际权重 = TargetWeight * Progress
	FailureRate     float64     // 当前失败率
	Reason          string      // 状态变更原因
	LastChangeMs    int64       // 上次状态变更时间
	LastRampMs      int64       // 上次放量时间
}

// CanaryManager 灰度切流管理器。
//
// 管理单个 canary 端点的渐进式放量和自动回滚。
// 与 Engine 通过端点的 Weight 字段协作：CanaryManager 控制 canary 端点的权重，
// Engine 负责权重归一化和端点选择。
type CanaryManager struct {
	config CanaryEndpointConfig
	state  CanaryStateSnapshot

	// 引用（由外部 Engine 提供）
	failureRate  func() (float64, bool) // 获取当前失败率和有效性
	setWeight    func(float64)           // 设置端点权重
}

// NewCanaryManager 创建灰度管理器。
//
// config: 灰度配置
// failureRateFn: 获取当前失败率的函数（由 Engine 提供）
// setWeightFn: 设置端点权重的函数（由 Engine 提供）
func NewCanaryManager(
	config CanaryEndpointConfig,
	failureRateFn func() (float64, bool),
	setWeightFn func(float64),
) *CanaryManager {
	if config.TargetWeight <= 0 {
		config.TargetWeight = 0.1
	}
	if config.TargetWeight > 1 {
		config.TargetWeight = 1
	}
	if config.RampStep <= 0 {
		config.RampStep = 0.05
	}
	if config.RampIntervalMs <= 0 {
		config.RampIntervalMs = 60000 // 默认 60 秒
	}
	if config.RollbackThreshold <= 0 {
		config.RollbackThreshold = 0.1 // 默认 10%
	}
	if config.RollbackMinSamples <= 0 {
		config.RollbackMinSamples = 20
	}

	m := &CanaryManager{
		config:      config,
		failureRate: failureRateFn,
		setWeight:   setWeightFn,
	}
	m.state.State = CanaryIdle
	m.state.CurrentProgress = 0
	m.state.CurrentWeight = 0
	m.state.Reason = "idle"
	return m
}

// Start 启动灰度放量（从 Idle → RampingUp）。
func (m *CanaryManager) Start(nowMs int64) bool {
	if m.state.State != CanaryIdle && m.state.State != CanaryRolledBack {
		return false
	}
	m.setState(CanaryRampingUp, "started", nowMs)
	m.state.LastRampMs = nowMs
	// 第一步放量
	m.rampUp(nowMs)
	return true
}

// Tick 周期调用，推进灰度状态（检查放量间隔 + 自动回滚）。
//
// 返回：状态是否变化了
func (m *CanaryManager) Tick(nowMs int64) bool {
	// 先检查自动回滚
	if m.checkAutoRollback(nowMs) {
		return true
	}

	// 放量中：按间隔推进
	if m.state.State == CanaryRampingUp {
		elapsed := nowMs - m.state.LastRampMs
		if elapsed >= m.config.RampIntervalMs {
			return m.rampUp(nowMs)
		}
	}

	return false
}

// rampUp 提升一次放量步长。
func (m *CanaryManager) rampUp(nowMs int64) bool {
	newProgress := m.state.CurrentProgress + m.config.RampStep
	if newProgress >= 1.0 {
		newProgress = 1.0
		m.setState(CanaryStable, "reached_target", nowMs)
	}

	m.state.CurrentProgress = newProgress
	m.state.CurrentWeight = m.config.TargetWeight * newProgress
	m.state.LastRampMs = nowMs

	// 同步到端点权重
	if m.setWeight != nil {
		m.setWeight(m.state.CurrentWeight)
	}

	return true
}

// checkAutoRollback 检查是否需要自动回滚。
//
// 返回：是否触发了回滚
func (m *CanaryManager) checkAutoRollback(nowMs int64) bool {
	if m.state.State == CanaryIdle || m.state.State == CanaryRolledBack {
		return false
	}

	rate, valid := m.failureRate()
	if !valid {
		return false // 样本不足，不回滚
	}

	if rate >= m.config.RollbackThreshold {
		m.rollback("failure_rate_exceeded", nowMs)
		return true
	}
	return false
}

// Rollback 手动触发回滚。
func (m *CanaryManager) Rollback(reason string, nowMs int64) {
	m.rollback(reason, nowMs)
}

// rollback 执行回滚。
func (m *CanaryManager) rollback(reason string, nowMs int64) {
	m.setState(CanaryRollingBack, reason, nowMs)
	// 立即降到 0
	m.state.CurrentProgress = 0
	m.state.CurrentWeight = 0
	if m.setWeight != nil {
		m.setWeight(0)
	}
	m.setState(CanaryRolledBack, reason, nowMs)
}

// setState 变更状态并记录时间。
func (m *CanaryManager) setState(state CanaryState, reason string, nowMs int64) {
	m.state.State = state
	m.state.Reason = reason
	m.state.LastChangeMs = nowMs
}

// State 返回当前灰度状态快照。
func (m *CanaryManager) State() CanaryStateSnapshot {
	return m.state
}

// IsTenantAllowed 判断租户是否在灰度白名单中。
// 白名单为空 = 所有租户都允许。
func (m *CanaryManager) IsTenantAllowed(tenant string) bool {
	if len(m.config.AllowedTenants) == 0 {
		return true
	}
	for _, t := range m.config.AllowedTenants {
		if t == tenant {
			return true
		}
	}
	return false
}

// StateString 返回状态可读名称。
func (s CanaryState) String() string {
	switch s {
	case CanaryIdle:
		return "IDLE"
	case CanaryRampingUp:
		return "RAMPING_UP"
	case CanaryStable:
		return "STABLE"
	case CanaryRollingBack:
		return "ROLLING_BACK"
	case CanaryRolledBack:
		return "ROLLED_BACK"
	default:
		return "UNKNOWN"
	}
}
