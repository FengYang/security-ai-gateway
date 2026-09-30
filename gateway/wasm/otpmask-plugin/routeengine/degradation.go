package routeengine

// ============================================================
// DegradationManager：三级降级策略管理器
// 设计依据：方案 §6.9 三级降级策略
//
// 四级状态（L0 正常 → L3 全故障）：
//   - L0 (Normal)：最高优先级组正常服务
//   - L1 (PartialDegraded)：高优先级组部分端点故障，已自动故障转移
//   - L2 (FullGroupDegraded)：高优先级组全部故障，已降级到低优先级组
//   - L3 (TotalFailure)：所有端点故障，返回 503（fail-closed）
//
// 迟滞效应（Hysteresis）：
//   - 降级：立刻降级（失败即触发）
//   - 恢复：连续成功达到阈值后才恢复（避免抖动）
//     * L3 → L2：低优先级组有端点恢复（连续 RecoveryThreshold 次成功）
//     * L2 → L1：高优先级组有端点恢复
//     * L1 → L0：高优先级组所有端点恢复
// ============================================================

// DegradationLevel 降级级别。
type DegradationLevel int

const (
	DegradationL0 DegradationLevel = iota // 正常
	DegradationL1                         // 部分降级（部分端点故障）
	DegradationL2                         // 整组降级（高优先级组全故障，切低优先级组）
	DegradationL3                         // 全故障（所有端点不可用）
)

// DegradationConfig 降级策略配置。
type DegradationConfig struct {
	RecoveryThreshold int // 恢复阈值（连续成功次数），默认 5
	// 迟滞窗口：连续 N 次成功才允许恢复到更高级别
}

// DegradationManager 三级降级管理器。
//
// 监控各优先级组的健康状态，决定当前系统处于哪个降级级别。
// 不直接操作端点状态，只读 Engine 中的状态做判断。
type DegradationManager struct {
	config DegradationConfig
	level  DegradationLevel // 当前降级级别

	// 恢复计数器：记录连续成功次数（用于迟滞效应）
	// key: 优先级值，value: 连续成功次数
	recoveryCounters map[int]int

	lastChangeMs int64 // 上次降级级别变更时间
}

// NewDegradationManager 创建降级管理器。
func NewDegradationManager(cfg DegradationConfig) *DegradationManager {
	if cfg.RecoveryThreshold <= 0 {
		cfg.RecoveryThreshold = 5
	}
	return &DegradationManager{
		config:           cfg,
		level:            DegradationL0,
		recoveryCounters: make(map[int]int),
	}
}

// Level 返回当前降级级别。
func (m *DegradationManager) Level() DegradationLevel {
	return m.level
}

// LastChangeMs 返回上次降级级别变更时间。
func (m *DegradationManager) LastChangeMs() int64 {
	return m.lastChangeMs
}

// Evaluate 根据当前端点状态评估降级级别。
//
// endpoints: 所有端点状态（按优先级分组）
// nowMs: 当前时间
// 返回：降级级别是否变化了
//
// 评估逻辑（从高到低检查）：
//  1. 所有端点都不可用 → L3
//  2. 最高优先级组全不可用 → L2
//  3. 最高优先级组部分不可用 → L1
//  4. 所有端点可用 → L0
//
// 迟滞效应：从低级别恢复到高级别（如 L2→L1）需要连续成功次数达标；
// 从高级别降级到低级别（如 L1→L2）立即生效。
func (m *DegradationManager) Evaluate(endpoints []*EndpointState, nowMs int64) bool {
	if len(endpoints) == 0 {
		return m.transitionTo(DegradationL3, nowMs)
	}

	// 按优先级分组
	groups := groupByPriorityDesc(endpoints)
	if len(groups) == 0 {
		return m.transitionTo(DegradationL3, nowMs)
	}

	highestPrio := groups[0].Priority
	highestGroupAllDown := allDown(groups[0].Endpoints)

	// 检查所有端点是否都不可用
	allEndpointsDown := true
	for _, g := range groups {
		if !allDown(g.Endpoints) {
			allEndpointsDown = false
			break
		}
	}

	var targetLevel DegradationLevel
	switch {
	case allEndpointsDown:
		targetLevel = DegradationL3
	case highestGroupAllDown:
		targetLevel = DegradationL2
	case groupPartialDown(groups[0].Endpoints):
		targetLevel = DegradationL1
	default:
		targetLevel = DegradationL0
	}

	// 迟滞效应：恢复需要连续成功达标，降级立即生效
	if targetLevel < m.level {
		// 恢复方向（级别数字变小 = 恢复）
		if m.checkRecoveryHysteresis(targetLevel, groups, highestPrio) {
			return m.transitionTo(targetLevel, nowMs)
		}
		// 未达恢复阈值，保持当前级别
		return false
	}

	// 降级方向或同级：立即生效
	if targetLevel == m.level {
		return false
	}
	return m.transitionTo(targetLevel, nowMs)
}

// RecordSuccess 记录一次成功（用于恢复计数器的迟滞效应）。
// priority: 成功端点所在的优先级组
func (m *DegradationManager) RecordSuccess(priority int) {
	m.recoveryCounters[priority]++
}

// RecordFailure 记录一次失败（重置恢复计数器）。
func (m *DegradationManager) RecordFailure(priority int) {
	m.recoveryCounters[priority] = 0
}

// checkRecoveryHysteresis 检查恢复是否达到迟滞阈值。
func (m *DegradationManager) checkRecoveryHysteresis(
	targetLevel DegradationLevel,
	groups []priorityGroup,
	highestPrio int,
) bool {
	switch targetLevel {
	case DegradationL0:
		// 恢复到 L0：最高优先级组所有端点都健康
		// 且最高优先级组连续成功数达标
		return m.recoveryCounters[highestPrio] >= m.config.RecoveryThreshold

	case DegradationL1:
		// 恢复到 L1：最高优先级组至少有一个端点健康
		// 且最高优先级组连续成功数达标
		return m.recoveryCounters[highestPrio] >= m.config.RecoveryThreshold

	case DegradationL2:
		// 恢复到 L2：至少有一个优先级组可用
		// （从 L3 恢复到 L2，只要有任何端点可用就行，但需要连续成功）
		for _, g := range groups {
			if !allDown(g.Endpoints) && m.recoveryCounters[g.Priority] >= m.config.RecoveryThreshold {
				return true
			}
		}
		return false

	default:
		// L3 不需要恢复条件
		return true
	}
}

// transitionTo 切换到指定降级级别。
// 返回：是否真的变化了
func (m *DegradationManager) transitionTo(level DegradationLevel, nowMs int64) bool {
	if m.level == level {
		return false
	}
	m.level = level
	m.lastChangeMs = nowMs
	// 级别变化时重置所有恢复计数器
	m.recoveryCounters = make(map[int]int)
	return true
}

// ============================================================
// 辅助类型和函数
// ============================================================

type priorityGroup struct {
	Priority  int
	Endpoints []*EndpointState
}

// groupByPriorityDesc 按优先级从高到低分组（数字越小优先级越高）。
func groupByPriorityDesc(endpoints []*EndpointState) []priorityGroup {
	groupMap := make(map[int][]*EndpointState)
	for _, ep := range endpoints {
		groupMap[ep.Priority] = append(groupMap[ep.Priority], ep)
	}
	// 收集并按优先级排序（从高到低 = 数字从小到大）
	var groups []priorityGroup
	// 简单的选择排序（端点数量通常不多）
	for prio := range groupMap {
		groups = append(groups, priorityGroup{Priority: prio, Endpoints: groupMap[prio]})
	}
	// 按优先级升序（数字小 = 优先级高）
	for i := 0; i < len(groups); i++ {
		for j := i + 1; j < len(groups); j++ {
			if groups[j].Priority < groups[i].Priority {
				groups[i], groups[j] = groups[j], groups[i]
			}
		}
	}
	return groups
}

// allDown 判断组内所有端点是否都不可用。
func allDown(eps []*EndpointState) bool {
	if len(eps) == 0 {
		return true
	}
	for _, ep := range eps {
		if ep.IsUsable() {
			return false
		}
	}
	return true
}

// groupPartialDown 判断组内是否部分端点不可用（不是全好也不是全坏）。
func groupPartialDown(eps []*EndpointState) bool {
	if len(eps) == 0 {
		return false
	}
	usableCount := 0
	for _, ep := range eps {
		if ep.IsUsable() {
			usableCount++
		}
	}
	return usableCount > 0 && usableCount < len(eps)
}

// LevelString 返回降级级别的可读名称。
func (l DegradationLevel) String() string {
	switch l {
	case DegradationL0:
		return "L0_NORMAL"
	case DegradationL1:
		return "L1_PARTIAL_DEGRADED"
	case DegradationL2:
		return "L2_FULL_GROUP_DEGRADED"
	case DegradationL3:
		return "L3_TOTAL_FAILURE"
	default:
		return "UNKNOWN"
	}
}
