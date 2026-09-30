package routeengine

// ============================================================
// CircuitBreaker：熔断器状态机（Hystrix 模式）
// 设计依据：方案 §6.3 熔断器（基于失败率，Hystrix 模式）
//
// 三状态：
//   - Closed：正常，流量通过
//   - Open：熔断，流量拒绝
//   - HalfOpen：半开，单请求探测
//
// 状态迁移：
//   Closed → Open：失败率 ≥ 阈值 且 样本数 ≥ minSamples
//   Open → HalfOpen：冷却时间到达 + 首个请求进入（Allow 判定）
//   HalfOpen → Open：探测失败
//   HalfOpen → Closed：探测成功
// ============================================================

// CircuitBreaker 熔断器状态机实例。
//
// 与方案对齐的字段（§6.3.5 配置参数）：
//   - FailureThreshold: 失败率阈值（0-1），默认 0.5
//   - MinSamples: 最小样本数，默认 10
//   - CooldownMs: 熔断冷却时间（毫秒），默认 30000
//
// 状态字段：
//   - State: 当前状态
//   - LastStateChangeMs: 上次状态变更时间（unix 毫秒）
//   - HalfOpenProbeSent: 半开状态是否已发送探测请求
type CircuitBreaker struct {
	// 配置参数
	FailureThreshold float64 // 失败率阈值（0-1）
	MinSamples       int64   // 最小样本数
	CooldownMs       int64   // 熔断冷却时间（毫秒）

	// 运行时状态
	State              CircuitState // 当前状态
	LastStateChangeMs  int64        // 上次状态变更时间（unix 毫秒）
	HalfOpenProbeSent  bool         // 半开状态是否已发送探测请求
}

// NewCircuitBreaker 创建熔断器（默认 Closed 状态）。
func NewCircuitBreaker(failureThreshold float64, minSamples int64, cooldownMs int64) *CircuitBreaker {
	if failureThreshold <= 0 || failureThreshold > 1 {
		failureThreshold = 0.5
	}
	if minSamples < 1 {
		minSamples = 10
	}
	if cooldownMs <= 0 {
		cooldownMs = 30000
	}
	return &CircuitBreaker{
		FailureThreshold:   failureThreshold,
		MinSamples:         minSamples,
		CooldownMs:         cooldownMs,
		State:              CircuitClosed,
		HalfOpenProbeSent:  false,
	}
}

// Allow 判断是否允许请求通过（请求路径调用，快速判断）。
//
// 返回 true 表示允许，false 表示拒绝（熔断打开）。
// 副作用：在 Open→HalfOpen 迁移时，更新状态并标记探测请求。
//
// 规则：
//   - Closed: 始终允许
//   - HalfOpen: 仅第一个请求允许（探测），后续拒绝
//   - Open: 冷却时间到 → 转 HalfOpen 并允许探测；否则拒绝
func (cb *CircuitBreaker) Allow(nowMs int64) bool {
	switch cb.State {
	case CircuitClosed:
		return true

	case CircuitHalfOpen:
		if cb.HalfOpenProbeSent {
			// 已有探测在飞，拒绝后续请求
			return false
		}
		// 标记探测请求已发出
		cb.HalfOpenProbeSent = true
		return true

	case CircuitOpen:
		// 检查冷却时间是否到达
		if nowMs-cb.LastStateChangeMs >= cb.CooldownMs {
			// 转 HalfOpen，允许第一个探测请求
			cb.State = CircuitHalfOpen
			cb.LastStateChangeMs = nowMs
			cb.HalfOpenProbeSent = true
			return true
		}
		return false

	default:
		return false
	}
}

// OnResult 处理请求结果，可能触发状态迁移。
//
// success: 请求是否成功
// failureRate: 当前 EWMA 失败率
// valid: 失败率统计是否有效（样本数足够）
// nowMs: 当前时间（unix 毫秒）
//
// 返回：状态是否发生了变更
func (cb *CircuitBreaker) OnResult(success bool, failureRate float64, valid bool, nowMs int64) bool {
	switch cb.State {
	case CircuitClosed:
		// Closed → Open：失败率超阈值且统计有效
		if valid && failureRate >= cb.FailureThreshold {
			cb.State = CircuitOpen
			cb.LastStateChangeMs = nowMs
			cb.HalfOpenProbeSent = false
			return true
		}
		return false

	case CircuitHalfOpen:
		// 半开状态下处理探测结果
		if success {
			// 探测成功 → Closed
			cb.State = CircuitClosed
			cb.LastStateChangeMs = nowMs
			cb.HalfOpenProbeSent = false
			return true
		}
		// 探测失败 → Open
		cb.State = CircuitOpen
		cb.LastStateChangeMs = nowMs
		cb.HalfOpenProbeSent = false
		return true

	case CircuitOpen:
		// Open 状态下，Allow 负责迁移到 HalfOpen
		// OnResult 在这里不做状态变更
		return false

	default:
		return false
	}
}

// Reset 重置熔断器到 Closed 状态（配置更新/手动恢复时用）。
func (cb *CircuitBreaker) Reset(nowMs int64) {
	cb.State = CircuitClosed
	cb.LastStateChangeMs = nowMs
	cb.HalfOpenProbeSent = false
}

// IsOpen 返回是否处于熔断打开状态。
func (cb *CircuitBreaker) IsOpen() bool {
	return cb.State == CircuitOpen
}

// IsClosed 返回是否处于闭合状态。
func (cb *CircuitBreaker) IsClosed() bool {
	return cb.State == CircuitClosed
}

// IsHalfOpen 返回是否处于半开状态。
func (cb *CircuitBreaker) IsHalfOpen() bool {
	return cb.State == CircuitHalfOpen
}
