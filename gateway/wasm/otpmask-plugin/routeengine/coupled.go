package routeengine

// ============================================================
// CoupleDecider：熔断-重试耦合决策器
// 设计依据：方案 §6.8 熔断-重试耦合
//
// 核心原则：
//  1. 熔断的端点不允许重试（硬约束）— 重试目标端点必须通过熔断器 Allow 检查
//  2. 重试不计入熔断器统计样本 — 避免重试风暴导致熔断概率被放大
//  3. 熔断打开时优先跳转到下一个健康端点，而非耗尽重试预算
//  4. 所有端点都熔断时，返回降级状态（交给降级策略处理）
//
// 组件协作：
//
//	┌─────────────┐     ┌──────────────┐     ┌──────────────┐
//	│ 熔断器(CB)  │────▶│ CoupleDecider│◀────│ 重试策略(RP) │
//	└─────────────┘     └──────┬───────┘     └──────────────┘
//	                           │
//	                  ┌────────▼────────┐
//	                  │ 重试预算(Budget) │
//	                  └─────────────────┘
// ============================================================

// CoupledDecision 耦合决策结果。
type CoupledDecision struct {
	ShouldRetry  bool   // 是否应该重试
	RetryEndpoint string // 重试目标端点
	DelayMs      int    // 重试延迟（毫秒）
	Reason       string // 决策原因
	AllEndpointsDown bool // 是否所有端点都熔断了（触发降级）
}

// CoupledDecider 熔断-重试耦合决策器。
//
// 封装熔断器 + 重试策略 + 重试预算的协调逻辑，
// 对外提供单一决策入口，避免上层直接操作三个组件。
type CoupledDecider struct {
	Retry   *RetryPolicy
	Budgets *BudgetManager

	// 端点熔断器集合（name -> *CircuitBreaker）
	// 由外部 Engine 维护，这里只持有引用做 Allow 判断
	circuits map[string]*CircuitBreaker
}

// NewCoupledDecider 创建耦合决策器。
//
// retry: 重试策略（不能为 nil）
// budgets: 重试预算（nil = 不限制）
// circuits: 端点熔断器映射（由 Engine 维护）
func NewCoupledDecider(retry *RetryPolicy, budgets *BudgetManager, circuits map[string]*CircuitBreaker) *CoupledDecider {
	if retry == nil {
		retry = NewRetryPolicy(RetryConfig{}, nil)
	}
	return &CoupledDecider{
		Retry:    retry,
		Budgets:  budgets,
		circuits: circuits,
	}
}

// SetCircuits 更新熔断器映射（配置热更新时调用）。
func (d *CoupledDecider) SetCircuits(circuits map[string]*CircuitBreaker) {
	d.circuits = circuits
}

// ShouldRetry 判断是否应该重试（熔断-重试耦合决策）。
//
// state: 当前请求的重试状态
// currentEndpoint: 当前失败的端点
// allEndpoints: 所有端点名称（按优先级排序，同优先级组内）
// nowMs: 当前时间
// isIdempotent: 请求是否幂等
// isRetry: 本次失败是否来自"重试请求"（true=重试，不计入熔断器样本）
//
// 返回：耦合决策结果
func (d *CoupledDecider) ShouldRetry(
	state *RetryState,
	currentEndpoint string,
	allEndpoints []string,
	nowMs int64,
	isIdempotent bool,
	isRetry bool,
) CoupledDecision {
	// 1. 记录失败到熔断器（仅首次请求，重试不计入）
	//    注意：调用方应在调用 ShouldRetry 前先调用 RecordFailure
	//    这里不直接修改熔断器状态，保持纯决策语义

	// 2. 过滤出熔断允许的端点（可用 = 熔断器 Allow 通过）
	available := d.filterAvailableEndpoints(allEndpoints, nowMs)

	// 3. 所有端点都熔断：返回全熔断信号（触发降级）
	if len(available) == 0 {
		return CoupledDecision{
			ShouldRetry:      false,
			Reason:           "all_endpoints_circuit_open",
			AllEndpointsDown: true,
		}
	}

	// 4. 当前端点已熔断：跳过快速重试，直接切到下一个健康端点
	currentOpen := d.isCircuitOpen(currentEndpoint)
	if currentOpen {
		// 当前端点熔断，不能做同端点快速重试
		// 找第一个可用的其他端点
		for _, ep := range available {
			if ep != currentEndpoint {
				// 检查重试预算
				if d.Budgets != nil && !d.Budgets.TryConsume(ep, nowMs) {
					continue
				}
				// 检查最大重试次数
				retryCount := state.Attempt - 1
				if retryCount >= d.Retry.Config.MaxRetries {
					return CoupledDecision{
						ShouldRetry: false,
						Reason:      "max_retries_reached",
					}
				}
				// 非幂等不重试
				if !isIdempotent {
					return CoupledDecision{
						ShouldRetry: false,
						Reason:      "non_idempotent",
					}
				}
				delay := d.Retry.calcDelay(state.Attempt, false)
				state.Attempt++
				state.LastEndpoint = ep
				state.ConsecutiveSameEpFail = 1
				return CoupledDecision{
					ShouldRetry:   true,
					RetryEndpoint: ep,
					DelayMs:       delay,
					Reason:        "failover_circuit_open",
				}
			}
		}
		// 没有可用的其他端点
		return CoupledDecision{
			ShouldRetry:      false,
			Reason:           "no_healthy_failover_target",
			AllEndpointsDown: true,
		}
	}

	// 5. 当前端点健康：走正常重试策略
	decision := d.Retry.ShouldRetry(
		state,
		currentEndpoint,
		available,
		currentEndpoint, // 预算 key 用当前端点
		nowMs,
		isIdempotent,
	)

	return CoupledDecision{
		ShouldRetry:     decision.ShouldRetry,
		RetryEndpoint:   decision.RetryEndpoint,
		DelayMs:         decision.DelayMs,
		Reason:          decision.Reason,
		AllEndpointsDown: false,
	}
}

// RecordFailure 记录一次失败到熔断器。
//
// isRetry: 是否为重试请求（重试不计入熔断器样本，避免重试风暴放大熔断）
// failureRate: 当前 EWMA 失败率
// valid: 失败率统计是否有效
func (d *CoupledDecider) RecordFailure(
	endpointName string,
	isRetry bool,
	failureRate float64,
	valid bool,
	nowMs int64,
) {
	if isRetry {
		// 方案 §6.8.1：重试不计入熔断器统计
		return
	}
	cb, ok := d.circuits[endpointName]
	if !ok {
		return
	}
	cb.OnResult(false, failureRate, valid, nowMs)
}

// RecordSuccess 记录一次成功到熔断器。
//
// isRetry: 是否为重试请求（重试的成功/失败都不计入，保持对称）
// failureRate: 当前 EWMA 失败率
// valid: 失败率统计是否有效
func (d *CoupledDecider) RecordSuccess(
	endpointName string,
	isRetry bool,
	failureRate float64,
	valid bool,
	nowMs int64,
) {
	if isRetry {
		return
	}
	cb, ok := d.circuits[endpointName]
	if !ok {
		return
	}
	cb.OnResult(true, failureRate, valid, nowMs)
}

// filterAvailableEndpoints 过滤出熔断器允许通过的端点。
func (d *CoupledDecider) filterAvailableEndpoints(endpoints []string, nowMs int64) []string {
	result := make([]string, 0, len(endpoints))
	for _, ep := range endpoints {
		cb, ok := d.circuits[ep]
		if !ok {
			// 没有熔断器记录的端点视为可用
			result = append(result, ep)
			continue
		}
		if cb.Allow(nowMs) {
			result = append(result, ep)
		}
	}
	return result
}

// isCircuitOpen 判断端点是否处于熔断打开状态。
func (d *CoupledDecider) isCircuitOpen(endpoint string) bool {
	cb, ok := d.circuits[endpoint]
	if !ok {
		return false
	}
	return cb.IsOpen()
}
