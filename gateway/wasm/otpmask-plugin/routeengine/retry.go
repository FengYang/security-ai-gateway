package routeengine

// ============================================================
// RetryPolicy：非流式重试策略
// 设计依据：方案 §6.5 非流式重试
//
// 核心能力：
//   - 快速重试（Fast Retry）：首次失败立即重试同一端点，无延迟
//   - 端点切换（Failover）：同一端点连续失败后，切换到同优先级组其他端点
//   - 指数退避（Exponential Backoff）：跨端点重试时使用，起始 10ms，最大 200ms
//   - 重试预算（RetryBudget）：令牌桶限流，防止重试风暴
//   - 幂等性判断：只对 GET/HEAD/OPTIONS/幂等 POST 重试，非幂等 POST 不重试
//
// 注意：本文件只实现策略计算（纯逻辑），不做实际 HTTP 重发。
// 实际重发由 Wasm 插件（route.go + 上层）根据决策执行。
// ============================================================

// RetryDecision 一次重试决策结果。
type RetryDecision struct {
	ShouldRetry  bool   // 是否应该重试
	RetryEndpoint string // 重试目标端点（空 = 用原端点快速重试）
	DelayMs      int    // 重试延迟（毫秒，0 = 立即重试）
	Reason       string // 决策原因
}

// RetryConfig 重试策略配置。
//
// 布尔字段默认值（Go 零值 = 默认行为）：
//   - DisableFastRetry: false = 启用同端点快速重试（默认开启）
//   - DisableFailover:  false = 启用端点切换重试（默认开启）
type RetryConfig struct {
	MaxRetries        int     // 最大重试次数（不含首次），默认 2
	DisableFastRetry  bool    // 是否禁用同端点快速重试（默认 false=启用）
	DisableFailover   bool    // 是否禁用端点切换重试（默认 false=启用）
	BaseBackoffMs     int     // 指数退避基础延迟（毫秒），默认 10
	MaxBackoffMs      int     // 最大退避延迟（毫秒），默认 200
	BackoffMultiplier float64 // 退避乘数，默认 2.0
}

// RetryState 单次请求的重试状态（随请求生命周期维护）。
//
// 使用方式：
//
//	 state := NewRetryState()
//	 for {
//			result := doRequest(endpoint)
//			if result.Success {
//				return result
//			}
//			decision := policy.ShouldRetry(state, endpoint, endpoints, errType)
//			if !decision.ShouldRetry {
//				return result
//			}
//			sleep(decision.DelayMs)
//			endpoint = decision.RetryEndpoint
//			state.Attempt++
//	 }
type RetryState struct {
	Attempt       int            // 已尝试次数（含首次，首次=1）
	LastEndpoint  string         // 上次尝试的端点
	ConsecutiveSameEpFail int    // 同一端点连续失败次数
}

// NewRetryState 创建初始重试状态。
func NewRetryState() *RetryState {
	return &RetryState{Attempt: 1}
}

// RetryPolicy 非流式重试策略。
type RetryPolicy struct {
	Config  RetryConfig
	Budgets *BudgetManager // 重试预算（nil = 不限流）
}

// NewRetryPolicy 创建重试策略。
func NewRetryPolicy(cfg RetryConfig, budgets *BudgetManager) *RetryPolicy {
	if cfg.MaxRetries <= 0 {
		cfg.MaxRetries = 2
	}
	if cfg.BaseBackoffMs <= 0 {
		cfg.BaseBackoffMs = 10
	}
	if cfg.MaxBackoffMs <= 0 {
		cfg.MaxBackoffMs = 200
	}
	if cfg.BackoffMultiplier <= 0 {
		cfg.BackoffMultiplier = 2.0
	}
	// bool 字段 DisableFastRetry / DisableFailover 的零值 false = 启用，符合默认语义
	return &RetryPolicy{
		Config:  cfg,
		Budgets: budgets,
	}
}

// ShouldRetry 判断是否应该重试，并给出重试决策。
//
// state: 当前请求的重试状态
// currentEndpoint: 当前失败的端点
// availableEndpoints: 同优先级组内所有可用端点（Engine 提供）
// budgetKey: 重试预算的 key（通常是端点 name）
// nowMs: 当前时间（用于预算消耗）
// isIdempotent: 请求是否幂等（GET/HEAD/OPTIONS = true）
//
// 返回：重试决策
func (p *RetryPolicy) ShouldRetry(
	state *RetryState,
	currentEndpoint string,
	availableEndpoints []string,
	budgetKey string,
	nowMs int64,
	isIdempotent bool,
) RetryDecision {
	// 1. 达到最大重试次数：不重试
	retryCount := state.Attempt - 1 // 已重试次数 = 总尝试 - 1（首次）
	if retryCount >= p.Config.MaxRetries {
		return RetryDecision{
			ShouldRetry: false,
			Reason:      "max_retries_reached",
		}
	}

	// 2. 非幂等请求：不重试（安全优先）
	if !isIdempotent {
		return RetryDecision{
			ShouldRetry: false,
			Reason:      "non_idempotent",
		}
	}

	// 3. 无可用端点：不重试
	if len(availableEndpoints) == 0 {
		return RetryDecision{
			ShouldRetry: false,
			Reason:      "no_available_endpoints",
		}
	}

	// 4. 重试预算检查（如果配置了预算）
	if p.Budgets != nil {
		if !p.Budgets.TryConsume(budgetKey, nowMs) {
			return RetryDecision{
				ShouldRetry: false,
				Reason:      "retry_budget_exhausted",
			}
		}
	}

	// 5. 选择重试端点
	nextEp := p.pickNextEndpoint(currentEndpoint, availableEndpoints, state)

	// 6. 计算延迟
	delayMs := p.calcDelay(state.Attempt, nextEp == currentEndpoint)

	// 7. 更新状态
	state.Attempt++
	state.LastEndpoint = nextEp
	if nextEp == currentEndpoint {
		state.ConsecutiveSameEpFail++
	} else {
		state.ConsecutiveSameEpFail = 1
	}

	return RetryDecision{
		ShouldRetry:  true,
		RetryEndpoint: nextEp,
		DelayMs:      delayMs,
		Reason:       "retry_allowed",
	}
}

// pickNextEndpoint 选择下一个重试端点。
//
// 策略：
//   - 同端点快速重试：优先同端点（ConsecutiveSameEpFail < 1 且未禁用）
//   - 端点切换：同端点失败后，切换到可用列表的下一个端点
func (p *RetryPolicy) pickNextEndpoint(
	current string,
	available []string,
	state *RetryState,
) string {
	if len(available) == 0 {
		return ""
	}

	// 同端点快速重试（只做 1 次快速重试，且未被禁用）
	if !p.Config.DisableFastRetry && state.ConsecutiveSameEpFail == 0 {
		// 检查当前端点是否仍在可用列表中
		for _, ep := range available {
			if ep == current {
				return current // 快速重试同一端点
			}
		}
	}

	// 端点切换：找下一个不同的可用端点（未被禁用）
	if !p.Config.DisableFailover {
		for _, ep := range available {
			if ep != current {
				return ep
			}
		}
	}

	// 兜底：返回当前端点（只有一个可用端点时）
	return current
}

// calcDelay 计算重试延迟。
//
// 规则：
//   - 同端点快速重试（第 1 次重试，同端点）：0ms（立即重试）
//   - 端点切换重试：指数退避
func (p *RetryPolicy) calcDelay(attempt int, sameEndpoint bool) int {
	// 第 1 次重试（attempt=1 即首次失败后的第 1 次重试）且同端点：0ms
	if sameEndpoint && attempt == 1 {
		return 0
	}
	// 指数退避
	backoff := float64(p.Config.BaseBackoffMs)
	// attempt-1 是因为第 1 次重试延迟 = BaseBackoffMs（如果不是快速重试）
	// 第 2 次重试延迟 = BaseBackoffMs * Multiplier
	power := attempt - 1
	if power < 0 {
		power = 0
	}
	for i := 0; i < power; i++ {
		backoff *= p.Config.BackoffMultiplier
	}
	if backoff > float64(p.Config.MaxBackoffMs) {
		backoff = float64(p.Config.MaxBackoffMs)
	}
	return int(backoff)
}
