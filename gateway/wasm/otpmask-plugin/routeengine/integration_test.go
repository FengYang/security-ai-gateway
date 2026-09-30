package routeengine

import (
	"testing"
)

// ============================================================
// W3 容错能力端到端集成测试
// 验证：EWMA 失败率 → 动态权重 → 熔断器 → 重试 → 降级 的完整链路
// ============================================================

// 场景1：正常流量下，两端点按权重分配，失败率稳定，无熔断，无降级
func TestE2E_NormalTraffic(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep-a", Weight: 0.7, Priority: 1, Enabled: true},
			{Name: "ep-b", Weight: 0.3, Priority: 1, Enabled: true},
		},
		EWMAMinSamples: 20,
		EWMAAlpha:      0.1,
	})

	// 100% 成功，跑 200 次
	for i := 0; i < 200; i++ {
		d := e.PickEndpoint()
		if d.EndpointName == "" {
			t.Fatalf("第 %d 次应选中端点", i)
		}
		e.RecordResult(d.EndpointName, true)
	}

	// 两端点都应健康、都在 Closed 状态
	for _, name := range []string{"ep-a", "ep-b"} {
		state, _ := e.GetEndpointCircuitState(name)
		if state != CircuitClosed {
			t.Fatalf("%s 应处于 Closed，got %v", name, state)
		}
		rate, valid := e.GetEndpointFailureRate(name)
		if !valid {
			t.Fatalf("%s 统计应有效", name)
		}
		if rate > 0.01 {
			t.Fatalf("%s 全成功下失败率应接近 0，got %.4f", name, rate)
		}
	}
}

// 场景2：一端点持续失败 → 失败率上升 → 权重下降 → 最终熔断 → 流量切到另一端点
func TestE2E_EndpointFailureAndCircuit(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep-a", Weight: 0.6, Priority: 1, Enabled: true},
			{Name: "ep-b", Weight: 0.4, Priority: 1, Enabled: true},
		},
		EWMAMinSamples:      10,
		EWMAAlpha:           0.3, // 较大 α，快速收敛便于测试
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:   10,
		CircuitCooldownMs:   60000,
	})

	// ep-a 持续失败 50 次，ep-b 持续成功
	for i := 0; i < 50; i++ {
		e.RecordResult("ep-a", false)
		e.RecordResult("ep-b", true)
	}

	// ep-a 应熔断
	stateA, _ := e.GetEndpointCircuitState("ep-a")
	if stateA != CircuitOpen {
		t.Fatalf("ep-a 应熔断（Open），got %v", stateA)
	}

	// ep-b 应健康
	stateB, _ := e.GetEndpointCircuitState("ep-b")
	if stateB != CircuitClosed {
		t.Fatalf("ep-b 应健康（Closed），got %v", stateB)
	}

	// PickEndpoint 应只选到 ep-b
	for i := 0; i < 100; i++ {
		d := e.PickEndpoint()
		if d.EndpointName != "ep-b" {
			t.Fatalf("ep-a 熔断后应只选 ep-b，got %s", d.EndpointName)
		}
	}
}

// 场景3：两端点都熔断 → 三级降级到 L3（全故障）
func TestE2E_AllEndpointsCircuitL3(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep-a", Weight: 0.6, Priority: 1, Enabled: true},
			{Name: "ep-b", Weight: 0.4, Priority: 1, Enabled: true},
			{Name: "ep-c", Weight: 1.0, Priority: 2, Enabled: true}, // 低优先级冷备
		},
		EWMAMinSamples:       5,
		EWMAAlpha:            0.5,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:    5,
		CircuitCooldownMs:    60000,
	})

	// 所有端点都失败
	for i := 0; i < 20; i++ {
		e.RecordResult("ep-a", false)
		e.RecordResult("ep-b", false)
		e.RecordResult("ep-c", false)
	}

	// 用 DegradationManager 评估
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 3})

	// 收集端点状态
	var eps []*EndpointState
	for name := range e.state {
		eps = append(eps, e.state[name])
	}

	now := int64(100000)
	m.Evaluate(eps, now)

	if m.Level() != DegradationL3 {
		t.Fatalf("所有端点熔断应降级到 L3，got %s", m.Level())
	}

	// PickEndpoint 应返回空决策（无可用端点）
	d := e.PickEndpoint()
	if d.EndpointName != "" {
		t.Fatalf("全熔断时 PickEndpoint 应返回空，got %s", d.EndpointName)
	}
	if d.Reason != "no_usable_endpoints" {
		t.Fatalf("reason 应为 no_usable_endpoints，got %s", d.Reason)
	}
}

// 场景4：高优先级组全挂 → L2 降级到低优先级组
func TestE2E_HighGroupDownL2(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep-a", Weight: 0.6, Priority: 1, Enabled: true},
			{Name: "ep-b", Weight: 0.4, Priority: 1, Enabled: true},
			{Name: "ep-backup", Weight: 1.0, Priority: 2, Enabled: true},
		},
		EWMAMinSamples:       5,
		EWMAAlpha:            0.5,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:    5,
		CircuitCooldownMs:    60000,
	})

	// 高优先级组（Priority=1）全失败，低优先级（Priority=2）正常
	for i := 0; i < 20; i++ {
		e.RecordResult("ep-a", false)
		e.RecordResult("ep-b", false)
		e.RecordResult("ep-backup", true)
	}

	// 评估降级级别
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 3})
	var eps []*EndpointState
	for _, ep := range e.state {
		eps = append(eps, ep)
	}
	m.Evaluate(eps, 100000)

	if m.Level() != DegradationL2 {
		t.Fatalf("高优先级组全挂应降级到 L2，got %s", m.Level())
	}

	// PickEndpoint 应选到 ep-backup（Priority=2 组）
	d := e.PickEndpoint()
	if d.EndpointName != "ep-backup" {
		t.Fatalf("高优先级组全挂时应选低优先级备份，got %s", d.EndpointName)
	}
}

// 场景5：重试策略 + 熔断耦合——当前端点熔断时，重试切换到健康端点
func TestE2E_RetryWithCircuitCoupling(t *testing.T) {
	// 准备熔断器：ep1 熔断，ep2 健康
	circuits := map[string]*CircuitBreaker{
		"ep1": {
			State:              CircuitOpen,
			LastStateChangeMs:  1000,
			FailureThreshold:   0.5,
			MinSamples:         10,
			CooldownMs:         60000,
		},
		"ep2": {
			State:            CircuitClosed,
			FailureThreshold: 0.5,
			MinSamples:       10,
			CooldownMs:       60000,
		},
	}

	budgets := NewBudgetManager(RetryBudgetConfig{MaxTokens: 10, RefillIntervalMs: 10000})
	retry := NewRetryPolicy(RetryConfig{MaxRetries: 3}, budgets)
	decider := NewCoupledDecider(retry, budgets, circuits)

	state := NewRetryState()
	// ep1 失败，应切换到 ep2
	decision := decider.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, 2000, true, false)

	if !decision.ShouldRetry {
		t.Fatalf("应允许重试（切换端点）")
	}
	if decision.RetryEndpoint != "ep2" {
		t.Fatalf("应切换到 ep2，got %s", decision.RetryEndpoint)
	}
	if decision.Reason != "failover_circuit_open" {
		t.Fatalf("reason 应为 failover_circuit_open，got %s", decision.Reason)
	}
}

// 场景6：熔断恢复期（HalfOpen）+ 成功 → Closed + 权重恢复
func TestE2E_CircuitRecoveryAndWeightRestore(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep-a", Weight: 0.6, Priority: 1, Enabled: true},
			{Name: "ep-b", Weight: 0.4, Priority: 1, Enabled: true},
		},
		EWMAMinSamples:       10,
		EWMAAlpha:            0.3,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:    10,
		CircuitCooldownMs:    1000, // 1 秒冷却，便于测试
		WeightAdjustStep:     0.1,
		WeightFailureThresh:  0.5,
		WeightRecoveryRatio:  0.5,
	})

	// 先让 ep-a 熔断
	for i := 0; i < 30; i++ {
		e.RecordResult("ep-a", false)
		e.RecordResult("ep-b", true)
	}
	stateA, _ := e.GetEndpointCircuitState("ep-a")
	if stateA != CircuitOpen {
		t.Fatalf("ep-a 应先熔断，got %v", stateA)
	}

	// 取熔断发生的时间，加上足够的冷却时间
	openTime := e.state["ep-a"].CircuitBreaker.LastStateChangeMs
	recoverTime := openTime + 5000 // 加 5 秒，远超 1 秒冷却

	// 冷却后 Allow 调用 → HalfOpen
	cb := e.state["ep-a"].CircuitBreaker
	if !cb.Allow(recoverTime) {
		t.Fatalf("冷却后 Allow 应返回 true（转 HalfOpen）")
	}
	if cb.State != CircuitHalfOpen {
		t.Fatalf("冷却后应转 HalfOpen，got %v", cb.State)
	}

	// HalfOpen 状态下探测成功 → Closed
	cb.OnResult(true, 0.0, true, 2100)
	if cb.State != CircuitClosed {
		t.Fatalf("探测成功应转 Closed，got %v", cb.State)
	}
}

// 场景7：重试预算耗尽 → 禁止重试
func TestE2E_RetryBudgetExhausted(t *testing.T) {
	budgets := NewBudgetManager(RetryBudgetConfig{
		MaxTokens:        3,
		RefillIntervalMs: 60000, // 1 分钟才补 1 个，测试期间不会补
	})
	retry := NewRetryPolicy(RetryConfig{MaxRetries: 10}, budgets)
	decider := NewCoupledDecider(retry, budgets, map[string]*CircuitBreaker{
		"ep1": {State: CircuitClosed, FailureThreshold: 0.5, MinSamples: 10, CooldownMs: 30000},
		"ep2": {State: CircuitClosed, FailureThreshold: 0.5, MinSamples: 10, CooldownMs: 30000},
	})

	now := int64(1000)
	state := NewRetryState()

	// 前 3 次应允许（消耗令牌）
	for i := 0; i < 3; i++ {
		d := decider.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, now, true, false)
		if !d.ShouldRetry {
			t.Fatalf("第 %d 次应允许重试", i+1)
		}
		now += 100
	}

	// 第 4 次应被预算拒绝
	d := decider.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, now, true, false)
	if d.ShouldRetry {
		t.Fatalf("第 4 次应被预算拒绝")
	}
	if d.Reason != "retry_budget_exhausted" {
		t.Fatalf("reason 应为 retry_budget_exhausted，got %s", d.Reason)
	}
}
