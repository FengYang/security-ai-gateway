package routeengine

import (
	"testing"
)

// ============================================================
// 熔断-重试耦合测试（方案 §6.8.6 测试清单节选）
// ============================================================

func makeTestCircuits() map[string]*CircuitBreaker {
	return map[string]*CircuitBreaker{
		"ep1": NewCircuitBreaker(0.5, 5, 30000),
		"ep2": NewCircuitBreaker(0.5, 5, 30000),
		"ep3": NewCircuitBreaker(0.5, 5, 30000),
	}
}

// 正常场景：两端点都健康，首次失败走快速重试
func TestCoupled_NormalFastRetry(t *testing.T) {
	circuits := makeTestCircuits()
	retry := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	d := NewCoupledDecider(retry, nil, circuits)

	state := NewRetryState()
	decision := d.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, 1000, true, false)
	if !decision.ShouldRetry {
		t.Fatalf("正常场景应允许快速重试")
	}
	if decision.RetryEndpoint != "ep1" {
		t.Fatalf("快速重试应同端点 ep1，got %s", decision.RetryEndpoint)
	}
	if decision.DelayMs != 0 {
		t.Fatalf("快速重试延迟应为 0ms，got %dms", decision.DelayMs)
	}
	if decision.AllEndpointsDown {
		t.Fatalf("不应标记全熔断")
	}
}

// 当前端点熔断：跳过快速重试，直接切到下一个健康端点
func TestCoupled_CurrentEndpointOpen(t *testing.T) {
	circuits := makeTestCircuits()
	// 让 ep1 熔断
	circuits["ep1"].State = CircuitOpen
	circuits["ep1"].LastStateChangeMs = 1000

	retry := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	d := NewCoupledDecider(retry, nil, circuits)

	state := NewRetryState()
	decision := d.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, 2000, true, false)
	if !decision.ShouldRetry {
		t.Fatalf("当前端点熔断应切换到健康端点")
	}
	if decision.RetryEndpoint != "ep2" {
		t.Fatalf("应切换到 ep2，got %s", decision.RetryEndpoint)
	}
	if decision.Reason != "failover_circuit_open" {
		t.Fatalf("reason 应为 failover_circuit_open，got %s", decision.Reason)
	}
}

// 所有端点都熔断：返回全熔断信号
func TestCoupled_AllEndpointsOpen(t *testing.T) {
	circuits := makeTestCircuits()
	for _, cb := range circuits {
		cb.State = CircuitOpen
		cb.LastStateChangeMs = 1000
	}
	retry := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	d := NewCoupledDecider(retry, nil, circuits)

	state := NewRetryState()
	decision := d.ShouldRetry(state, "ep1", []string{"ep1", "ep2", "ep3"}, 2000, true, false)
	if decision.ShouldRetry {
		t.Fatalf("全熔断时不应重试")
	}
	if !decision.AllEndpointsDown {
		t.Fatalf("应标记全熔断")
	}
	if decision.Reason != "all_endpoints_circuit_open" {
		t.Fatalf("reason 应为 all_endpoints_circuit_open，got %s", decision.Reason)
	}
}

// 重试不计入熔断器：isRetry=true 时 RecordFailure 不影响熔断器
func TestCoupled_RetryNotCountedInCircuit(t *testing.T) {
	circuits := makeTestCircuits()
	retry := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	d := NewCoupledDecider(retry, nil, circuits)

	now := int64(1000)
	// 先记 4 次首次失败（样本不足，不应熔断）
	for i := 0; i < 4; i++ {
		d.RecordFailure("ep1", false, 1.0, false, now+int64(i*100))
	}
	if circuits["ep1"].State != CircuitClosed {
		t.Fatalf("4 次首次失败（样本不足）不应熔断")
	}

	// 再记 5 次"重试失败"（isRetry=true，不计入）
	for i := 0; i < 5; i++ {
		d.RecordFailure("ep1", true, 1.0, true, now+500+int64(i*100))
	}
	if circuits["ep1"].State != CircuitClosed {
		t.Fatalf("重试失败不应计入熔断器，不应触发熔断")
	}

	// 再记 1 次首次失败（isRetry=false，valid=true，应触发熔断）
	d.RecordFailure("ep1", false, 1.0, true, now+2000)
	if circuits["ep1"].State != CircuitOpen {
		t.Fatalf("首次失败+有效统计应触发熔断")
	}
}

// 重试不计入熔断器（对称）：isRetry=true 时 RecordSuccess 也不计入
func TestCoupled_RetrySuccessNotCounted(t *testing.T) {
	circuits := makeTestCircuits()
	// 先让 ep1 进入半开
	circuits["ep1"].State = CircuitHalfOpen
	circuits["ep1"].HalfOpenProbeSent = true
	circuits["ep1"].LastStateChangeMs = 1000

	retry := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	d := NewCoupledDecider(retry, nil, circuits)

	// 重试成功不计入（半开状态仍保持，不转 Closed）
	d.RecordSuccess("ep1", true, 0.0, true, 2000)
	if circuits["ep1"].State != CircuitHalfOpen {
		t.Fatalf("重试成功不应计入，半开状态应保持")
	}

	// 首次成功计入（半开→Closed）
	d.RecordSuccess("ep1", false, 0.0, true, 3000)
	if circuits["ep1"].State != CircuitClosed {
		t.Fatalf("首次成功应计入，半开→Closed")
	}
}

// 非幂等请求：不重试
func TestCoupled_NonIdempotent(t *testing.T) {
	circuits := makeTestCircuits()
	retry := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	d := NewCoupledDecider(retry, nil, circuits)

	state := NewRetryState()
	decision := d.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, 1000, false, false)
	if decision.ShouldRetry {
		t.Fatalf("非幂等请求不应重试")
	}
	if decision.Reason != "non_idempotent" {
		t.Fatalf("reason 应为 non_idempotent，got %s", decision.Reason)
	}
}

// 达到最大重试次数：不重试
func TestCoupled_MaxRetries(t *testing.T) {
	circuits := makeTestCircuits()
	retry := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	d := NewCoupledDecider(retry, nil, circuits)

	state := &RetryState{Attempt: 3, LastEndpoint: "ep1", ConsecutiveSameEpFail: 3}
	decision := d.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, 1000, true, false)
	if decision.ShouldRetry {
		t.Fatalf("达到最大重试次数应不再重试")
	}
	if decision.Reason != "max_retries_reached" {
		t.Fatalf("reason 应为 max_retries_reached，got %s", decision.Reason)
	}
}

// 熔断冷却后进入 HalfOpen：探测请求被允许
func TestCoupled_CircuitCooldownHalfOpen(t *testing.T) {
	circuits := makeTestCircuits()
	circuits["ep1"].State = CircuitOpen
	circuits["ep1"].LastStateChangeMs = 1000
	// ep2 也熔断，但冷却时间已到（让 ep1 是当前端点，ep2 也熔断但先冷却好）
	circuits["ep2"].State = CircuitOpen
	circuits["ep2"].LastStateChangeMs = 1000

	retry := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	d := NewCoupledDecider(retry, nil, circuits)

	// 30 秒后（冷却时间到达）
	state := NewRetryState()
	decision := d.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, 31000+1000, true, false)
	// 冷却后熔断器 Allow 会把状态改为 HalfOpen 并允许通过
	if !decision.ShouldRetry {
		t.Fatalf("冷却后应允许探测重试")
	}
	// 当前端点 ep1 冷却后转 HalfOpen，应被选中
	if decision.RetryEndpoint != "ep1" {
		t.Fatalf("当前端点冷却后应优先探测，got %s", decision.RetryEndpoint)
	}
}

// SetCircuits：热更新熔断器映射
func TestCoupled_SetCircuits(t *testing.T) {
	circuits := makeTestCircuits()
	retry := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	d := NewCoupledDecider(retry, nil, circuits)

	// 换一套熔断器
	newCircuits := map[string]*CircuitBreaker{
		"new-ep": NewCircuitBreaker(0.5, 10, 30000),
	}
	d.SetCircuits(newCircuits)

	state := NewRetryState()
	// 旧端点 ep1 不再存在于 circuits 中，视为可用
	decision := d.ShouldRetry(state, "ep1", []string{"ep1", "new-ep"}, 1000, true, false)
	if !decision.ShouldRetry {
		t.Fatalf("无熔断器的端点应视为可用")
	}
}
