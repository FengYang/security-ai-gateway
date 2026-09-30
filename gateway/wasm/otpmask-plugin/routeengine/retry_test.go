package routeengine

import (
	"testing"
)

// ============================================================
// 非流式重试策略测试（方案 §6.5.10 测试清单节选）
// ============================================================

// 首次成功：不重试（验证初始状态）
func TestRetry_FirstSuccess(t *testing.T) {
	state := NewRetryState()
	// 首次成功，无需调用 ShouldRetry
	// 验证初始状态正确
	if state.Attempt != 1 {
		t.Fatalf("初始 Attempt 应为 1，got %d", state.Attempt)
	}
	if state.ConsecutiveSameEpFail != 0 {
		t.Fatalf("初始 ConsecutiveSameEpFail 应为 0，got %d", state.ConsecutiveSameEpFail)
	}
}

// 达到最大重试次数：不再重试
func TestRetry_MaxRetries(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	state := &RetryState{Attempt: 3, LastEndpoint: "ep1", ConsecutiveSameEpFail: 3}
	decision := p.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, "ep1", 1000, true)
	if decision.ShouldRetry {
		t.Fatalf("达到最大重试次数应不再重试")
	}
	if decision.Reason != "max_retries_reached" {
		t.Fatalf("reason 应为 max_retries_reached，got %s", decision.Reason)
	}
}

// 非幂等请求：不重试
func TestRetry_NonIdempotent(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	state := NewRetryState()
	decision := p.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, "ep1", 1000, false)
	if decision.ShouldRetry {
		t.Fatalf("非幂等请求不应重试")
	}
	if decision.Reason != "non_idempotent" {
		t.Fatalf("reason 应为 non_idempotent，got %s", decision.Reason)
	}
}

// 无可用端点：不重试
func TestRetry_NoAvailableEndpoints(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{MaxRetries: 2}, nil)
	state := NewRetryState()
	decision := p.ShouldRetry(state, "ep1", []string{}, "ep1", 1000, true)
	if decision.ShouldRetry {
		t.Fatalf("无可用端点不应重试")
	}
	if decision.Reason != "no_available_endpoints" {
		t.Fatalf("reason 应为 no_available_endpoints，got %s", decision.Reason)
	}
}

// 第 1 次重试：同端点快速重试（0ms 延迟）
func TestRetry_FastRetrySameEndpoint(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{
		MaxRetries:      2,
		BaseBackoffMs:   10,
	}, nil)
	state := NewRetryState()
	decision := p.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, "ep1", 1000, true)
	if !decision.ShouldRetry {
		t.Fatalf("第 1 次失败应允许重试")
	}
	if decision.RetryEndpoint != "ep1" {
		t.Fatalf("快速重试应同端点 ep1，got %s", decision.RetryEndpoint)
	}
	if decision.DelayMs != 0 {
		t.Fatalf("快速重试延迟应为 0ms，got %dms", decision.DelayMs)
	}
}

// 第 2 次重试：切换端点 + 指数退避
func TestRetry_FailoverToOtherEndpoint(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{
		MaxRetries:        2,
		BaseBackoffMs:     10,
		BackoffMultiplier: 2.0,
	}, nil)
	state := &RetryState{Attempt: 2, LastEndpoint: "ep1", ConsecutiveSameEpFail: 1}
	decision := p.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, "ep1", 1000, true)
	if !decision.ShouldRetry {
		t.Fatalf("第 2 次应允许切换端点重试")
	}
	if decision.RetryEndpoint != "ep2" {
		t.Fatalf("应切换到 ep2，got %s", decision.RetryEndpoint)
	}
	if decision.DelayMs != 20 { // attempt=2 (第 2 次重试) → 10 * 2 = 20
		t.Fatalf("退避延迟应为 20ms，got %dms", decision.DelayMs)
	}
}

// 只有一个端点：无法切换，只能同端点重试（带延迟）
func TestRetry_SingleEndpoint(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{
		MaxRetries:    2,
		BaseBackoffMs: 10,
	}, nil)
	state := &RetryState{Attempt: 2, LastEndpoint: "ep1", ConsecutiveSameEpFail: 1}
	decision := p.ShouldRetry(state, "ep1", []string{"ep1"}, "ep1", 1000, true)
	if !decision.ShouldRetry {
		t.Fatalf("单端点也应重试（同端点）")
	}
	if decision.RetryEndpoint != "ep1" {
		t.Fatalf("单端点只能重试 ep1，got %s", decision.RetryEndpoint)
	}
}

// 重试预算耗尽：不重试
func TestRetry_BudgetExhausted(t *testing.T) {
	bm := NewBudgetManager(RetryBudgetConfig{MaxTokens: 1, RefillIntervalMs: 60000})
	p := NewRetryPolicy(RetryConfig{MaxRetries: 5, DisableFastRetry: true}, bm)
	state := NewRetryState()
	now := int64(1000)

	// 第 1 次应成功消耗令牌
	decision1 := p.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, "ep1", now, true)
	if !decision1.ShouldRetry {
		t.Fatalf("第 1 次应有预算")
	}
	// 第 2 次预算耗尽（只有 1 个令牌）
	state2 := &RetryState{Attempt: 2, LastEndpoint: "ep1", ConsecutiveSameEpFail: 1}
	decision2 := p.ShouldRetry(state2, "ep1", []string{"ep1", "ep2"}, "ep1", now, true)
	if decision2.ShouldRetry {
		t.Fatalf("预算耗尽应不再重试")
	}
	if decision2.Reason != "retry_budget_exhausted" {
		t.Fatalf("reason 应为 retry_budget_exhausted，got %s", decision2.Reason)
	}
}

// 指数退避：延迟递增
func TestRetry_ExponentialBackoff(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{
		MaxRetries:        5,
		DisableFastRetry:  true, // 关掉快速重试，全部走退避
		BaseBackoffMs:     10,
		BackoffMultiplier: 2.0,
		MaxBackoffMs:      200,
	}, nil)
	// 第 1 次重试（attempt=1，不是快速重试）→ 10ms
	delay1 := p.calcDelay(1, false)
	if delay1 != 10 {
		t.Fatalf("第 1 次重试延迟应为 10ms，got %dms", delay1)
	}
	// 第 2 次 → 20ms
	delay2 := p.calcDelay(2, false)
	if delay2 != 20 {
		t.Fatalf("第 2 次重试延迟应为 20ms，got %dms", delay2)
	}
	// 第 3 次 → 40ms
	delay3 := p.calcDelay(3, false)
	if delay3 != 40 {
		t.Fatalf("第 3 次重试延迟应为 40ms，got %dms", delay3)
	}
	// 第 6 次 → 应受 MaxBackoffMs 限制
	delay6 := p.calcDelay(6, false)
	if delay6 != 200 {
		t.Fatalf("第 6 次重试延迟应封顶 200ms，got %dms", delay6)
	}
}

// 禁用同端点快速重试：直接切换端点
func TestRetry_DisableFastRetry(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{
		MaxRetries:       2,
		DisableFastRetry: true, // 禁用同端点快速重试
		BaseBackoffMs:    10,
	}, nil)
	state := NewRetryState()
	decision := p.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, "ep1", 1000, true)
	if !decision.ShouldRetry {
		t.Fatalf("应允许重试")
	}
	if decision.RetryEndpoint != "ep2" {
		t.Fatalf("禁用快速重试后应直接切换端点，got %s", decision.RetryEndpoint)
	}
}

// 禁用端点切换：只能同端点重试
func TestRetry_DisableFailover(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{
		MaxRetries:      2,
		DisableFailover: true, // 禁用端点切换
		BaseBackoffMs:   10,
	}, nil)
	state := NewRetryState()
	decision := p.ShouldRetry(state, "ep1", []string{"ep1", "ep2"}, "ep1", 1000, true)
	if !decision.ShouldRetry {
		t.Fatalf("应允许重试")
	}
	if decision.RetryEndpoint != "ep1" {
		t.Fatalf("禁用切换后应同端点重试，got %s", decision.RetryEndpoint)
	}
}

// 默认配置：零值时使用默认值（DisableFastRetry/DisableFailover 零值 false = 启用）
func TestRetry_DefaultConfig(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{}, nil)
	if p.Config.MaxRetries != 2 {
		t.Fatalf("默认 MaxRetries 应为 2，got %d", p.Config.MaxRetries)
	}
	if p.Config.BaseBackoffMs != 10 {
		t.Fatalf("默认 BaseBackoffMs 应为 10，got %d", p.Config.BaseBackoffMs)
	}
	if p.Config.MaxBackoffMs != 200 {
		t.Fatalf("默认 MaxBackoffMs 应为 200，got %d", p.Config.MaxBackoffMs)
	}
	if p.Config.BackoffMultiplier != 2.0 {
		t.Fatalf("默认 BackoffMultiplier 应为 2.0，got %f", p.Config.BackoffMultiplier)
	}
	if p.Config.DisableFastRetry {
		t.Fatalf("默认应启用快速重试（DisableFastRetry=false）")
	}
	if p.Config.DisableFailover {
		t.Fatalf("默认应启用端点切换（DisableFailover=false）")
	}
}

// 完整重试流程：模拟多轮循环
func TestRetry_FullFlow(t *testing.T) {
	p := NewRetryPolicy(RetryConfig{
		MaxRetries:        3,
		BaseBackoffMs:     10,
		BackoffMultiplier: 2.0,
	}, nil)
	state := NewRetryState()
	eps := []string{"ep1", "ep2"}

	// 第 1 次失败 → 快速重试 ep1（0ms）
	d1 := p.ShouldRetry(state, "ep1", eps, "ep1", 1000, true)
	if !d1.ShouldRetry || d1.RetryEndpoint != "ep1" || d1.DelayMs != 0 {
		t.Fatalf("第 1 次重试不符合预期: %+v", d1)
	}

	// 第 2 次失败 → 切换到 ep2（20ms）
	d2 := p.ShouldRetry(state, "ep1", eps, "ep1", 1000, true)
	if !d2.ShouldRetry || d2.RetryEndpoint != "ep2" {
		t.Fatalf("第 2 次重试不符合预期: %+v", d2)
	}

	// 第 3 次失败 → 再试 ep1（40ms？取决于可用端点顺序，这里始终 ep1 先）
	d3 := p.ShouldRetry(state, "ep2", eps, "ep2", 1000, true)
	if !d3.ShouldRetry {
		t.Fatalf("第 3 次重试应允许")
	}

	// 第 4 次 → 超过 MaxRetries=3，应拒绝
	d4 := p.ShouldRetry(state, "ep1", eps, "ep1", 1000, true)
	if d4.ShouldRetry {
		t.Fatalf("超过最大重试次数应拒绝")
	}
	if d4.Reason != "max_retries_reached" {
		t.Fatalf("reason 应为 max_retries_reached，got %s", d4.Reason)
	}
}
