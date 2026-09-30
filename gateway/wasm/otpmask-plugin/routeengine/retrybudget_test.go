package routeengine

import (
	"testing"
)

// ============================================================
// RetryBudget 单元测试（方案 §6.7.7 测试清单节选）
// ============================================================

// 初始满桶：MaxTokens 个令牌可用
func TestRB_InitialFull(t *testing.T) {
	b := NewRetryBudget(10, 10000, 1)
	now := int64(1000)
	if b.AvailableTokens(now) != 10 {
		t.Fatalf("初始应有 10 个令牌，got %d", b.AvailableTokens(now))
	}
}

// 正常消耗：每次 TryConsume 减 1
func TestRB_Consume(t *testing.T) {
	b := NewRetryBudget(10, 10000, 1)
	now := int64(1000)
	for i := 0; i < 5; i++ {
		if !b.TryConsume(now) {
			t.Fatalf("第 %d 次应成功消耗", i+1)
		}
	}
	if b.AvailableTokens(now) != 5 {
		t.Fatalf("消耗 5 次后应剩 5 个，got %d", b.AvailableTokens(now))
	}
}

// 令牌耗尽：TryConsume 返回 false
func TestRB_Exhausted(t *testing.T) {
	b := NewRetryBudget(3, 10000, 1)
	now := int64(1000)
	for i := 0; i < 3; i++ {
		if !b.TryConsume(now) {
			t.Fatalf("第 %d 次应成功", i+1)
		}
	}
	// 第 4 次应失败
	if b.TryConsume(now) {
		t.Fatalf("耗尽后应返回 false")
	}
	if b.AvailableTokens(now) != 0 {
		t.Fatalf("耗尽后令牌数应为 0，got %d", b.AvailableTokens(now))
	}
}

// 时间补充：到补充间隔后补充 RefillAmount 个
func TestRB_Refill(t *testing.T) {
	b := NewRetryBudget(10, 10000, 1) // 10s 补 1 个
	now := int64(1000)
	// 耗尽
	for i := 0; i < 10; i++ {
		b.TryConsume(now)
	}
	if b.AvailableTokens(now) != 0 {
		t.Fatalf("耗尽后应为 0")
	}
	// 过 10 秒，应补充 1 个
	now += 10000
	if b.AvailableTokens(now) != 1 {
		t.Fatalf("10s 后应补充 1 个，got %d", b.AvailableTokens(now))
	}
	// 再过 20 秒，应补充 2 个（共 3 个）
	now += 20000
	if b.AvailableTokens(now) != 3 {
		t.Fatalf("20s 后应补到 3 个，got %d", b.AvailableTokens(now))
	}
}

// 补充上限：不超过 MaxTokens
func TestRB_RefillMax(t *testing.T) {
	b := NewRetryBudget(10, 1000, 2) // 1s 补 2 个
	now := int64(1000)
	// 只消耗 3 个
	for i := 0; i < 3; i++ {
		b.TryConsume(now)
	}
	// 过 100 秒，最多补到 10（不能超过 MaxTokens）
	now += 100000
	if b.AvailableTokens(now) != 10 {
		t.Fatalf("不应超过 MaxTokens，got %d", b.AvailableTokens(now))
	}
}

// 补充间隔内不补充
func TestRB_NoRefillWithinInterval(t *testing.T) {
	b := NewRetryBudget(10, 10000, 1)
	now := int64(1000)
	b.TryConsume(now)
	// 过 5 秒（< 10s）
	now += 5000
	if b.AvailableTokens(now) != 9 {
		t.Fatalf("不足补充间隔不应补充，got %d", b.AvailableTokens(now))
	}
}

// Reset：重置到满桶
func TestRB_Reset(t *testing.T) {
	b := NewRetryBudget(10, 10000, 1)
	now := int64(1000)
	for i := 0; i < 7; i++ {
		b.TryConsume(now)
	}
	if b.AvailableTokens(now) != 3 {
		t.Fatalf("消耗 7 个后剩 3 个")
	}
	b.Reset(now + 1000)
	if b.AvailableTokens(now + 1000) != 10 {
		t.Fatalf("Reset 后应满桶 10 个，got %d", b.AvailableTokens(now+1000))
	}
}

// 默认参数：零值时使用默认值
func TestRB_DefaultConfig(t *testing.T) {
	b := NewRetryBudget(0, 0, 0)
	if b.MaxTokens != 10 {
		t.Fatalf("默认 MaxTokens 应为 10，got %d", b.MaxTokens)
	}
	if b.RefillIntervalMs != 10000 {
		t.Fatalf("默认 RefillIntervalMs 应为 10000，got %d", b.RefillIntervalMs)
	}
	if b.RefillAmount != 1 {
		t.Fatalf("默认 RefillAmount 应为 1，got %d", b.RefillAmount)
	}
}

// ============================================================
// BudgetManager 测试
// ============================================================

// 多端点独立：互不影响
func TestBM_MultiEndpointIndependent(t *testing.T) {
	m := NewBudgetManager(RetryBudgetConfig{
		MaxTokens:        10,
		RefillIntervalMs: 10000,
		RefillAmount:     1,
	})
	now := int64(1000)
	// ep1 消耗 3 个
	for i := 0; i < 3; i++ {
		m.TryConsume("ep1", now)
	}
	// ep2 消耗 7 个
	for i := 0; i < 7; i++ {
		m.TryConsume("ep2", now)
	}
	if m.Available("ep1", now) != 7 {
		t.Fatalf("ep1 应剩 7 个，got %d", m.Available("ep1", now))
	}
	if m.Available("ep2", now) != 3 {
		t.Fatalf("ep2 应剩 3 个，got %d", m.Available("ep2", now))
	}
}

// 懒加载：首次访问自动创建
func TestBM_LazyCreate(t *testing.T) {
	m := NewBudgetManager(RetryBudgetConfig{MaxTokens: 5})
	now := int64(1000)
	// 首次访问新端点应自动创建
	if m.Available("new-ep", now) != 5 {
		t.Fatalf("懒加载端点应有 5 个令牌，got %d", m.Available("new-ep", now))
	}
}

// RemoveEndpoint：移除端点
func TestBM_RemoveEndpoint(t *testing.T) {
	m := NewBudgetManager(RetryBudgetConfig{MaxTokens: 10})
	now := int64(1000)
	m.TryConsume("ep1", now)
	m.RemoveEndpoint("ep1")
	// 移除后再次访问应重新创建（满桶）
	if m.Available("ep1", now) != 10 {
		t.Fatalf("移除后重新创建应满桶，got %d", m.Available("ep1", now))
	}
}

// Reset 端点：重置到满桶
func TestBM_ResetEndpoint(t *testing.T) {
	m := NewBudgetManager(RetryBudgetConfig{MaxTokens: 10})
	now := int64(1000)
	for i := 0; i < 6; i++ {
		m.TryConsume("ep1", now)
	}
	m.Reset("ep1", now+1000)
	if m.Available("ep1", now+1000) != 10 {
		t.Fatalf("Reset 后应满桶，got %d", m.Available("ep1", now+1000))
	}
}
