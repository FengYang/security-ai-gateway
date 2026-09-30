package routeengine

import (
	"testing"
)

// ============================================================
// 熔断器单元测试（方案 §6.3.9 测试清单节选）
// ============================================================

// 初始状态：Closed，允许请求
func TestCB_InitialClosed(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 10, 30000)
	if cb.State != CircuitClosed {
		t.Fatalf("初始状态应为 Closed，got %v", cb.State)
	}
	if !cb.Allow(1000) {
		t.Fatalf("Closed 状态应允许请求")
	}
}

// Closed → Open：失败率超阈值 + 样本足够
func TestCB_ClosedToOpen(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 5, 30000)
	now := int64(1000)
	// 先喂 4 次失败（模拟样本数不足阶段，valid=false）
	for i := 0; i < 4; i++ {
		now += 100
		changed := cb.OnResult(false, 1.0, false, now) // 前 4 次样本不足
		if changed {
			t.Fatalf("样本不足时不应触发熔断，第 %d 次", i+1)
		}
	}
	if cb.State != CircuitClosed {
		t.Fatalf("样本不足应保持 Closed")
	}
	// 第 5 次：样本足够，失败率 1.0 ≥ 0.5，应触发熔断
	now += 100
	changed := cb.OnResult(false, 1.0, true, now)
	if !changed {
		t.Fatalf("第 5 次失败（样本足够）应触发熔断")
	}
	if cb.State != CircuitOpen {
		t.Fatalf("应转为 Open，got %v", cb.State)
	}
	if cb.LastStateChangeMs != now {
		t.Fatalf("状态变更时间应更新")
	}
}

// Closed 下样本不足：不熔断（即使失败率很高）
func TestCB_ClosedMinSamples(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 10, 30000)
	now := int64(1000)
	for i := 0; i < 5; i++ {
		now += 100
		changed := cb.OnResult(false, 1.0, false, now) // 无效
		if changed {
			t.Fatalf("样本不足时不应触发熔断")
		}
	}
	if cb.State != CircuitClosed {
		t.Fatalf("样本不足应保持 Closed")
	}
}

// Open → HalfOpen：冷却时间到达，首个请求转半开
func TestCB_OpenToHalfOpen(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 5, 10000) // 10 秒冷却
	now := int64(1000)
	// 先触发熔断
	for i := 0; i < 5; i++ {
		now += 100
		cb.OnResult(false, 1.0, true, now)
	}
	if cb.State != CircuitOpen {
		t.Fatalf("应先进入 Open")
	}

	// 冷却时间内：拒绝
	if cb.Allow(now + 5000) {
		t.Fatalf("冷却期内应拒绝")
	}
	if cb.State != CircuitOpen {
		t.Fatalf("冷却期内应保持 Open")
	}

	// 冷却时间到：转 HalfOpen 并允许探测
	allowed := cb.Allow(now + 10000 + 100)
	if !allowed {
		t.Fatalf("冷却后应允许探测请求")
	}
	if cb.State != CircuitHalfOpen {
		t.Fatalf("冷却后应转为 HalfOpen")
	}
	if !cb.HalfOpenProbeSent {
		t.Fatalf("应标记探测已发送")
	}
}

// HalfOpen：探测请求只有 1 个，后续请求被拒绝
func TestCB_HalfOpenSingleProbe(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 5, 10000)
	now := int64(1000)
	for i := 0; i < 5; i++ {
		now += 100
		cb.OnResult(false, 1.0, true, now)
	}

	// 冷却后进入 HalfOpen
	probeTime := now + 20000
	if !cb.Allow(probeTime) {
		t.Fatalf("第一个探测应允许")
	}
	// 第二个请求应被拒绝
	if cb.Allow(probeTime + 10) {
		t.Fatalf("半开状态下第二个请求应被拒绝")
	}
}

// HalfOpen → Closed：探测成功
func TestCB_HalfOpenToClosed(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 5, 10000)
	now := int64(1000)
	for i := 0; i < 5; i++ {
		now += 100
		cb.OnResult(false, 1.0, true, now)
	}

	probeTime := now + 20000
	cb.Allow(probeTime) // 触发 HalfOpen
	changed := cb.OnResult(true, 0.0, true, probeTime+100)
	if !changed {
		t.Fatalf("探测成功应触发状态变更")
	}
	if cb.State != CircuitClosed {
		t.Fatalf("探测成功应转为 Closed")
	}
	if cb.HalfOpenProbeSent {
		t.Fatalf("Closed 状态下探测标记应复位")
	}
}

// HalfOpen → Open：探测失败
func TestCB_HalfOpenToOpen(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 5, 10000)
	now := int64(1000)
	for i := 0; i < 5; i++ {
		now += 100
		cb.OnResult(false, 1.0, true, now)
	}

	probeTime := now + 20000
	cb.Allow(probeTime) // 触发 HalfOpen
	changed := cb.OnResult(false, 1.0, true, probeTime+100)
	if !changed {
		t.Fatalf("探测失败应触发状态变更")
	}
	if cb.State != CircuitOpen {
		t.Fatalf("探测失败应转回 Open")
	}
}

// 探测失败后重新进入冷却（冷却时间从新的状态变更时间算起）
func TestCB_HalfOpenFailResetsCooldown(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 5, 10000)
	now := int64(1000)
	for i := 0; i < 5; i++ {
		now += 100
		cb.OnResult(false, 1.0, true, now)
	}
	firstOpenTime := cb.LastStateChangeMs

	// 冷却后探测失败
	probeTime := now + 20000
	cb.Allow(probeTime)
	cb.OnResult(false, 1.0, true, probeTime+100)

	if cb.LastStateChangeMs <= firstOpenTime {
		t.Fatalf("探测失败后冷却时间应重置")
	}
	// 新的冷却期内仍应拒绝
	if cb.Allow(probeTime + 5000) {
		t.Fatalf("新冷却期内应拒绝")
	}
}

// Reset：重置到 Closed
func TestCB_Reset(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 5, 10000)
	now := int64(1000)
	for i := 0; i < 5; i++ {
		now += 100
		cb.OnResult(false, 1.0, true, now)
	}
	if cb.State != CircuitOpen {
		t.Fatalf("应先进入 Open")
	}

	cb.Reset(now + 1000)
	if cb.State != CircuitClosed {
		t.Fatalf("Reset 后应转为 Closed")
	}
	if cb.HalfOpenProbeSent {
		t.Fatalf("Reset 后探测标记应清除")
	}
	if cb.LastStateChangeMs != now+1000 {
		t.Fatalf("Reset 后状态变更时间应更新")
	}
}

// IsOpen/IsClosed/IsHalfOpen 辅助方法
func TestCB_StateHelpers(t *testing.T) {
	cb := NewCircuitBreaker(0.5, 5, 10000)
	if !cb.IsClosed() {
		t.Fatal("初始应 Closed")
	}
	if cb.IsOpen() {
		t.Fatal("初始不应 Open")
	}
	if cb.IsHalfOpen() {
		t.Fatal("初始不应 HalfOpen")
	}
}
