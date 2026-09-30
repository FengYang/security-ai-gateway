package routeengine

import (
	"testing"
)

// 被动模式：ShouldCheck 永远返回 false
func TestHealthCheck_PassiveMode(t *testing.T) {
	h := NewHealthChecker(
		HealthCheckConfig{Mode: HealthCheckPassive, IntervalMs: 1000},
		nil, nil, nil,
	)
	h.RegisterEndpoint("ep1")

	if h.ShouldCheck("ep1") {
		t.Fatal("被动模式不应触发主动检查")
	}
}

// 主动模式：按间隔触发
func TestHealthCheck_ActiveModeInterval(t *testing.T) {
	h := NewHealthChecker(
		HealthCheckConfig{
			Mode:             HealthCheckActive,
			IntervalMs:       5000,
			SuccessThreshold: 3,
			FailureThreshold: 3,
		},
		nil, nil, nil,
	)
	h.RegisterEndpoint("ep1")
	h.SetNow(0)

	// 第一次应检查
	if !h.ShouldCheck("ep1") {
		t.Fatal("首次应触发检查")
	}

	// 间隔未到，不应再检查
	h.SetNow(1000)
	if h.ShouldCheck("ep1") {
		t.Fatal("间隔未到不应检查")
	}

	// 有检查在飞，即使过了间隔也不重复
	h.SetNow(6000)
	if h.ShouldCheck("ep1") {
		t.Fatal("检查在飞不应重复")
	}

	// 完成检查后，下一次间隔到时应再次检查
	h.RecordCheckResult("ep1", true)
	h.SetNow(11000)
	if !h.ShouldCheck("ep1") {
		t.Fatal("完成后间隔到应再次检查")
	}
}

// MIXED 模式：低流量触发，高流量跳过
func TestHealthCheck_MixedModeTraffic(t *testing.T) {
	rps := 0.0
	valid := true
	h := NewHealthChecker(
		HealthCheckConfig{
			Mode:          HealthCheckMixed,
			IntervalMs:    1000,
			LowTrafficRPS: 1.0,
		},
		func(name string) (float64, bool) { return rps, valid },
		nil, nil,
	)
	h.RegisterEndpoint("ep1")
	h.SetNow(0)

	// 低流量（0.2 RPS < 1.0）→ 触发
	rps = 0.2
	if !h.ShouldCheck("ep1") {
		t.Fatal("低流量应触发主动检查")
	}
	h.RecordCheckResult("ep1", true)

	// 高流量（5.0 RPS >= 1.0）→ 跳过
	h.SetNow(2000)
	rps = 5.0
	if h.ShouldCheck("ep1") {
		t.Fatal("高流量不应触发主动检查")
	}

	// 流量无效（无数据）→ 视为低流量，触发
	h.SetNow(3000)
	valid = false
	if !h.ShouldCheck("ep1") {
		t.Fatal("流量无效时应视为低流量并触发")
	}
}

// 连续失败触发主动不健康判定
func TestHealthCheck_ActiveUnhealthy(t *testing.T) {
	h := NewHealthChecker(
		HealthCheckConfig{
			Mode:             HealthCheckActive,
			IntervalMs:       100,
			FailureThreshold: 3,
			SuccessThreshold: 3,
		},
		nil, nil, nil,
	)
	h.RegisterEndpoint("ep1")

	if h.IsActivelyUnhealthy("ep1") {
		t.Fatal("初始应为健康")
	}

	// 失败 2 次 → 还没到阈值
	h.RecordCheckResult("ep1", false)
	h.RecordCheckResult("ep1", false)
	if h.IsActivelyUnhealthy("ep1") {
		t.Fatal("2 次失败不应判定不健康")
	}

	// 第 3 次失败 → 判定不健康
	h.RecordCheckResult("ep1", false)
	if !h.IsActivelyUnhealthy("ep1") {
		t.Fatal("3 次失败应判定不健康")
	}

	// 成功 3 次 → 恢复
	for i := 0; i < 3; i++ {
		h.RecordCheckResult("ep1", true)
	}
	if h.IsActivelyUnhealthy("ep1") {
		t.Fatal("3 次成功应恢复健康")
	}
}

// 主动检查结果回写到 Engine（通过回调）
func TestHealthCheck_RecordResultCallback(t *testing.T) {
	var recordedName string
	var recordedSuccess bool
	var callCount int

	h := NewHealthChecker(
		HealthCheckConfig{
			Mode:             HealthCheckActive,
			IntervalMs:       100,
			FailureThreshold: 3,
			SuccessThreshold: 3,
		},
		nil,
		func(name string, success bool) {
			recordedName = name
			recordedSuccess = success
			callCount++
		},
		nil,
	)
	h.RegisterEndpoint("ep1")

	h.RecordCheckResult("ep1", true)
	if callCount != 1 {
		t.Fatalf("应回调 1 次，got %d", callCount)
	}
	if recordedName != "ep1" {
		t.Fatalf("回调 name 错误，got %s", recordedName)
	}
	if !recordedSuccess {
		t.Fatal("回调 success 应为 true")
	}
}

// TickEndpoints 返回所有需要检查的端点
func TestHealthCheck_TickEndpoints(t *testing.T) {
	h := NewHealthChecker(
		HealthCheckConfig{
			Mode:       HealthCheckActive,
			IntervalMs: 1000,
		},
		nil, nil, nil,
	)
	h.RegisterEndpoint("ep1")
	h.RegisterEndpoint("ep2")
	h.SetNow(0)

	eps := h.TickEndpoints()
	if len(eps) != 2 {
		t.Fatalf("首次 tick 应返回 2 个端点，got %d", len(eps))
	}

	// 完成 ep1 的检查
	h.RecordCheckResult("ep1", true)

	// 间隔未到，再次 tick 不应返回
	h.SetNow(500)
	eps = h.TickEndpoints()
	if len(eps) != 0 {
		t.Fatalf("间隔未到不应返回端点，got %d", len(eps))
	}

	// 间隔到了，ep1 应返回
	h.SetNow(1500)
	eps = h.TickEndpoints()
	if len(eps) != 1 {
		t.Fatalf("应返回 1 个端点（ep2 还在飞），got %d", len(eps))
	}
}

// 注销端点
func TestHealthCheck_Unregister(t *testing.T) {
	h := NewHealthChecker(
		HealthCheckConfig{
			Mode:       HealthCheckActive,
			IntervalMs: 1000,
		},
		nil, nil, nil,
	)
	h.RegisterEndpoint("ep1")
	h.SetNow(0)

	eps := h.TickEndpoints()
	if len(eps) != 1 {
		t.Fatalf("应返回 1 个端点，got %d", len(eps))
	}

	h.UnregisterEndpoint("ep1")
	h.RecordCheckResult("ep1", true) // 已注销，应安全忽略

	eps = h.TickEndpoints()
	if len(eps) != 0 {
		t.Fatalf("注销后不应再返回端点，got %d", len(eps))
	}
}

// Mode 字符串
func TestHealthCheck_ModeString(t *testing.T) {
	if HealthCheckPassive.String() != "PASSIVE" {
		t.Fatal("Passive string wrong")
	}
	if HealthCheckActive.String() != "ACTIVE" {
		t.Fatal("Active string wrong")
	}
	if HealthCheckMixed.String() != "MIXED" {
		t.Fatal("Mixed string wrong")
	}
}

// GetEndpointState 可观测性
func TestHealthCheck_GetEndpointState(t *testing.T) {
	h := NewHealthChecker(
		HealthCheckConfig{
			Mode:             HealthCheckActive,
			IntervalMs:       100,
			FailureThreshold: 2,
			SuccessThreshold: 2,
		},
		nil, nil, nil,
	)
	h.RegisterEndpoint("ep1")
	h.SetNow(1000)

	// 未注册的端点
	_, ok := h.GetEndpointState("nonexistent")
	if ok {
		t.Fatal("不存在的端点应返回 false")
	}

	// 失败 2 次 → 不健康
	h.RecordCheckResult("ep1", false)
	h.RecordCheckResult("ep1", false)

	state, ok := h.GetEndpointState("ep1")
	if !ok {
		t.Fatal("ep1 应存在")
	}
	if !state.ActiveUnhealthy {
		t.Fatal("ep1 应不健康")
	}
	if state.ConsecutiveFail != 2 {
		t.Fatalf("连续失败应为 2，got %d", state.ConsecutiveFail)
	}
	if state.Mode != "ACTIVE" {
		t.Fatalf("模式应为 ACTIVE，got %s", state.Mode)
	}
}
