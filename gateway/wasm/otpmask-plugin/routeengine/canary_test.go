package routeengine

import (
	"testing"
)

// ============================================================
// 灰度切流测试
// ============================================================

// 初始状态：Idle，进度 0
func TestCanary_InitialIdle(t *testing.T) {
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:         "canary-ep",
		TargetWeight: 0.2,
		RampStep:     0.05,
	}, nil, nil)

	if m.State().State != CanaryIdle {
		t.Fatalf("初始状态应为 Idle，got %s", m.State().State)
	}
	if m.State().CurrentProgress != 0 {
		t.Fatalf("初始进度应为 0，got %.4f", m.State().CurrentProgress)
	}
}

// Start 后进入 RampingUp，第一步放量
func TestCanary_StartRamping(t *testing.T) {
	var setWeight float64
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:             "canary-ep",
		TargetWeight:     0.2,
		RampStep:         0.05, // 5% 步长
		RampIntervalMs:   60000,
	},
		func() (float64, bool) { return 0.0, false },
		func(w float64) { setWeight = w },
	)

	started := m.Start(1000)
	if !started {
		t.Fatalf("Start 应返回 true")
	}
	if m.State().State != CanaryRampingUp {
		t.Fatalf("状态应为 RampingUp，got %s", m.State().State)
	}
	// 第一步放量：5%
	if m.State().CurrentProgress != 0.05 {
		t.Fatalf("第一步进度应为 0.05，got %.4f", m.State().CurrentProgress)
	}
	// 当前权重 = 目标权重 * 进度 = 0.2 * 0.05 = 0.01
	expectedWeight := m.config.TargetWeight * m.config.RampStep
	if absFloat(m.State().CurrentWeight-expectedWeight) > 1e-9 {
		t.Fatalf("当前权重应为 %.4f，got %.4f", expectedWeight, m.State().CurrentWeight)
	}
	if absFloat(setWeight-expectedWeight) > 1e-9 {
		t.Fatalf("setWeight 回调应收到 %.4f，got %.4f", expectedWeight, setWeight)
	}
}

// Tick 推进放量（间隔到达）
func TestCanary_TickRampUp(t *testing.T) {
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:           "canary-ep",
		TargetWeight:   0.2,
		RampStep:       0.05,
		RampIntervalMs: 60000, // 60 秒
	},
		func() (float64, bool) { return 0.0, false },
		nil,
	)

	m.Start(0)
	// 初始第一步：0.05

	// 30 秒后：未到间隔，不推进
	changed := m.Tick(30000)
	if changed {
		t.Fatalf("未到间隔不应推进")
	}
	if m.State().CurrentProgress != 0.05 {
		t.Fatalf("进度应保持 0.05，got %.4f", m.State().CurrentProgress)
	}

	// 60 秒后：到间隔，推进一步
	changed = m.Tick(60000)
	if !changed {
		t.Fatalf("到间隔应推进")
	}
	if m.State().CurrentProgress != 0.1 {
		t.Fatalf("第二步进度应为 0.1，got %.4f", m.State().CurrentProgress)
	}
}

// 放量到目标权重后进入 Stable
func TestCanary_ReachStable(t *testing.T) {
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:           "canary-ep",
		TargetWeight:   0.1,
		RampStep:       1.0, // 一步到位（100% 进度）
		RampIntervalMs: 1000,
	},
		func() (float64, bool) { return 0.0, false },
		nil,
	)

	// Start 第一步就到 100% = Stable
	m.Start(0)

	if m.State().State != CanaryStable {
		t.Fatalf("一步到位应直接 Stable，got %s", m.State().State)
	}
	if m.State().CurrentProgress != 1.0 {
		t.Fatalf("进度应到 1.0，got %.4f", m.State().CurrentProgress)
	}
	if absFloat(m.State().CurrentWeight-0.1) > 1e-9 {
		t.Fatalf("权重应达到目标 0.1，got %.4f", m.State().CurrentWeight)
	}
}

// 自动回滚：失败率超阈值时立即回滚
func TestCanary_AutoRollback(t *testing.T) {
	failureRate := 0.0
	valid := false
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:               "canary-ep",
		TargetWeight:       0.2,
		RampStep:           0.1,
		RampIntervalMs:     60000,
		RollbackThreshold:  0.05, // 5% 阈值
		RollbackMinSamples: 10,
	},
		func() (float64, bool) { return failureRate, valid },
		nil,
	)

	m.Start(1000)
	if m.State().State != CanaryRampingUp {
		t.Fatalf("初始应为 RampingUp")
	}

	// 样本不足：即使失败率高也不回滚
	failureRate = 0.5
	valid = false
	changed := m.Tick(2000)
	if changed {
		t.Fatalf("样本不足不应回滚")
	}
	if m.State().State == CanaryRolledBack {
		t.Fatalf("样本不足不应回滚")
	}

	// 样本充足 + 失败率超阈值：立即回滚
	valid = true
	changed = m.Tick(3000)
	if !changed {
		t.Fatalf("失败率超阈值应触发回滚")
	}
	if m.State().State != CanaryRolledBack {
		t.Fatalf("应回滚到 RolledBack，got %s", m.State().State)
	}
	if m.State().CurrentWeight != 0 {
		t.Fatalf("回滚后权重应为 0，got %.4f", m.State().CurrentWeight)
	}
	if m.State().Reason != "failure_rate_exceeded" {
		t.Fatalf("回滚原因应为 failure_rate_exceeded，got %s", m.State().Reason)
	}
}

// Stable 状态下也可触发回滚
func TestCanary_StableRollback(t *testing.T) {
	failureRate := 0.0
	valid := true
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:               "canary-ep",
		TargetWeight:       0.1,
		RampStep:           1.0, // 一步到位
		RampIntervalMs:     1000,
		RollbackThreshold:  0.05,
		RollbackMinSamples: 10,
	},
		func() (float64, bool) { return failureRate, valid },
		nil,
	)

	m.Start(0) // 一步到 Stable
	if m.State().State != CanaryStable {
		t.Fatalf("应直接到 Stable，got %s", m.State().State)
	}

	// Stable 状态下失败率飙升
	failureRate = 0.2
	changed := m.Tick(5000)
	if !changed {
		t.Fatalf("Stable 下失败率超阈值应回滚")
	}
	if m.State().State != CanaryRolledBack {
		t.Fatalf("应回滚，got %s", m.State().State)
	}
}

// 手动回滚
func TestCanary_ManualRollback(t *testing.T) {
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:         "canary-ep",
		TargetWeight: 0.2,
		RampStep:     0.1,
	},
		func() (float64, bool) { return 0.0, false },
		nil,
	)

	m.Start(1000)
	m.Rollback("manual_triggered", 2000)

	if m.State().State != CanaryRolledBack {
		t.Fatalf("手动回滚后应是 RolledBack，got %s", m.State().State)
	}
	if m.State().Reason != "manual_triggered" {
		t.Fatalf("回滚原因应为 manual_triggered，got %s", m.State().Reason)
	}
}

// 回滚后可以重新启动
func TestCanary_RollbackThenRestart(t *testing.T) {
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:         "canary-ep",
		TargetWeight: 0.2,
		RampStep:     0.1,
	},
		func() (float64, bool) { return 0.0, false },
		nil,
	)

	m.Start(1000)
	m.Rollback("test", 2000)

	if m.State().State != CanaryRolledBack {
		t.Fatalf("先确保回滚")
	}

	// 重新启动
	restarted := m.Start(3000)
	if !restarted {
		t.Fatalf("回滚后应可重新启动")
	}
	if m.State().State != CanaryRampingUp {
		t.Fatalf("重新启动后应为 RampingUp，got %s", m.State().State)
	}
}

// 租户白名单：白名单内租户允许，白名单外拒绝
func TestCanary_TenantWhitelist(t *testing.T) {
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:           "canary-ep",
		TargetWeight:   0.2,
		AllowedTenants: []string{"tenant-a", "tenant-b"},
	},
		nil, nil,
	)

	if !m.IsTenantAllowed("tenant-a") {
		t.Fatalf("白名单内租户应允许")
	}
	if !m.IsTenantAllowed("tenant-b") {
		t.Fatalf("白名单内租户应允许")
	}
	if m.IsTenantAllowed("tenant-c") {
		t.Fatalf("白名单外租户应拒绝")
	}
	if m.IsTenantAllowed("") {
		t.Fatalf("空租户应拒绝")
	}
}

// 白名单为空：所有租户都允许
func TestCanary_EmptyWhitelistAllowsAll(t *testing.T) {
	m := NewCanaryManager(CanaryEndpointConfig{
		Name:         "canary-ep",
		TargetWeight: 0.2,
		AllowedTenants: []string{}, // 空 = 全部允许
	},
		nil, nil,
	)

	if !m.IsTenantAllowed("any-tenant") {
		t.Fatalf("空白名单应允许所有租户")
	}
	if !m.IsTenantAllowed("") {
		t.Fatalf("空白名单应允许空租户")
	}
}

// 默认参数
func TestCanary_DefaultConfig(t *testing.T) {
	m := NewCanaryManager(CanaryEndpointConfig{}, nil, nil)

	if m.config.TargetWeight != 0.1 {
		t.Fatalf("默认 TargetWeight 应为 0.1，got %.4f", m.config.TargetWeight)
	}
	if m.config.RampStep != 0.05 {
		t.Fatalf("默认 RampStep 应为 0.05，got %.4f", m.config.RampStep)
	}
	if m.config.RampIntervalMs != 60000 {
		t.Fatalf("默认 RampIntervalMs 应为 60000，got %d", m.config.RampIntervalMs)
	}
	if m.config.RollbackThreshold != 0.1 {
		t.Fatalf("默认 RollbackThreshold 应为 0.1，got %.4f", m.config.RollbackThreshold)
	}
	if m.config.RollbackMinSamples != 20 {
		t.Fatalf("默认 RollbackMinSamples 应为 20，got %d", m.config.RollbackMinSamples)
	}
}

// StateString 可读名称
func TestCanary_StateString(t *testing.T) {
	if CanaryIdle.String() != "IDLE" {
		t.Fatal("Idle string wrong")
	}
	if CanaryRampingUp.String() != "RAMPING_UP" {
		t.Fatal("RampingUp string wrong")
	}
	if CanaryStable.String() != "STABLE" {
		t.Fatal("Stable string wrong")
	}
	if CanaryRollingBack.String() != "ROLLING_BACK" {
		t.Fatal("RollingBack string wrong")
	}
	if CanaryRolledBack.String() != "ROLLED_BACK" {
		t.Fatal("RolledBack string wrong")
	}
}

func absFloat(x float64) float64 {
	if x < 0 {
		return -x
	}
	return x
}
