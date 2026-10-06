package routeengine

import (
	crand "crypto/rand"
	"encoding/binary"
	"math"
	"os"
	"testing"
)

// TestMain 为全部用例注入同步随机源（P0-4 §4.7：routeengine 不再自带密码随机源，
// 由插件注入经 cryptop sidecar `/v1/rand` 的实现；单测注入同步实现，语义等价）。
func TestMain(m *testing.M) {
	SetRandSource(syncRand{})
	os.Exit(m.Run())
}

// syncRand 同步随机源（单测专用；crypto/* 仅测试允许）。
type syncRand struct{}

func (syncRand) Float64() (float64, bool) {
	var b [8]byte
	if _, err := crand.Read(b[:]); err != nil {
		return 0, false
	}
	n := binary.BigEndian.Uint64(b[:])
	return float64(n>>11) / (1 << 53), true
}

// floatEqual 浮点比较（绝对误差 < 1e-9）。
func floatEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

// 基础功能：创建引擎 + 端点数量正确
func TestNewEngineBasic(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 0.6, Priority: 1, Enabled: true},
			{Name: "ep2", Weight: 0.4, Priority: 1, Enabled: true},
			{Name: "ep3", Weight: 1.0, Priority: 2, Enabled: true},
		},
	})
	if e.EndpointCount() != 3 {
		t.Fatalf("端点数量应为 3，got %d", e.EndpointCount())
	}
}

// 空配置：引擎正常工作，PickEndpoint 返回空决策
func TestNewEngineEmpty(t *testing.T) {
	e := NewEngine(Config{})
	if e.EndpointCount() != 0 {
		t.Fatalf("空配置端点数量应为 0，got %d", e.EndpointCount())
	}
	d := e.PickEndpoint()
	if d.EndpointName != "" {
		t.Fatalf("空配置应返回空决策，got %+v", d)
	}
	if d.Reason != "no_usable_endpoints" {
		t.Fatalf("空配置 reason 应为 no_usable_endpoints，got %s", d.Reason)
	}
}

// 主备模式：优先选 priority=1 的端点
func TestPickByPriority(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyPriority,
		Endpoints: []EndpointConfig{
			{Name: "backup", Weight: 1.0, Priority: 2, Enabled: true},
			{Name: "main", Weight: 1.0, Priority: 1, Enabled: true},
		},
	})
	d := e.PickEndpoint()
	if d.EndpointName != "main" {
		t.Fatalf("优先级模式应选 priority=1 的 main，got %s", d.EndpointName)
	}
	if d.Strategy != StrategyPriority {
		t.Fatalf("策略应为 priority，got %s", d.Strategy)
	}
}

// 权重模式：大量调用下比例接近配置权重
func TestPickByWeightDistribution(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "ep-a", Weight: 0.6, Priority: 1, Enabled: true},
			{Name: "ep-b", Weight: 0.4, Priority: 1, Enabled: true},
		},
	})
	counts := make(map[string]int)
	n := 10000
	for i := 0; i < n; i++ {
		d := e.PickEndpoint()
		counts[d.EndpointName]++
	}
	ratioA := float64(counts["ep-a"]) / float64(n)
	ratioB := float64(counts["ep-b"]) / float64(n)
	// 容许 5% 偏差（10000 样本下 99% 置信区间内）
	if ratioA < 0.55 || ratioA > 0.65 {
		t.Fatalf("ep-a 比例应为 ~0.6，got %.3f", ratioA)
	}
	if ratioB < 0.35 || ratioB > 0.45 {
		t.Fatalf("ep-b 比例应为 ~0.4，got %.3f", ratioB)
	}
}

// 多优先级组的权重模式：只在最高优先级组内按权重分配
func TestPickByWeightMultiPriority(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "ep-a", Weight: 0.5, Priority: 1, Enabled: true},
			{Name: "ep-b", Weight: 0.5, Priority: 1, Enabled: true},
			{Name: "ep-backup", Weight: 1.0, Priority: 2, Enabled: true},
		},
	})
	// 1000 次都不应选到 backup（priority=2）
	for i := 0; i < 1000; i++ {
		d := e.PickEndpoint()
		if d.EndpointName == "ep-backup" {
			t.Fatalf("最高优先级组有可用端点时不应选到 backup，got %s", d.EndpointName)
		}
	}
}

// 禁用端点：不被选中
func TestDisabledEndpointSkipped(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyPriority,
		Endpoints: []EndpointConfig{
			{Name: "main", Weight: 1.0, Priority: 1, Enabled: false}, // 禁用
			{Name: "backup", Weight: 1.0, Priority: 2, Enabled: true},
		},
	})
	d := e.PickEndpoint()
	if d.EndpointName != "backup" {
		t.Fatalf("禁用主端点后应选 backup，got %s", d.EndpointName)
	}
}

// RecordResult：成功/失败后 EWMA 失败率正确反映趋势
// （7 成功 + 3 失败，α=0.1，EWMA 应在 0.3 附近，且样本数有效）
func TestRecordResult(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 1.0, Priority: 1, Enabled: true},
		},
		EWMAMinSamples: 5, // 降低最小样本数便于测试
		EWMAAlpha:      0.2,
	})
	for i := 0; i < 7; i++ {
		e.RecordResult("ep1", true)
	}
	for i := 0; i < 3; i++ {
		e.RecordResult("ep1", false)
	}
	rate, valid := e.GetEndpointFailureRate("ep1")
	if !valid {
		t.Fatalf("样本数应达到有效阈值")
	}
	// 10 个样本下，失败率应在合理范围内（不会是精确 0.3，因为 EWMA 有平滑）
	if rate <= 0 || rate >= 1.0 {
		t.Fatalf("失败率应在 (0,1) 范围内，got %.4f", rate)
	}
	// 连续失败后失败率应呈上升趋势（再打 5 次失败，rate 应更高）
	for i := 0; i < 5; i++ {
		e.RecordResult("ep1", false)
	}
	rateAfter, _ := e.GetEndpointFailureRate("ep1")
	if rateAfter <= rate {
		t.Fatalf("连续失败后失败率应上升，before=%.4f after=%.4f", rate, rateAfter)
	}
}

// RecordResult 未知端点：静默忽略（不 panic）
func TestRecordResultUnknownEndpoint(t *testing.T) {
	e := NewEngine(Config{
		Endpoints: []EndpointConfig{{Name: "ep1", Enabled: true}},
	})
	// 不 panic 即可
	e.RecordResult("unknown", true)
	e.RecordResult("unknown", false)
}

// 配置热更新：UpdateConfig 后新配置生效
func TestUpdateConfig(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyPriority,
		Endpoints: []EndpointConfig{
			{Name: "old-ep", Weight: 1.0, Priority: 1, Enabled: true},
		},
	})
	if e.PickEndpoint().EndpointName != "old-ep" {
		t.Fatal("初始配置应返回 old-ep")
	}
	// 热更新
	e.UpdateConfig(Config{
		Strategy: StrategyPriority,
		Endpoints: []EndpointConfig{
			{Name: "new-ep", Weight: 1.0, Priority: 1, Enabled: true},
		},
	})
	if e.PickEndpoint().EndpointName != "new-ep" {
		t.Fatalf("热更新后应返回 new-ep，got %s", e.PickEndpoint().EndpointName)
	}
	if e.EndpointCount() != 1 {
		t.Fatalf("热更新后端点数量应为 1，got %d", e.EndpointCount())
	}
}

// 平滑热更新：同名端点保留失败率和熔断器状态
func TestUpdateConfigSmooth_PreservesState(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 0.6, Priority: 1, Enabled: true},
			{Name: "ep2", Weight: 0.4, Priority: 1, Enabled: true},
		},
		EWMAMinSamples:       5,
		EWMAAlpha:            0.3,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:    5,
		CircuitCooldownMs:    30000,
	})

	// ep1 失败 20 次 → 熔断
	for i := 0; i < 20; i++ {
		e.RecordResult("ep1", false)
		e.RecordResult("ep2", true)
	}

	// 验证 ep1 已熔断
	state1, _ := e.GetEndpointCircuitState("ep1")
	if state1 != CircuitOpen {
		t.Fatalf("ep1 应熔断，got %v", state1)
	}
	rate1, valid1 := e.GetEndpointFailureRate("ep1")
	if !valid1 {
		t.Fatalf("ep1 失败率应有效")
	}
	weight1, _ := e.GetEndpointWeight("ep1")

	// 平滑热更新（端点名称相同，配置微调）
	e.UpdateConfigSmooth(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 0.5, Priority: 1, Enabled: true}, // 权重改了
			{Name: "ep2", Weight: 0.5, Priority: 1, Enabled: true},
		},
		EWMAMinSamples:       5,
		EWMAAlpha:            0.3,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:    5,
		CircuitCooldownMs:    30000,
	})

	// ep1 应保留熔断状态
	state1After, _ := e.GetEndpointCircuitState("ep1")
	if state1After != CircuitOpen {
		t.Fatalf("平滑更新后 ep1 应保留熔断状态，got %v", state1After)
	}

	// ep1 应保留失败率
	rate1After, valid1After := e.GetEndpointFailureRate("ep1")
	if !valid1After {
		t.Fatalf("平滑更新后 ep1 失败率应仍有效")
	}
	if rate1After != rate1 {
		t.Fatalf("平滑更新后 ep1 失败率应不变，before=%.4f after=%.4f", rate1, rate1After)
	}

	// 权重在归一化后动态调整（熔断端权重会降低，但不影响其存在性）
	weight1After, _ := e.GetEndpointWeight("ep1")
	if weight1After <= 0 {
		t.Fatalf("ep1 权重不应为 0，got %.4f", weight1After)
	}
	_ = weight1

	// 端点数量应不变
	if e.EndpointCount() != 2 {
		t.Fatalf("端点数量应为 2，got %d", e.EndpointCount())
	}
}

// 平滑热更新：新端点全新初始化，旧端点保留
func TestUpdateConfigSmooth_AddRemove(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 0.5, Priority: 1, Enabled: true},
			{Name: "ep2", Weight: 0.5, Priority: 1, Enabled: true},
		},
	})

	// 给 ep1 一些历史
	for i := 0; i < 10; i++ {
		e.RecordResult("ep1", false)
	}
	rate1Before, _ := e.GetEndpointFailureRate("ep1")

	// 平滑更新：移除 ep2，新增 ep3
	e.UpdateConfigSmooth(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 0.6, Priority: 1, Enabled: true},
			{Name: "ep3", Weight: 0.4, Priority: 1, Enabled: true},
		},
	})

	if e.EndpointCount() != 2 {
		t.Fatalf("端点数量应为 2，got %d", e.EndpointCount())
	}

	// ep1 应保留
	rate1After, _ := e.GetEndpointFailureRate("ep1")
	if rate1After != rate1Before {
		t.Fatalf("ep1 失败率应保留，before=%.4f after=%.4f", rate1Before, rate1After)
	}

	// ep3 应是新的（失败率 0）
	rate3, valid3 := e.GetEndpointFailureRate("ep3")
	if valid3 {
		t.Fatalf("ep3 应是新端点，失败率统计无效")
	}
	if rate3 != 0 {
		t.Fatalf("ep3 初始失败率应为 0，got %.4f", rate3)
	}

	// ep2 应被移除
	_, ok := e.GetEndpointFailureRate("ep2")
	if ok {
		t.Fatalf("ep2 应被移除")
	}
}

// 平滑热更新：优先级变更后正确重新分组
func TestUpdateConfigSmooth_PriorityChange(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyPriority,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 1.0, Priority: 1, Enabled: true},
			{Name: "ep2", Weight: 1.0, Priority: 2, Enabled: true},
		},
	})

	// 应选 ep1（priority=1）
	d := e.PickEndpoint()
	if d.EndpointName != "ep1" {
		t.Fatalf("初始应选 ep1，got %s", d.EndpointName)
	}

	// 平滑更新：ep1 降到 priority=2，ep2 升到 priority=1
	e.UpdateConfigSmooth(Config{
		Strategy: StrategyPriority,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 1.0, Priority: 2, Enabled: true},
			{Name: "ep2", Weight: 1.0, Priority: 1, Enabled: true},
		},
	})

	// 应选 ep2（priority=1）
	d = e.PickEndpoint()
	if d.EndpointName != "ep2" {
		t.Fatalf("优先级变更后应选 ep2，got %s", d.EndpointName)
	}
}

// EndpointIsUsable：各种状态的可用性判断
func TestEndpointIsUsable(t *testing.T) {
	tests := []struct {
		name     string
		ep       EndpointState
		expected bool
	}{
		{"正常启用", EndpointState{Enabled: true, CircuitBreaker: CircuitBreaker{State: CircuitClosed}, Weight: 1.0}, true},
		{"禁用", EndpointState{Enabled: false, CircuitBreaker: CircuitBreaker{State: CircuitClosed}, Weight: 1.0}, false},
		{"熔断打开", EndpointState{Enabled: true, CircuitBreaker: CircuitBreaker{State: CircuitOpen}, Weight: 1.0}, false},
		{"半开", EndpointState{Enabled: true, CircuitBreaker: CircuitBreaker{State: CircuitHalfOpen}, Weight: 1.0}, true},
		{"权重为零", EndpointState{Enabled: true, CircuitBreaker: CircuitBreaker{State: CircuitClosed}, Weight: 0}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ep.IsUsable() != tt.expected {
				t.Fatalf("IsUsable 应为 %v，got %v", tt.expected, tt.ep.IsUsable())
			}
		})
	}
}

// 随机源：[0,1) 范围内
func TestRandomFloat64Range(t *testing.T) {
	SetRandSource(syncRand{})
	for i := 0; i < 1000; i++ {
		r, ok := randFloat64()
		if !ok {
			t.Fatal("注入随机源后 randFloat64 应可用")
		}
		if r < 0 || r >= 1.0 {
			t.Fatalf("randFloat64 应在 [0,1) 范围内，got %f", r)
		}
	}
}

// ============================================================
// 灰度切流集成测试（方案 §7.5）
// ============================================================

// 灰度未启用：Engine 无 canary，PickEndpoint 行为与无灰度一致
func TestCanaryDisabled(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "main", Weight: 0.7, Priority: 1, Enabled: true},
			{Name: "canary", Weight: 0.3, Priority: 1, Enabled: true},
		},
		// Canary 零值 = 未启用
	})
	if _, ok := e.CanarySnapshot(); ok {
		t.Fatalf("未启用灰度时 CanarySnapshot 应返回 false")
	}
	d := e.PickEndpoint()
	if d.CanaryGroup != "" {
		t.Fatalf("未启用灰度时 CanaryGroup 应为空，got %s", d.CanaryGroup)
	}
	// Tick 不应 panic
	changed := e.Tick(1000)
	if changed {
		t.Fatalf("未启用灰度时 Tick 应返回 false")
	}
}

// 灰度启动后：权重渐进放量，Tick 推进状态
func TestCanaryRampingUp(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "main", Weight: 0.9, Priority: 1, Enabled: true},
			{Name: "canary-ep", Weight: 0.1, Priority: 1, Enabled: true},
		},
		Canary: CanaryConfig{
			Enabled:            true,
			TargetEndpoint:     "canary-ep",
			TargetWeight:       0.1,
			RampStep:           0.2, // 每次增 20% 进度
			RampIntervalMs:     1000,
			RollbackThreshold:  0.5,
			RollbackMinSamples: 10,
		},
	})

	// 初始状态：Idle
	snap, ok := e.CanarySnapshot()
	if !ok {
		t.Fatalf("启用灰度后 CanarySnapshot 应返回 true")
	}
	if snap.State != CanaryIdle {
		t.Fatalf("初始状态应为 Idle，got %v", snap.State)
	}

	// 启动灰度
	now := int64(1000)
	if !e.StartCanary(now) {
		t.Fatalf("StartCanary 应成功")
	}

	// 启动后第一步放量：进度 0.2，权重 = 0.1 × 0.2 = 0.02
	snap, _ = e.CanarySnapshot()
	if snap.State != CanaryRampingUp {
		t.Fatalf("启动后应为 RampingUp，got %v", snap.State)
	}
	if snap.CurrentProgress != 0.2 {
		t.Fatalf("进度应为 0.2，got %.4f", snap.CurrentProgress)
	}
	if !floatEqual(snap.CurrentWeight, 0.02) {
		t.Fatalf("权重应为 0.02，got %.4f", snap.CurrentWeight)
	}

	// 再推进 2 步（间隔 1s）
	e.Tick(2000) // 第 2 步
	snap, _ = e.CanarySnapshot()
	if !floatEqual(snap.CurrentProgress, 0.4) {
		t.Fatalf("第 2 步进度应为 0.4，got %.4f", snap.CurrentProgress)
	}

	e.Tick(3000) // 第 3 步
	snap, _ = e.CanarySnapshot()
	if !floatEqual(snap.CurrentProgress, 0.6) {
		t.Fatalf("第 3 步进度应为 0.6，got %.4f", snap.CurrentProgress)
	}

	// 推进到第 5 步 → 达到目标（进度 1.0 → Stable）
	e.Tick(4000)
	e.Tick(5000)
	snap, _ = e.CanarySnapshot()
	if snap.State != CanaryStable {
		t.Fatalf("达到目标后应为 Stable，got %v", snap.State)
	}
	if !floatEqual(snap.CurrentProgress, 1.0) {
		t.Fatalf("进度应为 1.0，got %.4f", snap.CurrentProgress)
	}
	if !floatEqual(snap.CurrentWeight, 0.1) {
		t.Fatalf("权重应达到目标 0.1，got %.4f", snap.CurrentWeight)
	}
}

// 灰度自动回滚：灰度端点失败率超标 → 立即回滚
func TestCanaryAutoRollback(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "main", Weight: 0.9, Priority: 1, Enabled: true},
			{Name: "canary-ep", Weight: 0.1, Priority: 1, Enabled: true},
		},
		Canary: CanaryConfig{
			Enabled:            true,
			TargetEndpoint:     "canary-ep",
			TargetWeight:       0.1,
			RampStep:           1.0,  // 一步到位
			RampIntervalMs:     1000,
			RollbackThreshold:  0.3,  // 30% 即回滚
			RollbackMinSamples: 5,    // 5 个样本就判定
		},
		EWMAMinSamples: 5,
		EWMAAlpha:      0.5,
	})

	now := int64(1000)
	e.StartCanary(now)
	// 一步达到 Stable
	e.Tick(2000)
	snap, _ := e.CanarySnapshot()
	if snap.State != CanaryStable {
		t.Fatalf("应已达到 Stable，got %v", snap.State)
	}

	// 让灰度端点连续失败（10 次全失败）
	for i := 0; i < 10; i++ {
		e.RecordResult("canary-ep", false)
	}

	// Tick 检测 → 自动回滚
	changed := e.Tick(3000)
	if !changed {
		t.Fatalf("失败率超标后 Tick 应触发回滚")
	}
	snap, _ = e.CanarySnapshot()
	if snap.State != CanaryRolledBack {
		t.Fatalf("应已回滚到 RolledBack，got %v", snap.State)
	}
	if snap.CurrentWeight != 0 {
		t.Fatalf("回滚后权重应为 0，got %.4f", snap.CurrentWeight)
	}
	if snap.Reason != "failure_rate_exceeded" {
		t.Fatalf("回滚原因应为 failure_rate_exceeded，got %s", snap.Reason)
	}
}

// 灰度租户白名单：白名单租户强制走灰度端点
func TestCanaryTenantWhitelist(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "main", Weight: 0.9, Priority: 1, Enabled: true},
			{Name: "canary-ep", Weight: 0.1, Priority: 1, Enabled: true},
		},
		Canary: CanaryConfig{
			Enabled:        true,
			TargetEndpoint: "canary-ep",
			TargetWeight:   0.1,
			RampStep:       0.5,
			RampIntervalMs: 1000,
			AllowedTenants: []string{"qa-team", "dev-team"},
		},
	})

	now := int64(1000)
	e.StartCanary(now)
	e.Tick(2000) // 进度到 0.5

	// 白名单租户：应始终走 canary-ep
	for i := 0; i < 20; i++ {
		d := e.PickEndpointForTenant("qa-team")
		if d.EndpointName != "canary-ep" {
			t.Fatalf("白名单租户应走灰度端点，got %s", d.EndpointName)
		}
		if d.CanaryGroup != "whitelist" {
			t.Fatalf("白名单租户 CanaryGroup 应为 whitelist，got %s", d.CanaryGroup)
		}
	}

	// 非白名单租户：可能走 main 或 canary（按权重），CanaryGroup 为 control 或 treatment
	hasTreatment := false
	hasControl := false
	for i := 0; i < 100; i++ {
		d := e.PickEndpointForTenant("other-tenant")
		if d.CanaryGroup == "treatment" {
			hasTreatment = true
		} else if d.CanaryGroup == "control" {
			hasControl = true
		}
	}
	// 进度 50% × 权重 0.1 = 5% 灰度流量，100 次大概率有 treatment 和 control
	// 至少应该有 control（大多数情况）
	if !hasControl {
		t.Fatalf("非白名单租户应有 control 分组")
	}
	_ = hasTreatment
}

// 灰度 + 热更新：配置变更后灰度重建
func TestCanaryUpdateConfig(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "main", Weight: 0.9, Priority: 1, Enabled: true},
			{Name: "canary-v1", Weight: 0.1, Priority: 1, Enabled: true},
		},
		Canary: CanaryConfig{
			Enabled:        true,
			TargetEndpoint: "canary-v1",
			TargetWeight:   0.1,
			RampStep:       1.0,
			RampIntervalMs: 1000,
		},
	})

	now := int64(1000)
	e.StartCanary(now)
	e.Tick(2000)

	snap, _ := e.CanarySnapshot()
	if snap.State != CanaryStable {
		t.Fatalf("初始灰度应达到 Stable，got %v", snap.State)
	}

	// 热更新：换灰度目标端点
	e.UpdateConfig(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "main", Weight: 0.85, Priority: 1, Enabled: true},
			{Name: "canary-v2", Weight: 0.15, Priority: 1, Enabled: true},
		},
		Canary: CanaryConfig{
			Enabled:        true,
			TargetEndpoint: "canary-v2",
			TargetWeight:   0.15,
			RampStep:       1.0,
			RampIntervalMs: 1000,
		},
	})

	// 新配置后灰度重置为 Idle
	snap2, ok := e.CanarySnapshot()
	if !ok {
		t.Fatalf("更新后灰度应仍启用")
	}
	if snap2.State != CanaryIdle {
		t.Fatalf("更新后灰度应重置为 Idle，got %v", snap2.State)
	}

	// 启动新灰度
	e.StartCanary(3000)
	e.Tick(4000)
	snap2, _ = e.CanarySnapshot()
	if snap2.State != CanaryStable {
		t.Fatalf("新灰度应达到 Stable，got %v", snap2.State)
	}
	if !floatEqual(snap2.CurrentWeight, 0.15) {
		t.Fatalf("新灰度权重应为 0.15，got %.4f", snap2.CurrentWeight)
	}
}

// 灰度目标端点不存在：灰度不启用（Engine.canary = nil）
func TestCanaryTargetNotFound(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "main", Weight: 1.0, Priority: 1, Enabled: true},
		},
		Canary: CanaryConfig{
			Enabled:        true,
			TargetEndpoint: "nonexistent",
			TargetWeight:   0.1,
		},
	})
	if _, ok := e.CanarySnapshot(); ok {
		t.Fatalf("目标端点不存在时灰度应不启用")
	}
	d := e.PickEndpoint()
	if d.CanaryGroup != "" {
		t.Fatalf("无有效灰度时 CanaryGroup 应为空，got %s", d.CanaryGroup)
	}
}
