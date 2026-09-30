package routeengine

import (
	"testing"
)

// ============================================================
// 三级降级测试（方案 §6.9.10 测试清单节选）
// ============================================================

func makeTestEndpoints() []*EndpointState {
	return []*EndpointState{
		{Name: "ep1", Priority: 1, Enabled: true, Weight: 0.6, CircuitBreaker: CircuitBreaker{State: CircuitClosed}},
		{Name: "ep2", Priority: 1, Enabled: true, Weight: 0.4, CircuitBreaker: CircuitBreaker{State: CircuitClosed}},
		{Name: "ep3", Priority: 2, Enabled: true, Weight: 1.0, CircuitBreaker: CircuitBreaker{State: CircuitClosed}},
	}
}

// 初始状态：L0 正常
func TestDegradation_InitialL0(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 5})
	if m.Level() != DegradationL0 {
		t.Fatalf("初始级别应为 L0，got %s", m.Level())
	}
}

// 所有端点正常 → L0
func TestDegradation_AllHealthyL0(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 5})
	eps := makeTestEndpoints()
	changed := m.Evaluate(eps, 1000)
	if m.Level() != DegradationL0 {
		t.Fatalf("所有端点正常应为 L0，got %s", m.Level())
	}
	// 初始就是 L0，不应变化
	if changed {
		t.Fatalf("同级不应标记变化")
	}
}

// 高优先级组部分端点故障 → L1
func TestDegradation_PartialFailureL1(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 5})
	eps := makeTestEndpoints()
	// ep1 熔断（Priority=1 组部分故障）
	eps[0].CircuitBreaker.State = CircuitOpen
	eps[0].Weight = 0

	changed := m.Evaluate(eps, 1000)
	if !changed {
		t.Fatalf("应标记级别变化")
	}
	if m.Level() != DegradationL1 {
		t.Fatalf("部分端点故障应为 L1，got %s", m.Level())
	}
}

// 高优先级组全故障，低优先级组正常 → L2
func TestDegradation_HighGroupAllDownL2(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 5})
	eps := makeTestEndpoints()
	// Priority=1 的两个端点都熔断
	eps[0].CircuitBreaker.State = CircuitOpen
	eps[0].Weight = 0
	eps[1].CircuitBreaker.State = CircuitOpen
	eps[1].Weight = 0

	changed := m.Evaluate(eps, 1000)
	if !changed {
		t.Fatalf("应标记级别变化")
	}
	if m.Level() != DegradationL2 {
		t.Fatalf("高优先级组全故障应为 L2，got %s", m.Level())
	}
}

// 所有端点都故障 → L3
func TestDegradation_AllDownL3(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 5})
	eps := makeTestEndpoints()
	// 所有端点都熔断
	for _, ep := range eps {
		ep.CircuitBreaker.State = CircuitOpen
		ep.Weight = 0
	}

	changed := m.Evaluate(eps, 1000)
	if !changed {
		t.Fatalf("应标记级别变化")
	}
	if m.Level() != DegradationL3 {
		t.Fatalf("所有端点故障应为 L3，got %s", m.Level())
	}
}

// 空端点列表 → L3
func TestDegradation_EmptyEndpointsL3(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 5})
	changed := m.Evaluate([]*EndpointState{}, 1000)
	if !changed {
		t.Fatalf("应标记级别变化")
	}
	if m.Level() != DegradationL3 {
		t.Fatalf("空端点列表应为 L3，got %s", m.Level())
	}
}

// 迟滞效应：从 L1 恢复到 L0 需要连续成功达标
func TestDegradation_HysteresisL1ToL0(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 3})
	eps := makeTestEndpoints()
	// 先到 L1
	eps[0].CircuitBreaker.State = CircuitOpen
	eps[0].Weight = 0
	m.Evaluate(eps, 1000)
	if m.Level() != DegradationL1 {
		t.Fatalf("先确保在 L1")
	}

	// ep1 恢复健康
	eps[0].CircuitBreaker.State = CircuitClosed
	eps[0].Weight = 0.6

	// 第 1 次成功：未达阈值，仍应保持 L1
	m.RecordSuccess(1)
	changed := m.Evaluate(eps, 2000)
	if changed {
		t.Fatalf("连续成功 1 次（未达阈值 3）不应恢复")
	}
	if m.Level() != DegradationL1 {
		t.Fatalf("未达阈值应保持 L1，got %s", m.Level())
	}

	// 第 2 次成功：仍未达
	m.RecordSuccess(1)
	changed = m.Evaluate(eps, 3000)
	if changed {
		t.Fatalf("连续成功 2 次不应恢复")
	}

	// 第 3 次成功：达到阈值，应恢复到 L0
	m.RecordSuccess(1)
	changed = m.Evaluate(eps, 4000)
	if !changed {
		t.Fatalf("连续成功 3 次（达到阈值）应恢复")
	}
	if m.Level() != DegradationL0 {
		t.Fatalf("恢复后应为 L0，got %s", m.Level())
	}
}

// 迟滞效应：失败重置恢复计数器
func TestDegradation_HysteresisFailureResets(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 5})
	eps := makeTestEndpoints()
	eps[0].CircuitBreaker.State = CircuitOpen
	eps[0].Weight = 0
	m.Evaluate(eps, 1000)

	// 积累 4 次成功
	for i := 0; i < 4; i++ {
		m.RecordSuccess(1)
	}
	// 一次失败 → 计数器归零
	m.RecordFailure(1)
	// 再积累 4 次成功（不足 5 次）
	for i := 0; i < 4; i++ {
		m.RecordSuccess(1)
	}

	eps[0].CircuitBreaker.State = CircuitClosed
	eps[0].Weight = 0.6

	changed := m.Evaluate(eps, 5000)
	if changed {
		t.Fatalf("失败后重新计数，4 次不应达阈值")
	}
	if m.Level() != DegradationL1 {
		t.Fatalf("应保持 L1，got %s", m.Level())
	}
}

// 降级是立即的（不等待）
func TestDegradation_DowngradeImmediate(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 100}) // 恢复阈值很高
	eps := makeTestEndpoints()

	// 从 L0 直接到 L2（高优先级组全挂）
	eps[0].CircuitBreaker.State = CircuitOpen
	eps[0].Weight = 0
	eps[1].CircuitBreaker.State = CircuitOpen
	eps[1].Weight = 0

	changed := m.Evaluate(eps, 1000)
	if !changed {
		t.Fatalf("降级应立即生效")
	}
	if m.Level() != DegradationL2 {
		t.Fatalf("应直接降到 L2，got %s", m.Level())
	}
}

// LastChangeMs 记录变更时间
func TestDegradation_LastChangeMs(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{RecoveryThreshold: 5})
	eps := makeTestEndpoints()
	eps[0].CircuitBreaker.State = CircuitOpen
	eps[0].Weight = 0

	m.Evaluate(eps, 12345)
	if m.LastChangeMs() != 12345 {
		t.Fatalf("LastChangeMs 应为 12345，got %d", m.LastChangeMs())
	}
}

// 默认恢复阈值
func TestDegradation_DefaultThreshold(t *testing.T) {
	m := NewDegradationManager(DegradationConfig{})
	if m.config.RecoveryThreshold != 5 {
		t.Fatalf("默认恢复阈值应为 5，got %d", m.config.RecoveryThreshold)
	}
}

// LevelString 可读名称
func TestDegradation_LevelString(t *testing.T) {
	if DegradationL0.String() != "L0_NORMAL" {
		t.Fatalf("L0 String 不对")
	}
	if DegradationL1.String() != "L1_PARTIAL_DEGRADED" {
		t.Fatalf("L1 String 不对")
	}
	if DegradationL2.String() != "L2_FULL_GROUP_DEGRADED" {
		t.Fatalf("L2 String 不对")
	}
	if DegradationL3.String() != "L3_TOTAL_FAILURE" {
		t.Fatalf("L3 String 不对")
	}
}

// 辅助函数测试：groupByPriorityDesc 按优先级分组
func TestGroupByPriorityDesc(t *testing.T) {
	eps := []*EndpointState{
		{Name: "a", Priority: 2},
		{Name: "b", Priority: 1},
		{Name: "c", Priority: 3},
		{Name: "d", Priority: 1},
	}
	groups := groupByPriorityDesc(eps)
	if len(groups) != 3 {
		t.Fatalf("应分 3 组，got %d", len(groups))
	}
	if groups[0].Priority != 1 {
		t.Fatalf("第一组优先级应为 1（最高），got %d", groups[0].Priority)
	}
	if len(groups[0].Endpoints) != 2 {
		t.Fatalf("优先级 1 应有 2 个端点，got %d", len(groups[0].Endpoints))
	}
	if groups[1].Priority != 2 {
		t.Fatalf("第二组优先级应为 2，got %d", groups[1].Priority)
	}
	if groups[2].Priority != 3 {
		t.Fatalf("第三组优先级应为 3，got %d", groups[2].Priority)
	}
}

// 辅助函数测试：allDown
func TestAllDown(t *testing.T) {
	closed := []*EndpointState{{CircuitBreaker: CircuitBreaker{State: CircuitClosed}, Weight: 1.0, Enabled: true}}
	open := []*EndpointState{{CircuitBreaker: CircuitBreaker{State: CircuitOpen}, Weight: 0, Enabled: true}}
	mixed := []*EndpointState{
		{CircuitBreaker: CircuitBreaker{State: CircuitClosed}, Weight: 1.0, Enabled: true},
		{CircuitBreaker: CircuitBreaker{State: CircuitOpen}, Weight: 0, Enabled: true},
	}
	if allDown(closed) {
		t.Fatalf("closed 不应是 allDown")
	}
	if !allDown(open) {
		t.Fatalf("open 应是 allDown")
	}
	if allDown(mixed) {
		t.Fatalf("mixed 不应是 allDown")
	}
	if !allDown([]*EndpointState{}) {
		t.Fatalf("空列表应是 allDown")
	}
}

// 辅助函数测试：groupPartialDown
func TestGroupPartialDown(t *testing.T) {
	allUp := []*EndpointState{
		{CircuitBreaker: CircuitBreaker{State: CircuitClosed}, Weight: 1.0, Enabled: true},
		{CircuitBreaker: CircuitBreaker{State: CircuitClosed}, Weight: 1.0, Enabled: true},
	}
	allDown := []*EndpointState{
		{CircuitBreaker: CircuitBreaker{State: CircuitOpen}, Weight: 0, Enabled: true},
		{CircuitBreaker: CircuitBreaker{State: CircuitOpen}, Weight: 0, Enabled: true},
	}
	partial := []*EndpointState{
		{CircuitBreaker: CircuitBreaker{State: CircuitClosed}, Weight: 1.0, Enabled: true},
		{CircuitBreaker: CircuitBreaker{State: CircuitOpen}, Weight: 0, Enabled: true},
	}
	if groupPartialDown(allUp) {
		t.Fatalf("allUp 不应是 partialDown")
	}
	if groupPartialDown(allDown) {
		t.Fatalf("allDown 不应是 partialDown")
	}
	if !groupPartialDown(partial) {
		t.Fatalf("partial 应是 partialDown")
	}
}
