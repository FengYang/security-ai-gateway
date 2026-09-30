package routeengine

import (
	"testing"
)

// ============================================================
// Engine 可观测性快照测试
// ============================================================

// Snapshot 基本结构验证
func TestSnapshot_Basic(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "z-ep", Weight: 0.3, Priority: 1, Enabled: true},
			{Name: "a-ep", Weight: 0.7, Priority: 1, Enabled: true},
			{Name: "backup", Weight: 1.0, Priority: 2, Enabled: true},
		},
	})

	snap := e.Snapshot()

	if snap.Strategy != StrategyFailureAware {
		t.Fatalf("Strategy 应为 failure-aware，got %s", snap.Strategy)
	}
	if snap.EndpointCount != 3 {
		t.Fatalf("EndpointCount 应为 3，got %d", snap.EndpointCount)
	}
	if snap.UsableCount != 3 {
		t.Fatalf("UsableCount 应为 3，got %d", snap.UsableCount)
	}
	if len(snap.Endpoints) != 3 {
		t.Fatalf("Endpoints 长度应为 3，got %d", len(snap.Endpoints))
	}

	// 验证按名称排序
	if snap.Endpoints[0].Name != "a-ep" {
		t.Fatalf("第一个应为 a-ep，got %s", snap.Endpoints[0].Name)
	}
	if snap.Endpoints[1].Name != "backup" {
		t.Fatalf("第二个应为 backup，got %s", snap.Endpoints[1].Name)
	}
	if snap.Endpoints[2].Name != "z-ep" {
		t.Fatalf("第三个应为 z-ep，got %s", snap.Endpoints[2].Name)
	}
}

// Snapshot 反映失败率和熔断状态
func TestSnapshot_ReflectsState(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 0.6, Priority: 1, Enabled: true},
			{Name: "ep2", Weight: 0.4, Priority: 1, Enabled: true},
		},
		EWMAMinSamples:       5,
		EWMAAlpha:            0.5,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:    5,
		CircuitCooldownMs:    30000,
	})

	// ep1 持续失败（最终应熔断）
	for i := 0; i < 30; i++ {
		e.RecordResult("ep1", false)
		e.RecordResult("ep2", true)
	}

	snap := e.Snapshot()

	// 找到 ep1
	var ep1Snap *EndpointSnapshot
	for i := range snap.Endpoints {
		if snap.Endpoints[i].Name == "ep1" {
			ep1Snap = &snap.Endpoints[i]
			break
		}
	}
	if ep1Snap == nil {
		t.Fatal("ep1 快照不存在")
	}

	// ep1 应熔断
	if ep1Snap.CircuitState != CircuitOpen {
		t.Fatalf("ep1 应处于 Open，got %v", ep1Snap.CircuitState)
	}
	// ep1 失败率应高
	if ep1Snap.FailureRate < 0.5 {
		t.Fatalf("ep1 失败率应 > 0.5，got %.4f", ep1Snap.FailureRate)
	}
	// ep1 样本数应有效
	if !ep1Snap.FailureValid {
		t.Fatalf("ep1 失败率统计应有效")
	}
	// 可用数应为 1（只剩 ep2）
	if snap.UsableCount != 1 {
		t.Fatalf("UsableCount 应为 1，got %d", snap.UsableCount)
	}
}

// 空引擎快照
func TestSnapshot_Empty(t *testing.T) {
	e := NewEngine(Config{})
	snap := e.Snapshot()
	if snap.EndpointCount != 0 {
		t.Fatalf("空引擎 EndpointCount 应为 0，got %d", snap.EndpointCount)
	}
	if snap.UsableCount != 0 {
		t.Fatalf("空引擎 UsableCount 应为 0，got %d", snap.UsableCount)
	}
	if len(snap.Endpoints) != 0 {
		t.Fatalf("空引擎 Endpoints 长度应为 0，got %d", len(snap.Endpoints))
	}
}
