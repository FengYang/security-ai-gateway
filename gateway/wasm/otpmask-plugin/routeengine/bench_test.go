package routeengine

import (
	"fmt"
	"testing"
)

// ============================================================
// PickEndpoint 基准测试
// ============================================================

// BenchmarkPickEndpoint_Single 单端点基线（最简化路径）
func BenchmarkPickEndpoint_Single(b *testing.B) {
	e := NewEngine(Config{
		Strategy: StrategyPriority,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 1.0, Priority: 1, Enabled: true},
		},
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.PickEndpoint()
	}
}

// BenchmarkPickEndpoint_10Weighted 10 端点权重路由（典型生产场景）
func BenchmarkPickEndpoint_10Weighted(b *testing.B) {
	eps := make([]EndpointConfig, 10)
	for i := 0; i < 10; i++ {
		eps[i] = EndpointConfig{
			Name:     epName(i),
			Weight:   0.1,
			Priority: 1,
			Enabled:  true,
		}
	}
	e := NewEngine(Config{
		Strategy:  StrategyWeighted,
		Endpoints: eps,
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.PickEndpoint()
	}
}

// BenchmarkPickEndpoint_10FailureAware 10 端点失败率感知（带熔断过滤）
func BenchmarkPickEndpoint_10FailureAware(b *testing.B) {
	eps := make([]EndpointConfig, 10)
	for i := 0; i < 10; i++ {
		eps[i] = EndpointConfig{
			Name:     epName(i),
			Weight:   0.1,
			Priority: 1,
			Enabled:  true,
		}
	}
	e := NewEngine(Config{
		Strategy:         StrategyFailureAware,
		Endpoints:        eps,
		EWMAMinSamples:   10,
		EWMAAlpha:        0.2,
		CircuitMinSamples: 20,
	})
	// 预热：建立统计基线
	for i := 0; i < 100; i++ {
		for j := 0; j < 10; j++ {
			e.RecordResult(epName(j), j%5 != 0) // 20% 失败率
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.PickEndpoint()
	}
}

// BenchmarkPickEndpoint_WithCanary 带灰度切流的路由
func BenchmarkPickEndpoint_WithCanary(b *testing.B) {
	e := NewEngine(Config{
		Strategy: StrategyWeighted,
		Endpoints: []EndpointConfig{
			{Name: "ep-stable", Weight: 0.9, Priority: 1, Enabled: true},
			{Name: "ep-canary", Weight: 0.1, Priority: 1, Enabled: true},
		},
		Canary: CanaryConfig{
			Enabled:        true,
			TargetEndpoint: "ep-canary",
			TargetWeight:   0.1,
		},
	})
	e.StartCanary(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.PickEndpoint()
	}
}

// ============================================================
// RecordResult 基准测试
// ============================================================

// BenchmarkRecordResult_Success 纯成功记录（EWMA + 熔断器检查）
func BenchmarkRecordResult_Success(b *testing.B) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 1.0, Priority: 1, Enabled: true},
		},
		EWMAMinSamples: 10,
		EWMAAlpha:      0.2,
	})
	// 预热过最小样本数
	for i := 0; i < 20; i++ {
		e.RecordResult("ep1", true)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.RecordResult("ep1", true)
	}
}

// BenchmarkRecordResult_Failure 纯失败记录（触发熔断路径）
func BenchmarkRecordResult_Failure(b *testing.B) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep1", Weight: 1.0, Priority: 1, Enabled: true},
		},
		EWMAMinSamples:      5,
		EWMAAlpha:           0.5,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:   10,
		CircuitCooldownMs:   60000,
	})
	// 先积累一些成功样本
	for i := 0; i < 10; i++ {
		e.RecordResult("ep1", true)
	}
	b.ResetTimer()
	// 注意：一段时间后会熔断，之后走熔断快速路径
	for i := 0; i < b.N; i++ {
		e.RecordResult("ep1", false)
	}
}

// BenchmarkRecordResult_10EndpointsMixed 10 端点混合结果（更接近真实场景）
func BenchmarkRecordResult_10EndpointsMixed(b *testing.B) {
	eps := make([]EndpointConfig, 10)
	for i := 0; i < 10; i++ {
		eps[i] = EndpointConfig{
			Name:     epName(i),
			Weight:   0.1,
			Priority: 1,
			Enabled:  true,
		}
	}
	e := NewEngine(Config{
		Strategy:         StrategyFailureAware,
		Endpoints:        eps,
		EWMAMinSamples:   10,
		EWMAAlpha:        0.2,
		CircuitMinSamples: 20,
	})
	// 预热
	for ep := 0; ep < 10; ep++ {
		for i := 0; i < 20; i++ {
			e.RecordResult(epName(ep), true)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		epIdx := i % 10
		success := i%7 != 0 // ~14% 失败率
		e.RecordResult(epName(epIdx), success)
	}
}

// ============================================================
// Tick 基准测试
// ============================================================

// BenchmarkTick_10Endpoints 10 端点下 Tick 性能（权重归一化 + 灰度渐进）
func BenchmarkTick_10Endpoints(b *testing.B) {
	eps := make([]EndpointConfig, 10)
	for i := 0; i < 10; i++ {
		eps[i] = EndpointConfig{
			Name:     epName(i),
			Weight:   0.1,
			Priority: 1,
			Enabled:  true,
		}
	}
	e := NewEngine(Config{
		Strategy:            StrategyFailureAware,
		Endpoints:           eps,
		WeightAdjustStep:    0.05,
		WeightFailureThresh: 0.3,
		WeightRecoveryRatio: 0.5,
		Canary: CanaryConfig{
			Enabled:        true,
			TargetEndpoint: "ep-0",
			TargetWeight:   0.2,
			RampStep:       0.02,
			RampIntervalMs: 1000,
		},
	})
	e.StartCanary(0)
	now := int64(0)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		now += 1000
		e.Tick(now)
	}
}

// ============================================================
// 大规模端点基准测试（P1-4：评审补充）
// 验证 100+ 端点规模下的决策性能与内存占用
// ============================================================

// BenchmarkPickEndpoint_100Weighted 100 端点权重路由（大规模场景）
func BenchmarkPickEndpoint_100Weighted(b *testing.B) {
	eps := make([]EndpointConfig, 100)
	for i := 0; i < 100; i++ {
		eps[i] = EndpointConfig{
			Name:     fmt.Sprintf("ep-%03d", i),
			Weight:   1.0 / 100,
			Priority: 1,
			Enabled:  true,
		}
	}
	e := NewEngine(Config{
		Strategy:  StrategyWeighted,
		Endpoints: eps,
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.PickEndpoint()
	}
}

// BenchmarkPickEndpoint_100FailureAware 100 端点失败率感知（带熔断过滤）
func BenchmarkPickEndpoint_100FailureAware(b *testing.B) {
	eps := make([]EndpointConfig, 100)
	for i := 0; i < 100; i++ {
		eps[i] = EndpointConfig{
			Name:     fmt.Sprintf("ep-%03d", i),
			Weight:   1.0 / 100,
			Priority: 1,
			Enabled:  true,
		}
	}
	e := NewEngine(Config{
		Strategy:             StrategyFailureAware,
		Endpoints:            eps,
		EWMAMinSamples:       10,
		EWMAAlpha:            0.2,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:    20,
	})
	// 预热：部分端点失败以建立 EWMA 基线（模拟真实场景）
	for i := 0; i < 200; i++ {
		for j := 0; j < 100; j++ {
			// 每 5 个端点有 1 个失败率较高
			success := j%5 != 0 || i%3 != 0
			e.RecordResult(fmt.Sprintf("ep-%03d", j), success)
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.PickEndpoint()
	}
}

// BenchmarkPickEndpoint_10PriorityGroups 10 个优先级组（每级 10 端点）
func BenchmarkPickEndpoint_10PriorityGroups(b *testing.B) {
	eps := make([]EndpointConfig, 100)
	for i := 0; i < 100; i++ {
		eps[i] = EndpointConfig{
			Name:     fmt.Sprintf("ep-p%d-%d", i/10, i%10),
			Weight:   0.1,
			Priority: (i / 10) + 1, // 10 个优先级组
			Enabled:  true,
		}
	}
	e := NewEngine(Config{
		Strategy:  StrategyPriority,
		Endpoints: eps,
	})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = e.PickEndpoint()
	}
}

// BenchmarkUpdateConfigSmooth_100Endpoints 100 端点下配置平滑更新性能
// 验证热更新路径的时间复杂度（应为 O(n)，n 为端点数）
func BenchmarkUpdateConfigSmooth_100Endpoints(b *testing.B) {
	eps := make([]EndpointConfig, 100)
	for i := 0; i < 100; i++ {
		eps[i] = EndpointConfig{
			Name:     fmt.Sprintf("ep-%03d", i),
			Weight:   1.0 / 100,
			Priority: 1,
			Enabled:  true,
		}
	}
	e := NewEngine(Config{
		Strategy:  StrategyFailureAware,
		Endpoints: eps,
	})
	// 预热：积累一些状态
	for i := 0; i < 100; i++ {
		for j := 0; j < 100; j++ {
			e.RecordResult(fmt.Sprintf("ep-%03d", j), true)
		}
	}
	// 构造新配置（部分端点权重变化，模拟灰度调整）
	newEps := make([]EndpointConfig, 100)
	copy(newEps, eps)
	newEps[0].Weight = 0.05
	newEps[1].Weight = 0.15
	newConfig := Config{
		Strategy:  StrategyFailureAware,
		Endpoints: newEps,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		e.UpdateConfigSmooth(newConfig)
	}
}

// ============================================================
// 辅助函数
// ============================================================

func epName(i int) string {
	names := []string{"ep-0", "ep-1", "ep-2", "ep-3", "ep-4", "ep-5", "ep-6", "ep-7", "ep-8", "ep-9"}
	return names[i%10]
}
