package routeengine

// ============================================================
// 竞态条件测试（P1-3：评审补充）
// 验证 Engine 在并发读写场景下无数据竞争
// 运行方式：go test -race -run TestRace ./...
//
// 设计说明：
//   - Wasm 单线程假设下路由引擎本无并发需求，但管理面 API（控制面推送配置
//     / 灰度操作 / 快照读取）可能与数据面请求路径并发（多 worker 下），
//     因此用 -race 验证所有导出方法的并发安全性。
//   - 本文件测试覆盖：并发 PickEndpoint + RecordResult + Tick +
//     UpdateConfigSmooth + Snapshot + GetEndpoint* 的混合场景。
// ============================================================

import (
	"fmt"
	"sync"
	"testing"
)

// make10Endpoints 创建 10 个端点的配置（典型场景）。
func make10Endpoints() []EndpointConfig {
	eps := make([]EndpointConfig, 10)
	for i := 0; i < 10; i++ {
		eps[i] = EndpointConfig{
			Name:     fmt.Sprintf("ep-%d", i),
			Weight:   0.1,
			Priority: 1,
			Enabled:  true,
		}
	}
	return eps
}

// TestRace_PickAndRecord 并发 PickEndpoint + RecordResult 无竞态。
// 模拟多 worker 下请求路径的并发读写。
func TestRace_PickAndRecord(t *testing.T) {
	e := NewEngine(Config{
		Strategy:             StrategyFailureAware,
		Endpoints:            make10Endpoints(),
		EWMAMinSamples:       5,
		EWMAAlpha:            0.2,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:    10,
		CircuitCooldownMs:    1000,
	})

	var wg sync.WaitGroup
	// 8 个 goroutine 并发：4 读（Pick）+ 4 写（Record）
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				_ = e.PickEndpoint()
			}
		}()
	}
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				epIdx := i % 10
				success := (i+id)%5 != 0 // 不同 goroutine 失败率不同
				e.RecordResult(fmt.Sprintf("ep-%d", epIdx), success)
			}
		}(g)
	}
	wg.Wait()
}

// TestRace_UpdateConfigSmooth 并发配置更新无竞态。
// 模拟控制面热更新与数据面请求并发的场景。
func TestRace_UpdateConfigSmooth(t *testing.T) {
	e := NewEngine(Config{
		Strategy:  StrategyWeighted,
		Endpoints: make10Endpoints(),
	})

	var wg sync.WaitGroup
	// 6 个读 goroutine
	for g := 0; g < 6; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				_ = e.PickEndpoint()
				_ = e.EndpointCount()
				_, _ = e.GetEndpointFailureRate("ep-0")
			}
		}()
	}
	// 2 个写 goroutine（模拟配置热更新）
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				eps := make10Endpoints()
				// 动态调整权重，模拟灰度放量
				eps[0].Weight = 0.1 + float64(id%5)*0.02
				e.UpdateConfigSmooth(Config{
					Strategy:  StrategyWeighted,
					Endpoints: eps,
				})
			}
		}(g)
	}
	wg.Wait()
}

// TestRace_TickAndSnapshot 并发 Tick + Snapshot 无竞态。
// 模拟定时任务与监控采样并发的场景。
func TestRace_TickAndSnapshot(t *testing.T) {
	e := NewEngine(Config{
		Strategy: StrategyFailureAware,
		Endpoints: []EndpointConfig{
			{Name: "ep-stable", Weight: 0.9, Priority: 1, Enabled: true},
			{Name: "ep-canary", Weight: 0.1, Priority: 1, Enabled: true},
		},
		Canary: CanaryConfig{
			Enabled:            true,
			TargetEndpoint:     "ep-canary",
			TargetWeight:       0.1,
			RampStep:           0.01,
			RampIntervalMs:     10,
			RollbackThreshold:  0.05,
			RollbackMinSamples: 5,
		},
	})
	e.StartCanary(0)

	var wg sync.WaitGroup
	// Tick goroutine（模拟定时推进）
	wg.Add(1)
	go func() {
		defer wg.Done()
		now := int64(0)
		for i := 0; i < 500; i++ {
			now += 5
			e.Tick(now)
		}
	}()
	// 采样 goroutine（模拟监控/日志）
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				_ = e.Snapshot()
				_, _ = e.CanarySnapshot()
				_ = e.UsableEndpointNames()
			}
		}()
	}
	// 请求路径 goroutine
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				d := e.PickEndpoint()
				if d.EndpointName != "" {
					success := (i+id)%10 != 0
					e.RecordResult(d.EndpointName, success)
				}
			}
		}(g)
	}
	wg.Wait()
}

// TestRace_FullMix 全混合场景：所有导出方法并发调用。
// 这是最严苛的竞态验证，覆盖管理面 + 数据面 + 监控面的并发混合。
func TestRace_FullMix(t *testing.T) {
	e := NewEngine(Config{
		Strategy:             StrategyFailureAware,
		Endpoints:            make10Endpoints(),
		EWMAMinSamples:       5,
		EWMAAlpha:            0.2,
		CircuitFailureThresh: 0.5,
		CircuitMinSamples:    10,
		CircuitCooldownMs:    500,
		WeightAdjustStep:     0.05,
		WeightFailureThresh:  0.3,
		WeightRecoveryRatio:  0.5,
		Canary: CanaryConfig{
			Enabled:            true,
			TargetEndpoint:     "ep-0",
			TargetWeight:       0.2,
			RampStep:           0.02,
			RampIntervalMs:     20,
			RollbackThreshold:  0.1,
			RollbackMinSamples: 10,
		},
	})
	e.StartCanary(0)

	var wg sync.WaitGroup
	now := int64(0)

	// 1. 请求路径（Pick + Record）
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 800; i++ {
				d := e.PickEndpoint()
				if d.EndpointName != "" {
					e.RecordResult(d.EndpointName, (i+id)%7 != 0)
				}
			}
		}(g)
	}

	// 2. 租户维度路由
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				tenant := fmt.Sprintf("tenant-%d", (i+id)%5)
				_ = e.PickEndpointForTenant(tenant)
			}
		}(g)
	}

	// 3. 定时 Tick
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			now += 10
			e.Tick(now)
		}
	}()

	// 4. 配置热更新
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			eps := make10Endpoints()
			eps[i%10].Weight = 0.05 + float64(i%10)*0.01
			e.UpdateConfigSmooth(Config{
				Strategy:             StrategyFailureAware,
				Endpoints:            eps,
				EWMAMinSamples:       5,
				EWMAAlpha:            0.2,
				CircuitFailureThresh: 0.5,
				CircuitMinSamples:    10,
				CircuitCooldownMs:    500,
			})
		}
	}()

	// 5. 监控采样
	for g := 0; g < 2; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				_ = e.Snapshot()
				for _, name := range e.EndpointNames() {
					_, _ = e.GetEndpointFailureRate(name)
					_, _ = e.GetEndpointCircuitState(name)
					_, _ = e.GetEndpointWeight(name)
					_, _ = e.EndpointPriority(name)
					_, _ = e.EndpointURL(name)
				}
				_ = e.EndpointCount()
				_, _ = e.CanarySnapshot()
			}
		}()
	}

	// 6. 灰度操作（模拟手动灰度控制）
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			if i%10 == 5 {
				e.RollbackCanary("manual_test", int64(i*100))
			} else if i%10 == 0 {
				e.StartCanary(int64(i * 100))
			}
		}
	}()

	wg.Wait()
}
