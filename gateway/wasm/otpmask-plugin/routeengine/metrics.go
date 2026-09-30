package routeengine

// ============================================================
// Engine 可观测性快照
// 设计依据：方案 §10 可观测性
//
// 说明（重要）：
// proxy-wasm 的 MetricGauge 在多 worker 下由 Envoy 按累加聚合（各 worker 独立
// 实例，共享进程级统计），"当前值"语义不成立（同 metrics.go 文件中已说明的
// 版本号 gauge 问题）。因此路由运行时 Gauge 类指标（失败率、熔断状态、降级级别）
// 在 Engine 内存态维护，通过 Snapshot() 方法导出，由日志/调试接口消费。
// Counter 类指标（请求数、重试数、熔断事件数）通过 proxy-wasm Counter 暴露。
// ============================================================

// EndpointSnapshot 单端点运行时快照。
type EndpointSnapshot struct {
	Name            string         // 端点名称
	URL             string         // 端点地址
	Priority        int            // 优先级
	Enabled         bool           // 是否启用
	BaseWeight      float64        // 基础权重
	CurrentWeight   float64        // 当前权重（动态调整后）
	FailureRate     float64        // EWMA 失败率（0-1）
	SampleCount     int64          // 累计样本数
	FailureValid    bool           // 失败率统计是否有效（样本充足）
	CircuitState    CircuitState   // 熔断器状态
}

// EngineSnapshot 引擎运行时快照（用于监控、日志、调试）。
type EngineSnapshot struct {
	Strategy         Strategy            // 当前策略
	EndpointCount    int                 // 端点总数
	UsableCount      int                 // 可用端点数
	Endpoints        []EndpointSnapshot  // 各端点快照（按名称排序，输出稳定）
	Canary           *CanaryStateSnapshot // 灰度状态快照（nil 表示无灰度）
}

// Snapshot 生成引擎运行时快照（读路径，RLock）。
//
// 用于：
//   - 日志定期输出（onTick）
//   - 调试接口返回
//   - 与外部监控系统集成
func (e *Engine) Snapshot() EngineSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	snap := EngineSnapshot{
		Strategy:      e.config.Strategy,
		EndpointCount: len(e.state),
		Endpoints:     make([]EndpointSnapshot, 0, len(e.state)),
	}

	// 按名称收集（输出稳定顺序）
	names := make([]string, 0, len(e.state))
	for name := range e.state {
		names = append(names, name)
	}
	// 简单选择排序（端点数量通常不多）
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}

	for _, name := range names {
		ep := e.state[name]
		es := EndpointSnapshot{
			Name:         ep.Name,
			URL:          ep.URL,
			Priority:     ep.Priority,
			Enabled:      ep.Enabled,
			BaseWeight:   ep.BaseWeight,
			CurrentWeight: ep.Weight,
			FailureRate:  ep.Failure.GetRate(),
			SampleCount:  ep.Failure.GetSampleCount(),
			FailureValid: ep.Failure.Valid(),
			CircuitState: ep.CircuitBreaker.State,
		}
		snap.Endpoints = append(snap.Endpoints, es)
		if ep.IsUsable() {
			snap.UsableCount++
		}
	}

	// 灰度状态快照
	if e.canary != nil {
		cs := e.canary.State()
		snap.Canary = &cs
	}

	return snap
}
