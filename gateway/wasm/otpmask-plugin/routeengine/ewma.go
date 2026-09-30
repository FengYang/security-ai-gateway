package routeengine

import (
	"math"
	"time"
)

// ============================================================
// EWMARate：指数加权移动平均失败率统计
// 设计依据：方案 §6.2 EWMA 失败率感知
// 线程模型：Wasm 单线程，读路径直接读，写路径直接写，无需 atomic
// ============================================================

// EWMARate EWMA 失败率统计器。
//
// 更新公式：rate_new = α × sample + (1 - α) × rate_old
// 其中 sample：失败 = 1.0，成功 = 0.0。
//
// 时间衰减：如果距上次更新超过 DecayHalfLife 秒，失败率和样本数
// 按 0.5^(elapsed / half_life) 衰减，避免"旧失败"长期影响决策。
type EWMARate struct {
	Rate           float64 // 当前失败率估计值（0-1）
	Alpha          float64 // 平滑系数（0 < α ≤ 1），默认 0.1
	SampleCount    int64   // 累计样本数（已衰减）
	MinSamples     int64   // 最小样本数，低于则统计无效，默认 10
	LastUpdateMs   int64   // 上次更新时间（unix 毫秒）
	DecayHalfLifeS int64   // 时间衰减半衰期（秒），0 = 不衰减，默认 60
}

// NewEWMARate 创建 EWMA 失败率统计器。
//
//	alpha: 平滑系数（0 < alpha ≤ 1），默认 0.1
//	minSamples: 最小样本数，低于此值 Valid() 返回 false，默认 10
//	decayHalfLifeSec: 时间衰减半衰期（秒），0 = 不衰减，默认 60
func NewEWMARate(alpha float64, minSamples int64, decayHalfLifeSec int64) *EWMARate {
	if alpha <= 0 || alpha > 1 {
		alpha = 0.1 // 钳制到默认值
	}
	if minSamples < 1 {
		minSamples = 10
	}
	return &EWMARate{
		Alpha:          alpha,
		MinSamples:     minSamples,
		DecayHalfLifeS: decayHalfLifeSec,
	}
}

// Record 记录一个请求结果，更新 EWMA 失败率。
// success: true=成功(sample=0), false=失败(sample=1)
// nowMs: 当前时间（unix 毫秒）
// 返回：更新后的失败率
func (e *EWMARate) Record(success bool, nowMs int64) float64 {
	// 1. 时间衰减
	e.decayIfNeeded(nowMs)

	// 2. EWMA 更新
	var sample float64
	if success {
		sample = 0.0
	} else {
		sample = 1.0
	}
	e.Rate = e.Alpha*sample + (1-e.Alpha)*e.Rate
	e.SampleCount++
	e.LastUpdateMs = nowMs

	return e.Rate
}

// GetRate 获取当前失败率（0-1）。读路径直接读，无锁。
func (e *EWMARate) GetRate() float64 {
	return e.Rate
}

// Valid 判断统计是否有效（样本数 ≥ minSamples）。
func (e *EWMARate) Valid() bool {
	return e.SampleCount >= e.MinSamples
}

// GetSampleCount 获取累计样本数（已衰减）。
func (e *EWMARate) GetSampleCount() int64 {
	return e.SampleCount
}

// Reset 重置统计（配置更新/端点恢复时用）。
func (e *EWMARate) Reset() {
	e.Rate = 0
	e.SampleCount = 0
	e.LastUpdateMs = 0
}

// decayIfNeeded 如果距上次更新超过半衰期，对失败率和样本数做时间衰减。
func (e *EWMARate) decayIfNeeded(nowMs int64) {
	if e.DecayHalfLifeS <= 0 || e.LastUpdateMs == 0 {
		return
	}
	elapsedMs := nowMs - e.LastUpdateMs
	if elapsedMs <= 0 {
		return
	}
	halfLifeMs := e.DecayHalfLifeS * 1000
	if elapsedMs < halfLifeMs {
		return // 不足一个半衰期，不衰减（减少计算开销）
	}
	halfLives := float64(elapsedMs) / float64(halfLifeMs)
	decayFactor := math.Pow(0.5, halfLives)
	e.Rate *= decayFactor
	e.SampleCount = int64(float64(e.SampleCount) * decayFactor)
	if e.SampleCount < 0 {
		e.SampleCount = 0
	}
}

// ============================================================
// 权重调整（基于失败率的动态权重）
// 设计依据：方案 §6.2 失败率感知动态调整
// ============================================================

// WeightAdjustConfig 动态权重调整配置。
type WeightAdjustConfig struct {
	BaseWeight       float64 // 基础权重（配置值）
	MinWeight        float64 // 最小权重，默认 0.05（5%）
	AdjustStep       float64 // 每次调整步长，默认 0.1（10%）
	FailureThreshold float64 // 失败率阈值，超了就降权，默认 0.5
	RecoveryRatio    float64 // 恢复阈值比例，失败率 < threshold*ratio 时升权，默认 0.5
}

// AdjustWeight 根据失败率调整权重。
// 输入：当前权重 + 失败率 + 是否有效
// 输出：调整后的新权重 + 是否变化了
//
// 规则：
//   - 统计无效（样本不足）→ 不调整
//   - 失败率 ≥ threshold → 降权（-step）
//   - 失败率 < threshold * recoveryRatio → 升权（+step）
//   - 中间区间 → 不调整（保持稳定）
func AdjustWeight(current float64, failureRate float64, valid bool, cfg WeightAdjustConfig) (newWeight float64, changed bool) {
	if !valid {
		return current, false // 样本不足，不调整
	}
	minW := cfg.MinWeight
	if minW <= 0 {
		minW = 0.05
	}
	baseW := cfg.BaseWeight
	if baseW <= 0 {
		baseW = 1.0
	}
	step := cfg.AdjustStep
	if step <= 0 {
		step = 0.1
	}
	thresh := cfg.FailureThreshold
	if thresh <= 0 {
		thresh = 0.5
	}
	recoveryRatio := cfg.RecoveryRatio
	if recoveryRatio <= 0 {
		recoveryRatio = 0.5
	}

	if failureRate >= thresh {
		// 降权
		newW := current - step
		if newW < minW {
			newW = minW
		}
		if newW != current {
			return newW, true
		}
		return current, false
	}

	if failureRate < thresh*recoveryRatio {
		// 升权（上限 baseWeight）
		newW := current + step
		if newW > baseW {
			newW = baseW
		}
		if newW != current {
			return newW, true
		}
		return current, false
	}

	// 中间区间：不调整
	return current, false
}

// NormalizeWeights 同优先级组内权重归一化（就地修改）。
// 输入：端点列表（同优先级组），修改每个端点的 CurrentWeight
//
// 归一化后所有权重之和 = 1.0。
// 如果所有权重之和为 0（全熔断/全降权到 0），不做归一化。
func NormalizeWeights(endpoints []*EndpointState) {
	if len(endpoints) == 0 {
		return
	}
	var total float64
	for _, ep := range endpoints {
		if ep.Weight > 0 {
			total += ep.Weight
		}
	}
	if total <= 0 {
		return // 全熔断或权重全 0，不做归一化
	}
	for _, ep := range endpoints {
		if ep.Weight > 0 {
			ep.Weight = ep.Weight / total
		}
	}
}

// nowMs 返回当前 unix 毫秒时间。
// 抽取为变量便于测试注入。
var nowMs = func() int64 {
	return time.Now().UnixMilli()
}
