package cacheengine

import (
	"math/rand"
	"sync"
	"time"
)

// JitterInjector 侧信道抖动注入器（§7.3）。
// 为命中与未命中两条路径注入同分布随机延迟，降低外部可区分性。
type JitterInjector interface {
	// Sample 为一次查询采样延迟；两侧（hit/miss）都要调用，保证同分布。
	Sample(ctx LookupContext) time.Duration
}

// uniformJitter 均匀分布抖动（U[0, max_ms]）。
type uniformJitter struct {
	cfg     *CacheConfig
	mu      sync.Mutex
	rng     *rand.Rand
	enabled bool
	maxMs   int
}

// NewJitterInjector 构造抖动注入器。
func NewJitterInjector(cfg *CacheConfig) JitterInjector {
	j := &uniformJitter{
		cfg: cfg,
	}
	if cfg != nil && cfg.Semantic.Jitter.Enabled {
		j.enabled = true
		j.maxMs = cfg.Semantic.Jitter.MaxMs
		if j.maxMs <= 0 {
			j.maxMs = 20
		}
		if j.maxMs > 100 {
			j.maxMs = 100
		}
	}
	j.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	return j
}

// newJitterInjectorWithSeed 仅供确定性回归测试（BM-4 KS）使用：固定随机源，
// 消除「单次 KS 检验在 H0 成立时 p≤0.05 的固有 5% 随机误拒」导致的 flaky。
// 生产路径仍由 NewJitterInjector 使用时间种子；判据（p>0.05）不放宽——
// 若实现真的引入 hit/miss 分布偏差，任何种子下 KS 都会失败，故固定种子不构成掩盖。
func newJitterInjectorWithSeed(cfg *CacheConfig, seed int64) JitterInjector {
	j := NewJitterInjector(cfg)
	if u, ok := j.(*uniformJitter); ok {
		u.rng = rand.New(rand.NewSource(seed))
	}
	return j
}

// Sample 采样一次抖动值。
func (j *uniformJitter) Sample(ctx LookupContext) time.Duration {
	if !j.enabled || j.cfg == nil {
		return 0
	}

	// hit_only_compensation: 只在命中路径加抖动，未命中不加
	// 安全性略低，但 miss 路径额外延迟更低
	if j.cfg.Semantic.Jitter.HitOnlyCompensation {
		// 调用方根据是否命中决定是否 wait；此处仍返回采样值
		// 由调用方（finishHit 等）使用
	}

	j.mu.Lock()
	ms := j.rng.Intn(j.maxMs + 1) // [0, maxMs]
	j.mu.Unlock()

	return time.Duration(ms) * time.Millisecond
}
