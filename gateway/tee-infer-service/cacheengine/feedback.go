package cacheengine

import (
	"sync"
	"sync/atomic"
	"time"
)

// FeedbackDetector 误命中反馈检测器（§6.6）。
// 职责：
//   - 记录用户反馈的误命中事件（thumbs_down / report_false_positive）
//   - 按场景统计误命中率
//   - 误命中率超阈值时自动调高该场景的相似度阈值（自适应）
//   - 定时重置统计窗口
//
// 设计原则：
//   - fail-closed：异常时不影响正常缓存命中
//   - 内存态：不持久化（进程重启后重置）
//   - 自适应只上调不下降（保守策略，宁可少命中也不误命中）

type FeedbackDetector interface {
	// Report 上报一次误命中反馈。
	Report(scene string)

	// RecordHit 记录一次正常命中（用于计算误命中率）。
	RecordHit(scene string)

	// FalsePositiveRate 返回指定场景的误命中率（0~1）。
	FalsePositiveRate(scene string) float64

	// AdjustedThreshold 返回经过自适应调整后的场景阈值。
	// 基于基础阈值 + 误命中率上调（每超 1% 上调 0.01，上限 0.99）。
	AdjustedThreshold(scene string, baseThreshold float64) float64

	// Stats 返回反馈统计快照。
	Stats() FeedbackStats

	// Close 关闭检测器。
	Close()
}

// FeedbackStats 反馈统计快照。
type FeedbackStats struct {
	TotalHits         uint64            // 总命中数
	TotalFalsePos     uint64            // 总误命中反馈数
	ByScene           map[string]SceneFeedback // 按场景统计
	WindowStart       int64             // 统计窗口开始时间（unix ms）
}

// SceneFeedback 单场景反馈统计。
type SceneFeedback struct {
	Hits        uint64
	FalsePos    uint64
	Rate        float64 // FalsePos / Hits（Hits=0 时为 0）
	Adjusted    float64 // 调整后的阈值
}

// feedbackDetector 默认实现。
type feedbackDetector struct {
	mu          sync.RWMutex
	totalHits   uint64
	totalFP     uint64
	scenes      map[string]*sceneFB
	windowStart int64
	windowDur   time.Duration
	autoTune    bool
	maxBoost    float64 // 最大上调幅度（如 0.1 = 最多上调 0.1）
	step        float64 // 每 1% 误命中率上调多少
	nowFn       nowFunc
	done        chan struct{}
}

// sceneFB 单场景数据。
type sceneFB struct {
	hits    uint64
	falsePos uint64
	boost   float64 // 累计上调量
}

// FeedbackConfig 反馈检测器配置。
type FeedbackConfig struct {
	Enabled        bool
	AutoTune       bool          // 是否自动调整阈值
	WindowDuration time.Duration // 统计窗口时长
	MaxBoost       float64       // 最大上调幅度
	StepPerPercent float64       // 每 1% 误命中率上调步长
}

// DefaultFeedbackConfig 返回默认配置。
func DefaultFeedbackConfig() FeedbackConfig {
	return FeedbackConfig{
		Enabled:        true,
		AutoTune:       true,
		WindowDuration: 10 * time.Minute,
		MaxBoost:       0.10,  // 最多上调 0.10
		StepPerPercent: 0.005, // 每 1% 误命中率上调 0.005
	}
}

// NewFeedbackDetector 构造误命中反馈检测器。
func NewFeedbackDetector(cfg FeedbackConfig) FeedbackDetector {
	if !cfg.Enabled {
		return &nullFeedbackDetector{}
	}
	if cfg.WindowDuration <= 0 {
		cfg.WindowDuration = 10 * time.Minute
	}
	if cfg.MaxBoost <= 0 {
		cfg.MaxBoost = 0.10
	}
	if cfg.StepPerPercent <= 0 {
		cfg.StepPerPercent = 0.005
	}

	d := &feedbackDetector{
		scenes:      make(map[string]*sceneFB),
		windowStart: defaultNow().UnixMilli(),
		windowDur:   cfg.WindowDuration,
		autoTune:    cfg.AutoTune,
		maxBoost:    cfg.MaxBoost,
		step:        cfg.StepPerPercent,
		nowFn:       defaultNow,
		done:        make(chan struct{}),
	}

	// 启动窗口重置定时任务
	go d.windowLoop()

	return d
}

// windowLoop 定时重置统计窗口。
func (d *feedbackDetector) windowLoop() {
	ticker := time.NewTicker(d.windowDur)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.resetWindow()
		case <-d.done:
			return
		}
	}
}

// resetWindow 重置统计窗口。
func (d *feedbackDetector) resetWindow() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.totalHits = 0
	d.totalFP = 0
	for k := range d.scenes {
		// 保留 boost（累计上调量跨窗口保留）
		d.scenes[k].hits = 0
		d.scenes[k].falsePos = 0
	}
	d.windowStart = d.nowFn().UnixMilli()
}

// Report 上报误命中。
func (d *feedbackDetector) Report(scene string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	atomic.AddUint64(&d.totalFP, 1)
	s := d.getScene(scene)
	s.falsePos++

	// 自适应调整
	if d.autoTune {
		d.adjustBoostLocked(s)
	}
}

// RecordHit 记录一次命中。
func (d *feedbackDetector) RecordHit(scene string) {
	d.mu.Lock()
	defer d.mu.Unlock()

	atomic.AddUint64(&d.totalHits, 1)
	s := d.getScene(scene)
	s.hits++
}

// getScene 获取或创建场景数据（调用方须持有锁）。
func (d *feedbackDetector) getScene(scene string) *sceneFB {
	s, ok := d.scenes[scene]
	if !ok {
		s = &sceneFB{}
		d.scenes[scene] = s
	}
	return s
}

// adjustBoostLocked 根据误命中率调整 boost（调用方须持有锁）。
func (d *feedbackDetector) adjustBoostLocked(s *sceneFB) {
	if s.hits == 0 {
		return
	}
	rate := float64(s.falsePos) / float64(s.hits) // 0~1
	percent := rate * 100

	targetBoost := percent * d.step
	if targetBoost > d.maxBoost {
		targetBoost = d.maxBoost
	}
	if targetBoost > s.boost {
		s.boost = targetBoost // 只上调不下降
	}
}

// FalsePositiveRate 返回指定场景的误命中率。
func (d *feedbackDetector) FalsePositiveRate(scene string) float64 {
	d.mu.RLock()
	defer d.mu.RUnlock()
	s, ok := d.scenes[scene]
	if !ok || s.hits == 0 {
		return 0
	}
	return float64(s.falsePos) / float64(s.hits)
}

// AdjustedThreshold 返回调整后的阈值（基础阈值 + boost，上限 0.99）。
func (d *feedbackDetector) AdjustedThreshold(scene string, base float64) float64 {
	if !d.autoTune {
		return base
	}
	d.mu.RLock()
	defer d.mu.RUnlock()

	boost := float64(0)
	if s, ok := d.scenes[scene]; ok {
		boost = s.boost
	}
	result := base + boost
	if result > 0.99 {
		return 0.99
	}
	return result
}

// Stats 返回统计快照。
func (d *feedbackDetector) Stats() FeedbackStats {
	d.mu.RLock()
	defer d.mu.RUnlock()

	snap := FeedbackStats{
		TotalHits:   atomic.LoadUint64(&d.totalHits),
		TotalFalsePos: atomic.LoadUint64(&d.totalFP),
		ByScene:     make(map[string]SceneFeedback),
		WindowStart: d.windowStart,
	}

	for name, s := range d.scenes {
		rate := float64(0)
		if s.hits > 0 {
			rate = float64(s.falsePos) / float64(s.hits)
		}
		snap.ByScene[name] = SceneFeedback{
			Hits:     s.hits,
			FalsePos: s.falsePos,
			Rate:     rate,
			Adjusted: 0, // 由调用方结合基础阈值计算
		}
	}
	return snap
}

// Close 关闭检测器。
func (d *feedbackDetector) Close() {
	select {
	case <-d.done:
	default:
		close(d.done)
	}
}

// ===== null 实现（禁用时） =====

type nullFeedbackDetector struct{}

func (n *nullFeedbackDetector) Report(scene string)                    {}
func (n *nullFeedbackDetector) RecordHit(scene string)                 {}
func (n *nullFeedbackDetector) FalsePositiveRate(scene string) float64 { return 0 }
func (n *nullFeedbackDetector) AdjustedThreshold(scene string, base float64) float64 { return base }
func (n *nullFeedbackDetector) Stats() FeedbackStats                  { return FeedbackStats{} }
func (n *nullFeedbackDetector) Close()                                {}
