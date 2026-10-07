package cacheengine

// ===== 运行状态：内存水位只读态 / 时钟回拨 / 估算占用（§6.9.1 / §6.9.2） =====

// IsReadOnly 返回当前是否处于只读态（高水位；§6.9.2）。
func (e *engine) IsReadOnly() bool { return e.readOnly.Load() }

// UpdateReadOnly 依据内存水位更新只读态（§6.9.2）：
// usedRatio ≥ watermark_high → 只读（停写，已存在条目仍可读）；≤ watermark_low → 自动恢复写。
// 由外部（运行时/运维）按实测占用率调用；缓存模块不自建内存分配器。
func (e *engine) UpdateReadOnly(usedRatio float64) {
	switch {
	case usedRatio >= e.cfg.Memory.WatermarkHigh:
		e.readOnly.Store(true)
	case usedRatio <= e.cfg.Memory.WatermarkLow:
		e.readOnly.Store(false)
	}
}

// SetEstimatedBytes 设置估算内存占用（§9.1 #24 estimated_bytes，供 gauge）。
func (e *engine) SetEstimatedBytes(n int64) { e.estBytes.Store(n) }

// CheckClockSkew 检测时钟回拨（§6.9.1）：nowMs 小于上次观测值即计一次 clock_skew。
// 返回本次是否发生回拨。
func (e *engine) CheckClockSkew(nowMs int64) bool {
	last := e.lastNowMs.Load()
	if last != 0 && nowMs < last {
		e.stats.observeClockSkew()
		return true
	}
	e.lastNowMs.Store(nowMs)
	return false
}
