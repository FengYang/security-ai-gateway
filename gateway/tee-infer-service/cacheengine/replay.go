package cacheengine

import (
	"time"
)

// Replayer 命中回放接口。
type Replayer interface {
	// Replay 回放缓存条目，返回需要发送的分片序列。
	// 非流式：返回单分片（Text = 全文，At = 0）。
	// 流式：返回 Segments 序列，按 At 节拍 paced 发送。
	Replay(entry *Entry, stream bool) []Segment
}

// entryReplayer 默认回放实现。
type entryReplayer struct {
	cfg *CacheConfig
}

// NewReplayer 构造回放器。
func NewReplayer(cfg *CacheConfig) Replayer {
	return &entryReplayer{cfg: cfg}
}

// Replay 回放缓存条目。
func (r *entryReplayer) Replay(entry *Entry, stream bool) []Segment {
	if entry == nil {
		return nil
	}

	// 非流式请求或条目无分片 → 单块回放
	if !stream || len(entry.Segments) == 0 {
		return []Segment{{Text: entry.Text, At: 0}}
	}

	// 流式请求 + 有分片 → paced 回放
	// 应用 min_gap / max_gap 钳制（§6.12.3）
	// 注意：第 0 个分片不钳制（它是时间基准点）
	segs := make([]Segment, len(entry.Segments))
	var prev time.Duration
	for i, s := range entry.Segments {
		if i == 0 {
			segs[i] = Segment{Text: s.Text, At: s.At}
			prev = s.At
			continue
		}
		gap := s.At - prev
		if r.cfg != nil && r.cfg.Stream.Enabled {
			if gap < r.cfg.Stream.MinGap.D() {
				gap = r.cfg.Stream.MinGap.D()
			}
			if gap > r.cfg.Stream.MaxGap.D() {
				gap = r.cfg.Stream.MaxGap.D()
			}
		}
		at := prev + gap
		segs[i] = Segment{Text: s.Text, At: at}
		prev = at
	}

	return segs
}

// segmentsDegradeReason 返回流式分片降级原因（§9.1 #21）；空串 = 未降级。
// 仅在"本应产生分片但被降级"时给出原因（不含 stream=false / finish!=stop / 无分片等常态）。
func segmentsDegradeReason(ctx StoreContext, res InferResult, cfg *CacheConfig) string {
	if !ctx.Stream || res.Finish != "stop" || len(res.Segments) == 0 {
		return ""
	}
	if cfg == nil || !cfg.Stream.Enabled {
		return "disabled"
	}
	if len(res.Segments) > cfg.Stream.MaxSegments {
		return "too_many_segments"
	}
	var total int
	for _, s := range res.Segments {
		total += len(s.Text)
		if total > int(cfg.Exact.MaxEntryBytes.Bytes()) {
			return "too_large"
		}
	}
	return ""
}

// segmentsFor 流式分片采集判断（§6.1.3 伪代码 segmentsFor）。
// 返回可写入缓存的分片；超限/异常返回 nil（降级单块）。
func segmentsFor(ctx StoreContext, res InferResult, cfg *CacheConfig) []Segment {
	if !ctx.Stream || res.Finish != "stop" {
		return nil
	}
	if cfg == nil || !cfg.Stream.Enabled {
		return nil
	}
	if len(res.Segments) == 0 {
		return nil
	}

	// 分片数上限
	if len(res.Segments) > cfg.Stream.MaxSegments {
		return nil
	}

	// 总字节上限
	var total int
	for _, s := range res.Segments {
		total += len(s.Text)
		if total > int(cfg.Exact.MaxEntryBytes.Bytes()) {
			return nil
		}
	}

	return res.Segments
}
