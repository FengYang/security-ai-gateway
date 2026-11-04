package main

// P0-2 批次 B2：原生语义缓存主链接线（命中/回填迁移 + §6.12 分段回放 + §7.3 抖动注入）。
//
// 设计依据：详设 §6.12（流式分段缓存与首段即回）、§7.3.1（抖动注入侧接入点）、
// §4.5（命中路径计费口径）、§7.5（信封重加密，经既有 streamTextInfer 天然满足）。
//
// 原则：默认 mode=off 时不进入本文件任何路径（零行为变化）；缓存异常一律 fail-open 到 miss。

import (
	"time"

	"security-ai-gateway/gateway/tee-infer-service/cacheengine"
	"security-ai-gateway/gateway/tee-infer-service/model"
)

// cacheGuardVerDefault 原生缓存的 GuardVer 取值（词库版本接入前的占位常量）。
// 词库/守卫版本就绪后，此处替换为真实版本即可让旧缓存自然失效（键含 GuardVer）。
const cacheGuardVerDefault = "v1"

// 回放节拍默认钳制上/下界（§6.12.3：min_gap=8ms / max_gap=400ms），
// 仅当配置未提供有效值时兜底。
const (
	replayDefaultMinGap = 8 * time.Millisecond
	replayDefaultMaxGap = 400 * time.Millisecond
)

// cacheReplayConfig §6.12 回放节拍参数（启动期从缓存配置快照，进程内只读）。
type cacheReplayConfig struct {
	minGap time.Duration
	maxGap time.Duration
}

// buildCacheLookupContext 构造原生语义缓存的查询上下文。
// 键材质由 cacheengine.exactKey 统一计算（含 EngineType/Model/MaxNewTokens/stream/参数），
// 故此处只需把主链已有字段原样映射。
func buildCacheLookupContext(tenant, engType, modelName, txHash, promptText string,
	maxNewTokens int, stream bool, policyVer string) cacheengine.LookupContext {
	return cacheengine.LookupContext{
		TenantID:        tenant,
		EngineType:      engType,
		Model:           modelName,
		MaxNewTokens:    maxNewTokens,
		TransformedHash: txHash,
		PromptText:      promptText,
		Stream:          stream,
		PolicyVer:       policyVer,
		GuardVer:        cacheGuardVerDefault,
	}
}

// jitterRecorder 抖动注入量记录器（§9.1 #11）；cacheengine.CacheEngine 满足之，nil 安全。
type jitterRecorder interface {
	RecordJitter(path string, d time.Duration)
}

// waitUntilRelease 首片/首字节前的抖动等待 + 指标发射（§7.3.1 注入侧 / §9.1 #11）。
// 命中与未命中共用同一注入点，保证两侧同分布（J-1）；releaseAt 已过 → 自然 no-op（B-7.3-6），
// 且**仅在实际发生注入时**记录指标。仅在缓存生效（mode != off）时才会带非零抖动。
func waitUntilRelease(rec jitterRecorder, path string, releaseAt time.Time) {
	d := time.Until(releaseAt)
	if d <= 0 {
		return
	}
	if rec != nil {
		rec.RecordJitter(path, d)
	}
	time.Sleep(d)
}

// clampDuration 把回放节拍钳制到 [lo, hi]（§6.12.3，防"精确复刻"成侧信道）。
func clampDuration(d, lo, hi time.Duration) time.Duration {
	if lo <= 0 {
		lo = replayDefaultMinGap
	}
	if hi <= 0 {
		hi = replayDefaultMaxGap
	}
	if d < lo {
		return lo
	}
	if d > hi {
		return hi
	}
	return d
}

// segmentCapturingEngine 包装 model.Engine，旁路采集流式分片（§6.12 写入侧）。
//
// 注意：必须在 cmaas 引擎判定之后包装——否则 `eng.(*model.CmaasEngine)` 判定失效，
// 会向 cmaas 上游透传错误模型名（model_not_found）。同时显式转发可选方法，避免副作用。
//
// 约束：本包装器为单次 Generate 的请求内临时对象，不可跨请求复用
// （first/start/segs 不复位，复用会破坏首片 At=0 不变量）。
type segmentCapturingEngine struct {
	inner     model.Engine
	releaseAt time.Time
	rec       jitterRecorder
	first     bool
	start     time.Time // 首片到达时刻：后续分片 At 的唯一时间基准点（首片自身 At=0，不用它）
	segs      []cacheengine.Segment
}

// newSegmentCapturingEngine 构造分片采集包装器；releaseAt 为 miss 路径抖动释放时刻，
// rec 为抖动指标记录器（可 nil）。
func newSegmentCapturingEngine(inner model.Engine, releaseAt time.Time, rec jitterRecorder) *segmentCapturingEngine {
	return &segmentCapturingEngine{inner: inner, releaseAt: releaseAt, rec: rec, first: true}
}

// Predict 透传内层引擎。
func (e *segmentCapturingEngine) Predict(f []float64) int { return e.inner.Predict(f) }

// Generate 透传内层生成，逐 delta 记录分片（文本 + 相对首片的偏移）。
//
// 分片偏移口径（与 cacheengine.Segment.At「与首片的相对偏移」定义一致）：
//   - 首片是**时间基准点**，其偏移按定义恒为 0（cacheengine.replay.go 单块回放同样用 At=0）；
//   - 后续分片 = 距首片到达时刻（e.start）的实耗，故 gap = At[i] - At[i-1] 即真实相邻间隔。
//
// 反例：若首片也记 time.Since(e.start)，取值只是 e.start 之后那次 time.Now 的调度噪声（亚微秒级），
// 既非确定性又无语义；更实质的是分片会随条目落盘——`redisbackend.persistEntry` 的**明文 DTO** 含
// Segments（json 序列化含 At），首片噪声会让「内容完全相同的工件」明文 DTO 字节级不同，破坏工件
// 可复现性与去重比对。（注意：seal 之后的密文本就因随机 nonce 每次不同，不能作为论据。）
func (e *segmentCapturingEngine) Generate(req model.GenerateRequest, onDelta func(string) error) error {
	return e.inner.Generate(req, func(d string) error {
		var at time.Duration // 零值 = 首片的基准点偏移，恰好是期望语义
		if e.first {
			e.first = false
			// §7.3：miss 路径首字节前同样等待 releaseAt（通常已过 = no-op，防"快速未命中"漏网）。
			waitUntilRelease(e.rec, "miss", e.releaseAt)
			e.start = time.Now()
		} else {
			at = time.Since(e.start)
		}
		e.segs = append(e.segs, cacheengine.Segment{Text: d, At: at})
		return onDelta(d)
	})
}

// LastKeyFingerprint 显式转发内层可选方法（供审计 KeyFP 归因）；内层不支持则返回空。
func (e *segmentCapturingEngine) LastKeyFingerprint() string {
	if fp, ok := e.inner.(interface{ LastKeyFingerprint() string }); ok {
		return fp.LastKeyFingerprint()
	}
	return ""
}

// segments 返回已采集分片（nil 安全）。
func (e *segmentCapturingEngine) segments() []cacheengine.Segment {
	if e == nil {
		return nil
	}
	return e.segs
}

// segmentReplayEngine 命中回放引擎（§6.12）：首片前抖动等待，随后按原始节拍 paced 回放。
// 实现 model.Engine，复用 streamTextInfer 既有 emit 出口 —— 信封按当前会话密钥逐片重封
// （I-8：counter 单调）与 seq/终止帧形态与非命中路径天然一致。
type segmentReplayEngine struct {
	text      string
	segs      []cacheengine.Segment
	releaseAt time.Time
	minGap    time.Duration
	maxGap    time.Duration
	rec       jitterRecorder
}

// Predict vectors 路径不支持（缓存仅用于 text 路径），返回 -1。
func (segmentReplayEngine) Predict([]float64) int { return -1 }

// Generate 首段即回（§6.12.3）：首片发出前等待至 releaseAt；无分片则整段单块回放。
func (r *segmentReplayEngine) Generate(_ model.GenerateRequest, onDelta func(string) error) error {
	waitUntilRelease(r.rec, "hit", r.releaseAt)
	if len(r.segs) == 0 {
		if r.text == "" {
			return nil
		}
		return onDelta(r.text)
	}
	// 首片立即发出，不等后续分片（TTFT 最小化）。
	if err := onDelta(r.segs[0].Text); err != nil {
		return err
	}
	prev := r.segs[0].At
	for _, sg := range r.segs[1:] {
		if gap := clampDuration(sg.At-prev, r.minGap, r.maxGap); gap > 0 {
			// §6.12.3：pacing 等待发生在发射协程（本 Generate 由写出路径驱动），不阻塞查询/推理线程。
			time.Sleep(gap)
		}
		if err := onDelta(sg.Text); err != nil {
			return err
		}
		prev = sg.At
	}
	return nil
}
