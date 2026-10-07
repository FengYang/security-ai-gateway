package cacheengine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// CacheEngine 缓存编排入口（§4.1.1）。
// 实现必须并发安全。
// 绝不返回错误（fail-open 到 miss）：任何内部异常都记为 miss + 指标，不阻断推理链路。
type CacheEngine interface {
	Lookup(ctx LookupContext) LookupResult
	Store(ctx StoreContext, res InferResult) StoreOutcome
	Invalidate(sel InvalidateSelector) (int, error)
	Stats() StatsSnapshot
	// RenderPrometheus 以 Prometheus 文本格式输出缓存指标（§9.1）。
	RenderPrometheus(w io.Writer)
	Close() error
}

// engine 默认实现。
type engine struct {
	cfg     *CacheConfig
	exact   ExactStore
	neg     NegativeStore
	sem     SemanticStore
	scene   SceneClassifier
	cache   *cacheabilityEngine
	ttl     *TTLResolver
	replay  Replayer
	sf      SingleFlight
	scanner FastScanner
	jitter  JitterInjector
	canary  CanaryController
	l1      RedisBackend // 形态 B/C 的 Redis 密文 L1（nil = 仅进程内 L0）
	stats   *statsCollector
	feedback FeedbackDetector
	nowFn   nowFunc
	closed  atomic.Bool

	invCancelMu sync.Mutex       // 保护 invCancel
	invCancel   context.CancelFunc // 失效广播消费的取消函数（nil = 未启动）
}

// EngineOption 引擎选项（用于可选依赖注入）。
type EngineOption func(*engine)

// WithExactStore 注入精确存储。
func WithExactStore(s ExactStore) EngineOption {
	return func(e *engine) { e.exact = s }
}

// WithNegativeStore 注入负向存储。
func WithNegativeStore(s NegativeStore) EngineOption {
	return func(e *engine) { e.neg = s }
}

// WithSceneClassifier 注入场景分类器。
func WithSceneClassifier(s SceneClassifier) EngineOption {
	return func(e *engine) { e.scene = s }
}

// WithFastScanner 注入读时快审扫描器。
func WithFastScanner(s FastScanner) EngineOption {
	return func(e *engine) { e.scanner = s }
}

// WithSemanticStore 注入语义缓存存储。
func WithSemanticStore(s SemanticStore) EngineOption {
	return func(e *engine) { e.sem = s }
}

// WithFeedbackDetector 注入误命中反馈检测器。
func WithFeedbackDetector(f FeedbackDetector) EngineOption {
	return func(e *engine) { e.feedback = f }
}

// WithCanaryController 注入灰度控制器。
func WithCanaryController(c CanaryController) EngineOption {
	return func(e *engine) { e.canary = c }
}

// WithRedisBackend 注入 Redis 密文 L1（形态 B/C，§5.3）；nil = 仅进程内 L0。
func WithRedisBackend(b RedisBackend) EngineOption {
	return func(e *engine) { e.l1 = b }
}

// NewCacheEngine 构造缓存引擎。
// mode=off 时引擎返回 NullCacheEngine 行为（永不命中），保证向后兼容。
func NewCacheEngine(cfg CacheConfig, opts ...EngineOption) CacheEngine {
	cfgCopy := cfg
	e := &engine{
		cfg:   &cfgCopy,
		nowFn: defaultNow,
	}

	// 应用选项
	for _, opt := range opts {
		opt(e)
	}

	// 初始化默认组件
	if e.scene == nil {
		e.scene = NewRuleSceneClassifier()
	}
	if e.cache == nil {
		e.cache = newCacheabilityEngine(e.cfg, e.scene)
	}
	if e.ttl == nil {
		e.ttl = NewTTLResolver(e.cfg)
	}
	if e.replay == nil {
		e.replay = NewReplayer(e.cfg)
	}
	if e.sf == nil && e.cfg.SingleFlight.Enabled {
		e.sf = NewSingleFlight(e.cfg.SingleFlight)
	}
	if e.jitter == nil {
		e.jitter = NewJitterInjector(e.cfg)
	}
	if e.stats == nil {
		e.stats = newStatsCollector()
	}
	if e.exact == nil && e.cfg.Exact.Enabled {
		e.exact = NewLRUExactStore(e.cfg.Exact.MaxEntries, int(e.cfg.Exact.MaxEntryBytes.Bytes()))
	}
	if e.neg == nil && e.cfg.Negative.Enabled {
		e.neg = NewLRUNegativeStore(e.cfg.Negative.MaxEntries)
	}
	if e.scanner == nil {
		e.scanner = &stubScanner{} // 默认识别为不可用，读时快审 fail-closed
	}
	if e.canary == nil {
		e.canary = NewConfigCanaryController(e.cfg)
	}

	// 初始化语义缓存（二期）
	if e.sem == nil && e.cfg.Mode == ModeSemantic {
		// 默认 stub：embedder 不可用，语义层自动降级
		// 生产环境通过 WithSemanticStore 注入真正实现
	}

	return e
}

// ===== CacheEngine 接口实现 =====

// Lookup 查询缓存。
// 顺序：① 请求级开关 → ② 场景分类 → ③ 可缓存性判定 → ④ 精确 → ⑤ 负向 → ⑥ 语义
func (e *engine) Lookup(ctx LookupContext) (res LookupResult) {
	start := time.Now()
	// §6.11#9 / B-6.11-1：缓存模块 panic 必须在 Engine 边界 recover 并转 miss，绝不拖垮推理主链。
	defer func() {
		if r := recover(); r != nil {
			e.stats.observePanic()
			res = LookupResult{Hit: false, Kind: "miss", RejectReason: "panic"}
		}
		if time.Since(start) > slowLookupThreshold {
			e.stats.observeSlowLookup("overall") // B-6.11-3：仅观测，不中断
		}
	}()
	if e.closed.Load() {
		return LookupResult{Hit: false, Kind: "miss", RejectReason: "closed"}
	}

	// 0. 请求级开关（全局 mode + 租户策略）
	if e.cfg.Mode == ModeOff || tenantPolicy(e.cfg, ctx.TenantID) == PolicyOff {
		e.observePrecheck("disabled", start)
		return LookupResult{
			Hit:          false,
			Kind:         "miss",
			RejectReason: "disabled",
			Jitter:       e.jitter.Sample(ctx),
		}
	}

	// 灰度写只读（write_only）
	if e.canary.Enabled() && e.canary.WriteOnly() {
		e.observePrecheck("disabled", start)
		return LookupResult{
			Hit:          false,
			Kind:         "miss",
			RejectReason: "canary_write_only",
			Jitter:       e.jitter.Sample(ctx),
		}
	}

	// 灰度流量控制
	if e.canary.Enabled() && !e.canary.Allowed(ctx) {
		e.observePrecheck("disabled", start)
		return LookupResult{
			Hit:          false,
			Kind:         "miss",
			RejectReason: "canary_skip",
			Jitter:       e.jitter.Sample(ctx),
		}
	}

	// 1. 场景分类（必须先于可缓存性判定）
	ctx.Scene = e.scene.Classify(ctx.PromptText)

	// 2. 可缓存性判定
	if d := e.cache.Cacheable(&ctx); !d.Cacheable {
		e.observePrecheck("not_cacheable", start)
		return LookupResult{
			Hit:           false,
			Kind:          "miss",
			RejectReason:  "not_cacheable:" + d.Reason,
			CacheDecision: &d,
			Jitter:        e.jitter.Sample(ctx),
		}
	}

	// single-flight 合并
	if e.sf != nil && e.cfg.SingleFlight.Enabled {
		sfKey := ctx.TenantID + ":" + ctx.TransformedHash
		result, _ := e.sf.Do(sfKey, func() (LookupResult, error) {
			return e.doLookup(ctx), nil
		})
		return result
	}

	return e.doLookup(ctx)
}

// observePrecheck 记录 precheck 阶段结果与耗时（指标契约：result 须在枚举内）。
func (e *engine) observePrecheck(result string, start time.Time) {
	e.stats.observeLookup("precheck", result)
	e.stats.observeLookupDuration("precheck", time.Since(start))
}

// doLookup 实际查询（不含 single-flight）。
func (e *engine) doLookup(ctx LookupContext) (res LookupResult) {
	start := time.Now()
	deepest := "precheck"
	defer func() { e.stats.observeLookupDuration(deepest, time.Since(start)) }()

	// 3. L0 精确（进程内）
	if e.exact != nil && e.cfg.Exact.Enabled {
		deepest = "exact"
		key := e.exactKey(ctx)
		if entry, ok := e.exact.Get(key); ok {
			if !EntryUsable(entry, ctx.GuardVer, ctx.PolicyVer, e.nowFn()) {
				e.exact.Delete(key)
			} else {
				return e.finishHit(ctx, entry, KindExact, 1.0, 1.0)
			}
		}
		e.stats.observeLookup("exact", "miss")
		// L1 读穿（形态 B/C，§5.3）：密文在 TEE 内解封后回填 L0（L0 仅热点，淘汰不联动删 L1）。
		if e.l1 != nil {
			if entry, _, hit, err := e.l1.Get(context.Background(), KindExact, key); err == nil && hit {
				if EntryUsable(entry, ctx.GuardVer, ctx.PolicyVer, e.nowFn()) {
					e.exact.Put(key, entry)
					return e.finishHit(ctx, entry, KindExact, 1.0, 1.0)
				}
			}
		}
	}

	// 4. 负向缓存
	if e.neg != nil && e.cfg.Negative.Enabled {
		deepest = "negative"
		nkey := e.negKey(ctx)
		if p, ok := e.neg.Get(nkey); ok &&
			p.PolicyVer == ctx.PolicyVer && p.GuardVer == ctx.GuardVer {
			return e.finishNegative(ctx, p)
		}
		e.stats.observeLookup("negative", "miss")
		// 负向 L1 读穿（形态 B/C）。
		if e.l1 != nil {
			if entry, _, hit, err := e.l1.Get(context.Background(), KindNegative, nkey); err == nil && hit &&
				entry.Negative != nil {
				p := entry.Negative
				if p.PolicyVer == ctx.PolicyVer && p.GuardVer == ctx.GuardVer {
					e.neg.Put(nkey, p, e.cfg.Negative.TTL.D())
					return e.finishNegative(ctx, p)
				}
			}
		}
	}

	// 5. L2 语义（二期）
	if e.sem != nil && e.sem.Enabled(ctx.TenantID) {
		deepest = "semantic"
		hit, entryID, sim, sceneStr, th, reason := e.sem.Lookup(ctx)
		if hit && e.exact != nil {
			// 从 ExactStore 取正文
			entry, ok := e.exact.Get(entryID)
			if ok && EntryUsable(entry, ctx.GuardVer, ctx.PolicyVer, e.nowFn()) {
				// 严格场景（code/math）做实体指纹二次校验
				if e.needsFingerprintCheck(sceneStr) {
					qfp := ExtractEntities(ctx.PromptText)
					rfp := ExtractEntities(entry.Text)
					fpTh := e.fingerprintThreshold(sceneStr)
					if !qfp.Compatible(rfp, fpTh) {
						// 实体不兼容 → 不命中（指标枚举归一化为 miss，详见 §9.1 #34/#37）
						e.stats.observeLookup("semantic", "miss")
						return LookupResult{
							Hit:          false,
							Kind:         "miss",
							RejectReason: "fingerprint_mismatch",
							Similarity:   sim,
							TopCandidate: sim,
							Jitter:       e.jitter.Sample(ctx),
						}
					}
				}
				e.stats.observeLookup("semantic", "hit")
				// 记录反馈统计命中
				if e.feedback != nil {
					e.feedback.RecordHit(sceneStr)
				}
				return e.finishHit(ctx, entry, KindSemantic, sim, sim)
			}
			// 正文已失效 → 清理向量索引
			if ok {
				e.exact.Delete(entryID)
			}
			_ = e.sem.Delete(entryID)
			e.stats.observeLookup("semantic", "miss") // 枚举归一化（原 entry_evicted）
		} else if hit {
			e.stats.observeLookup("semantic", "miss") // 枚举归一化（原 no_exact_store）
		} else {
			e.stats.observeLookup("semantic", "miss")
			_ = reason
			_ = th
		}

		// 语义未命中，返回 miss（带上 top 候选信息用于观察）
		return LookupResult{
			Hit:          false,
			Kind:         "miss",
			RejectReason: "semantic_miss:" + reason,
			Similarity:   sim,
			TopCandidate: sim,
			Jitter:       e.jitter.Sample(ctx),
		}
	}

	// 6. 终态未命中
	return LookupResult{
		Hit:          false,
		Kind:         "miss",
		RejectReason: "not_found",
		Jitter:       e.jitter.Sample(ctx),
	}
}

// finishHit 命中收尾：读时快审 → 抖动采样 → 组装结果。
// 精确与语义两条命中路径共用本收尾。
func (e *engine) finishHit(ctx LookupContext, entry *Entry, kind EntryKind, sim, topCand float64) LookupResult {
	// 读时快审（§7.2）
	allow, action, v := e.readFastCheck(entry, ctx.GuardVer)
	if !allow {
		e.stats.observeLookup(string(kind), "fastcheck_miss")
		if action == "block" {
			return LookupResult{
				Hit: true, Kind: KindNegative,
				Entry: negativeFromScan(ctx, v),
				FastScan: v, Similarity: sim, TopCandidate: topCand,
				Jitter: e.jitter.Sample(ctx),
			}
		}
		// treat_as_miss：仍记命中计数（观测用），但不返回内容
		entry.HitCount++
		return LookupResult{
			Hit: false, Kind: "miss", RejectReason: "guard",
			FastScan: v, TopCandidate: topCand,
			Jitter: e.jitter.Sample(ctx),
		}
	}

	entry.HitCount++
	entry.LastHitAt = unixMs(e.nowFn)
	e.stats.observeLookup(string(kind), "hit")
	e.stats.addSavedTokens(int64(entry.TokensIn))

	return LookupResult{
		Hit: true, Kind: kind, Entry: entry,
		Similarity: sim, TopCandidate: topCand,
		FastScan: ScanVerdict{Allow: true},
		Jitter:   e.jitter.Sample(ctx),
	}
}

// finishNegative 负向命中收尾。
func (e *engine) finishNegative(ctx LookupContext, p *NegativePayload) LookupResult {
	e.stats.observeLookup("negative", "hit")
	entry := &Entry{
		Kind:     KindNegative,
		Negative: p,
		TenantID: ctx.TenantID,
	}
	return LookupResult{
		Hit: true, Kind: KindNegative, Entry: entry,
		RejectReason: p.Reason,
		Jitter:       e.jitter.Sample(ctx),
	}
}

// negativeFromScan 读时快审 block 动作的拒答载荷。
func negativeFromScan(ctx LookupContext, v ScanVerdict) *Entry {
	return &Entry{
		Kind: KindNegative,
		Negative: &NegativePayload{
			Stage:     "output_guard",
			Reason:    "read_fast_check:" + v.Reason,
			PolicyVer: ctx.PolicyVer,
			GuardVer:  ctx.GuardVer,
		},
	}
}

// ===== 写入 =====

// Store 写入缓存。
// 仅当 ctx.Writable 为真（写前审查通过）时才真正落库。
func (e *engine) Store(ctx StoreContext, res InferResult) (out StoreOutcome) {
	// §6.11#9：写入路径同样 panic 隔离（转 skipped，不拖垮主链）。
	defer func() {
		if r := recover(); r != nil {
			e.stats.observePanic()
			out = StoreOutcome{Stored: false, Layer: "skipped", Skipped: "panic"}
		}
	}()
	if e.closed.Load() {
		return StoreOutcome{Stored: false, Layer: "skipped", Skipped: "closed"}
	}
	if e.cfg.Mode == ModeOff {
		return StoreOutcome{Stored: false, Layer: "skipped", Skipped: "disabled"}
	}

	// 写前审查门禁
	if !ctx.Writable && e.cfg.Guard.WriteRequiresOutGuard {
		return StoreOutcome{Stored: false, Layer: "skipped", Skipped: "not_writable"}
	}

	// 可缓存性判定（写入侧重新判定）
	ctx.Scene = e.scene.Classify(ctx.PromptText)
	if d := e.cache.Cacheable(&ctx.LookupContext); !d.Cacheable {
		return StoreOutcome{Stored: false, Layer: "skipped", Skipped: "not_cacheable:" + d.Reason}
	}

	// 拒答 → 写负向缓存（§6.3）
	if res.Negative != nil && e.neg != nil && e.cfg.Negative.Enabled {
		if e.shouldWriteNegative(res.Negative) {
			nkey := e.negKey(ctx.LookupContext)
			negTTL := e.cfg.Negative.TTL.D()
			e.neg.Put(nkey, res.Negative, negTTL)
			e.stats.observeStore("negative")
			if e.l1 != nil {
				expireAt := unixMs(e.nowFn) + negTTL.Milliseconds()
				ne := &Entry{Kind: KindNegative, TenantID: ctx.TenantID, Negative: res.Negative,
					ExpireAt: expireAt, PolicyVer: ctx.PolicyVer, GuardVer: ctx.GuardVer}
				meta := MetaRec{Tenant: ctx.TenantID, ExpireAt: expireAt,
					PolicyVer: ctx.PolicyVer, GuardVer: ctx.GuardVer, Model: ctx.Model}
				if err := e.l1.Put(context.Background(), KindNegative, nkey, ne, meta, negTTL); err != nil {
					_ = err // fail-open
				}
			}
			return StoreOutcome{Stored: true, Layer: "negative"}
		}
	}

	// 正常响应 → 写正向缓存
	if res.Negative != nil {
		// 负向但不在 only_for 范围内 → 不写
		return StoreOutcome{Stored: false, Layer: "skipped", Skipped: "negative_not_allowed"}
	}

	// 正向写入前置检查
	if res.Finish != "stop" {
		return StoreOutcome{Stored: false, Layer: "skipped", Skipped: "finish_not_stop"}
	}
	if res.TokensOut < e.cfg.Exact.MinTokens {
		return StoreOutcome{Stored: false, Layer: "skipped", Skipped: "too_short"}
	}
	if int64(len(res.Text)) > e.cfg.Exact.MaxEntryBytes.Bytes() {
		return StoreOutcome{Stored: false, Layer: "skipped", Skipped: "too_long"}
	}

	// 构造 Entry
	ttl := e.ttl.TTLFor(ctx)
	now := unixMs(e.nowFn)
	segs := segmentsFor(ctx, res, e.cfg)

	entry := &Entry{
		Kind:       KindExact,
		TenantID:   ctx.TenantID,
		EngineType: ctx.EngineType,
		Model:      ctx.Model,
		ModelVer:   ctx.ModelVer,
		Text:       res.Text,
		Segments:   segs,
		TokensIn:   res.TokensIn,
		TokensOut:  res.TokensOut,
		CreatedAt:  now,
		ExpireAt:   now + ttl.Milliseconds(),
		PolicyVer:  ctx.PolicyVer,
		GuardVer:   ctx.GuardVer,
		Checksum:   ComputeChecksum(res.Text),
		HitCount:   0,
		LastHitAt:  now,
	}

	// 写精确层
	key := e.exactKey(ctx.LookupContext)
	entry.KeyHash = key
	entry.PromptHash = ctx.TransformedHash
	entry.EntryID = ComputeEntryID(ctx.TenantID, key)

	if e.exact != nil && e.cfg.Exact.Enabled {
		e.exact.Put(key, entry)
		e.stats.observeStore("exact")
		// L1 写穿（形态 B/C）：Redis TTL = 内存 TTL + ttl_slack（由 backend 施加）。
		if e.l1 != nil {
			meta := MetaRec{Tenant: ctx.TenantID, ExpireAt: entry.ExpireAt,
				PolicyVer: ctx.PolicyVer, GuardVer: ctx.GuardVer, Model: ctx.Model}
			if err := e.l1.Put(context.Background(), KindExact, key, entry, meta, ttl); err != nil {
				_ = err // fail-open：L1 写失败降级为仅 L0（§6.9）
			}
		}
	}

	// 写语义层（二期）
	if e.sem != nil && e.sem.Enabled(ctx.TenantID) {
		meta := VectorMeta{
			EntryID:       key, // 用 exact key 作为向量索引 ID，便于回查正文
			TenantID:      ctx.TenantID,
			EngineType:    ctx.EngineType,
			Model:         ctx.Model,
			PolicyVer:     ctx.PolicyVer,
			GuardVer:      ctx.GuardVer,
			Scene:         SceneClass(ctx.Scene),
			SecurityLevel: ctx.SecurityLevel,
			ExpireAt:      entry.ExpireAt,
		}
		if err := e.sem.Store(key, res.Text, meta); err != nil {
			// fail-open：向量写入失败不影响精确层命中
			return StoreOutcome{Stored: true, Layer: "exact"}
		}
		e.stats.observeStore("semantic")
		return StoreOutcome{Stored: true, Layer: "both"}
	}

	return StoreOutcome{Stored: true, Layer: "exact"}
}

// shouldWriteNegative 判断是否应写入负向缓存（依据 only_for 配置）。
func (e *engine) shouldWriteNegative(p *NegativePayload) bool {
	if len(e.cfg.Negative.OnlyFor) == 0 {
		return true
	}
	for _, stage := range e.cfg.Negative.OnlyFor {
		if p.Stage == stage {
			return true
		}
	}
	return false
}

// ===== 主动失效 =====

// Invalidate 主动失效，返回受影响条目数。
func (e *engine) Invalidate(sel InvalidateSelector) (int, error) {
	if e.closed.Load() {
		return 0, fmt.Errorf("engine closed")
	}

	count := 0

	if sel.All {
		// 全量清空：重建 store
		if e.exact != nil {
			count += e.exact.Len()
			e.exact = NewLRUExactStore(e.cfg.Exact.MaxEntries, int(e.cfg.Exact.MaxEntryBytes.Bytes()))
		}
		if e.neg != nil {
			count += e.neg.Len()
			e.neg = NewLRUNegativeStore(e.cfg.Negative.MaxEntries)
		}
		e.stats.observeInvalidate("all", count)
		return count, nil
	}

	if sel.KeyHash != "" && e.exact != nil {
		if e.exact.Delete(sel.KeyHash) {
			count++
		}
	}

	if sel.TenantID != "" {
		if e.exact != nil {
			count += e.exact.DeleteByTenant(sel.TenantID)
		}
		if e.neg != nil {
			count += e.neg.DeleteByTenant(sel.TenantID)
		}
	}

	// 按 model：遍历删除（精确层）
	if sel.Model != "" && e.exact != nil {
		count += e.deleteByModel(sel.Model)
	}

	// L1 失效（形态 B/C，§6.8）：删除 Redis 侧密文并广播给其它副本。
	if e.l1 != nil {
		ctx := context.Background()
		switch {
		case sel.All:
			// 全量清理由 Redis 侧运维（DB/前缀级）承担，这里仅广播。
		case sel.KeyHash != "":
			_, _ = e.l1.Delete(ctx, KindExact, sel.KeyHash)
			_, _ = e.l1.Delete(ctx, KindNegative, sel.KeyHash)
		case sel.TenantID != "":
			_, _ = e.l1.DeleteByTenant(ctx, sel.TenantID)
		case sel.Model != "":
			_, _ = e.l1.DeleteByModel(ctx, sel.Model)
		}
		ev := InvalidateEvent{Op: "key", Target: sel.KeyHash}
		switch {
		case sel.All:
			ev = InvalidateEvent{Op: "all"}
		case sel.TenantID != "":
			ev = InvalidateEvent{Op: "tenant", Target: sel.TenantID}
		case sel.Model != "":
			ev = InvalidateEvent{Op: "model", Target: sel.Model}
		}
		if err := e.l1.Publish(ctx, ev); err != nil {
			_ = err // fail-open：广播失败不影响本地失效（§6.8.3）
		}
	}

	e.stats.observeInvalidate("selective", count)
	return count, nil
}

// deleteByModel 按模型删除精确缓存条目。
func (e *engine) deleteByModel(model string) int {
	// lruExactStore 没有按 model 批量删除的优化接口，
	// 这里先返回 0；一期可接受，二期接 Redis 后有 SCAN 实现。
	return 0
}

// ===== 统计 =====

// Stats 返回统计快照。
func (e *engine) Stats() StatsSnapshot {
	snap := StatsSnapshot{
		Mode:            string(e.cfg.Mode),
		Evictions:       0,
		Lookups:         make(map[string]uint64),
		FastCheckBlocks: 0,
		SavedTokens:     0,
	}
	if e.exact != nil {
		snap.ExactEntries = e.exact.Len()
		snap.Evictions = e.exact.Evictions()
	}
	if e.neg != nil {
		snap.NegativeEntries = e.neg.Len()
	}
	if e.sem != nil {
		snap.VectorEntries = e.sem.Size()
	}
	if e.stats != nil {
		e.stats.fillSnapshot(&snap)
	}
	return snap
}

// Close 优雅关闭（B-6.11-4）：置关闭标志、停止失效广播消费、释放 L1 连接池。
// 不阻塞在途请求（在途请求读到 closed 后按 miss 返回）。
func (e *engine) Close() error {
	e.closed.Store(true)
	e.invCancelMu.Lock()
	if e.invCancel != nil {
		e.invCancel()
		e.invCancel = nil
	}
	e.invCancelMu.Unlock()
	if e.l1 != nil {
		return e.l1.Close()
	}
	return nil
}

// ===== 内部辅助 =====

// exactKey 计算精确键（§5.2.1）。
func (e *engine) exactKey(ctx LookupContext) string {
	scopeKey := ctx.TenantID
	if e.cfg.Scope == "per_engine_model" {
		scopeKey = "*"
	}

	material := fmt.Sprintf("%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%d\x1f%s\x1f%s\x1f%s",
		ctx.PolicyVer,
		scopeKey,
		ctx.EngineType,
		ctx.Model,
		ctx.ModelVer,
		ctx.MaxNewTokens,
		ctx.Gen.Canonical(),
		streamFlag(ctx.Stream),
		ctx.TransformedHash,
	)
	h := sha256.Sum256([]byte(material))
	return hex.EncodeToString(h[:])
}

// negKey 计算负向键（§5.2.3）。
func (e *engine) negKey(ctx LookupContext) string {
	material := fmt.Sprintf("%s\x1f%s\x1f%s\x1f%s\x1f%s\x1f%s",
		ctx.PolicyVer,
		ctx.GuardVer,
		ctx.TenantID,
		ctx.EngineType,
		ctx.Model,
		ctx.TransformedHash,
	)
	h := sha256.Sum256([]byte(material))
	return hex.EncodeToString(h[:])
}

// streamFlag 流式标志。
func streamFlag(stream bool) string {
	if stream {
		return "s"
	}
	return "n"
}

// ===== 实体指纹与误命中反馈 =====

// needsFingerprintCheck 判断场景是否需要实体指纹二次校验。
// 严格场景（code、math）需要，一般场景（factual、general）不需要。
func (e *engine) needsFingerprintCheck(scene string) bool {
	strict := e.cfg.Semantic.Threshold.StrictFingerprint
	if len(strict) == 0 {
		// 默认严格场景
		return scene == "code" || scene == "math"
	}
	for _, s := range strict {
		if s == scene {
			return true
		}
	}
	return false
}

// fingerprintThreshold 实体指纹 Jaccard 阈值（默认 0.3）。
func (e *engine) fingerprintThreshold(scene string) float64 {
	// 配置中暂未提供独立的指纹阈值字段，使用 0.3 保守默认
	return 0.3
}

// ReportFalsePositive 上报一次误命中反馈（由业务层调用）。
// 触发反馈统计和自适应阈值调整。
func (e *engine) ReportFalsePositive(scene string) {
	if e.feedback != nil {
		e.feedback.Report(scene)
	}
	e.stats.observeFP()
}
