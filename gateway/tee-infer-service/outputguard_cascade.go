// 级联并发控制器（GA-输出侧内容审查-技术实现方案 §3.6.3；§3.2 文件清单 outputguard_cascade.go）。
//
// 职责（OG-13）：把判定单元（句）的判定结果按**生成顺序**下发，解耦"乱序完成 / 有序下发"。
//
// 冻结结构（§5.8 冻结项 #9）：数据结构＝`[]slot` + `sync.Cond`（非环形数组、非 channel-per-slot）；
// slot 状态机＝4 态 `pending`/`done`/`timeout`/`closed`，**单向无回退**。
//
// 下发游标语义（§3.6.3 执行细节 3）：
//   - 每个 delta 归属到"覆盖其最后 rune 的槽位"（认领制：槽位创建时认领一段 delta 区间）；
//   - delta 可下发 ⟺ 其归属槽位已终态；游标沿 delta 顺序推进——**不跳发、不合并帧**；
//   - 未认领的 delta（字节尚未构成判定单元）在阻塞形态下不下发（否则未审内容先出）；
//   - 下发**按原始 delta 原样写出**（不重组句、不改字节）：阻塞与不阻塞形态的字节序列
//     完全一致，仅时间不同——满足 §2.3"不改变输出字节"红线。
//
// 阻塞开关（§3.6.3「M3 打开阻塞只需把开关从 false 改 true，不改数据结构」）：
//   - `BlockEmission=false`（生产 shadow 缺省）：emitter 不等 pending，行为与 M2 逐字节一致；
//   - `BlockEmission=true`（浸泡预演，非 §5 参数表参数）：emitter 遇 pending 即停，产出真实首帧延迟增量；
//     两形态下槽位/定时器/并发计数/指标路径完全相同（§3.6.3 末段要求）。
//
// 容量与降级（§3.6.3 细节 1/2/5、§3.6.4 降级表）：
//   - 提交前检查并发：`inFlight >= P-CONCURRENCY` → 该句直接按 P-DEGRADE（**不排队**）＋容量阀计数；
//   - 每槽一个 `time.AfterFunc(P-TIMEOUT)`：到期置 timeout ＋ 唤醒 emitter ＋ `degraded{reason=l2_timeout}`；
//   - 超 `P-MAX-SLOTS`：不再新建槽位，按 P-DEGRADE 收尾并记指标（该单元 delta 直接放行）；
//   - L2 迟到结果：丢弃 ＋ `l2_call{result=late}`（**不回改已下发内容**）。
//
// 方案 2 画像（M2 R10 用户确认，本文件保留）：L1 命中**不短路** L2——槽位按"L1 命中即决"立即终态
// （不阻塞下发，满足 §3.6.3 的 L1 命中即决时序语义），L2 仍异步提交作完整 shadow 画像；
// 画像调用不参与阻塞、不迁移槽位状态，其结果只按 hit/miss 记画像指标；
// L1 命中遇上并发阀时跳过画像调用（画像非安全判定，不触发 fail-closed）。
//
// shadow 语义硬边界：本文件**不含任何删除/改写下发内容的逻辑**——fail-closed 在 M3 只计数与留痕
// （内容拦截属 M4 enforcing）。终止码/终止帧属 OG-5（管线层），不在本文件。
//
// 已知限制（诚实标注，登记台账）：`OutputClassifier` 接口签名已冻结（§5.8 #1）不含 context，
// 故断连时无法真正取消在飞 L2；靠客户端超时（P-TIMEOUT，与 `-output-guard-l2-timeout` 同源）
// 自然收敛，goroutine 不泄漏（≤ P-TIMEOUT 内必然返回）。
package main

import (
	"sync"
	"time"
)

// 槽位状态（§3.6.3 四态；单向无回退）。
const (
	slotPending = iota // L2 在飞；emitter 遇 pending 即停（阻塞形态）
	slotDone           // 终态：L1 命中即决 / L2 正常返回 / 未启用 L2
	slotTimeout        // 终态：定时器到期、提交时超并发上限、超槽位上限、L2 调用失败或类目未映射（均按 P-DEGRADE 处置）
	slotClosed         // 终态：Close（断连/收尾）
)

// delta 归属哨兵（deltaGates 取值）。
const (
	gateUnclaimed = -1 // 该 delta 的字节尚未构成任何判定单元（阻塞形态下不下发）
	gateReleased  = -2 // 该 delta 无归属槽位但已放行（超槽位上限 / Finish 收尾兜底）
)

// fail-closed 归因（`degraded_total{reason}` 与审计 Result 共用；§3.6.4 降级表）。
const (
	degradeReasonL2Timeout = "l2_timeout"     // 定时器到期（P-TIMEOUT）
	degradeReasonOverload  = "l2_overload"    // 提交时超 P-CONCURRENCY（容量阀，不排队）
	degradeReasonSlotsFull = "l2_slots_full"  // 超 P-MAX-SLOTS（每请求句数上限）
	degradeReasonL2Unavail = "l2_unavailable" // L2 调用失败（unreachable/timeout/bad_status/bad_response）
	degradeReasonUnmapped  = "l2_unmapped"    // 类目未映射（格式错误＝P-DEGRADE，与 P-CONF-BAND 同语义）
	degradeReasonBadConf   = "l2_bad_conf"    // 命中但置信度缺失（P-CONF-BAND：格式错误＝P-DEGRADE）
)

// cascadeSlot 单句槽位（创建后永不删除——下标即 seq，供 delta 归属引用）。
type cascadeSlot struct {
	seq                int
	state              int
	unit               string   // 判定单元原文（L2 输入；不落审计、不落日志，§4.11 日志红线）
	action             string   // pass|flag|block|mask（shadow 恒 flag/pass；M4 按动作表）
	category           string   // 内部类目 ID（命中时）
	l1Cats             []string // 该单元 L1 命中类目（判 l2_only_hit 用）
	deltaFrom, deltaTo int      // 该单元认领的 delta 区间（含端点，绝对下标）
	timer              *time.Timer
	l2InFlight         bool // 该槽位有在飞 L2（含画像调用）：决定 inFlight 是否回补
	profiling          bool // 画像调用（L1 命中后仍在飞的 L2）：结果只留痕，不迁移状态
}

// cascade 单请求级联控制器（`[]slot` + `sync.Cond`，§5.8 #9）。
type cascade struct {
	mu   sync.Mutex
	cond *sync.Cond

	params outputGuardCascadeParams
	mode   string

	l1   OutputClassifier
	l2   OutputClassifier // nil = 纯 L1（无级联）
	emit outputEmitFunc   // 唯一出口（§2.3 I2）

	m             *otpmaskMetrics
	a             *auditChain
	tenant        string
	requestID     string
	policyVersion string

	slots    []*cascadeSlot
	inFlight int // 在飞 L2 句数（＝ buffer_queue_depth gauge 口径；含画像调用）

	// 下发缓冲与游标：deltas[i] 的绝对下标恒为 i（本请求内不做压缩；已下发即置空释放负载）。
	deltas     []string
	deltaGates []int // 每个 delta 的归属槽位下标（或 gateUnclaimed/gateReleased）
	claimUntil int   // 下一个尚未被任何槽位认领的 delta 下标
	emitIdx    int   // 下发游标（下一个待下发的 delta 下标）

	seenCategory   map[string]bool // 同请求同类目只记一次（避免重复计数）
	firstHitCat    string          // 首次命中的内部类目 ID（chunk-meta 用）
	firstHitAction string

	closed  bool // Close 已调用（含 emit 失败）
	noMore  bool // Finish 已调用：不再有新槽位，未认领 delta 视为放行
	emitErr error

	firstDeltaAt time.Time // 首个 delta 进入管线时刻（§4.3.2 首帧延迟增量起点）
	firstEmitAt  time.Time // 首次写出时刻

	sentences     int64 // 判定句数（派生 gauge 分母）
	failclosed    int64 // 按 P-DEGRADE 处置的句数（派生 gauge 分子）
	l2Calls       int64 // 已发起的 L2 调用数（含画像；l2_cascade_ratio 分子）
	degradedAudit bool  // 每请求只落一条 output_guard_degraded（避免长流刷链）
}

// newCascade 构造请求级级联控制器。params 须为 resolve 后的取值。
func newCascade(params outputGuardCascadeParams, mode string, l1, l2 OutputClassifier, m *otpmaskMetrics,
	a *auditChain, tenant, requestID, policyVersion string) *cascade {
	c := &cascade{
		params:        params,
		mode:          mode,
		l1:            l1,
		l2:            l2,
		m:             m,
		a:             a,
		tenant:        tenant,
		requestID:     requestID,
		policyVersion: policyVersion,
		seenCategory:  make(map[string]bool, 4),
	}
	c.cond = sync.NewCond(&c.mu)
	return c
}

// pushDelta 处理引擎下发的一个 delta：入缓冲 → 判定单元逐个提交 → 推进下发游标。
// 返回 emit 错误（慢客户端＝非 nil；调用方据此终止引擎，§4.3 慢客户端行）。
func (c *cascade) pushDelta(delta string, units []string, emit outputEmitFunc) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.emit = emit
	if c.closed {
		return c.emitErr
	}
	c.beginDeltaLocked(delta)
	for _, u := range units {
		c.submitUnitLocked(u)
	}
	return c.emitReadyLocked()
}

// finish 收尾（Finish）：提交尾部单元 → 置 noMore → 等在飞 L2 收敛（上限＝P-TIMEOUT）
// 且下发缓冲排空 → 返回 emit 错误。
func (c *cascade) finish(units []string, emit outputEmitFunc) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.emit = emit
	if c.closed {
		return c.emitErr
	}
	for _, u := range units {
		c.submitUnitLocked(u)
	}
	c.noMore = true
	c.releaseUnclaimedLocked()
	// 放行未认领 delta 后必须自己推进一次游标：此时可能已无在飞 L2
	// （无人会再调 emitReadyLocked），否则游标永久卡住、Finish 永不返回。
	if err := c.emitReadyLocked(); err != nil {
		return err
	}
	for !c.closed && (c.emitIdx < len(c.deltas) || c.inFlight > 0) {
		c.cond.Wait()
	}
	return c.emitErr
}

// close 幂等释放：置 closed、停表、丢弃缓冲并唤醒等待者（防 goroutine 泄漏）。
func (c *cascade) close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.markClosedLocked()
}

// firstHit 返回首次命中的内部类目与动作（供 chunk-meta / 终止帧；空 = 未命中）。
func (c *cascade) firstHit() (cat, action string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.firstHitCat, c.firstHitAction
}

// cascadeStats 级联观测快照（测试与浸泡报告用；不含判定内容）。
type cascadeStats struct {
	Sentences       int64
	FailClosed      int64
	L2Calls         int64
	Slots           int
	Emitted         int
	HasFirstFrame   bool
	FirstFrameDelay time.Duration
}

func (c *cascade) stats() cascadeStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := cascadeStats{
		Sentences:  c.sentences,
		FailClosed: c.failclosed,
		L2Calls:    c.l2Calls,
		Slots:      len(c.slots),
		Emitted:    c.emitIdx,
	}
	if !c.firstEmitAt.IsZero() && !c.firstDeltaAt.IsZero() {
		st.HasFirstFrame = true
		st.FirstFrameDelay = c.firstEmitAt.Sub(c.firstDeltaAt)
	}
	return st
}

// beginDeltaLocked 把 delta 记入下发缓冲（不改内容）；首个 delta 时刻即首帧延迟口径起点。
func (c *cascade) beginDeltaLocked(delta string) {
	if c.firstDeltaAt.IsZero() {
		c.firstDeltaAt = time.Now()
	}
	c.deltas = append(c.deltas, delta)
	c.deltaGates = append(c.deltaGates, gateUnclaimed)
}

// submitUnitLocked 为一个判定单元建槽位并决定判定路径（§3.6.3 提交点）。
func (c *cascade) submitUnitLocked(unit string) {
	if unit == "" || c.closed {
		return
	}
	c.sentences++
	if c.m != nil {
		c.m.incOGSentence()
	}
	// 槽位上限（§3.6.3 细节 5）：不再新建槽位，按 P-DEGRADE 收尾并记指标；
	// 该单元认领的 delta 直接放行（shadow 不拦内容；enforcing 的截断属 M4）。
	if len(c.slots) >= c.params.MaxSlots {
		if c.m != nil {
			c.m.incOGBufferFull()
		}
		c.releaseUnitDeltasLocked()
		c.failClosedLocked(degradeReasonSlotsFull)
		return
	}
	s := &cascadeSlot{
		seq:       len(c.slots),
		state:     slotPending,
		unit:      unit,
		action:    catActionPass,
		deltaTo:   len(c.deltas) - 1,
		deltaFrom: c.claimUntil,
	}
	if s.deltaFrom > s.deltaTo {
		s.deltaFrom = s.deltaTo
	}
	if s.deltaFrom < 0 {
		s.deltaFrom = 0
	}
	c.slots = append(c.slots, s)
	for d := s.deltaFrom; d <= s.deltaTo && d < len(c.deltaGates); d++ {
		c.deltaGates[d] = s.seq // 认领：delta 归属"覆盖其最后 rune 的槽位"
	}
	c.claimUntil = s.deltaTo + 1

	// ---- L1 规则层（同步即决）----
	if cat := c.classifyL1Locked(s); cat != "" {
		s.action = catActionForMode(cat, c.mode)
		s.category = cat
		c.finishLocked(s, slotDone) // L1 命中即决：不阻塞下发（§3.6.3）
		// 方案 2 画像：L2 仍异步跑（不参与阻塞）；超并发阀时跳过（画像非安全判定）
		if c.l2 != nil && c.inFlight < c.params.Concurrency {
			c.startL2Locked(s, true)
		}
		return
	}
	if c.l2 == nil {
		c.finishLocked(s, slotDone) // 纯 L1 形态：无级联，直接终态
		return
	}
	// ---- 级联：提交前检查并发（容量阀，不排队）----
	if c.inFlight >= c.params.Concurrency {
		if c.m != nil {
			c.m.incOGBufferFull()
		}
		c.finishLocked(s, slotTimeout)
		c.failClosedLocked(degradeReasonOverload)
		return
	}
	c.startL2Locked(s, false)
}

// classifyL1Locked 跑 L1 规则层并留痕，返回命中的内部类目 ID（空 = 未命中/未映射）。
func (c *cascade) classifyL1Locked(s *cascadeSlot) string {
	if c.l1 == nil {
		return ""
	}
	raw, _, _ := c.l1.Classify(s.unit)
	if raw == "" {
		return ""
	}
	cat := raw
	if !isValidCategory(cat) {
		mapped, ok := mapL1Category(cat)
		if !ok {
			// L1 未映射不影响 L2 继续跑（与 M1/M2 行为一致）
			if c.m != nil {
				c.m.incOGUnmapped("l1", cat)
			}
			return ""
		}
		cat = mapped
	}
	s.l1Cats = append(s.l1Cats, cat)
	if c.m != nil {
		c.m.incOGL1Hit(cat)
	}
	c.recordHitLocked(cat)
	return cat
}

// startL2Locked 异步提交一次 L2 判定（不阻塞引擎继续生成，§3.6.3 关键性质"引擎不停"）。
// profiling=true 表示画像调用（L1 已命中）：不挂定时器、不迁移槽位状态。
func (c *cascade) startL2Locked(s *cascadeSlot, profiling bool) {
	c.inFlight++
	c.l2Calls++
	s.l2InFlight = true
	s.profiling = profiling
	if c.m != nil {
		c.m.addOGBufferQueueDepth(1) // OG-13 缺陷2：进程级聚合 +1（不再以本 cascade 本地值覆写全局）
		c.m.incOGL2CallStarted()
	}
	if !profiling {
		s.timer = time.AfterFunc(c.params.Timeout, func() { c.onSlotTimeout(s.seq) })
	}
	go func() {
		start := time.Now()
		cat, conf, _ := c.l2.Classify(s.unit)
		elapsed := time.Since(start).Seconds()

		c.mu.Lock()
		defer c.mu.Unlock()
		if c.m != nil {
			c.m.observeOGL2DurationSeconds(elapsed)
		}
		c.settleInFlightLocked(s)
		switch {
		case c.closed:
			// 断连/收尾后返回：丢弃（记 late，与超时迟到同口径）
			if c.m != nil {
				c.m.incOGL2Call("", "late")
			}
		case s.profiling:
			// 画像调用：结果只留痕（hit/miss/error/unmapped），不迁移槽位状态
			c.normalizeVerdictLocked(s, cat, conf)
		case s.state != slotPending:
			// 已按 timeout/closed 处置（迟到）：丢弃，不回改已下发内容（§3.6.3 边界表）
			if c.m != nil {
				c.m.incOGL2Call("", "late")
			}
		default:
			v := c.normalizeVerdictLocked(s, cat, conf)
			s.action, s.category = v.action, v.cat
			c.finishLocked(s, v.state)
			if v.reason != "" {
				c.failClosedLocked(v.reason)
			}
		}
		c.emitReadyLocked()
	}()
}

// verdictResult L2 判定归一化结果（槽位迁移 + 画像留痕共用）。
type verdictResult struct {
	state  int    // slotDone | slotTimeout
	action string // 槽位动作（shadow 下恒 flag/pass）
	cat    string // 内部类目 ID（命中且已映射）
	reason string // 非空 = 按 P-DEGRADE 处置的归因
}

// normalizeVerdictLocked 把 L2 返回值归一化为槽位结果，并落画像/命中留痕。
// 语义（§5.2 P-CONF-BAND、§4.2.3 映射纪律）：置信度缺失与类目未映射同属"格式错误"＝P-DEGRADE。
func (c *cascade) normalizeVerdictLocked(s *cascadeSlot, cat string, conf float64) verdictResult {
	if conf < 0 {
		// 调用失败哨兵（unreachable/timeout/bad_status/bad_response）；
		// degraded{reason=<具体原因>} 已由 HTTP 封装记录（那里知道原因）
		if c.m != nil {
			c.m.incOGL2Call("", "error")
		}
		return verdictResult{state: slotTimeout, action: catActionBlock, reason: degradeReasonL2Unavail}
	}
	if cat == "" {
		if c.m != nil {
			c.m.incOGL2Call("", "miss")
		}
		return verdictResult{state: slotDone, action: catActionPass}
	}
	if conf <= 0 {
		// P-CONF-BAND：置信度是命中的必带字段；后端只返 category 不返 confidence ＝ 格式错误，
		// 不做默认猜测（M2 曾按 1.0 兜底，M3 修正）。
		if c.m != nil {
			c.m.incOGL2Call(cat, "bad_conf")
		}
		return verdictResult{state: slotTimeout, action: catActionBlock, reason: degradeReasonBadConf}
	}
	internal := cat
	if !isValidCategory(internal) {
		mapped, ok := mapL1Category(internal)
		if !ok {
			if c.m != nil {
				c.m.incOGL2Call(cat, "unmapped")
				c.m.incOGUnmapped("l2", cat)
			}
			return verdictResult{state: slotTimeout, action: catActionBlock, reason: degradeReasonUnmapped}
		}
		internal = mapped
	}
	if c.m != nil {
		c.m.incOGL2Call(internal, "hit")
		if !containsCat(s.l1Cats, internal) {
			c.m.incOGL2OnlyHit(internal) // L1 未检出该类目 = L2 专属贡献
		}
	}
	c.recordHitLocked(internal)
	return verdictResult{state: slotDone, action: catActionForMode(internal, c.mode), cat: internal}
}

// onSlotTimeout 定时器到期（§3.6.3 细节 2）：置 timeout ＋ 唤醒 emitter ＋ degraded{reason=l2_timeout}。
func (c *cascade) onSlotTimeout(seq int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if seq < 0 || seq >= len(c.slots) {
		return
	}
	s := c.slots[seq]
	if s.state != slotPending || s.profiling {
		return // 单向无回退：已终态/画像调用无定时器
	}
	c.finishLocked(s, slotTimeout)
	c.failClosedLocked(degradeReasonL2Timeout)
	c.emitReadyLocked()
}

// finishLocked 槽位迁移到终态（单向：仅 pending 可迁移；停表 + 收敛在飞计数 + 唤醒等待者）。
func (c *cascade) finishLocked(s *cascadeSlot, state int) {
	if s.state != slotPending {
		return
	}
	s.state = state
	if s.timer != nil {
		s.timer.Stop()
	}
	c.cond.Broadcast()
}

// settleInFlightLocked 在该槽位的 L2 调用返回时收敛在飞计数（幂等；Close 已清零则不再减）。
func (c *cascade) settleInFlightLocked(s *cascadeSlot) {
	if !s.l2InFlight {
		return
	}
	s.l2InFlight = false
	if c.inFlight > 0 {
		c.inFlight--
		if c.m != nil {
			c.m.addOGBufferQueueDepth(-1) // 进程级聚合 −1（与 startL2Locked +1 配对）
		}
	}
	c.cond.Broadcast()
}

// emitReadyLocked 推进下发游标：连续写出所有"归属槽位已终态"的 delta（不跳发、不合并帧）。
// 阻塞形态下遇 pending/未认领即停（队头阻塞）；非阻塞形态（生产 shadow）不等 pending。
func (c *cascade) emitReadyLocked() error {
	if c.emitErr != nil {
		return c.emitErr
	}
	if c.emit == nil {
		return nil
	}
	for c.emitIdx < len(c.deltas) {
		if c.params.BlockEmission {
			switch g := c.deltaGates[c.emitIdx]; {
			case g == gateUnclaimed:
				return nil // 字节尚未构成判定单元：不下发（否则未审内容先出）
			case g >= 0 && c.slots[g].state == slotPending:
				return nil // 前序句未决 → 后续句排队等待（§3.6.3 按序下发）
			}
		}
		payload := c.deltas[c.emitIdx]
		if err := c.emit(payload, ""); err != nil {
			c.emitErr = err
			c.markClosedLocked() // 慢客户端：立即释放（§4.3）
			return err
		}
		c.deltas[c.emitIdx] = "" // 已写出：释放负载（帧级缓冲不随输出增长）
		c.emitIdx++
		if c.firstEmitAt.IsZero() {
			c.firstEmitAt = time.Now()
			if c.m != nil && !c.firstDeltaAt.IsZero() {
				// 首帧延迟增量口径（§4.3.2）：首次写出时刻 − 首个 delta 进入管线时刻
				// （无审查时首帧即首个 delta；不含 handler 前段与网络）。
				c.m.observeOGFirstFrameDelaySeconds(c.firstEmitAt.Sub(c.firstDeltaAt).Seconds())
			}
		}
		c.cond.Broadcast()
	}
	return nil
}

// markClosedLocked 置 closed 并释放：停表、置未决槽位为 closed、丢弃缓冲、唤醒等待者。
func (c *cascade) markClosedLocked() {
	if c.closed {
		return
	}
	c.closed = true
	residual := c.inFlight // 尚未 settle 的在飞 L2（其 HTTP 回调可能迟到）
	for _, s := range c.slots {
		if s.state == slotPending {
			s.state = slotClosed
			if s.timer != nil {
				s.timer.Stop()
			}
		}
		// 销账：关闭后迟到的 L2 回调 settleInFlightLocked 须为 no-op，
		// 否则其 −1 与下面的残留扣减重复，导致进程级全局 gauge 漂移为负。
		s.l2InFlight = false
	}
	c.inFlight = 0
	if c.m != nil && residual > 0 {
		// OG-13 缺陷2：只扣本 cascade 的残留量，不覆写全局（其他请求的在飞计数保留）。
		c.m.addOGBufferQueueDepth(-int64(residual))
	}
	c.deltas, c.deltaGates = nil, nil
	c.cond.Broadcast()
}

// releaseUnitDeltasLocked 放行"当前未认领的 delta"（超槽位上限的单元：无槽位可归属）。
func (c *cascade) releaseUnitDeltasLocked() {
	for d := c.claimUntil; d < len(c.deltaGates); d++ {
		c.deltaGates[d] = gateReleased
	}
	if len(c.deltas) > 0 {
		c.claimUntil = len(c.deltas)
	}
}

// releaseUnclaimedLocked 收尾兜底：Finish 后仍未认领的 delta 一律放行（防游标永久卡住）。
func (c *cascade) releaseUnclaimedLocked() {
	for d := range c.deltaGates {
		if c.deltaGates[d] == gateUnclaimed {
			c.deltaGates[d] = gateReleased
		}
	}
}

// failClosedLocked 记录一次"按 P-DEGRADE 处置"的句：计数 + degraded 指标 + 审计（每请求一条）。
func (c *cascade) failClosedLocked(reason string) {
	c.failclosed++
	if c.m != nil {
		c.m.incOGFailClosedSentence()
		c.m.incOGDegraded("l2", reason)
	}
	if c.degradedAudit || c.a == nil {
		return
	}
	c.degradedAudit = true
	// 每请求最多一条（长流逐句落链会刷爆审计链；逐句量级由 degraded_total{reason} 承载）。
	c.a.append(AuditEvent{
		TenantID:        c.tenant,
		RequestID:       c.requestID,
		Action:          "output_guard_degraded",
		Result:          reason,
		OGMode:          c.mode,
		OGPolicyVersion: c.policyVersion,
	})
}

// recordHitLocked 记录一次命中（L1/L2 命中共用）：首见类目 → would_reject 指标 + 审计。
func (c *cascade) recordHitLocked(cat string) {
	if c.seenCategory[cat] {
		return
	}
	c.seenCategory[cat] = true
	if c.firstHitCat == "" {
		c.firstHitCat = cat
		c.firstHitAction = catActionForMode(cat, c.mode)
	}
	if c.m != nil {
		c.m.incOGWouldReject(cat)
	}
	if c.a == nil {
		return
	}
	// Result 取值：would_reject_<内部类目 ID>（OG-7 规范化）；证据字段 omitempty、不进 hash。
	c.a.append(AuditEvent{
		TenantID:        c.tenant,
		RequestID:       c.requestID,
		Action:          "output_would_reject",
		Result:          "would_reject_" + cat,
		OGCategory:      cat,
		OGMode:          c.mode,
		OGPolicyVersion: c.policyVersion,
	})
}

// containsCat 判断内部类目是否在命中集合内。
func containsCat(cats []string, cat string) bool {
	for _, c := range cats {
		if c == cat {
			return true
		}
	}
	return false
}
