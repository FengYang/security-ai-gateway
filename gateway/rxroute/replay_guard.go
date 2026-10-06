package rxroute

// ============================================================
// ReplayGuard：处方头防重放（P1-2，方案 §6.3.2）
//
// 设计原则：
//   - 内存 LRU + 时间过期双淘汰，控制内存上限
//   - 精确匹配（非 Bloom Filter），避免误判
//   - 单线程安全（Wasm 环境）；并发安全由调用方保证
//     （如果多 goroutine 调用，外层需加锁）
//   - 时间窗口 = TimeSkew（30s），与处方有效期对齐
//     （过期处方本身就会被时效校验拒绝，无需再占内存）
//
// 内存估算：
//   10,000 条 JTI（16 字节 UUID + 8 字节时间戳 + map 开销）
//   ≈ 10,000 × (16+8+32) ≈ 560 KB，对 Wasm 完全可接受
// ============================================================

import (
	"container/list"
	"time"
)

// ReplayGuard 防重放守卫：记录已消费的 JTI，拒绝重复使用。
//
// 零值可用吗？否。必须用 NewReplayGuard 构造（需要 maxCapacity）。
// 并发安全：不安全。Wasm 单线程环境直接使用；多 goroutine 需外层加锁。
type ReplayGuard struct {
	maxCap    int                // 最大容量（LRU 淘汰上限）
	ll        *list.List         // LRU 链表（最前=最近使用，最后=最久未使用）
	idx       map[string]*list.Element // JTI → 链表节点
	windowSec int64              // 时间窗口（秒），与 TimeSkew 对齐
}

// replayItem LRU 链表节点存储的内容。
type replayItem struct {
	jti       string
	consumedAt int64 // 消费时间（Unix 秒）
}

// NewReplayGuard 构造防重放守卫。
//
// maxCapacity：最大 JTI 容量，超过则 LRU 淘汰最老的条目。
//   建议默认 10,000（30s 窗口 × ~333 QPS = 10,000）。
// windowSec：时间窗口（秒），超过窗口的条目自动失效（与处方有效期对齐）。
//   建议使用 rxroute.TimeSkew（30s）。
func NewReplayGuard(maxCapacity int, windowSec int64) *ReplayGuard {
	if maxCapacity <= 0 {
		maxCapacity = 10000
	}
	if windowSec <= 0 {
		windowSec = int64(TimeSkew)
	}
	return &ReplayGuard{
		maxCap:    maxCapacity,
		ll:        list.New(),
		idx:       make(map[string]*list.Element, maxCapacity),
		windowSec: windowSec,
	}
}

// Consume 标记一个 JTI 为已消费。
// 返回 true = 首次消费（通过）；false = 重复消费（重放，拒绝）。
//
// nowUnix：当前时间（Unix 秒），由调用方传入（便于测试注入）。
//
// 规则：
//   1. JTI 为空 → 直接拒绝（无法判断是否重放，fail-closed）
//   2. JTI 已存在 → 拒绝（重放）
//   3. JTI 不存在 → 记录并通过
//   4. 插入后容量超限 → LRU 淘汰最老条目
//   5. 插入时顺带清理超时条目（从链表尾部向前扫，遇到未过期就停）
func (g *ReplayGuard) Consume(jti string, nowUnix int64) bool {
	if g == nil || g.idx == nil {
		// 未初始化，fail-closed：拒绝
		return false
	}
	if jti == "" {
		return false
	}

	// 命中：重复消费 → 拒绝
	if ele, ok := g.idx[jti]; ok {
		item := ele.Value.(*replayItem)
		// 即使命中，如果已过期也当作新条目（理论上不会发生，因为过期处方会被时效校验先拒绝）
		if nowUnix-item.consumedAt <= g.windowSec {
			// 移到最前（最近使用）
			g.ll.MoveToFront(ele)
			return false
		}
		// 已过期：移除旧条目，继续当新条目处理
		g.ll.Remove(ele)
		delete(g.idx, jti)
	}

	// 清理过期条目（从尾部往前扫，遇到未过期就停）
	g.evictExpired(nowUnix)

	// 容量超限：淘汰最老的
	if g.ll.Len() >= g.maxCap {
		g.evictOldest()
	}

	// 插入新条目
	item := &replayItem{jti: jti, consumedAt: nowUnix}
	ele := g.ll.PushFront(item)
	g.idx[jti] = ele
	return true
}

// evictExpired 从链表尾部向前清理已过期条目。
// 因为消费时间单调递增（大致），尾部是最老的，所以从后往前扫很快。
func (g *ReplayGuard) evictExpired(nowUnix int64) {
	for {
		back := g.ll.Back()
		if back == nil {
			return
		}
		item := back.Value.(*replayItem)
		if nowUnix-item.consumedAt > g.windowSec {
			g.ll.Remove(back)
			delete(g.idx, item.jti)
		} else {
			// 遇到未过期的就停（时间大致单调递增）
			return
		}
	}
}

// evictOldest 淘汰最老的一条（LRU）。
func (g *ReplayGuard) evictOldest() {
	back := g.ll.Back()
	if back == nil {
		return
	}
	item := back.Value.(*replayItem)
	g.ll.Remove(back)
	delete(g.idx, item.jti)
}

// IsReplay 检查一个 JTI 是否已被消费（不修改状态，纯查询）。
// 返回 true = 已消费（重放）；false = 未消费。
// 注意：这是一个辅助方法，不会改变 LRU 顺序。正式消费请用 Consume。
func (g *ReplayGuard) IsReplay(jti string, nowUnix int64) bool {
	if g == nil || g.idx == nil || jti == "" {
		return true // fail-closed
	}
	ele, ok := g.idx[jti]
	if !ok {
		return false
	}
	item := ele.Value.(*replayItem)
	return nowUnix-item.consumedAt <= g.windowSec
}

// Size 返回当前已记录的 JTI 数量（用于可观测性）。
func (g *ReplayGuard) Size() int {
	if g == nil || g.idx == nil {
		return 0
	}
	return len(g.idx)
}

// Capacity 返回配置的最大容量。
func (g *ReplayGuard) Capacity() int {
	if g == nil {
		return 0
	}
	return g.maxCap
}

// Reset 清空所有记录（测试用/重置用）。
func (g *ReplayGuard) Reset() {
	if g == nil || g.idx == nil {
		return
	}
	g.ll.Init()
	for k := range g.idx {
		delete(g.idx, k)
	}
}

// ---- 便捷构造函数 ----

// DefaultReplayGuard 用默认参数构造防重放守卫（10,000 容量 × 30s 窗口）。
func DefaultReplayGuard() *ReplayGuard {
	return NewReplayGuard(10000, int64(TimeSkew))
}

// ---- 时间源便捷方法 ----

// ConsumeNow 用当前时间戳消费（便捷方法，测试用注入时间的请用 Consume）。
func (g *ReplayGuard) ConsumeNow(jti string) bool {
	return g.Consume(jti, time.Now().Unix())
}
