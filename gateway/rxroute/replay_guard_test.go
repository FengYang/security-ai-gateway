package rxroute

// ============================================================
// P1-2：ReplayGuard 单元测试
// 覆盖：基本消费 / 重放拒绝 / 空 JTI / LRU 淘汰 / 过期清理 / 边界值 / 并发安全
// ============================================================

import (
	"sync"
	"testing"
)

// ---- 基本功能 ----

// TestReplayGuard_FirstConsume 首次消费返回 true。
func TestReplayGuard_FirstConsume(t *testing.T) {
	g := NewReplayGuard(100, 30)
	if !g.Consume("jti-001", 1000) {
		t.Fatal("首次消费应返回 true")
	}
	if g.Size() != 1 {
		t.Fatalf("size=%d, want 1", g.Size())
	}
}

// TestReplayGuard_ReplayRejected 第二次消费同 JTI 返回 false（重放拒绝）。
func TestReplayGuard_ReplayRejected(t *testing.T) {
	g := NewReplayGuard(100, 30)
	g.Consume("jti-001", 1000)
	if g.Consume("jti-001", 1001) {
		t.Fatal("重放应返回 false")
	}
	if g.Size() != 1 {
		t.Fatalf("重放不应增加 size：%d", g.Size())
	}
}

// TestReplayGuard_EmptyJTI 空 JTI 直接拒绝（fail-closed）。
func TestReplayGuard_EmptyJTI(t *testing.T) {
	g := NewReplayGuard(100, 30)
	if g.Consume("", 1000) {
		t.Fatal("空 JTI 应拒绝")
	}
	if g.Size() != 0 {
		t.Fatalf("空 JTI 不应记录：size=%d", g.Size())
	}
}

// TestReplayGuard_NilGuard nil 守卫直接拒绝。
func TestReplayGuard_NilGuard(t *testing.T) {
	var g *ReplayGuard
	if g.Consume("jti-001", 1000) {
		t.Fatal("nil guard 应拒绝")
	}
	if g.Size() != 0 {
		t.Fatal("nil guard size 应为 0")
	}
	if g.Capacity() != 0 {
		t.Fatal("nil guard capacity 应为 0")
	}
}

// ---- LRU 淘汰 ----

// TestReplayGuard_LRUEviction 超过容量时 LRU 淘汰最老条目。
func TestReplayGuard_LRUEviction(t *testing.T) {
	capacity := 10
	g := NewReplayGuard(capacity, 300) // 大窗口，确保不会因为过期而减少

	// 填满容量
	for i := 0; i < capacity; i++ {
		jti := jtiOf(i)
		if !g.Consume(jti, 1000) {
			t.Fatalf("第 %d 条应被接受", i)
		}
	}
	if g.Size() != capacity {
		t.Fatalf("size=%d, want %d", g.Size(), capacity)
	}

	// 第 1 条（jti-00）是最老的，应该还在
	if !g.IsReplay(jtiOf(0), 1001) {
		t.Fatal("最老条目在容量内不应被淘汰")
	}

	// 再消费一个新 JTI → 应该淘汰最老的（jti-00）
	if !g.Consume("jti-new", 1002) {
		t.Fatal("新 JTI 应被接受（LRU 淘汰最老的）")
	}
	if g.Size() != capacity {
		t.Fatalf("size 应保持容量上限：%d", g.Size())
	}

	// 最老的 jti-00 应该被淘汰了
	if g.IsReplay(jtiOf(0), 1003) {
		t.Fatal("最老条目应被 LRU 淘汰")
	}
	// 最新的 jti-new 应该在
	if !g.IsReplay("jti-new", 1003) {
		t.Fatal("新条目应在守卫中")
	}
}

// TestReplayGuard_ReplayUpdatesLRU 重放时会把条目移到最前（最近使用）。
func TestReplayGuard_ReplayUpdatesLRU(t *testing.T) {
	g := NewReplayGuard(3, 300)

	// 依次消费 jti-0, jti-1, jti-2
	g.Consume(jtiOf(0), 1000)
	g.Consume(jtiOf(1), 1001)
	g.Consume(jtiOf(2), 1002)

	// 重放 jti-0（最老的）→ 应该移到最前
	g.Consume(jtiOf(0), 1003)

	// 再消费一个新的 → 应该淘汰 jti-1（因为 jti-0 被重放后变新了）
	g.Consume("jti-new", 1004)

	if g.IsReplay(jtiOf(0), 1005) {
		// jti-0 还在（因为被重放过，变新了）
	} else {
		t.Fatal("jti-0 被重放后变新，不应被淘汰")
	}
	if g.IsReplay(jtiOf(1), 1005) {
		t.Fatal("jti-1 是最老的，应被淘汰")
	}
}

// ---- 过期清理 ----

// TestReplayGuard_ExpiredEntriesCleared 超过时间窗口的条目被清理。
func TestReplayGuard_ExpiredEntriesCleared(t *testing.T) {
	window := int64(10) // 10 秒窗口
	g := NewReplayGuard(100, window)

	// t=0 消费一批
	g.Consume("jti-old1", 0)
	g.Consume("jti-old2", 1)
	g.Consume("jti-old3", 2)
	if g.Size() != 3 {
		t.Fatalf("初始 size=%d, want 3", g.Size())
	}

	// t=100（远超窗口）消费一个新的 → 顺带清理旧的
	g.Consume("jti-new", 100)
	if g.Size() != 1 {
		t.Fatalf("过期后 size=%d, want 1", g.Size())
	}
	if g.IsReplay("jti-old1", 100) {
		t.Fatal("过期条目应被清理")
	}
	if !g.IsReplay("jti-new", 100) {
		t.Fatal("新条目应存在")
	}
}

// TestReplayGuard_ExpiredAndReused 过期后再次消费视为新条目。
func TestReplayGuard_ExpiredAndReused(t *testing.T) {
	window := int64(10)
	g := NewReplayGuard(100, window)

	// t=0 消费
	g.Consume("jti-001", 0)

	// t=100（过期）再消费 → 应该当作新的接受（因为旧的已过期，被移除了）
	if !g.Consume("jti-001", 100) {
		t.Fatal("过期后的 JTI 应被当作新条目接受")
	}
	if g.Size() != 1 {
		t.Fatalf("size=%d, want 1", g.Size())
	}
}

// ---- IsReplay 纯查询 ----

// TestReplayGuard_IsReplay 纯查询不修改状态。
func TestReplayGuard_IsReplay(t *testing.T) {
	g := NewReplayGuard(100, 30)

	if g.IsReplay("jti-001", 1000) {
		t.Fatal("未消费的 JTI IsReplay 应返回 false")
	}

	g.Consume("jti-001", 1000)
	if !g.IsReplay("jti-001", 1001) {
		t.Fatal("已消费的 JTI IsReplay 应返回 true")
	}

	// 过期后 IsReplay 也应返回 false
	if !g.IsReplay("jti-001", 1000+31) {
		// 时间已超过窗口，应视为过期
	} else {
		t.Fatal("过期 JTI IsReplay 应返回 false")
	}
}

// ---- 默认构造 ----

// TestDefaultReplayGuard 默认构造参数合理。
func TestDefaultReplayGuard(t *testing.T) {
	g := DefaultReplayGuard()
	if g.Capacity() != 10000 {
		t.Fatalf("default capacity=%d, want 10000", g.Capacity())
	}
	if g.Size() != 0 {
		t.Fatal("default size 应为 0")
	}
}

// ---- Reset ----

// TestReplayGuard_Reset 清空所有记录。
func TestReplayGuard_Reset(t *testing.T) {
	g := NewReplayGuard(100, 30)
	for i := 0; i < 50; i++ {
		g.Consume(jtiOf(i), 1000)
	}
	if g.Size() != 50 {
		t.Fatalf("size=%d, want 50", g.Size())
	}
	g.Reset()
	if g.Size() != 0 {
		t.Fatalf("reset 后 size=%d, want 0", g.Size())
	}
	// reset 后应可以重新消费
	if !g.Consume("jti-0", 2000) {
		t.Fatal("reset 后原 JTI 应可重新消费")
	}
}

// ---- 边界值 ----

// TestReplayGuard_ZeroCapacity 零容量使用默认值。
func TestReplayGuard_ZeroCapacity(t *testing.T) {
	g := NewReplayGuard(0, 30)
	if g.Capacity() != 10000 {
		t.Fatalf("零容量应使用默认值 10000，实际 %d", g.Capacity())
	}
}

// TestReplayGuard_ZeroWindow 零窗口使用默认值（TimeSkew）。
func TestReplayGuard_ZeroWindow(t *testing.T) {
	g := NewReplayGuard(100, 0)
	// 验证窗口 = TimeSkew = 30
	g.Consume("jti-001", 1000)
	if !g.IsReplay("jti-001", 1000+int64(TimeSkew)-1) {
		t.Fatal("TimeSkew-1 秒内应该还在窗口内")
	}
	if g.IsReplay("jti-001", 1000+int64(TimeSkew)+1) {
		t.Fatal("超过 TimeSkew+1 秒应该过期")
	}
}

// ---- 并发安全（多 goroutine 下的正确性）----

// TestReplayGuard_ConcurrentConsume 并发消费不同 JTI 不出错。
// 注意：ReplayGuard 本身非并发安全，此测试验证"加锁后使用"的模式
// （生产环境 Wasm 单线程无需加锁，但此测试确保数据结构本身在外部加锁时可用）。
func TestReplayGuard_ConcurrentConsume(t *testing.T) {
	g := NewReplayGuard(10000, 300)
	var mu sync.Mutex
	var wg sync.WaitGroup

	// 10 个 goroutine，每个消费 1000 个不同的 JTI
	for gx := 0; gx < 10; gx++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				jti := jtiOf(id*1000 + i)
				mu.Lock()
				result := g.Consume(jti, 1000)
				mu.Unlock()
				if !result {
					t.Errorf("goroutine %d: JTI %s 首次消费应成功", id, jti)
				}
			}
		}(gx)
	}
	wg.Wait()

	if g.Size() != 10000 {
		t.Fatalf("并发消费后 size=%d, want 10000", g.Size())
	}
}

// TestReplayGuard_ConcurrentSameJTI 并发消费同一 JTI 只有一个成功。
func TestReplayGuard_ConcurrentSameJTI(t *testing.T) {
	g := NewReplayGuard(100, 300)
	var mu sync.Mutex
	var wg sync.WaitGroup
	successCount := 0

	// 20 个 goroutine 同时消费同一个 JTI
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			mu.Lock()
			defer mu.Unlock()
			if g.Consume("same-jti", 1000) {
				successCount++
			}
		}()
	}
	wg.Wait()

	if successCount != 1 {
		t.Fatalf("同一 JTI 应只有 1 次成功，实际 %d 次", successCount)
	}
}

// ---- 大量数据正确性 ----

// TestReplayGuard_LargeScale 大规模数据下的正确性与内存控制。
func TestReplayGuard_LargeScale(t *testing.T) {
	capacity := 5000
	// 大窗口（100 万秒），确保过期清理不干扰 LRU 测试
	g := NewReplayGuard(capacity, 1000000)

	// 消费 10000 个 JTI（超过容量）
	for i := 0; i < 10000; i++ {
		g.Consume(jtiOf(i), int64(i))
	}

	// size 不应超过容量
	if g.Size() > capacity {
		t.Fatalf("size=%d 超过容量 %d", g.Size(), capacity)
	}
	if g.Size() != capacity {
		t.Fatalf("size=%d, 应该刚好等于容量 %d", g.Size(), capacity)
	}

	// 最后 capacity 个应该还在（LRU）
	// 插入 0..9999（共 10000 条），容量 5000 → 剩余 5000..9999（共 5000 条）
	// 注意：插入第 capacity+1 条时淘汰第 0 条，所以边界是 capacity 本身在
	for i := capacity; i < 10000; i++ {
		if !g.IsReplay(jtiOf(i), int64(i+1)) {
			t.Fatalf("最近的 JTI %d 应该还在", i)
		}
	}

	// 最早的应该被淘汰了
	if g.IsReplay(jtiOf(0), 1) {
		t.Fatal("最早的 JTI 应被淘汰")
	}
}

// ---- ConsumeNow 便捷方法 ----

// TestReplayGuard_ConsumeNow ConsumeNow 使用当前时间。
func TestReplayGuard_ConsumeNow(t *testing.T) {
	g := NewReplayGuard(100, 30)
	if !g.ConsumeNow("jti-now") {
		t.Fatal("ConsumeNow 首次应成功")
	}
	if g.ConsumeNow("jti-now") {
		t.Fatal("ConsumeNow 第二次应失败")
	}
}

// ---- 辅助函数 ----

func jtiOf(i int) string {
	return "jti-" + itoa(i)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
