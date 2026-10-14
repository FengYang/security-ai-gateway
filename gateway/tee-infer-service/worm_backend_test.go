package main

// 回归测试：fileWorm.Close() 与周期 flush 循环的竞态死锁（2026-10-14 整包回归实勘）。
//
// 历史 bug：loop() 在 select 中直接读 w.stop 字段，Close() 却先 close(stop) 再置空该字段。
// 只要 loop 在「Close 置空字段之后」才求值 select（两种实勘路径）：
//   - 路径 A（构造后立即 Close）：go w.loop() 尚未被调度，Close 已置空字段，
//     loop 启动后 select 读到 nil 通道 → <-nil 永久阻塞；
//   - 路径 B（flush 在途）：tick 已触发、loop 持锁 fsync 中，Close 置空字段，
//     loop 返回 for 后重入 select 读到 nil 通道 → 永久阻塞。
// 两者均导致 Close 的 wg.Wait() 死锁。现象：TestAuditFilteredTokensEvidenceField
// 整包回归挂起直至 100s 超时（栈：Close 阻塞于 wg.Wait、loop 阻塞于 select）。
//
// 修复：loop 取构造期 stop 快照（循环体不再读字段）+ Close 用 stopOnce 只关一次。
// 修复前本测试必挂；修复后全部通过。

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// closeWithin 在独立 goroutine 中执行 Close 并断言其在限定时间内返回。
func closeWithin(t *testing.T, w *fileWorm, limit time.Duration, what string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- w.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("%s：Close 返回错误: %v", what, err)
		}
	case <-time.After(limit):
		t.Fatalf("%s：Close 死锁（loop 重入 select 读到被置空的 nil 通道，wg.Wait 永久阻塞）", what)
	}
}

// TestFileWormCloseNoDeadlockDuringFlush：flush 在途 / 构造后立即 Close 均不得死锁。
func TestFileWormCloseNoDeadlockDuringFlush(t *testing.T) {
	// 大事件：RequestID 撑到 ~1MB，使 flush 的 fsync 在途窗口达毫秒级（路径 B 竞态窗口）。
	big := strings.Repeat("x", 1<<20)
	for i := 0; i < 20; i++ {
		// 路径 A：构造后立即 Close（loop 可能尚未被调度——修复前高概率复现死锁）。
		dirA := t.TempDir()
		wA, err := newFileWormWithConfig(filepath.Join(dirA, "a.jsonl"), defaultWormFsyncConfig())
		if err != nil {
			t.Fatalf("构造 fileWorm 失败: %v", err)
		}
		closeWithin(t, wA, 10*time.Second, "路径A（构造后立即 Close）")

		// 路径 B：灌入大事件后等 tick 进入 flush（持锁 fsync 在途）再 Close。
		dirB := t.TempDir()
		wB, err := newFileWormWithConfig(filepath.Join(dirB, "b.jsonl"), WormFsyncConfig{
			Mode:     FsyncBatch,
			Every:    1000, // Append 不触发 fsync，只由周期 flush 走慢路径
			Interval: time.Millisecond,
		})
		if err != nil {
			t.Fatalf("构造 fileWorm 失败: %v", err)
		}
		if err := wB.Append(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok", RequestID: big}); err != nil {
			t.Fatalf("Append 失败: %v", err)
		}
		time.Sleep(3 * time.Millisecond) // 1ms 间隔的 tick 已触发、loop 进入 flush
		closeWithin(t, wB, 10*time.Second, "路径B（flush 在途时 Close）")
	}
}

// TestFileWormCloseIdempotent：Close 重复调用不得 panic（stop 双 close）且二次调用立即返回。
func TestFileWormCloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	w, err := newFileWormWithConfig(filepath.Join(dir, "worm.jsonl"), defaultWormFsyncConfig())
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	closeWithin(t, w, 10*time.Second, "首次 Close")
	// 二次 Close：stopOnce 保证不双 close（双 close 会 panic）；wg 已归零应立即返回。
	closeWithin(t, w, 5*time.Second, "二次 Close")
}