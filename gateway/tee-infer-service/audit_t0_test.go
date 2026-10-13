package main

// P1-7 T0 单元测试（D-17 落盘强度 / A4-01 统一写盘入口 / A4-07 行序≡链序）。

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---- D-17：batch 档按条数阈值 fsync ----

func TestFileWormBatchFsyncByCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.jsonl")
	// interval 设大（避免定时 flush 干扰），仅验证条数阈值。
	w, err := newFileWormWithConfig(path, WormFsyncConfig{Mode: FsyncBatch, Every: 3, Interval: time.Hour})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	defer w.Close()

	for i := 0; i < 2; i++ {
		if err := w.Append(AuditEvent{EventID: "e", TenantID: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.SyncCount(); got != 0 {
		t.Fatalf("未达阈值不应 fsync，got %d", got)
	}
	if err := w.Append(AuditEvent{EventID: "e", TenantID: "t"}); err != nil {
		t.Fatal(err)
	}
	if got := w.SyncCount(); got != 1 {
		t.Fatalf("达阈值（3 条）应 fsync 1 次，got %d", got)
	}
}

// ---- D-17：per_event 档每条 fsync ----

func TestFileWormPerEventFsync(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.jsonl")
	w, err := newFileWormWithConfig(path, WormFsyncConfig{Mode: FsyncPerEvent})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	defer w.Close()

	for i := 0; i < 4; i++ {
		if err := w.Append(AuditEvent{EventID: "e", TenantID: "t"}); err != nil {
			t.Fatal(err)
		}
	}
	if got := w.SyncCount(); got != 4 {
		t.Fatalf("per_event 档每条应 fsync（4 条 → 4 次），got %d", got)
	}
}

// ---- D-17：batch 档静默期尾部事件由定时 flush 落盘 ----

func TestFileWormIntervalFlush(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.jsonl")
	// every 设大（不触发条数阈值），interval 20ms → 仅定时 flush 生效。
	w, err := newFileWormWithConfig(path, WormFsyncConfig{Mode: FsyncBatch, Every: 100000, Interval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	defer w.Close()

	if err := w.Append(AuditEvent{EventID: "e", TenantID: "t"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if w.SyncCount() >= 1 {
			return // 定时 flush 生效
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("定时 flush 未在窗口内触发（静默期尾部事件滞留 page cache）")
}

// ---- D-17：档位解析 ----

func TestAuditFsyncConfigFromFlag(t *testing.T) {
	c, err := auditFsyncConfigFromFlag("")
	if err != nil || c.Mode != FsyncBatch {
		t.Fatalf("空值应为默认 batch: %+v err=%v", c, err)
	}
	c, err = auditFsyncConfigFromFlag("batch")
	if err != nil || c.Mode != FsyncBatch || c.Every != 1000 || c.Interval != time.Second {
		t.Fatalf("batch 档应为 1000/1s: %+v err=%v", c, err)
	}
	c, err = auditFsyncConfigFromFlag("per_event")
	if err != nil || c.Mode != FsyncPerEvent {
		t.Fatalf("per_event 档解析失败: %+v err=%v", c, err)
	}
	if _, err := auditFsyncConfigFromFlag("bogus"); err == nil {
		t.Fatal("非法档位应报错")
	}
}

// ---- D-17：/config 暴露的档位信息 ----

func TestWormFsyncInfo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.jsonl")
	c, err := newAuditChainWORMWithConfig(path, "", WormFsyncConfig{Mode: FsyncPerEvent})
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	defer c.Close()

	mode, _, interval, _, ok := c.WormFsyncInfo()
	if !ok || mode != "per_event" {
		t.Fatalf("WormFsyncInfo 异常: ok=%v mode=%s interval=%s", ok, mode, interval)
	}

	// 内存模式（无 worm）→ ok=false
	mem := newAuditChain()
	if _, _, _, _, ok := mem.WormFsyncInfo(); ok {
		t.Fatal("纯内存模式不应暴露落盘档位")
	}
}

// ---- A4-01 / A4-07：统一写盘入口，文件行序 ≡ 链序 ----

func TestUnifiedWritePathOrdering(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a.jsonl")
	c, err := newAuditChainWORM(path, "")
	if err != nil {
		t.Fatalf("构造失败: %v", err)
	}
	// 交替经两条入口写盘：append（既有 30 处落链点通道）与 appendOrFail（业务变更类）。
	for i := 0; i < 5; i++ {
		c.append(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok", RequestID: fmt.Sprintf("r-%d", i)})
	}
	for i := 0; i < 3; i++ {
		if _, err := c.appendOrFail(AuditEvent{TenantID: "t1", Action: "cfg", Result: "ok"}); err != nil {
			t.Fatalf("appendOrFail 失败: %v", err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatalf("关闭失败: %v", err)
	}

	// 文件物理行数 = 逻辑事件数（无重复写 / 无丢失）。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 8 {
		t.Fatalf("文件行数应为 8（无重复/丢失），got %d", len(lines))
	}

	// 重启恢复：load() 逐行校验 prev_hash 相接 + hashWithErr 复算——
	// 若「行序 ≠ 链序」（双句柄交错），此处必断链。
	c2, err := newAuditChainWORM(path, "")
	if err != nil {
		t.Fatalf("行序与链序不一致（load 断链）: %v", err)
	}
	defer c2.Close()
	if ok, n := c2.verify(); !ok || n != 8 {
		t.Fatalf("恢复后链完整性校验失败: ok=%v n=%d", ok, n)
	}

	// 显式断言物理行序：前 5 行为 append 的 r-0..r-4（按调用顺序落盘）。
	got := c2.query("t1")
	for i := 0; i < 5; i++ {
		if got[i].RequestID != fmt.Sprintf("r-%d", i) {
			t.Fatalf("行序错乱 @%d: 期望 r-%d，实际 %q", i, i, got[i].RequestID)
		}
	}
}
