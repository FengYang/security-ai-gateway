package main

// T5 审计 fail-closed 单元测试（GAP-09，方案甲）。
//
// 覆盖场景：
//   - append 签名不变（回归验证：既有 append 行为零变化）
//   - appendOrFail 正常路径（写入成功 → 落链 + 无 error）
//   - appendOrFail + fail-closed（写失败 → 返回 error + 不落链 + M-7/M-8 触发）
//   - appendOrFail + fail-open（写失败 → 仅告警 + 落内存链 + M-7 fail_open）
//   - 纯内存模式（worm=nil）：appendOrFail 始终成功
//   - SetFailClosed 动态切换（先 fail-open 再 fail-closed）
//   - WormBackend：fileWorm 写文件 + 恢复
//   - 哈希链完整性：appendOrFail 写成功时链 hash 正确
//   - M-7/M-8 回调计数（验证唯一生产点）

import (
	"os"
	"path/filepath"
	"testing"
)

// ---- appendOrFail 正常路径 ----

func TestAppendOrFailHappyPath(t *testing.T) {
	chain := newAuditChain()
	worm := newMemoryWorm()
	chain.SetWormBackend(worm)
	chain.SetFailClosed(true)

	e := AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"}
	got, err := chain.appendOrFail(e)
	if err != nil {
		t.Fatalf("正常写入应无 error: %v", err)
	}
	if got.TenantID != "t1" {
		t.Fatalf("返回事件不对: %+v", got)
	}
	if chain.len() != 1 {
		t.Fatalf("链长度应为 1，got %d", chain.len())
	}
	if worm.Len() != 1 {
		t.Fatalf("worm 写入数应为 1，got %d", worm.Len())
	}
	// 链完整性校验
	ok, n := chain.verify()
	if !ok || n != 1 {
		t.Fatalf("链完整性校验失败: ok=%v n=%d", ok, n)
	}
}

// ---- appendOrFail + fail-closed 写失败 ----

func TestAppendOrFailClosedWriteFail(t *testing.T) {
	chain := newAuditChain()
	worm := newMemoryWorm()
	chain.SetWormBackend(worm)
	chain.SetFailClosed(true)

	var wormFailCount int
	var rejectCount int
	chain.SetWormWriteFailHook(func(policy string) {
		if policy != "fail_closed" {
			t.Fatalf("policy 应为 fail_closed，got %s", policy)
		}
		wormFailCount++
	})
	chain.SetFailClosedRejectHook(func() { rejectCount++ })

	// 先写一条成功的
	e1 := AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"}
	_, err := chain.appendOrFail(e1)
	if err != nil {
		t.Fatalf("第一条应成功: %v", err)
	}

	// 模拟写失败
	worm.SetFail(true)
	e2 := AuditEvent{TenantID: "t1", Action: "infer", Result: "deny"}
	_, err = chain.appendOrFail(e2)
	if err == nil {
		t.Fatal("fail-closed 下写失败应返回 error")
	}
	if chain.len() != 1 {
		t.Fatalf("写失败不应落链，链长度应为 1，got %d", chain.len())
	}
	if wormFailCount != 1 {
		t.Fatalf("M-7 应触发 1 次，got %d", wormFailCount)
	}
	if rejectCount != 1 {
		t.Fatalf("M-8 应触发 1 次，got %d", rejectCount)
	}
	// 链完整性（只有一条，应完整）
	ok, n := chain.verify()
	if !ok || n != 1 {
		t.Fatalf("链完整性校验失败: ok=%v n=%d", ok, n)
	}
}

// ---- appendOrFail + fail-open 写失败 ----

func TestAppendOrFailOpenWriteFail(t *testing.T) {
	chain := newAuditChain()
	worm := newMemoryWorm()
	chain.SetWormBackend(worm)
	chain.SetFailClosed(false) // fail-open

	var wormFailCount int
	var rejectCount int
	var lastPolicy string
	chain.SetWormWriteFailHook(func(policy string) {
		lastPolicy = policy
		wormFailCount++
	})
	chain.SetFailClosedRejectHook(func() { rejectCount++ })

	// 模拟写失败
	worm.SetFail(true)
	e := AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"}
	got, err := chain.appendOrFail(e)
	if err != nil {
		t.Fatalf("fail-open 下写失败不应返回 error: %v", err)
	}
	if chain.len() != 1 {
		t.Fatalf("fail-open 下仍应落内存链，长度应为 1，got %d", chain.len())
	}
	if wormFailCount != 1 {
		t.Fatalf("M-7 应触发 1 次，got %d", wormFailCount)
	}
	if lastPolicy != "fail_open" {
		t.Fatalf("policy 应为 fail_open，got %s", lastPolicy)
	}
	if rejectCount != 0 {
		t.Fatalf("M-8 不应触发（fail-open），got %d", rejectCount)
	}
	_ = got
}

// ---- 纯内存模式（worm=nil） ----

func TestAppendOrFailMemoryMode(t *testing.T) {
	chain := newAuditChain()
	// 不 SetWormBackend，worm=nil
	chain.SetFailClosed(true) // 即使 fail-closed，纯内存也不会失败

	var rejectCount int
	chain.SetFailClosedRejectHook(func() { rejectCount++ })

	e := AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"}
	_, err := chain.appendOrFail(e)
	if err != nil {
		t.Fatalf("纯内存模式应始终成功: %v", err)
	}
	if chain.len() != 1 {
		t.Fatalf("链长度应为 1，got %d", chain.len())
	}
	if rejectCount != 0 {
		t.Fatalf("M-8 不应触发，got %d", rejectCount)
	}
}

// ---- SetFailClosed 动态切换 ----

func TestSetFailClosedDynamic(t *testing.T) {
	chain := newAuditChain()
	worm := newMemoryWorm()
	chain.SetWormBackend(worm)

	// 初始：fail-open（默认 false）
	if chain.FailClosed() {
		t.Fatal("初始应为 fail-open")
	}

	worm.SetFail(true)

	// fail-open 模式：写失败不拒
	e1 := AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"}
	_, err := chain.appendOrFail(e1)
	if err != nil {
		t.Fatalf("fail-open 下不应拒: %v", err)
	}
	if chain.len() != 1 {
		t.Fatalf("fail-open 应落内存链: %d", chain.len())
	}

	// 切换到 fail-closed
	chain.SetFailClosed(true)
	if !chain.FailClosed() {
		t.Fatal("切换后应为 fail-closed")
	}

	// fail-closed 模式：写失败即拒
	e2 := AuditEvent{TenantID: "t1", Action: "infer", Result: "deny"}
	_, err = chain.appendOrFail(e2)
	if err == nil {
		t.Fatal("fail-closed 下应拒")
	}
	if chain.len() != 1 {
		t.Fatalf("链长度应仍为 1，got %d", chain.len())
	}
}

// ---- append 签名不变（回归验证） ----

func TestAppendSignatureUnchanged(t *testing.T) {
	// 验证 append 行为与之前一致：调用签名不变、落链正常
	chain := newAuditChain()
	worm := newMemoryWorm()
	chain.SetWormBackend(worm)
	chain.SetFailClosed(true) // 即使 fail-closed，append 也不返回 error

	e := AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"}
	// append 签名：func (c *auditChain) append(e AuditEvent) AuditEvent
	got := chain.append(e) // 不返回 error
	if got.TenantID != "t1" {
		t.Fatalf("append 返回事件不对: %+v", got)
	}
	if chain.len() != 1 {
		t.Fatalf("链长度应为 1，got %d", chain.len())
	}

	// append 在写失败时也不返回 error（旧行为保持）
	worm.SetFail(true)
	e2 := AuditEvent{TenantID: "t1", Action: "infer", Result: "deny"}
	got2 := chain.append(e2) // 仍只返回 AuditEvent
	if got2.Result != "deny" {
		t.Fatalf("append 写失败时仍返回事件: %+v", got2)
	}
	if chain.len() != 2 {
		t.Fatalf("append 写失败时仍落内存链（旧行为），长度应为 2，got %d", chain.len())
	}
}

// ---- fileWorm 测试 ----

func TestFileWormAppendAndClose(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	w, err := newFileWorm(path)
	if err != nil {
		t.Fatalf("创建 fileWorm 失败: %v", err)
	}
	defer w.Close()

	if w.Name() != "file:"+path {
		t.Fatalf("Name 不对: %s", w.Name())
	}

	e := AuditEvent{EventID: "evt-1", TenantID: "t1", Action: "infer", Result: "ok"}
	if err := w.Append(e); err != nil {
		t.Fatalf("Append 失败: %v", err)
	}

	// 验证文件存在且非空
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("文件不存在: %v", err)
	}
	if info.Size() == 0 {
		t.Fatal("文件为空")
	}
}

func TestFileWormEmptyPath(t *testing.T) {
	_, err := newFileWorm("")
	if err == nil {
		t.Fatal("空路径应报错")
	}
}

// ---- 链 hash 一致性（appendOrFail 写成功时与 append 等价） ----

func TestAppendOrFailHashConsistency(t *testing.T) {
	chain1 := newAuditChain()
	chain2 := newAuditChain()
	worm1 := newMemoryWorm()
	worm2 := newMemoryWorm()
	chain1.SetWormBackend(worm1)
	chain2.SetWormBackend(worm2)

	// 用 append 写 3 条
	for i := 0; i < 3; i++ {
		chain1.append(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"})
	}
	// 用 appendOrFail 写 3 条
	for i := 0; i < 3; i++ {
		_, err := chain2.appendOrFail(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"})
		if err != nil {
			t.Fatalf("appendOrFail 失败: %v", err)
		}
	}

	// 长度应一致
	if chain1.len() != chain2.len() {
		t.Fatalf("链长度不一致: %d vs %d", chain1.len(), chain2.len())
	}
	// 注意：因为 Timestamp 不同，hash 必然不同；这里只验证链完整性
	ok1, n1 := chain1.verify()
	ok2, n2 := chain2.verify()
	if !ok1 || !ok2 {
		t.Fatalf("链完整性: ok1=%v ok2=%v", ok1, ok2)
	}
	if n1 != 3 || n2 != 3 {
		t.Fatalf("链长度: n1=%d n2=%d", n1, n2)
	}
}

// ---- M-7/M-8 回调仅由 appendOrFail 触发（唯一性验证） ----

func TestM7M8OnlyInAppendOrFail(t *testing.T) {
	chain := newAuditChain()
	worm := newMemoryWorm()
	chain.SetWormBackend(worm)

	var m7count, m8count int
	chain.SetWormWriteFailHook(func(string) { m7count++ })
	chain.SetFailClosedRejectHook(func() { m8count++ })

	// append 写失败：不应触发 M-7/M-8（M-7 唯一生产点是 appendOrFail）
	worm.SetFail(true)
	chain.append(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"})
	if m7count != 0 {
		t.Fatalf("append 写失败不应触发 M-7，got %d", m7count)
	}
	if m8count != 0 {
		t.Fatalf("append 写失败不应触发 M-8，got %d", m8count)
	}

	// appendOrFail 写失败 + fail-closed：M-7 +1, M-8 +1
	chain.SetFailClosed(true)
	chain.appendOrFail(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"})
	if m7count != 1 {
		t.Fatalf("M-7 应为 1，got %d", m7count)
	}
	if m8count != 1 {
		t.Fatalf("M-8 应为 1，got %d", m8count)
	}
}
