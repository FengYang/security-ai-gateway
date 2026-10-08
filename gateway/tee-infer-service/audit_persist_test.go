package main

// C-5 WORM 审计持久化测试：文件追加、启动恢复、篡改检测、锚定。

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testEvent(tenant string) AuditEvent {
	return AuditEvent{TenantID: tenant, RequestID: "req-x", Action: "infer", Result: "ok"}
}

func TestAuditWORMAppendAndRecover(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "audit.jsonl")
	anchor := filepath.Join(dir, "anchor.jsonl")

	c, err := newAuditChainWORM(events, anchor)
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	for i := 0; i < 3; i++ {
		c.append(testEvent("t1"))
	}
	rec := c.anchorNow()
	if rec == nil || rec.Events != 3 || rec.ChainHash == "" {
		t.Fatalf("锚定记录异常: %+v", rec)
	}
	c.Close()

	// 文件行数 = 3 事件 + 1 锚定
	raw, _ := os.ReadFile(events)
	if n := len(strings.Split(strings.TrimSpace(string(raw)), "\n")); n != 3 {
		t.Fatalf("事件文件行数 %d != 3", n)
	}

	// 重启恢复：新链从文件加载，verify 通过且事件数一致
	c2, err := newAuditChainWORM(events, anchor)
	if err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	defer c2.Close()
	if c2.len() != 3 {
		t.Fatalf("恢复事件数 %d != 3", c2.len())
	}
	if ok, _ := c2.verify(); !ok {
		t.Fatal("恢复链 verify 失败")
	}
	if c2.lastHex != rec.ChainHash {
		t.Fatalf("恢复链尾哈希 != 锚定哈希: %s vs %s", c2.lastHex, rec.ChainHash)
	}
}

func TestAuditWORMTamperDetected(t *testing.T) {
	dir := t.TempDir()
	events := filepath.Join(dir, "audit.jsonl")

	c, err := newAuditChainWORM(events, "")
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	for i := 0; i < 3; i++ {
		c.append(testEvent("t1"))
	}
	c.Close()

	// 篡改第二行（把 result 改掉），恢复应检测到哈希链断裂
	lines, _ := os.ReadFile(events)
	parts := strings.Split(strings.TrimSpace(string(lines)), "\n")
	parts[1] = strings.Replace(parts[1], `"result":"ok"`, `"result":"tampered"`, 1)
	_ = os.WriteFile(events, []byte(strings.Join(parts, "\n")+"\n"), 0o600)

	if _, err := newAuditChainWORM(events, ""); err == nil {
		t.Fatal("篡改后恢复应失败（哈希链断裂）")
	}
}

// TestAuditFilteredTokensEvidenceField：OG-7 filtered_tokens 为证据字段——
// 不进 hash()（旧链在新代码下可复算）、零值 omitempty 不落盘（等同旧版本行）、
// 携带该字段的新行经 WORM 恢复后值可读回且全链 verify 通过。
func TestAuditFilteredTokensEvidenceField(t *testing.T) {
	// 1) 不进 hash：仅 FilteredTokens 不同的两个事件哈希必须相等。
	base := testEvent("t1")
	withTokens := base
	withTokens.FilteredTokens = 42
	if base.hash() != withTokens.hash() {
		t.Fatal("filtered_tokens 为证据字段，不得进入 hash()")
	}

	dir := t.TempDir()
	events := filepath.Join(dir, "audit.jsonl")

	// 2) 旧版本行：零值 omitempty，落盘 JSON 不含 filtered_tokens 键。
	c, err := newAuditChainWORM(events, "")
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	c.append(base)
	oldTail := c.lastHex
	c.Close()

	raw, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "filtered_tokens") {
		t.Fatalf("零值证据字段不应落盘（omitempty）：%s", raw)
	}

	// 3) 重启恢复旧链（链尾哈希一致）后追加携带 filtered_tokens 的新行（prev_hash 自动衔接）。
	c2, err := newAuditChainWORM(events, "")
	if err != nil {
		t.Fatalf("旧链恢复失败: %v", err)
	}
	if c2.lastHex != oldTail {
		t.Fatalf("旧链尾哈希应一致：got %s want %s", c2.lastHex, oldTail)
	}
	c2.append(withTokens)
	c2.Close()

	// 4) 再次重启：两行全部恢复、链可复算、新字段值读回 42。
	c3, err := newAuditChainWORM(events, "")
	if err != nil {
		t.Fatalf("含 filtered_tokens 新链恢复失败: %v", err)
	}
	defer c3.Close()
	if ok, n := c3.verify(); !ok || n != 2 {
		t.Fatalf("混合新旧行的审计链应可复算：ok=%v n=%d", ok, n)
	}
	got := c3.query("t1")
	if len(got) != 2 || got[0].FilteredTokens != 0 || got[1].FilteredTokens != 42 {
		t.Fatalf("字段读回异常：%+v", got)
	}
}

// TestAuditTraceIDEvidenceField：P1-2 trace_id 为证据字段（D-5）——
// 不进 hash()（旧链在新代码下可复算）、零值 omitempty 不落盘（等同旧版本行）、
// 携带该字段的新行经 WORM 恢复后值可读回且全链 verify 通过。
func TestAuditTraceIDEvidenceField(t *testing.T) {
	// 1) 不进 hash：仅 TraceID 不同的两个事件哈希必须相等。
	base := testEvent("t1")
	withTrace := base
	withTrace.TraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	if base.hash() != withTrace.hash() {
		t.Fatal("trace_id 为证据字段，不得进入 hash()")
	}

	dir := t.TempDir()
	events := filepath.Join(dir, "audit.jsonl")

	// 2) 旧版本行：零值 omitempty，落盘 JSON 不含 trace_id 键。
	c, err := newAuditChainWORM(events, "")
	if err != nil {
		t.Fatalf("初始化失败: %v", err)
	}
	c.append(base)
	oldTail := c.lastHex
	c.Close()

	raw, err := os.ReadFile(events)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "trace_id") {
		t.Fatalf("零值证据字段不应落盘（omitempty）：%s", raw)
	}

	// 3) 重启恢复旧链（链尾哈希一致）后追加携带 trace_id 的新行。
	c2, err := newAuditChainWORM(events, "")
	if err != nil {
		t.Fatalf("旧链恢复失败: %v", err)
	}
	if c2.lastHex != oldTail {
		t.Fatalf("旧链尾哈希应一致：got %s want %s", c2.lastHex, oldTail)
	}
	c2.append(withTrace)
	c2.Close()

	// 4) 再次重启：两行全部恢复、链可复算、trace_id 值读回。
	c3, err := newAuditChainWORM(events, "")
	if err != nil {
		t.Fatalf("含 trace_id 新链恢复失败: %v", err)
	}
	defer c3.Close()
	if ok, n := c3.verify(); !ok || n != 2 {
		t.Fatalf("混合新旧行的审计链应可复算：ok=%v n=%d", ok, n)
	}
	got := c3.query("t1")
	if len(got) != 2 || got[0].TraceID != "" ||
		got[1].TraceID != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("字段读回异常：%+v", got)
	}
}
