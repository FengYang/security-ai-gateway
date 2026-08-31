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
