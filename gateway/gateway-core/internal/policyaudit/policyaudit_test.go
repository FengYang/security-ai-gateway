// policyaudit_test.go — 策略变更审计链测试（Phase 1 门禁 #7 / 判据 7）。
//
// 覆盖：固定向量一致性（与 audit-verify "core" schema 对齐）、链式追加与篡改检测、
// WORM 持久化与重启恢复（含损坏文件 fail-closed）、List 截断、字段级差异落链内容。
package policyaudit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// vecCore 与 gateway/audit-verify/verifier_test.go 的 vecCore 必须一致
// （由 PowerShell + .NET SHA256 独立算出；任一侧 hash() 变更都必须同步两处）。
const vecCore = "e6526a8b628dc5e070de7e5b0c7ed04cafa29551663bf6c8da7dc98ae00e8e67"

// fixedEvent 与 verifier_test.go 的 coreEventFixed 同字段。
func fixedEvent() Event {
	return Event{
		EventID: "pol-1", Timestamp: 1789272000000000000, Actor: "ops-admin",
		Action: "apply", VersionFrom: 3, VersionTo: 4,
		RuleID: "t-a-rate", Change: "updated", Field: "rpm",
		OldValue: "60", NewValue: "120", RequestID: "req-xyz", Result: "ok",
	}
}

// TestHashFixedVector 锁死独立验证器一致性（双实现漂移即失败）。
func TestHashFixedVector(t *testing.T) {
	ev := fixedEvent()
	if got := ev.hash(); got != vecCore {
		t.Fatalf("哈希与独立向量不符（须同步 audit-verify 的 core schema 与向量）\n got=%s\nwant=%s", got, vecCore)
	}
}

// TestChainAppendAndVerify 链式追加 + 完整性校验 + List 截断。
func TestChainAppendAndVerify(t *testing.T) {
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	ev := fixedEvent()
	ev.EventID = ""
	first, err := c.Append(ev)
	if err != nil {
		t.Fatal(err)
	}
	if first.PrevHash != "" || first.EventID == "" || first.Timestamp == 0 {
		t.Fatalf("首条事件应自动补 EventID/Timestamp 且 PrevHash 为空: %+v", first)
	}
	second, err := c.Append(ev)
	if err != nil {
		t.Fatal(err)
	}
	if second.PrevHash != first.hash() {
		t.Fatalf("次条事件 PrevHash 应指向首条哈希: %+v", second)
	}
	if ok, n := c.Verify(); !ok || n != 2 {
		t.Fatalf("链应完整（2 条）: ok=%v n=%d", ok, n)
	}
	if got := c.List(1); len(got) != 1 || got[0].EventID != second.EventID {
		t.Fatalf("List(1) 应返回最后一条: %+v", got)
	}
	if got := c.List(0); len(got) != 2 {
		t.Fatalf("List(0) 应返回全部: %d", len(got))
	}
	// 篡改中间事件 → 校验失败并给出断裂位置
	c.events[0].NewValue = "9999"
	if ok, at := c.Verify(); ok || at != 1 {
		t.Fatalf("篡改应被检出: ok=%v at=%d", ok, at)
	}
}

// TestWORMReloadAndTamperDetected WORM 持久化 + 重启恢复 + 篡改 fail-closed。
func TestWORMReloadAndTamperDetected(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy-audit.jsonl")
	c, err := New(path)
	if err != nil {
		t.Fatal(err)
	}
	ev := fixedEvent()
	if _, err := c.Append(ev); err != nil {
		t.Fatal(err)
	}
	ev.Field, ev.OldValue, ev.NewValue = "enabled", "true", "false"
	if _, err := c.Append(ev); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	re, err := New(path)
	if err != nil {
		t.Fatalf("正常文件应可恢复: %v", err)
	}
	if ok, n := re.Verify(); !ok || n != 2 {
		t.Fatalf("恢复后链应完整: ok=%v n=%d", ok, n)
	}
	_ = re.Close()

	// 篡改**第一行**（其哈希被第二行的 prev_hash 引用）→ 恢复必须失败（fail-closed）。
	// 注：尾部行篡改需锚点才能检出（与 audit-verify 的 TestTailTamperNeedsAnchor 同语义），
	// 故此处篡改被后继引用的行。
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), `"field":"rpm"`, `"field":"rpm-x"`, 1)
	if tampered == string(raw) {
		t.Fatal("篡改替换未命中（测试夹具失效）")
	}
	if err := os.WriteFile(path, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	c2, err := New(path)
	if err == nil {
		_ = c2.Close()
		t.Fatal("篡改后恢复应失败（哈希链断裂）")
	}
}

// TestEventJSONRoundTrip 落盘 JSON 字段名与审计 schema 一致（防改字段名导致验证器读不到）。
func TestEventJSONRoundTrip(t *testing.T) {
	raw, err := json.Marshal(fixedEvent())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"event_id", "timestamp", "actor", "action", "version_from",
		"version_to", "rule_id", "change", "field", "old_value", "new_value", "request_id", "result"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("落盘字段缺 %s（audit-verify core schema 依赖该字段名）", k)
		}
	}
}
