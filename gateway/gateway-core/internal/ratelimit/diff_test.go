// diff_test.go — 策略表逐规则差异测试（门禁 #7 / 判据 7 变更留痕的输入）。
package ratelimit

import (
	"testing"
	"time"
)

// diffTable 构造测试表。
func diffTable(version int, rules ...Rule) *Table {
	t := NewTable(version, time.Unix(1_760_000_000, 0))
	t.Rules = rules
	return t
}

func rule(id string, rpm int64, action Action) Rule {
	return Rule{ID: id, Kind: KindRate, Scope: ScopeTenant, Target: "t-a",
		RPM: rpm, Action: action, Enabled: true}
}

// TestDiffRules_firstApply 首次下发（old=nil）→ 全部 added，且新值为整条摘要。
func TestDiffRules_firstApply(t *testing.T) {
	next := diffTable(2, rule("t-a-rate", 600, ActionReject))
	got := DiffRules(nil, next)
	if len(got) != 1 || got[0].Change != "added" || got[0].RuleID != "t-a-rate" {
		t.Fatalf("首次下发应为 added: %+v", got)
	}
	if got[0].Old != "" || got[0].New == "" {
		t.Fatalf("added 应记录新值摘要、旧值为空: %+v", got[0])
	}
	if ChangeSummary(got) == "无规则变化" {
		t.Fatalf("摘要不应为空: %s", ChangeSummary(got))
	}
}

// TestDiffRules_updatedAndRemoved 字段级变更 + 规则删除，且输出稳定排序。
func TestDiffRules_updatedAndRemoved(t *testing.T) {
	old := diffTable(2, rule("t-a-rate", 600, ActionReject), rule("t-b-rate", 60, ActionReject))
	next := diffTable(3, rule("t-a-rate", 1200, ActionShadow))
	got := DiffRules(old, next)
	// t-a-rate：rpm 600→1200、action reject→shadow；t-b-rate：removed
	if len(got) != 3 {
		t.Fatalf("应产出 3 条差异: %+v", got)
	}
	if got[0].RuleID != "t-a-rate" || got[0].Change != "updated" || got[0].Field != "rpm" ||
		got[0].Old != "600" || got[0].New != "1200" {
		t.Fatalf("rpm 变更记录不符: %+v", got[0])
	}
	if got[1].Field != "action" || got[1].Old != "reject" || got[1].New != "shadow" {
		t.Fatalf("action 变更记录不符: %+v", got[1])
	}
	if got[2].RuleID != "t-b-rate" || got[2].Change != "removed" || got[2].Old == "" || got[2].New != "" {
		t.Fatalf("removed 记录不符: %+v", got[2])
	}
	// 相同表 → 无差异
	if d := DiffRules(next, diffTable(4, rule("t-a-rate", 1200, ActionShadow))); len(d) != 0 {
		t.Fatalf("相同内容不应有差异: %+v", d)
	}
}

// TestCanonicalBytesFixture 锁定"控制面规范字节"契约（判据 5：插件侧 ratelimitcache
// 复刻同一编码；任一侧字段/顺序/标签变更都必须同步，否则插件侧会**静默拒收**拉取结果）。
func TestCanonicalBytesFixture(t *testing.T) {
	tbl := diffTable(2, Rule{ID: "t-a-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-a",
		RPM: 600, Action: ActionReject, Enabled: true})
	tbl.IssuedAt = "2026-09-13T10:00:00Z"
	got, err := tbl.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := `{"version":2,"issued_at":"2026-09-13T10:00:00Z","rules":[{"id":"t-a-rate","kind":"rate","scope":"tenant","target":"t-a","rpm":600,"action":"reject","enabled":true}]}`
	if string(got) != want {
		t.Fatalf("规范字节与固定夹具不符（插件侧 ratelimitcache 依赖该编码）\n got=%s\nwant=%s", got, want)
	}
}

// TestTableClone 克隆不带签名且规则独立（回滚以历史版本构造新版本时不污染历史对象）。
func TestTableClone(t *testing.T) {
	src := diffTable(5, rule("t-a-rate", 600, ActionReject))
	src.Signature = []byte("sig")
	cp := src.Clone()
	if cp.Signature != nil {
		t.Fatalf("克隆不应带签名（须重新签发）: %v", cp.Signature)
	}
	cp.Rules[0].RPM = 9999
	if src.Rules[0].RPM != 600 {
		t.Fatalf("克隆应深拷贝规则: %+v", src.Rules[0])
	}
	if cp.Version != 5 {
		t.Fatalf("克隆应保留版本: %d", cp.Version)
	}
}
