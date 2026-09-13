package ratelimit

import (
	"testing"
	"time"
)

// teeTable 构造 TEE 编译用例表。
func teeTable(rules ...Rule) *Table {
	t := NewTable(3, time.Unix(1_760_000_000, 0))
	t.Rules = rules
	return t
}

// TestCompileTEEQuota_budget 预算规则映射为 tee-infer max_tokens，并必须带语义 gap 说明。
func TestCompileTEEQuota_budget(t *testing.T) {
	updates, notes, err := CompileTEEQuota(teeTable(
		Rule{ID: "t-a-budget", Kind: KindBudget, Scope: ScopeTenant, Target: "t-a",
			DailyBudgetTokens: 50_000_000, Action: ActionReject, Enabled: true},
	))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(updates) != 1 || updates[0].Tenant != "t-a" || updates[0].MaxTokens != 50_000_000 {
		t.Fatalf("配额更新不符: %+v", updates)
	}
	if !notesContain(notes, "语义不完全等价") || !notesContain(notes, "无自然日重置") {
		t.Fatalf("必须如实标注语义 gap: %v", notes)
	}
}

// TestCompileTEEQuota_skips tpm/影子/非 tenant 维度/禁用一律不下发并记 Note。
func TestCompileTEEQuota_skips(t *testing.T) {
	updates, notes, err := CompileTEEQuota(teeTable(
		Rule{ID: "t-a-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-a",
			RPM: 600, TPM: 200000, Action: ActionReject, Enabled: true},
		Rule{ID: "shadow-budget", Kind: KindBudget, Scope: ScopeTenant, Target: "t-s",
			DailyBudgetTokens: 1_000, Action: ActionShadow, Enabled: true},
		Rule{ID: "model-budget", Kind: KindBudget, Scope: ScopeModel, Target: "qwen-plus",
			DailyBudgetTokens: 1_000, Action: ActionReject, Enabled: true},
		Rule{ID: "off-budget", Kind: KindBudget, Scope: ScopeTenant, Target: "t-off",
			DailyBudgetTokens: 1_000, Action: ActionReject, Enabled: false},
	))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(updates) != 0 {
		t.Fatalf("不应下发任何配额更新: %+v", updates)
	}
	for _, want := range []string{"无执行者", "action=shadow", "仅支持 tenant", "已禁用"} {
		if !notesContain(notes, want) {
			t.Fatalf("缺少 Note(%s): %v", want, notes)
		}
	}
}

// TestCompileTEEQuota_invalid 非法表不得编译。
func TestCompileTEEQuota_invalid(t *testing.T) {
	if _, _, err := CompileTEEQuota(nil); err == nil {
		t.Fatal("nil 表应报错")
	}
	bad := teeTable(Rule{ID: "bad", Kind: KindBudget, Scope: ScopeTenant, Target: "t-a",
		DailyBudgetTokens: 0, Action: ActionReject, Enabled: true})
	if _, _, err := CompileTEEQuota(bad); err == nil {
		t.Fatal("非法表应报错")
	}
}
