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

// TestCompileTEEQuota_budgetAndTPM 预算 → day 窗口；tpm → minute 窗口（S3b 闭合两个缺口）。
func TestCompileTEEQuota_budgetAndTPM(t *testing.T) {
	updates, notes, err := CompileTEEQuota(teeTable(
		Rule{ID: "t-a-budget", Kind: KindBudget, Scope: ScopeTenant, Target: "t-a",
			DailyBudgetTokens: 50_000_000, Action: ActionReject, Enabled: true},
		Rule{ID: "t-a-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-a",
			RPM: 600, TPM: 200_000, Action: ActionReject, Enabled: true},
	))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(updates) != 2 {
		t.Fatalf("应下发 2 条（日预算 + 每分钟 tpm）: %+v", updates)
	}
	if updates[0].Tenant != "t-a" || updates[0].MaxTokens != 50_000_000 || updates[0].Window != "day" {
		t.Fatalf("日预算应映射为 window=day: %+v", updates[0])
	}
	if updates[1].MaxTokens != 200_000 || updates[1].Window != "minute" {
		t.Fatalf("tpm 应映射为 window=minute: %+v", updates[1])
	}
	if !notesContain(notes, "UTC+8 自然日窗口") || !notesContain(notes, "内存态") {
		t.Fatalf("预算须带窗口语义与内存态声明: %v", notes)
	}
	if !notesContain(notes, "每分钟窗口") {
		t.Fatalf("tpm 须说明窗口语义: %v", notes)
	}
}

// TestCompileTEEQuota_skips 非 tenant 维度 / 影子 / 禁用一律不下发并记 Note。
func TestCompileTEEQuota_skips(t *testing.T) {
	updates, notes, err := CompileTEEQuota(teeTable(
		Rule{ID: "shadow-budget", Kind: KindBudget, Scope: ScopeTenant, Target: "t-s",
			DailyBudgetTokens: 1_000, Action: ActionShadow, Enabled: true},
		Rule{ID: "model-budget", Kind: KindBudget, Scope: ScopeModel, Target: "qwen-plus",
			DailyBudgetTokens: 1_000, Action: ActionReject, Enabled: true},
		Rule{ID: "apikey-tpm", Kind: KindRate, Scope: ScopeAPIKey, Target: "consumer-1",
			TPM: 1_000, Action: ActionReject, Enabled: true},
		Rule{ID: "off-budget", Kind: KindBudget, Scope: ScopeTenant, Target: "t-off",
			DailyBudgetTokens: 1_000, Action: ActionReject, Enabled: false},
	))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(updates) != 0 {
		t.Fatalf("不应下发任何配额更新: %+v", updates)
	}
	for _, want := range []string{"action=shadow", "仅支持 tenant 维度", "仅支持 tenant 维度", "已禁用"} {
		if !notesContain(notes, want) {
			t.Fatalf("缺少 Note(%s): %v", want, notes)
		}
	}
}

// TestCompileTEEQuota_rateWithoutTPM 仅 rpm 的 rate 规则在 TEE 侧无内容（不下发、不记噪声 Note）。
func TestCompileTEEQuota_rateWithoutTPM(t *testing.T) {
	updates, notes, err := CompileTEEQuota(teeTable(
		Rule{ID: "t-a-rpm", Kind: KindRate, Scope: ScopeTenant, Target: "t-a",
			RPM: 600, Action: ActionReject, Enabled: true},
	))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(updates) != 0 || len(notes) != 0 {
		t.Fatalf("仅 rpm 时 TEE 侧应无动作: updates=%+v notes=%v", updates, notes)
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
