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
// B 项起同租户两维度**同时下发**（不再"择一"），并按 minute < day 规范化顺序（与规则书写顺序解耦）。
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
	if len(updates) != 1 {
		t.Fatalf("同租户应合并为 1 条更新: %+v", updates)
	}
	u := updates[0]
	if u.Tenant != "t-a" || len(u.Limits) != 2 ||
		u.Limits[0] != (QuotaLimit{Window: "minute", MaxTokens: 200_000}) ||
		u.Limits[1] != (QuotaLimit{Window: "day", MaxTokens: 50_000_000}) {
		t.Fatalf("两维度应同时下发且按 minute<day 规范化: %+v", u)
	}
	if !notesContain(notes, "UTC+8 自然日窗口") || !notesContain(notes, "内存态") {
		t.Fatalf("预算须带窗口语义与内存态声明: %v", notes)
	}
	if !notesContain(notes, "多维 enforce") {
		t.Fatalf("多维下发须记 Note: %v", notes)
	}
	if notesContain(notes, "预算优先") || notesContain(notes, "未下发") {
		t.Fatalf("B 项后不应再有择一/未下发 Note: %v", notes)
	}

	// 仅 tpm（无预算）→ minute 窗口
	updates, notes, err = CompileTEEQuota(teeTable(
		Rule{ID: "t-b-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-b",
			RPM: 600, TPM: 200_000, Action: ActionReject, Enabled: true},
	))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(updates) != 1 || len(updates[0].Limits) != 1 ||
		updates[0].Limits[0] != (QuotaLimit{Window: "minute", MaxTokens: 200_000}) {
		t.Fatalf("tpm 应映射为 window=minute: %+v", updates)
	}
	if !notesContain(notes, "每分钟窗口") {
		t.Fatalf("tpm 须说明窗口语义: %v", notes)
	}
}

// TestCompileTEEQuota_shadow 影子规则（判据 4）：按租户合并下发 shadow（只计数不拒绝），
// 并与同租户 enforce 合并为一条更新（避免"两次下发互相清空"）。
func TestCompileTEEQuota_shadow(t *testing.T) {
	// 仅影子（rate：rpm+tpm；budget：日预算）→ 合并为一条 shadow
	updates, notes, err := CompileTEEQuota(teeTable(
		Rule{ID: "t-s-rate-shadow", Kind: KindRate, Scope: ScopeTenant, Target: "t-s",
			RPM: 600, TPM: 1_000, Action: ActionShadow, Enabled: true},
		Rule{ID: "t-s-budget-shadow", Kind: KindBudget, Scope: ScopeTenant, Target: "t-s",
			DailyBudgetTokens: 9_000, Action: ActionShadow, Enabled: true},
	))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(updates) != 1 || updates[0].Tenant != "t-s" || len(updates[0].Limits) != 0 || updates[0].Shadow == nil {
		t.Fatalf("影子应合并为一条（无 enforce）: %+v", updates)
	}
	sh := updates[0].Shadow
	if sh.RPM != 600 || sh.TPM != 1_000 || sh.DailyBudgetTokens != 9_000 {
		t.Fatalf("影子三维度应合并: %+v", sh)
	}
	if !notesContain(notes, "影子") || !notesContain(notes, "would_reject") {
		t.Fatalf("影子须说明语义: %v", notes)
	}

	// 同租户 enforce + shadow → 一条更新同时携带（契约＝每租户完整状态）
	updates, _, err = CompileTEEQuota(teeTable(
		Rule{ID: "t-c-budget", Kind: KindBudget, Scope: ScopeTenant, Target: "t-c",
			DailyBudgetTokens: 5_000, Action: ActionReject, Enabled: true},
		Rule{ID: "t-c-shadow", Kind: KindRate, Scope: ScopeTenant, Target: "t-c",
			RPM: 60, Action: ActionShadow, Enabled: true},
	))
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(updates) != 1 || len(updates[0].Limits) != 1 ||
		updates[0].Limits[0] != (QuotaLimit{Window: "day", MaxTokens: 5_000}) ||
		updates[0].Shadow == nil || updates[0].Shadow.RPM != 60 {
		t.Fatalf("enforce 与 shadow 应合并到一条更新: %+v", updates)
	}
}

// TestCompileTEEQuota_skips 非 tenant 维度 / 禁用不下发并记 Note（影子例外：按租户下发）。
func TestCompileTEEQuota_skips(t *testing.T) {
	updates, notes, err := CompileTEEQuota(teeTable(
		Rule{ID: "shadow-model", Kind: KindBudget, Scope: ScopeModel, Target: "qwen-plus",
			DailyBudgetTokens: 1_000, Action: ActionShadow, Enabled: true},
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
	for _, want := range []string{"影子仅支持 tenant 维度", "仅支持 tenant 维度", "已禁用"} {
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
