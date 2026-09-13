package ratelimit

import (
	"fmt"
)

// 本文件实现设计 v1.1 §2「执行点矩阵」的 TEE 侧编译：把 kind=budget 规则编译为
// tee-infer 的 `POST /usage/quota {"tenant","max_tokens"}` 兼容形态（S3）。
//
// 诚实边界（实链核实，2026-09-13）：
//   - tee-infer 现有配额是 **per-tenant 累计上限**（`s.quota[tenant]=max_tokens`），
//     全仓**无任何"自然日/分钟窗口"重置逻辑**，且为内存态（重启丢失）；
//   - 因此 `daily_budget_tokens` 只能**近似**映射为 max_tokens（语义 gap 已登记）；
//   - `tpm`（每分钟 token）在 tee-infer **无执行者** → 不下发并如实记录（需新增窗口能力）。

// QuotaUpdate tee-infer 配额更新（字段与其 quotaRequest 一字不差）。
type QuotaUpdate struct {
	Tenant    string `json:"tenant"`
	MaxTokens int64  `json:"max_tokens"`
}

// CompileTEEQuota 编译 TEE 侧配额更新；返回更新列表 + 如实 Note。
//
// 仅处理 kind=budget、scope=tenant、action=reject、enabled 的规则；
// 其余情形一律不下发并记录 Note（避免"看着配了其实不生效"）。
func CompileTEEQuota(t *Table) ([]QuotaUpdate, []string, error) {
	if t == nil {
		return nil, nil, fmt.Errorf("ratelimit: 限流表为空")
	}
	if err := t.Validate(); err != nil {
		return nil, nil, err
	}
	notes := make([]string, 0, len(t.Rules))
	updates := make([]QuotaUpdate, 0, len(t.Rules))

	for i := range t.Rules {
		r := &t.Rules[i]
		switch {
		case !r.Enabled:
			notes = append(notes, fmt.Sprintf("规则 %s 已禁用：不下发 TEE 配额", r.ID))
		case r.Kind == KindRate:
			if r.TPM > 0 {
				notes = append(notes, fmt.Sprintf("规则 %s 的 tpm=%d 在 tee-infer **无执行者**（现有配额无分钟窗口）：不下发；需 tee-infer 新增窗口能力（独立工作包）", r.ID, r.TPM))
			}
			// rpm 属数据面执行点，此处无需动作
		case r.Action == ActionShadow:
			notes = append(notes, fmt.Sprintf("规则 %s 为 action=shadow：tee-infer 无影子配额能力，不下发（避免误拦）", r.ID))
		case r.Scope != ScopeTenant:
			notes = append(notes, fmt.Sprintf("规则 %s 为 scope=%s：tee-infer 配额仅支持 tenant 维度，不下发", r.ID, r.Scope))
		default:
			updates = append(updates, QuotaUpdate{Tenant: r.Target, MaxTokens: r.DailyBudgetTokens})
			notes = append(notes, fmt.Sprintf("规则 %s 的 daily_budget_tokens=%d 映射为 tee-infer max_tokens：**语义不完全等价**（tee-infer 为累计上限、无自然日重置、内存态重启丢失）——gap 已登记",
				r.ID, r.DailyBudgetTokens))
		}
	}
	return updates, notes, nil
}
