package ratelimit

import (
	"fmt"
)

// 本文件实现设计 v1.1 §2「执行点矩阵」的 TEE 侧编译：把 `tpm` 与 `kind=budget`
// 编译为 tee-infer 的 `POST /usage/quota {"tenant","max_tokens","window"}` 兼容形态（S3/S3b）。
//
// 窗口语义（S3b 起 tee-infer 支持，字段与常量一一对应）：
//   - `tpm`                → `window="minute"`（每分钟窗口）
//   - `daily_budget_tokens` → `window="day"`   （UTC+8 自然日窗口）
//   - 未设 window          → 累计上限（P1 既有语义，行为不变）
//
// 残余边界（实链核实，如实声明）：
//   - tee-infer 配额与窗口计数均为**内存态**：进程重启后配置与窗口计数丢失（需持久化才可跨重启）；
//   - 多副本 tee-infer 各自计数（本项目当前单实例；横向扩展需共享计数后端）。

// QuotaUpdate tee-infer 配额更新（字段与其 quotaRequest 对齐：tenant/max_tokens/window）。
type QuotaUpdate struct {
	Tenant    string `json:"tenant"`
	MaxTokens int64  `json:"max_tokens"`
	Window    string `json:"window,omitempty"` // minute | day；缺省 = 累计（P1 语义）
}

// CompileTEEQuota 编译 TEE 侧配额更新；返回更新列表 + 如实 Note。
//
// 处理：kind=rate 且 tpm>0 → minute 窗口；kind=budget → day 窗口（仅 tenant 维度）。
// 其余（非 tenant 维度 / 影子 / 禁用 / 无 tpm 的 rate）不下发并记录 Note。
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
		case r.Action == ActionShadow:
			notes = append(notes, fmt.Sprintf("规则 %s 为 action=shadow：tee-infer 无影子配额能力，不下发（避免误拦）", r.ID))
		case r.Kind == KindRate:
			if r.TPM <= 0 {
				// rpm 属数据面执行点，TEE 侧无内容
				continue
			}
			if r.Scope != ScopeTenant {
				notes = append(notes, fmt.Sprintf("规则 %s 的 tpm：tee-infer 配额仅支持 tenant 维度（scope=%s），不下发", r.ID, r.Scope))
				continue
			}
			updates = append(updates, QuotaUpdate{Tenant: r.Target, MaxTokens: r.TPM, Window: "minute"})
			notes = append(notes, fmt.Sprintf("规则 %s 的 tpm=%d 以**每分钟窗口**下发（window=minute）；与数据面 QPS 计数器相互独立", r.ID, r.TPM))
		default: // KindBudget
			if r.Scope != ScopeTenant {
				notes = append(notes, fmt.Sprintf("规则 %s 为 scope=%s：tee-infer 配额仅支持 tenant 维度，不下发", r.ID, r.Scope))
				continue
			}
			updates = append(updates, QuotaUpdate{Tenant: r.Target, MaxTokens: r.DailyBudgetTokens, Window: "day"})
			notes = append(notes, fmt.Sprintf("规则 %s 的 daily_budget_tokens=%d 以**UTC+8 自然日窗口**下发（window=day）；**配额与窗口计数为内存态，进程重启丢失**（待持久化）", r.ID, r.DailyBudgetTokens))
		}
	}
	return updates, notes, nil
}
