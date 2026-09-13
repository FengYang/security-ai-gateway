package ratelimit

import (
	"fmt"
	"sort"
)

// 本文件实现设计 v1.1 §2「执行点矩阵」的 TEE 侧编译：把 `tpm`、`kind=budget` 与
// `action=shadow` 规则编译为 tee-infer 的
// `POST /usage/quota {"tenant","max_tokens","window","shadow"}` 形态（S3/S3b/S5）。
//
// 窗口语义（S3b 起 tee-infer 支持，字段与常量一一对应）：
//   - `tpm`                → `window="minute"`（每分钟窗口）
//   - `daily_budget_tokens` → `window="day"`   （UTC+8 自然日窗口）
//   - 未设 window          → 累计上限（P1 既有语义，行为不变）
//
// 影子语义（S5 判据 4）：`action=shadow` 的规则以 `shadow` 下发 → tee-infer **只计数不拒绝**，
// 命中落审计 `would_reject`（密态链路 /infer、/v1/infer；明文 Provider 路由不经 TEE，
// 其 RPM 影子仍无执行器——已如实登记，见设计 §5 依赖项）。
//
// 契约要点（**每租户完整状态**）：tee-infer 侧一次下发即该租户的完整状态（缺省 shadow = 清除）。
// 故本编译**按租户合并** enforce 与 shadow，避免"两次下发互相清空"。
//
// 残余边界（实链核实，如实声明）：
//   - tee-infer 配额与窗口计数均为**内存态**：进程重启后配置与窗口计数丢失（需持久化才可跨重启）；
//   - 多副本 tee-infer 各自计数（本项目当前单实例；横向扩展需共享计数后端）；
//   - **同一租户同时存在 tpm(minute) 与预算(day) 两条 enforce 规则时**：tee-infer 当前仅支持
//     单一 enforce 窗口 → 本编译按"预算优先（财务级别）"择一下发，另一条如实记 Note（后续工作包：
//     tee-infer 支持多维度 enforce）。

// QuotaUpdate tee-infer 配额更新（字段与其 quotaRequest 对齐：tenant/max_tokens/window/shadow）。
type QuotaUpdate struct {
	Tenant    string       `json:"tenant"`
	MaxTokens int64        `json:"max_tokens"`
	Window    string       `json:"window,omitempty"` // minute | day；缺省 = 累计（P1 语义）
	Shadow    *ShadowQuota `json:"shadow,omitempty"` // 非 nil = 影子（只计数不拒绝）
}

// ShadowQuota 影子阈值（判据 4）：三个维度各自独立窗口计数（rpm/tpm=minute，daily=day）。
type ShadowQuota struct {
	RPM               int64 `json:"rpm,omitempty"`
	TPM               int64 `json:"tpm,omitempty"`
	DailyBudgetTokens int64 `json:"daily_budget_tokens,omitempty"`
}

// configured 是否配置了任何影子维度。
func (s *ShadowQuota) configured() bool {
	return s != nil && (s.RPM > 0 || s.TPM > 0 || s.DailyBudgetTokens > 0)
}

// CompileTEEQuota 编译 TEE 侧配额更新（按租户合并 enforce + shadow）；返回更新列表 + 如实 Note。
func CompileTEEQuota(t *Table) ([]QuotaUpdate, []string, error) {
	if t == nil {
		return nil, nil, fmt.Errorf("ratelimit: 限流表为空")
	}
	if err := t.Validate(); err != nil {
		return nil, nil, err
	}
	notes := make([]string, 0, len(t.Rules))
	// 按租户聚合（键 = scope=tenant 的 target）
	type tenantSpec struct {
		enforceMax    int64
		enforceWindow string
		enforceRule   string
		shadow        ShadowQuota
		shadowRules   []string
		tpmRule       string // 与预算冲突时用于 Note
	}
	specs := map[string]*tenantSpec{}
	get := func(tenant string) *tenantSpec {
		s := specs[tenant]
		if s == nil {
			s = &tenantSpec{}
			specs[tenant] = s
		}
		return s
	}

	for i := range t.Rules {
		r := &t.Rules[i]
		if !r.Enabled {
			notes = append(notes, fmt.Sprintf("规则 %s 已禁用：不下发 TEE 配额", r.ID))
			continue
		}
		if r.Scope != ScopeTenant {
			if r.Action == ActionShadow {
				notes = append(notes, fmt.Sprintf("规则 %s 为 scope=%s 的影子：tee-infer 影子仅支持 tenant 维度，不下发", r.ID, r.Scope))
				continue
			}
			if r.Kind == KindBudget || r.TPM > 0 {
				notes = append(notes, fmt.Sprintf("规则 %s 为 scope=%s：tee-infer 配额仅支持 tenant 维度，不下发", r.ID, r.Scope))
			}
			continue
		}
		s := get(r.Target)

		// 影子：只计数不拒绝（判据 4）。校验保证 shadow 规则至少有一个阈值（Validate 已拦空阈值规则）。
		if r.Action == ActionShadow {
			switch {
			case r.Kind == KindRate:
				if r.RPM > 0 {
					s.shadow.RPM = r.RPM
				}
				if r.TPM > 0 {
					s.shadow.TPM = r.TPM
				}
			default: // KindBudget
				s.shadow.DailyBudgetTokens = r.DailyBudgetTokens
			}
			s.shadowRules = append(s.shadowRules, r.ID)
			notes = append(notes, fmt.Sprintf("规则 %s 以**影子**下发（只计数不拒绝，命中落审计 would_reject）；覆盖经 tee-infer 的密态链路，明文 Provider 路由不经 TEE → 其 RPM 影子无执行器（已登记）", r.ID))
			continue
		}

		// enforce：tpm（minute）/ 预算（day）
		switch {
		case r.Kind == KindRate:
			if r.TPM <= 0 {
				continue // rpm 属数据面执行点，TEE 侧无内容
			}
			if s.enforceMax > 0 && s.enforceWindow == "day" {
				notes = append(notes, fmt.Sprintf("规则 %s 的 tpm=%d 未下发：同租户 %s 的日预算已占用唯一 enforce 窗口（tee-infer 当前仅支持单一 enforce 窗口，按预算优先；已登记后续工作包）", r.ID, r.TPM, s.enforceRule))
				continue
			}
			s.enforceMax, s.enforceWindow, s.enforceRule = r.TPM, "minute", r.ID
			s.tpmRule = r.ID
		default: // KindBudget
			if s.enforceMax > 0 && s.enforceWindow == "minute" {
				notes = append(notes, fmt.Sprintf("规则 %s 的 daily_budget_tokens=%d 以**日预算优先**覆盖同租户 tpm 配额（%s；tee-infer 当前仅支持单一 enforce 窗口，已登记后续工作包）", r.ID, r.DailyBudgetTokens, s.tpmRule))
			}
			s.enforceMax, s.enforceWindow, s.enforceRule = r.DailyBudgetTokens, "day", r.ID
		}
	}

	tenants := make([]string, 0, len(specs))
	for tenant := range specs {
		tenants = append(tenants, tenant)
	}
	sort.Strings(tenants)

	updates := make([]QuotaUpdate, 0, len(tenants))
	for _, tenant := range tenants {
		s := specs[tenant]
		u := QuotaUpdate{Tenant: tenant, MaxTokens: s.enforceMax, Window: s.enforceWindow}
		if s.shadow.configured() {
			sh := s.shadow
			u.Shadow = &sh
		}
		if u.MaxTokens <= 0 && u.Shadow == nil {
			continue // 无 enforce 也无影子：不下发（避免无意义写入）
		}
		updates = append(updates, u)
		if u.MaxTokens > 0 {
			switch u.Window {
			case "minute":
				notes = append(notes, fmt.Sprintf("规则 %s 的 tpm=%d 以**每分钟窗口**下发（window=minute）；与数据面 QPS 计数器相互独立", s.enforceRule, u.MaxTokens))
			case "day":
				notes = append(notes, fmt.Sprintf("规则 %s 的 daily_budget_tokens=%d 以**UTC+8 自然日窗口**下发（window=day）；**配额与窗口计数为内存态，进程重启丢失**（待持久化）", s.enforceRule, u.MaxTokens))
			}
		}
		if u.Shadow != nil {
			notes = append(notes, fmt.Sprintf("租户 %s 影子阈值已合并下发（规则 %v）", tenant, s.shadowRules))
		}
	}
	return updates, notes, nil
}
