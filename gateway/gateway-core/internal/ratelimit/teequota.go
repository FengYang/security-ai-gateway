package ratelimit

import (
	"fmt"
	"sort"
)

// 本文件实现设计 v1.1 §2「执行点矩阵」的 TEE 侧编译：把 `tpm`、`kind=budget` 与
// `action=shadow` 规则编译为 tee-infer 的
// `POST /usage/quota {"tenant","limits":[{"window","max_tokens"}],"shadow"}` 形态（S3/S3b/S5；B 项多维）。
//
// 窗口语义（S3b 起 tee-infer 支持，字段与常量一一对应）：
//   - `tpm`                → `{"window":"minute","max_tokens":<tpm>}`（每分钟窗口）
//   - `daily_budget_tokens` → `{"window":"day","max_tokens":<budget>}`（UTC+8 自然日窗口）
//
// B 项（多维 enforce）：同一租户的 tpm 与日预算**各占一条 limit，可同时生效**（任一维度超限即 429）；
// 改造前为"单一 enforce 窗口、预算优先、另一条记 Note"（该限制已解除）。
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
//   - **版本耦合**：本编译只发 `limits[]`（B 项契约）→ 控制面与 tee-infer 须**同版本升级**
//     （旧 tee-infer 不识别 `limits` 会把该次下发视为"清除配额"，见 QuotaUpdate 注释）。

// QuotaLimit 单维度 enforce 上限（B 项：多维度）：window="" 累计 | "minute" 每分钟 | "day" UTC+8 自然日。
type QuotaLimit struct {
	Window    string `json:"window,omitempty"`
	MaxTokens int64  `json:"max_tokens"`
}

// QuotaUpdate tee-infer 配额更新（字段与其 quotaRequest 对齐：tenant/limits/shadow）。
//
// B 项起**只发 limits[]**（tee-infer 侧的扁平 max_tokens/window 为 S3b 兼容写法，控制面不再使用）：
// 与 tee-infer "两写法互斥（同现 400）"契约一致，且同一租户可同时承载 tpm(minute) 与预算(day)。
//
// **版本耦合（如实，部署注意）**：控制面与 tee-infer 须同版本升级——旧 tee-infer 不识别 `limits`
// 会把该次下发视为"清除配额"（其 quotaRequest 解析后 MaxTokens=0）。
type QuotaUpdate struct {
	Tenant string       `json:"tenant"`
	Limits []QuotaLimit `json:"limits"`
	Shadow *ShadowQuota `json:"shadow,omitempty"` // 非 nil = 影子（只计数不拒绝）
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

// windowRank 维度规范化顺序（累计 < minute < day）：使下发顺序与 tee-infer 的主维度视图
// 不随规则在表中的书写顺序漂移（同一租户同一策略集 → 同一 limits 顺序，便于断言与排障）。
func windowRank(window string) int {
	switch window {
	case "minute":
		return 1
	case "day":
		return 2
	default: // ""（累计）
		return 0
	}
}

// CompileTEEQuota 编译 TEE 侧配额更新（按租户合并**多维** enforce + shadow）；返回更新列表 + 如实 Note。
func CompileTEEQuota(t *Table) ([]QuotaUpdate, []string, error) {
	if t == nil {
		return nil, nil, fmt.Errorf("ratelimit: 限流表为空")
	}
	if err := t.Validate(); err != nil {
		return nil, nil, err
	}
	notes := make([]string, 0, len(t.Rules))
	// 单维度 + 其来源规则（Note 用）。
	type quotaLimitRule struct {
		limit QuotaLimit
		rule  string
	}
	// 按租户聚合（键 = scope=tenant 的 target）
	type tenantSpec struct {
		limits      []quotaLimitRule
		shadow      ShadowQuota
		shadowRules []string
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

		// enforce：tpm → minute；日预算 → day。**B 项起两者可同时生效**（任一维度超限即 429）。
		switch {
		case r.Kind == KindRate:
			if r.TPM <= 0 {
				continue // rpm 属数据面执行点，TEE 侧无内容
			}
			s.limits = append(s.limits, quotaLimitRule{limit: QuotaLimit{Window: "minute", MaxTokens: r.TPM}, rule: r.ID})
		default: // KindBudget
			s.limits = append(s.limits, quotaLimitRule{limit: QuotaLimit{Window: "day", MaxTokens: r.DailyBudgetTokens}, rule: r.ID})
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
		// 规范化顺序（累计 < minute < day），与规则书写顺序解耦。
		sort.SliceStable(s.limits, func(i, j int) bool {
			return windowRank(s.limits[i].limit.Window) < windowRank(s.limits[j].limit.Window)
		})
		u := QuotaUpdate{Tenant: tenant, Limits: make([]QuotaLimit, 0, len(s.limits))}
		rules := make([]string, 0, len(s.limits))
		for _, lr := range s.limits {
			u.Limits = append(u.Limits, lr.limit)
			rules = append(rules, lr.rule)
		}
		if s.shadow.configured() {
			sh := s.shadow
			u.Shadow = &sh
		}
		if len(u.Limits) == 0 && u.Shadow == nil {
			continue // 无 enforce 也无影子：不下发（避免无意义写入）
		}
		updates = append(updates, u)
		for j, l := range u.Limits {
			switch l.Window {
			case "minute":
				notes = append(notes, fmt.Sprintf("规则 %s 的 tpm=%d 以**每分钟窗口**下发（limits window=minute）；与数据面 QPS 计数器相互独立", rules[j], l.MaxTokens))
			case "day":
				notes = append(notes, fmt.Sprintf("规则 %s 的 daily_budget_tokens=%d 以**UTC+8 自然日窗口**下发（limits window=day）；**配额与窗口计数为内存态，进程重启丢失**（待持久化）", rules[j], l.MaxTokens))
			}
		}
		if len(u.Limits) > 1 {
			notes = append(notes, fmt.Sprintf("租户 %s 的多维 enforce 已合并下发（规则 %v）：**任一维度超限即 429**，拒绝按维度归因（otpmask_quota_denies_total{window}）", tenant, rules))
		}
		if u.Shadow != nil {
			notes = append(notes, fmt.Sprintf("租户 %s 影子阈值已合并下发（规则 %v）", tenant, s.shadowRules))
		}
	}
	return updates, notes, nil
}
