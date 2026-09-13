// diff.go — 策略表逐规则差异（Phase 1 门禁 #7 / 判据 7：变更落链的"哪条规则、旧值→新值"）。
//
// 纯逻辑、无 I/O：把两份策略表比对为**规则级字段差异**列表，供控制面写入策略变更审计链。
package ratelimit

import (
	"fmt"
	"sort"
	"strings"
)

// RuleChange 单条差异（added/removed 为整条规则，updated 为某个字段）。
type RuleChange struct {
	RuleID string `json:"rule_id"`
	Change string `json:"change"`          // added | updated | removed（取值与 policyaudit 一致）
	Field  string `json:"field,omitempty"` // updated 时的字段名（added/removed 为空）
	Old    string `json:"old,omitempty"`
	New    string `json:"new,omitempty"`
}

// ruleSummary 整条规则的紧凑摘要（added/removed 时作为新值/旧值）。
func ruleSummary(r Rule) string {
	return fmt.Sprintf("kind=%s scope=%s target=%s rpm=%d tpm=%d daily_budget_tokens=%d burst_multiplier=%d action=%s enabled=%t",
		r.Kind, r.Scope, r.Target, r.RPM, r.TPM, r.DailyBudgetTokens, r.BurstMultiplier, r.Action, r.Enabled)
}

// ruleFieldValues 返回规则的 (字段名, 值) 序列（顺序固定，保证差异输出稳定）。
func ruleFieldValues(r Rule) [][2]string {
	return [][2]string{
		{"kind", string(r.Kind)},
		{"scope", string(r.Scope)},
		{"target", r.Target},
		{"rpm", fmt.Sprint(r.RPM)},
		{"tpm", fmt.Sprint(r.TPM)},
		{"daily_budget_tokens", fmt.Sprint(r.DailyBudgetTokens)},
		{"burst_multiplier", fmt.Sprint(r.BurstMultiplier)},
		{"action", string(r.Action)},
		{"enabled", fmt.Sprint(r.Enabled)},
	}
}

// DiffRules 比对两份策略表，返回逐规则差异（按规则 id、字段序稳定排序）。
// old 为 nil 视为空表（首次下发 → 全部 added）。
func DiffRules(old, next *Table) []RuleChange {
	oldByID := map[string]Rule{}
	if old != nil {
		for _, r := range old.Rules {
			oldByID[r.ID] = r
		}
	}
	nextByID := map[string]Rule{}
	if next != nil {
		for _, r := range next.Rules {
			nextByID[r.ID] = r
		}
	}

	seen := map[string]bool{}
	var ids []string
	for id := range oldByID {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	for id := range nextByID {
		if !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)

	var out []RuleChange
	for _, id := range ids {
		o, hadOld := oldByID[id]
		n, hasNew := nextByID[id]
		switch {
		case !hadOld && hasNew:
			out = append(out, RuleChange{RuleID: id, Change: "added", New: ruleSummary(n)})
		case hadOld && !hasNew:
			out = append(out, RuleChange{RuleID: id, Change: "removed", Old: ruleSummary(o)})
		default:
			ov, nv := ruleFieldValues(o), ruleFieldValues(n)
			for i := range ov {
				if ov[i][1] != nv[i][1] {
					out = append(out, RuleChange{RuleID: id, Change: "updated", Field: ov[i][0], Old: ov[i][1], New: nv[i][1]})
				}
			}
		}
	}
	return out
}

// ChangeSummary 生成差异摘要（日志/响应展示用；空差异 → "无规则变化"）。
func ChangeSummary(changes []RuleChange) string {
	if len(changes) == 0 {
		return "无规则变化"
	}
	parts := make([]string, 0, len(changes))
	for _, c := range changes {
		if c.Field == "" {
			parts = append(parts, fmt.Sprintf("%s:%s", c.RuleID, c.Change))
			continue
		}
		parts = append(parts, fmt.Sprintf("%s.%s:%s→%s", c.RuleID, c.Field, c.Old, c.New))
	}
	return strings.Join(parts, "; ")
}

// Clone 深拷贝策略表（回滚时以历史版本构造新版本，避免历史对象被后续修改）。
func (t *Table) Clone() *Table {
	if t == nil {
		return nil
	}
	cp := *t
	cp.Rules = make([]Rule, len(t.Rules))
	copy(cp.Rules, t.Rules)
	cp.Signature = nil // 副本不带签名：签名由落库前重新签发
	return &cp
}
