package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"security-ai-gateway/gateway/a2aproxy"
	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
)

// 本文件实现 P2-2 T-3a 的 A2A 复合限流表接口（与 /a2a-acls 同构但**独立策略域**）：
//
//	GET  /a2a-ratelimits           拉策略数据源（始终返回完整签名表）
//	PUT  /a2a-ratelimits           策略源写入（严格解码 → 校验 → 防回滚 → 签名 → 落库 → 变更落链）
//	GET  /a2a-ratelimits/history   策略变更审计查询
//	POST /a2a-ratelimits/rollback  按 version 回滚（以历史版本规则生成**新版本**，同时落链留痕）
//
// R-6：A2A 限流域**不与** MCP 域合并——独立端点前缀、独立表、独立签名对象。
// 冻结 §2.4 限流行：缺省不限流（无规则命中即放行）。

// rlHistoryLimit 是保留的限流历史版本数。
const rlHistoryLimit = policyHistoryLimit

// rlRollbackReq 回滚请求体。
type rlRollbackReq struct {
	Version int `json:"version"`
}

// handleGetRateLimitsA2A 返回当前限流表（含签名）；未配置时返回空表占位。
func (s *Server) handleGetRateLimitsA2A(w http.ResponseWriter, r *http.Request) {
	tbl := s.store.GetA2ARateLimitTable()
	if tbl == nil {
		tbl = a2aproxy.NewRateLimitTable(0, time.Unix(0, 0))
	}
	writeJSON(w, http.StatusOK, tbl)
}

// handlePutRateLimitsA2A 接收未签名的限流表：校验通过后由控制面签名并落库。
func (s *Server) handlePutRateLimitsA2A(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	// 严格解码：未知字段（如认证类配置）在此被拒——策略通道不得作为高权通道。
	tbl, err := a2aproxy.DecodeRateLimitTable(body)
	if err != nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	if err := tbl.Validate(); err != nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	// 规则排序：保证规范字节跨副本稳定（签名可复现）。
	a2aproxy.SortRateLimitRules(tbl.Rules)

	cur := s.store.GetA2ARateLimitTable()
	curVer := 0
	if cur != nil {
		curVer = cur.Version
	}
	switch aclCheckVersion(curVer, tbl.Version) {
	case aclVersionStale:
		s.metrics.incChange("rejected")
		writeError(w, http.StatusConflict, "version_stale",
			fmt.Sprintf("版本 %d 低于当前 %d，拒绝下发（防回滚；如需回滚请用 POST /a2a-ratelimits/rollback）", tbl.Version, curVer))
		return
	case aclVersionSame:
		s.metrics.incChange("rejected")
		writeError(w, http.StatusConflict, "version_same",
			fmt.Sprintf("版本 %d 与当前相同，拒绝下发（变更须递增版本，避免同版本内容漂移）", tbl.Version))
		return
	}
	s.applyRateLimitTableA2A(w, r, tbl, policyaudit.ActionApply, curVer)
}

// handleRateLimitHistoryA2A 返回限流策略变更审计。
func (s *Server) handleRateLimitHistoryA2A(w http.ResponseWriter, r *http.Request) {
	events := s.audit.List(0)
	items := make([]map[string]any, 0, len(events))
	for _, e := range events {
		if e.Action != rlAuditAction && e.Action != policyaudit.ActionRollback {
			continue
		}
		if e.RuleID == "" || !isRLRuleID(e.RuleID) {
			continue
		}
		items = append(items, map[string]any{
			"event_id":     e.EventID,
			"timestamp":    e.Timestamp,
			"actor":        e.Actor,
			"action":       e.Action,
			"version_from": e.VersionFrom,
			"version_to":   e.VersionTo,
			"rule_id":      e.RuleID,
			"change":       e.Change,
			"field":        e.Field,
			"old_value":    e.OldValue,
			"new_value":    e.NewValue,
			"request_id":   e.RequestID,
			"result":       e.Result,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": items})
}

// handleRateLimitRollbackA2A 按 version 回滚：以历史版本的规则构造**新版本**表
// （保持版本单调，不破坏防回滚约束），落链留痕。
func (s *Server) handleRateLimitRollbackA2A(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	var req rlRollbackReq
	if err := json.Unmarshal(body, &req); err != nil || req.Version <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体须为 JSON 且含正整数 version")
		return
	}
	cur := s.store.GetA2ARateLimitTable()
	if cur == nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusConflict, "no_table", "当前无生效表，无可回滚")
		return
	}
	src := s.findRLHistory(req.Version)
	if src == nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusBadRequest, "version_not_in_history",
			fmt.Sprintf("历史中无版本 %d（仅保留最近 %d 版，且进程重启后仅剩当前版本）", req.Version, rlHistoryLimit))
		return
	}
	next := &a2aproxy.RateLimitTable{
		Version:  cur.Version + 1,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
		Rules:    append([]a2aproxy.RateLimitRule{}, src.Rules...),
	}
	s.applyRateLimitTableA2A(w, r, next, policyaudit.ActionRollback, cur.Version)
}

// applyRateLimitTableA2A 统一的限流表生效路径（PUT 与回滚共用）：
// 差异计算 → 签名 → 落库 → 变更审计落链（fail-closed）→ 回传摘要。
func (s *Server) applyRateLimitTableA2A(w http.ResponseWriter, r *http.Request, tbl *a2aproxy.RateLimitTable, action string, fromVersion int) {
	// 无签名器不得签表（fail-closed：宁可不生效，也不得发出未签名策略）。
	if s.rlSigner == nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusServiceUnavailable, "signer_unavailable", "未配置限流表签名器，拒绝下发")
		return
	}
	prev := s.store.GetA2ARateLimitTable()
	changes := rlDiffRules(prev, tbl)

	if err := s.rlSigner.SignTable(tbl); err != nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusInternalServerError, "sign_failed", "限流表签名失败")
		return
	}
	s.store.SaveA2ARateLimitTable(tbl)
	s.recordRLHistory(tbl)

	// 变更审计落链：策略已生效但落链失败 → 拒绝 2xx（fail-closed，不静默不留痕）。
	if err := s.appendRateLimitAudit(r, action, fromVersion, tbl.Version, changes); err != nil {
		s.metrics.incChange("applied_unaudited")
		writeError(w, http.StatusInternalServerError, "audit_failed",
			fmt.Sprintf("限流表已在控制面生效但变更审计写入失败（fail-closed；请人工核查审计文件后决定是否重试）: %v", err))
		return
	}
	result := "applied"
	if action == policyaudit.ActionRollback {
		result = "rolled_back"
	}
	s.metrics.incChange(result)

	writeJSON(w, http.StatusOK, map[string]any{
		"version":             tbl.Version,
		"action":              action,
		"rules":               len(tbl.Rules),
		"changes":             changes,
		"rule_ids":            rlRuleIDs(tbl),
		"data_plane_compiled": true,
	})
}

// appendRateLimitAuditA2A 逐规则差异写入策略变更审计链。
func (s *Server) appendRateLimitAudit(r *http.Request, action string, from, to int, changes []rlRuleChange) error {
	actor := actorOf(r)
	reqID := r.Header.Get("X-Request-ID")
	for _, ch := range changes {
		ev := policyaudit.Event{
			Actor:       actor,
			Action:      rlAuditAction,
			VersionFrom: from,
			VersionTo:   to,
			RuleID:      ch.RuleID,
			Change:      ch.Change,
			Field:       ch.Field,
			OldValue:    ch.OldValue,
			NewValue:    ch.NewValue,
			RequestID:   reqID,
			Result:      policyaudit.ResultOK,
		}
		if action == policyaudit.ActionRollback {
			ev.Action = policyaudit.ActionRollback
		}
		if _, err := s.audit.Append(ev); err != nil {
			return err
		}
	}
	if len(changes) == 0 {
		ev := policyaudit.Event{
			Actor:       actor,
			Action:      rlAuditAction,
			VersionFrom: from,
			VersionTo:   to,
			RuleID:      rlAuditRuleID,
			Change:      "none",
			RequestID:   reqID,
			Result:      policyaudit.ResultOK,
		}
		if action == policyaudit.ActionRollback {
			ev.Action = policyaudit.ActionRollback
		}
		if _, err := s.audit.Append(ev); err != nil {
			return err
		}
	}
	return nil
}

// rlAuditAction 是限流变更在审计链上的 action 取值（独立策略域，R-6）。
const rlAuditAction = "a2a_ratelimit_changed"

// rlAuditRuleID 是"无具体规则变化"时的占位 rule_id。
const rlAuditRuleID = "a2a-rl"

// rlRuleChange 是一条限流规则的差异。
type rlRuleChange struct {
	RuleID   string `json:"rule_id"`
	Change   string `json:"change"` // added | removed | updated | none
	Field    string `json:"field,omitempty"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// rlDiffRules 计算限流表差异（按 rule_id 对齐）。
func rlDiffRules(prev, next *a2aproxy.RateLimitTable) []rlRuleChange {
	prevMap := map[string]a2aproxy.RateLimitRule{}
	if prev != nil {
		for _, r := range prev.Rules {
			prevMap[rlRuleIDOf(r)] = r
		}
	}
	nextMap := map[string]a2aproxy.RateLimitRule{}
	if next != nil {
		for _, r := range next.Rules {
			nextMap[rlRuleIDOf(r)] = r
		}
	}
	changes := make([]rlRuleChange, 0)
	for id, pr := range prevMap {
		if _, ok := nextMap[id]; !ok {
			changes = append(changes, rlRuleChange{
				RuleID: id, Change: "removed", OldValue: rlRuleSummary(pr),
			})
		}
	}
	for id, nr := range nextMap {
		pr, ok := prevMap[id]
		if !ok {
			changes = append(changes, rlRuleChange{
				RuleID: id, Change: "added", NewValue: rlRuleSummary(nr),
			})
			continue
		}
		if rlRuleSummary(pr) != rlRuleSummary(nr) {
			changes = append(changes, rlRuleChange{
				RuleID: id, Change: "updated",
				OldValue: rlRuleSummary(pr), NewValue: rlRuleSummary(nr),
			})
		}
	}
	sortRLChanges(changes)
	return changes
}

// sortRLChanges 按 rule_id 排序（确定性输出）。
func sortRLChanges(changes []rlRuleChange) {
	for i := 1; i < len(changes); i++ {
		for j := i; j > 0 && changes[j].RuleID < changes[j-1].RuleID; j-- {
			changes[j], changes[j-1] = changes[j-1], changes[j]
		}
	}
}

// rlRuleIDOf 规则标识（用于对齐差异）：tenant/agent/skill。
func rlRuleIDOf(r a2aproxy.RateLimitRule) string {
	return r.Tenant + "/" + r.Agent + "/" + r.Skill
}

// rlRuleSummary 规则的可审计摘要（rpm；描述字段不入链）。
func rlRuleSummary(r a2aproxy.RateLimitRule) string {
	return fmt.Sprintf("%s rpm=%d", rlRuleIDOf(r), r.RPM)
}

// rlRuleIDs 列出当前表的规则标识（确定性顺序）。
func rlRuleIDs(t *a2aproxy.RateLimitTable) []string {
	out := make([]string, 0)
	if t == nil {
		return out
	}
	for _, r := range t.Rules {
		out = append(out, rlRuleIDOf(r))
	}
	sortStrings(out)
	return out
}

// isRLRuleID 判断 rule_id 是否为限流规则标识（用于审计查询过滤）。
func isRLRuleID(id string) bool {
	if id == rlAuditRuleID {
		return true
	}
	parts := 0
	for i := 0; i < len(id); i++ {
		if id[i] == '/' {
			parts++
		}
	}
	return parts == 2
}

// SetRateLimitSigner 注入 A2A 限流表签名器（P2-2 T-3a）。
//
// 与 ACL 表**同一 K_rx 密钥**、同一分发通道，但限流是**独立策略域**（R-6）：
// 独立端点前缀（/a2a-ratelimits）、独立表对象、独立签名对象。
//
// nil（未注入）时限流端点仍可读，但 PUT/rollback 一律拒绝（无签名器不得签表）。
func (s *Server) SetRateLimitSigner(signer *a2aproxy.RateLimitSigner) {
	s.rlSigner = signer
}

// recordRLHistory 记录限流历史版本（用于按 version 回滚）。
func (s *Server) recordRLHistory(t *a2aproxy.RateLimitTable) {
	if t == nil {
		return
	}
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	s.rlHist = append(s.rlHist, t)
	if len(s.rlHist) > rlHistoryLimit {
		s.rlHist = s.rlHist[len(s.rlHist)-rlHistoryLimit:]
	}
}

// findRLHistory 按 version 查限流历史版本。
func (s *Server) findRLHistory(version int) *a2aproxy.RateLimitTable {
	s.rlMu.Lock()
	defer s.rlMu.Unlock()
	for _, t := range s.rlHist {
		if t.Version == version {
			return t
		}
	}
	return nil
}
