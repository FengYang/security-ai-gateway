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

// 本文件实现 P2-2 T-3 的 A2A ACL 策略表接口（与 /ratelimits 同构但**独立策略域**）：
//
//	GET  /a2a-acls           拉策略数据源（始终返回完整签名表）
//	PUT  /a2a-acls           策略源写入（严格解码 → 校验 → 防回滚 → 签名 → 落库 → 变更落链）
//	GET  /a2a-acls/history   策略变更审计查询
//	POST /a2a-acls/rollback  按 version 回滚（以历史版本规则生成**新版本**，同时落链留痕）
//
// R-6：A2A 策略域**不与** MCP 域合并——独立端点前缀、独立表、独立签名对象。
// 冻结 §2.4：ACL 为 allow-only（精确 > 通配 > 缺省 deny）。

// aclHistoryLimit 是保留的 ACL 历史版本数（与限流表同口径）。
const aclHistoryLimit = policyHistoryLimit

// aclRollbackReq 回滚请求体。
type aclRollbackReq struct {
	Version int `json:"version"`
}

// handleGetACLs 返回当前 ACL 表（含签名）；未配置时返回空表占位。
func (s *Server) handleGetACLs(w http.ResponseWriter, r *http.Request) {
	tbl := s.store.GetACLTable()
	if tbl == nil {
		// 从未下发策略：返回空表占位（数据面验签不过 → 保留旧表；空表即 deny-all）。
		tbl = a2aproxy.NewACLTable(0, time.Unix(0, 0))
	}
	writeJSON(w, http.StatusOK, tbl)
}

// handlePutACLs 接收未签名的 ACL 表：校验通过后由控制面签名并落库。
func (s *Server) handlePutACLs(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	// 严格解码：未知字段（如认证类配置）在此被拒——策略通道不得作为高权通道。
	tbl, err := a2aproxy.DecodeACLTable(body)
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
	a2aproxy.SortACLRules(tbl.Rules)

	cur := s.store.GetACLTable()
	curVer := 0
	if cur != nil {
		curVer = cur.Version
	}
	switch aclCheckVersion(curVer, tbl.Version) {
	case aclVersionStale:
		s.metrics.incChange("rejected")
		writeError(w, http.StatusConflict, "version_stale",
			fmt.Sprintf("版本 %d 低于当前 %d，拒绝下发（防回滚；如需回滚请用 POST /a2a-acls/rollback）", tbl.Version, curVer))
		return
	case aclVersionSame:
		s.metrics.incChange("rejected")
		writeError(w, http.StatusConflict, "version_same",
			fmt.Sprintf("版本 %d 与当前相同，拒绝下发（变更须递增版本，避免同版本内容漂移）", tbl.Version))
		return
	}
	s.applyACLTable(w, r, tbl, policyaudit.ActionApply, curVer)
}

// handleACLHistory 返回 ACL 策略变更审计（判据：谁/何时/哪条/旧→新）。
func (s *Server) handleACLHistory(w http.ResponseWriter, r *http.Request) {
	events := s.audit.List(0)
	items := make([]map[string]any, 0, len(events))
	for _, e := range events {
		if e.Action != aclAuditAction && e.Action != policyaudit.ActionRollback {
			continue
		}
		if e.RuleID == "" || !isACLRuleID(e.RuleID) {
			continue
		}
		items = append(items, map[string]any{
			"event_id":   e.EventID,
			"timestamp":  e.Timestamp,
			"actor":      e.Actor,
			"action":     e.Action,
			"version_from": e.VersionFrom,
			"version_to":   e.VersionTo,
			"rule_id":    e.RuleID,
			"change":     e.Change,
			"field":      e.Field,
			"old_value":  e.OldValue,
			"new_value":  e.NewValue,
			"request_id": e.RequestID,
			"result":     e.Result,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"events": items})
}

// handleACLRollback 按 version 回滚：以历史版本的规则构造**新版本**表
// （保持版本单调，不破坏防回滚约束），落链留痕。
func (s *Server) handleACLRollback(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	var req aclRollbackReq
	if err := json.Unmarshal(body, &req); err != nil || req.Version <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体须为 JSON 且含正整数 version")
		return
	}
	cur := s.store.GetACLTable()
	if cur == nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusConflict, "no_table", "当前无生效表，无可回滚")
		return
	}
	src := s.findACLHistory(req.Version)
	if src == nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusBadRequest, "version_not_in_history",
			fmt.Sprintf("历史中无版本 %d（仅保留最近 %d 版，且进程重启后仅剩当前版本）", req.Version, aclHistoryLimit))
		return
	}
	next := &a2aproxy.ACLTable{
		Version:  cur.Version + 1,
		IssuedAt: time.Now().UTC().Format(time.RFC3339),
		Rules:    append([]a2aproxy.ACLRule{}, src.Rules...),
	}
	s.applyACLTable(w, r, next, policyaudit.ActionRollback, cur.Version)
}

// applyACLTable 统一的 ACL 表生效路径（PUT 与回滚共用）：
// 差异计算 → 签名 → 落库 → 变更审计落链（fail-closed）→ 回传摘要。
func (s *Server) applyACLTable(w http.ResponseWriter, r *http.Request, tbl *a2aproxy.ACLTable, action string, fromVersion int) {
	// 无签名器不得签表（fail-closed：宁可不生效，也不得发出未签名策略）。
	if s.aclSigner == nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusServiceUnavailable, "signer_unavailable", "未配置 ACL 表签名器，拒绝下发")
		return
	}
	prev := s.store.GetACLTable()
	changes := aclDiffRules(prev, tbl)

	if err := s.aclSigner.SignTable(tbl); err != nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusInternalServerError, "sign_failed", "ACL 表签名失败")
		return
	}
	s.store.SaveACLTable(tbl)
	s.recordACLHistory(tbl)

	// 变更审计落链：策略已生效但落链失败 → 拒绝 2xx（fail-closed，不静默不留痕）。
	if err := s.appendACLAudit(r, action, fromVersion, tbl.Version, changes); err != nil {
		s.metrics.incChange("applied_unaudited")
		writeError(w, http.StatusInternalServerError, "audit_failed",
			fmt.Sprintf("ACL 表已在控制面生效但变更审计写入失败（fail-closed；请人工核查审计文件后决定是否重试）: %v", err))
		return
	}
	result := "applied"
	if action == policyaudit.ActionRollback {
		result = "rolled_back"
	}
	s.metrics.incChange(result)

	writeJSON(w, http.StatusOK, map[string]any{
		"version":   tbl.Version,
		"action":    action,
		"rules":     len(tbl.Rules),
		"changes":   changes,
		"rule_ids":  aclRuleIDs(tbl),
		"data_plane_compiled": true,
	})
}

// appendACLAudit 逐规则差异写入策略变更审计链。
//
// 一条差异 = 一条链上事件；无内容变化仅版本递增时记一条 change=none 事件。
func (s *Server) appendACLAudit(r *http.Request, action string, from, to int, changes []aclRuleChange) error {
	actor := actorOf(r)
	reqID := r.Header.Get("X-Request-ID")
	for _, ch := range changes {
		ev := policyaudit.Event{
			Actor:       actor,
			Action:      aclAuditAction,
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
			Action:      aclAuditAction,
			VersionFrom: from,
			VersionTo:   to,
			RuleID:      aclAuditRuleID,
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

// aclAuditAction 是 ACL 变更在审计链上的 action 取值。
//
// ⚠️ 与 policyaudit 既有 action 常量**分开**：A2A ACL 是独立策略域（R-6），
// 在链上用独立 action 便于审计侧按域筛选，且不改动 policyaudit 的既有常量表。
const aclAuditAction = "a2a_acl_changed"

// aclAuditRuleID 是"无具体规则变化"时的占位 rule_id。
const aclAuditRuleID = "a2a-acl"

// aclRuleChange 是一条 ACL 规则的差异。
type aclRuleChange struct {
	RuleID   string `json:"rule_id"`
	Change   string `json:"change"` // added | removed | updated | none
	Field    string `json:"field,omitempty"`
	OldValue string `json:"old_value,omitempty"`
	NewValue string `json:"new_value,omitempty"`
}

// aclDiffRules 计算 ACL 表差异（按 rule_id 对齐）。
func aclDiffRules(prev, next *a2aproxy.ACLTable) []aclRuleChange {
	prevMap := map[string]a2aproxy.ACLRule{}
	if prev != nil {
		for _, r := range prev.Rules {
			prevMap[aclRuleIDOf(r)] = r
		}
	}
	nextMap := map[string]a2aproxy.ACLRule{}
	if next != nil {
		for _, r := range next.Rules {
			nextMap[aclRuleIDOf(r)] = r
		}
	}
	changes := make([]aclRuleChange, 0)
	// 先记删除，再记新增，最后记修改（确定性顺序）。
	for id, pr := range prevMap {
		if _, ok := nextMap[id]; !ok {
			changes = append(changes, aclRuleChange{
				RuleID: id, Change: "removed", OldValue: aclRuleSummary(pr),
			})
		}
	}
	for id, nr := range nextMap {
		pr, ok := prevMap[id]
		if !ok {
			changes = append(changes, aclRuleChange{
				RuleID: id, Change: "added", NewValue: aclRuleSummary(nr),
			})
			continue
		}
		if aclRuleSummary(pr) != aclRuleSummary(nr) {
			changes = append(changes, aclRuleChange{
				RuleID: id, Change: "updated",
				OldValue: aclRuleSummary(pr), NewValue: aclRuleSummary(nr),
			})
		}
	}
	// 稳定排序（按 rule_id），保证审计与响应可复现。
	sortACLChanges(changes)
	return changes
}

// sortACLChanges 按 rule_id 排序（确定性输出）。
func sortACLChanges(changes []aclRuleChange) {
	for i := 1; i < len(changes); i++ {
		for j := i; j > 0 && changes[j].RuleID < changes[j-1].RuleID; j-- {
			changes[j], changes[j-1] = changes[j-1], changes[j]
		}
	}
}

// aclRuleIDOf 规则标识（用于对齐差异）：tenant/agent/skill[/subject]。
func aclRuleIDOf(r a2aproxy.ACLRule) string {
	id := r.Tenant + "/" + r.Agent + "/" + r.Skill
	if r.Subject != "" {
		id += "/" + r.Subject
	}
	return id
}

// aclRuleSummary 规则的可审计摘要（不含自由文本；描述字段不入链）。
func aclRuleSummary(r a2aproxy.ACLRule) string {
	return aclRuleIDOf(r)
}

// aclRuleIDs 列出当前表的规则标识（确定性顺序）。
func aclRuleIDs(t *a2aproxy.ACLTable) []string {
	out := make([]string, 0)
	if t == nil {
		return out
	}
	for _, r := range t.Rules {
		out = append(out, aclRuleIDOf(r))
	}
	sortACLChanges(nil) // no-op，保持函数对称
	sortStrings(out)
	return out
}

// sortStrings 原地排序字符串切片（避免引入 sort 包的额外依赖面）。
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// isACLRuleID 判断 rule_id 是否为 ACL 规则标识（用于审计查询过滤）。
func isACLRuleID(id string) bool {
	if id == aclAuditRuleID {
		return true
	}
	parts := 0
	for i := 0; i < len(id); i++ {
		if id[i] == '/' {
			parts++
		}
	}
	return parts >= 2 && parts <= 3
}

// aclVersionDecision 版本比较结果。
type aclVersionDecision int

const (
	aclVersionOK aclVersionDecision = iota
	aclVersionStale
	aclVersionSame
)

// aclCheckVersion 比较下发版本与当前版本（防回滚 + 禁同版本内容漂移）。
func aclCheckVersion(current, incoming int) aclVersionDecision {
	switch {
	case incoming < current:
		return aclVersionStale
	case incoming == current:
		return aclVersionSame
	default:
		return aclVersionOK
	}
}
