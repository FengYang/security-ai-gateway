package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
)

// 本文件实现门禁 #7 的限流表接口（设计 v1.1 §4）：
//   GET  /ratelimits           拉路径数据源（与 /routes 同构：始终返回完整签名表）
//   PUT  /ratelimits           策略源写入（严格解码 → 校验 → 防回滚 → 签名 → 落库 → 变更落链 → 返回编译产物）
//   GET  /ratelimits/history   策略变更审计查询（判据 7：谁/何时/哪条/旧→新 + 链校验）
//   POST /ratelimits/rollback  按 version 回滚（以历史版本规则生成**新版本**，同时落链留痕）
//
// 请求体上限由 main.go 的 limitBody 中间件统一约束（4MiB），此处不再重复限制。

// handleGetRateLimits 返回当前限流表（含签名）；未配置时返回空表占位。
func (s *Server) handleGetRateLimits(w http.ResponseWriter, r *http.Request) {
	tbl := s.store.GetRateLimitTable()
	if tbl == nil {
		// 从未下发策略：返回空表占位（插件侧验签不过 → 保留旧表/不限流），并计数一次
		// "无表可下发"（设计 §6：从未拉到 → 放行 + 告警可见）。
		s.metrics.incPullReject("no_table")
		tbl = ratelimit.NewTable(0, time.Unix(0, 0))
	}
	writeJSON(w, http.StatusOK, tbl)
}

// handlePutRateLimits 接收未签名的策略表：校验通过后由控制面签名并落库。
func (s *Server) handlePutRateLimits(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	tbl, err := ratelimit.DecodeTable(body)
	if err != nil {
		// 未知字段（如认证类配置）在此被拒：策略通道不得作为高权通道
		s.metrics.incChange("rejected")
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}
	if err := tbl.Validate(); err != nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusBadRequest, "invalid_policy", err.Error())
		return
	}

	cur := s.store.GetRateLimitTable()
	curVer := 0
	if cur != nil {
		curVer = cur.Version
	}
	switch ratelimit.CheckVersion(curVer, tbl.Version) {
	case ratelimit.VersionStale:
		s.metrics.incChange("rejected")
		writeError(w, http.StatusConflict, "version_stale",
			fmt.Sprintf("版本 %d 低于当前 %d，拒绝下发（防回滚；如需回滚请用 POST /ratelimits/rollback）", tbl.Version, curVer))
		return
	case ratelimit.VersionSame:
		s.metrics.incChange("rejected")
		writeError(w, http.StatusConflict, "version_same",
			fmt.Sprintf("版本 %d 与当前相同，拒绝下发（变更须递增版本，避免同版本内容漂移）", tbl.Version))
		return
	}
	s.applyTable(w, r, tbl, policyaudit.ActionApply, curVer)
}

// rollbackReq 回滚请求体。
type rollbackReq struct {
	Version int `json:"version"` // 回滚到该历史版本的规则
}

// handleRateLimitRollback 按 version 回滚：以历史版本的规则构造**新版本**表（保持版本单调，
// 不破坏防回滚约束），落链留痕（action=rollback，含逐规则 旧→新）。
func (s *Server) handleRateLimitRollback(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	var req rollbackReq
	if err := json.Unmarshal(body, &req); err != nil || req.Version <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体须为 JSON 且含正整数 version")
		return
	}
	cur := s.store.GetRateLimitTable()
	if cur == nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusConflict, "no_table", "当前无生效表，无可回滚")
		return
	}
	src := s.findHistory(req.Version)
	if src == nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusBadRequest, "version_not_in_history",
			fmt.Sprintf("历史中无版本 %d（仅保留最近 %d 版，且进程重启后仅剩当前版本）", req.Version, policyHistoryLimit))
		return
	}
	next := src.Clone()
	next.Version = cur.Version + 1
	next.IssuedAt = time.Now().UTC().Format(time.RFC3339)
	s.applyTable(w, r, next, policyaudit.ActionRollback, cur.Version)
}

// applyTable 统一的策略表生效路径（PUT 与回滚共用）：
// 差异计算 → 签名 → 落库 → 变更审计落链（fail-closed）→ 编译数据面产物 → TEE 侧配额下发。
func (s *Server) applyTable(w http.ResponseWriter, r *http.Request, tbl *ratelimit.Table, action string, fromVersion int) {
	prev := s.store.GetRateLimitTable()
	changes := ratelimit.DiffRules(prev, tbl)

	if err := s.rlsigner.SignTable(tbl); err != nil {
		s.metrics.incChange("rejected")
		writeError(w, http.StatusInternalServerError, "sign_failed", "策略表签名失败")
		return
	}
	s.store.SaveRateLimitTable(tbl)
	s.recordHistory(tbl)
	s.metrics.setTable(tbl.Version, ruleDimensionCounts(tbl))

	// 变更审计落链（判据 7）：策略已生效但落链失败 → 拒绝 2xx 并如实告知（不静默不留痕）
	if err := s.appendPolicyAudit(r, action, fromVersion, tbl.Version, changes); err != nil {
		s.metrics.incChange("applied_unaudited")
		writeError(w, http.StatusInternalServerError, "audit_failed",
			fmt.Sprintf("策略已在控制面生效但变更审计写入失败（fail-closed；请人工核查审计文件后决定是否重试）: %v", err))
		return
	}
	result := "applied"
	if action == policyaudit.ActionRollback {
		result = "rolled_back"
	}
	s.metrics.incChange(result)

	cfg, notes, cerr := ratelimit.CompileDataPlane(tbl, ratelimit.DefaultCompileOptions())
	updates, teeNotes, terr := ratelimit.CompileTEEQuota(tbl)
	notes = append(notes, teeNotes...)

	resp := map[string]any{
		"version":         tbl.Version,
		"action":          action,
		"rules":           len(tbl.Rules),
		"changes":         changes,
		"changes_summary": ratelimit.ChangeSummary(changes),
		"notes":           notes,
	}
	if cerr != nil {
		// 与设计 §6 一致：编译失败不下发数据面配置（保留现状），此处如实回报
		resp["data_plane_compiled"] = false
		resp["data_plane_error"] = cerr.Error()
	} else {
		resp["data_plane_compiled"] = true
		resp["data_plane_config"] = cfg
	}

	// TEE 侧配额下发（S3）：失败**不清零** tee-infer 现有配额，仅如实回报
	switch {
	case terr != nil:
		s.metrics.incTeeApplied("skipped")
		resp["tee_applied"] = false
		resp["tee_error"] = terr.Error()
	case s.teeQuota == nil:
		s.metrics.incTeeApplied("skipped")
		resp["tee_applied"] = false
		resp["tee_error"] = "未配置 tee-infer 下发器（OTP_CORE_TEE_URL 为空）：预算/TPM 未下发"
	case len(updates) == 0:
		s.metrics.incTeeApplied("ok")
		resp["tee_applied"] = true
		resp["tee_updates"] = 0
	default:
		if err := s.teeQuota.ApplyQuota(r.Context(), updates); err != nil {
			s.metrics.incTeeApplied("failed")
			resp["tee_applied"] = false
			resp["tee_error"] = err.Error()
		} else {
			s.metrics.incTeeApplied("ok")
			resp["tee_applied"] = true
			resp["tee_updates"] = len(updates)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

// appendPolicyAudit 逐规则差异写入策略变更审计链（一条差异 = 一条链上事件；
// 无内容变化仅版本递增时记一条 change=none 事件）。
func (s *Server) appendPolicyAudit(r *http.Request, action string, from, to int, changes []ratelimit.RuleChange) error {
	actor := actorOf(r)
	reqID := r.Header.Get("X-Request-ID")
	base := policyaudit.Event{
		Actor: actor, Action: action,
		VersionFrom: from, VersionTo: to,
		RequestID: reqID, Result: policyaudit.ResultOK,
	}
	if len(changes) == 0 {
		ev := base
		ev.Change = "none"
		_, err := s.audit.Append(ev)
		return err
	}
	for _, c := range changes {
		ev := base
		ev.RuleID, ev.Change, ev.Field = c.RuleID, c.Change, c.Field
		ev.OldValue, ev.NewValue = c.Old, c.New
		if _, err := s.audit.Append(ev); err != nil {
			return err
		}
	}
	return nil
}

// handleRateLimitHistory 返回策略变更审计事件（判据 7：谁/何时/哪条/旧→新）+ 链校验结果。
func (s *Server) handleRateLimitHistory(w http.ResponseWriter, r *http.Request) {
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, http.StatusBadRequest, "invalid_request", "limit 须为非负整数")
			return
		}
		limit = n
	}
	ok, brokenAt := s.audit.Verify()
	tbl := s.store.GetRateLimitTable()
	effective := 0
	if tbl != nil {
		effective = tbl.Version
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"effective_version": effective,
		"chain_ok":          ok,
		"chain_broken_at":   brokenAt,
		"events":            s.audit.List(limit),
		"events_total":      s.audit.Len(),
	})
}
