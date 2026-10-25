// Package main — 账号管理审计事件投递端点（M3-A 账号角色扩展）。
//
// 背景：账号表（多账号/角色）由 Java 控制台侧直接读写独立 K8s Secret
// （higress-console-adminext-users，console serviceaccount 已验证 Secret 读写权限）；
// G1 哈希链在本服务（单点 append，防篡改）。故账号写操作的审计经本端点投递落链：
//
//	Java AdminExtAccountController（写 Secret 成功后）→ POST /v1/adminext/audit-events
//	  →（内部 JWT）→ 本服务落 G1 链 → 204
//
// fail-closed 语义（与 broker_secret.go 同款）：
//   - 审计链未启用（ADMIN_AUDIT_FILE 未配置）→ 503，Java 侧回滚该次账号变更；
//   - 落链失败 → 500，Java 侧回滚；
//   - action 白名单外的投递 → 400（防任意字符串污染链）。
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// 审计动作白名单（M3-A：仅账号管理操作允许投递；凭据/配额写在本服务内直接落链）。
const (
	auditActionAccountCreate        = "account_create"
	auditActionAccountUpdate        = "account_update"
	auditActionAccountPasswordReset = "account_password_reset"
	auditActionAccountDelete        = "account_delete"
	// P1-3 §6.1 身份鉴别审计动作（登录/登出/锁定，账号管理域契约）。
	auditActionLoginSuccess    = "login_success"
	auditActionLoginFailure    = "login_failure"
	auditActionLogout          = "logout"
	auditActionAccountLocked   = "account_locked"
	auditActionAccountUnlocked = "account_unlocked"
	auditActionSessionKicked   = "session_kicked"
	// P2-4 §6.1 集群注册/摘除（含双签审批）；与 account_* 同级，白名单扩展段。
	auditActionClusterRegistryApproval = "cluster_registry_approval"
	auditActionClusterRegistryChanged  = "cluster_registry_changed"
)

// auditEventActions 投递端点接受的 action 集合。
var auditEventActions = map[string]struct{}{
	auditActionAccountCreate:        {},
	auditActionAccountUpdate:        {},
	auditActionAccountPasswordReset: {},
	auditActionAccountDelete:        {},
	auditActionLoginSuccess:         {},
	auditActionLoginFailure:         {},
	auditActionLogout:               {},
	auditActionAccountLocked:        {},
	auditActionAccountUnlocked:      {},
	auditActionSessionKicked:        {},
}

// maxTargetLen 目标资源名上限（账号名 ≤32，放宽到 64 防御性上限）。
const maxTargetLen = 64

// auditEventsPath 账号管理审计投递端点路径。
const auditEventsPath = "/v1/adminext/audit-events"

// auditEventRequest Java 控制台投递的审计事件请求体。
type auditEventRequest struct {
	Action string `json:"action"` // 白名单内动作（见 auditEventActions）
	Target string `json:"target"` // 目标资源名（账号管理 = 目标账号）
}

// auditEventHandler 账号管理审计投递 handler。
// chain 为 nil（审计链未启用）时端点恒 503（fail-closed：账号管理写操作被 Java 侧回滚）。
type auditEventHandler struct {
	chain *adminAuditChain
}

// handle POST /v1/adminext/audit-events：校验 → 落 G1 链 → 204。
func (h *auditEventHandler) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRule(w, r, epAuditEvents) {
		return
	}
	if h.chain == nil {
		writeError(w, http.StatusServiceUnavailable, "审计链未启用（ADMIN_AUDIT_FILE 未配置），账号管理写操作拒绝")
		return
	}

	var body auditEventRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if _, ok := auditEventActions[body.Action]; !ok {
		writeError(w, http.StatusBadRequest, "未知的审计动作（仅接受账号管理白名单内 action）")
		return
	}
	body.Target = strings.TrimSpace(body.Target)
	if body.Target == "" || len(body.Target) > maxTargetLen {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("target 必填且长度 ≤%d", maxTargetLen))
		return
	}

	c := claimsFrom(r.Context())
	rid := r.Header.Get("X-Request-ID")
	if err := h.chain.append(adminAuditEvent{
		Actor:     c.Sub,
		Action:    body.Action,
		Target:    body.Target,
		RequestID: rid,
		Result:    "ok",
	}); err != nil {
		log.Printf("[adminext] 审计事件落链失败（action=%s target=%s sub=%s rid=%s）: %v",
			body.Action, body.Target, c.Sub, rid, err)
		writeError(w, http.StatusInternalServerError, "审计链写入失败")
		return
	}
	log.Printf("[adminext] 审计事件落链：action=%s target=%s sub=%s rid=%s len=%d",
		body.Action, body.Target, c.Sub, rid, h.chain.len())
	w.WriteHeader(http.StatusNoContent)
}
