// Package main — 集群注册 API（P2-4 T-2.2）与双签受理端点。
//
// 口径来源：《GA-AI 网关能力补齐方案 · P2-4 多集群管理》§6.1 集群注册 API。
//
// 端点（RBAC：admin 写 / auditor 读；§6.1 表）：
//   - POST   /v1/adminext/clusters                    注册集群（签发集群身份凭证）
//   - GET    /v1/adminext/clusters                    集群列表（含状态/版本/心跳时间）
//   - POST   /v1/adminext/clusters/{id}/heartbeat     心跳上报（**须携带集群身份凭证**）
//   - POST   /v1/adminext/clusters/{id}/approval      产生一条双签审批事件（返回审批 ID）
//   - DELETE /v1/adminext/clusters/{id}               摘除（**须双签**；unreachable 走强制路径）
//
// 三层身份（叠加而非替代）：
//   1. 管理面会话 RBAC（admin 写 / auditor 读）；
//   2. 集群身份凭证（心跳必须；普通摘除也校验——证明操作者确与该集群身份绑定）；
//   3. 双签（摘除等受控变更必须，两名不同授权人各自审批，≤15min 有效、一次性消费）。
//
// 审计先行：受控变更**先落 admin 链再执行状态变更**——落链失败即拒绝变更（fail-closed）。
//
// 一处**明确的口径偏离**（已在报告登记）：设计文档要求 DELETE 也须携带集群凭证，
// 但 unreachable 强制摘除路径的前提正是"集群不可联机"——此时无法取得该集群凭证。
// 故：普通摘除校验凭证；强制摘除不校验凭证，但要求"不可达声明 + 租户离线处置确认"
// 并同样双签，且在审计 Detail 中标注强制路径。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// 集群注册相关请求体上限（4KiB，与审计投递端点同量级）。
const clusterBodyLimit = 4 << 10

// 集群凭证请求头（集群身份凭证载体；与 RBAC 叠加）。
const clusterCredentialHeader = "X-Cluster-Credential"

// 租户处置声明取值（摘除前置条件：状态为 active/degraded 且无租户绑定或显式迁移）。
const (
	tenantDispositionNone     = "none"     // 无租户绑定
	tenantDispositionMigrated = "migrated" // 租户已显式迁移
)

// clusterAPI 集群注册 API handler 组。
type clusterAPI struct {
	store     ClusterStore
	creds     ClusterCredentialStore
	approvals *clusterApprovalRegistry
	hb        ClusterHeartbeatConfig
}

// newClusterAPI 构造集群 API handler。
func newClusterAPI(store ClusterStore, approvals *clusterApprovalRegistry) *clusterAPI {
	return &clusterAPI{
		store:     store,
		creds:     store.Credentials(),
		approvals: approvals,
		hb:        DefaultClusterHeartbeatConfig(),
	}
}

// clusterRegisterRequest 注册请求体。
type clusterRegisterRequest struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	Form     string `json:"form"`
	Capacity struct {
		RPS         int `json:"rps"`
		Concurrency int `json:"concurrency"`
	} `json:"capacity"`
}

// clusterRegisterResponse 注册响应（凭证明文**只在本次返回一次**）。
type clusterRegisterResponse struct {
	Cluster          ClusterRecord `json:"cluster"`
	Credential       string        `json:"credential"`
	CredentialExpiry time.Time     `json:"credential_expires_at"`
}

// clusterHeartbeatRequest 心跳请求体。
type clusterHeartbeatRequest struct {
	AppliedConfigVersion string `json:"applied_config_version"`
}

// clusterApprovalRequest 双签审批请求体（target 固定为路径中的集群 ID）。
type clusterApprovalRequest struct {
	Note string `json:"note"`
}

// clusterApprovalResponse 审批响应。
type clusterApprovalResponse struct {
	ApprovalID string `json:"approval_id"`
	ExpiresIn  string `json:"expires_in"`
}

// clusterRemoveRequest 摘除请求体。
type clusterRemoveRequest struct {
	DualApprovalIDs [2]string `json:"dual_approval_ids"`
	// TenantDisposition 租户处置声明：none（无租户绑定）或 migrated（已显式迁移）。
	TenantDisposition string `json:"tenant_disposition"`
	// UnreachableDeclaration unreachable 强制摘除路径：集群不可达声明（必填）。
	UnreachableDeclaration string `json:"unreachable_declaration"`
	// TenantOfflineDisposition 强制摘除路径：租户离线处置/放弃确认（必填）。
	TenantOfflineDisposition string `json:"tenant_offline_disposition"`
}

// handleRegister POST /v1/adminext/clusters：注册集群 + 签发集群身份凭证。
func (a *clusterAPI) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRule(w, r, epClusterWrite) {
		return
	}
	var body clusterRegisterRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, clusterBodyLimit))
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	rec := &ClusterRecord{
		ID:       strings.TrimSpace(body.ID),
		Name:     strings.TrimSpace(body.Name),
		Endpoint: strings.TrimSpace(body.Endpoint),
		Form:     ClusterForm(strings.TrimSpace(body.Form)),
		Capacity: ClusterCapacity{RPS: body.Capacity.RPS, Concurrency: body.Capacity.Concurrency},
	}
	if err := ValidateClusterRecord(rec); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if a.approvals == nil || a.approvals.chain == nil {
		writeError(w, http.StatusServiceUnavailable, "审计链未启用（ADMIN_AUDIT_FILE 未配置），集群注册拒绝")
		return
	}
	c := claimsFrom(r.Context())
	// 审计先行：先落变更事件，落链失败不注册（fail-closed）。
	if err := a.approvals.AppendRegistryChange(c.Sub, rec.ID, [2]string{}, "注册集群 "+rec.Name); err != nil {
		log.Printf("[adminext] 集群注册审计落链失败（cluster=%s sub=%s）: %v", rec.ID, c.Sub, err)
		writeError(w, http.StatusInternalServerError, "审计链写入失败，集群未注册")
		return
	}
	if err := a.store.Register(r.Context(), rec); err != nil {
		writeError(w, http.StatusInternalServerError, "集群注册失败: "+err.Error())
		return
	}
	// 签发集群身份凭证（明文只在此刻返回一次）。
	token, cred, err := a.creds.Issue(r.Context(), rec.ID, DefaultClusterCredentialTTL, time.Now())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "集群身份凭证签发失败: "+err.Error())
		return
	}
	stored, err := a.store.Get(r.Context(), rec.ID)
	if err != nil {
		stored = rec
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(clusterRegisterResponse{
		Cluster:          *stored,
		Credential:       token,
		CredentialExpiry: cred.ExpiresAt,
	})
}

// handleList GET /v1/adminext/clusters：集群列表。
func (a *clusterAPI) handleList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epClusterRead) {
		return
	}
	list, err := a.store.List(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "集群列表读取失败")
		return
	}
	if list == nil {
		list = []*ClusterRecord{}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"clusters": list})
}

// handleHeartbeat POST /v1/adminext/clusters/{id}/heartbeat：心跳上报。
//
// 认证：**仅凭集群身份凭证**（集群自身调用，非管理面会话）；凭证缺失/过期/不匹配一律拒绝。
func (a *clusterAPI) handleHeartbeat(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		writeError(w, http.StatusBadRequest, "集群 ID 为空")
		return
	}
	if err := a.verifyClusterCredential(r, id); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	var body clusterHeartbeatRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, clusterBodyLimit))
	// 空体也允许（不上报配置版本时视为未知，不覆盖既有值）。
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	rec, err := a.store.Heartbeat(r.Context(), id, strings.TrimSpace(body.AppliedConfigVersion), time.Now())
	if err != nil {
		writeError(w, http.StatusConflict, "心跳记录失败: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"cluster":               rec,
		"heartbeat_period_secs": int(a.hb.Period.Seconds()),
	})
}

// handleApproval POST /v1/adminext/clusters/{id}/approval：产生一条双签审批事件。
func (a *clusterAPI) handleApproval(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRule(w, r, epClusterWrite) {
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		writeError(w, http.StatusBadRequest, "集群 ID 为空")
		return
	}
	if a.approvals == nil || a.approvals.chain == nil {
		writeError(w, http.StatusServiceUnavailable, "审计链未启用，审批拒绝")
		return
	}
	// 集群必须存在（不允许对不存在的集群审批）。
	if _, err := a.store.Get(r.Context(), id); err != nil {
		writeError(w, http.StatusNotFound, "集群不存在")
		return
	}
	c := claimsFrom(r.Context())
	approvalID, err := a.approvals.RegisterApproval(c.Sub, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "审批事件落链失败: "+err.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(clusterApprovalResponse{
		ApprovalID: approvalID,
		ExpiresIn:  clusterApprovalTTL.String(),
	})
}

// handleRemove DELETE /v1/adminext/clusters/{id}：摘除集群（双签必需）。
func (a *clusterAPI) handleRemove(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 DELETE")
		return
	}
	if !requireRule(w, r, epClusterWrite) {
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		writeError(w, http.StatusBadRequest, "集群 ID 为空")
		return
	}
	var body clusterRemoveRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, clusterBodyLimit))
	if err := dec.Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	rec, err := a.store.Get(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "集群不存在")
		return
	}

	force := rec.Status == ClusterStatusUnreachable
	if force {
		// 强制摘除：不可达声明 + 租户离线处置确认（不校验集群凭证——不可达集群无法提供）。
		if strings.TrimSpace(body.UnreachableDeclaration) == "" {
			writeError(w, http.StatusBadRequest, "unreachable 强制摘除须提交集群不可达声明")
			return
		}
		if strings.TrimSpace(body.TenantOfflineDisposition) == "" {
			writeError(w, http.StatusBadRequest, "unreachable 强制摘除须提交租户离线处置/放弃确认")
			return
		}
	} else {
		// 普通摘除前置：状态须为 active/degraded，且须声明无租户绑定或已显式迁移。
		if rec.Status != ClusterStatusActive && rec.Status != ClusterStatusDegraded {
			writeError(w, http.StatusConflict, "仅 active/degraded 集群可走普通摘除路径（当前状态 "+string(rec.Status)+"）")
			return
		}
		switch strings.TrimSpace(body.TenantDisposition) {
		case tenantDispositionNone, tenantDispositionMigrated:
		default:
			writeError(w, http.StatusBadRequest, "tenant_disposition 必填且取值 none（无租户绑定）或 migrated（已显式迁移）")
			return
		}
		// 普通摘除校验集群身份凭证（操作者确与该集群身份绑定）。
		if err := a.verifyClusterCredential(r, id); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
	}

	// 双签校验（actor 不同 / target 绑定 / ≤15min / 一次性消费）。
	c := claimsFrom(r.Context())
	now := time.Now()
	if err := a.approvals.ValidateDualApproval(c.Sub, id, body.DualApprovalIDs, now); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}
	detail := "摘除集群 " + id
	if force {
		detail += "（unreachable 强制摘除路径：不可达声明 + 租户离线处置确认）"
	} else {
		detail += "（普通摘除路径：tenant_disposition=" + strings.TrimSpace(body.TenantDisposition) + "）"
	}
	// 审计先行：落链失败不执行摘除（fail-closed）。
	if err := a.approvals.AppendRegistryChange(c.Sub, id, body.DualApprovalIDs, detail); err != nil {
		log.Printf("[adminext] 集群摘除审计落链失败（cluster=%s sub=%s）: %v", id, c.Sub, err)
		writeError(w, http.StatusInternalServerError, "审计链写入失败，摘除未执行")
		return
	}
	// 执行状态变更。
	target := ClusterStatusRemoved
	if force {
		target = ClusterStatusQuarantined // 强制路径置隔离，保留取证痕迹
	}
	if err := a.store.SetStatus(r.Context(), id, target, now); err != nil {
		writeError(w, http.StatusInternalServerError, "摘除执行失败: "+err.Error())
		return
	}
	// 摘除即吊销其集群身份凭证（后续请求一律拒绝）。
	if a.creds != nil {
		if _, err := a.creds.RevokeAll(r.Context(), id, now); err != nil {
			log.Printf("[adminext] 集群凭证吊销失败（cluster=%s）: %v", id, err)
		}
	}
	// 审批一次性消费。
	a.approvals.ConsumeDualApproval(body.DualApprovalIDs, now)
	w.WriteHeader(http.StatusNoContent)
}

// verifyClusterCredential 校验集群身份凭证（fail-closed）。
func (a *clusterAPI) verifyClusterCredential(r *http.Request, clusterID string) error {
	token := strings.TrimSpace(r.Header.Get(clusterCredentialHeader))
	if token == "" {
		return fmt.Errorf("缺少集群身份凭证（请求头 %s）", clusterCredentialHeader)
	}
	if a.creds == nil {
		return fmt.Errorf("集群身份凭证校验未启用（fail-closed）")
	}
	if _, err := a.creds.Verify(r.Context(), clusterID, token, time.Now()); err != nil {
		return fmt.Errorf("集群身份凭证校验失败: %w", err)
	}
	return nil
}

// registerClusterRoutes 注册集群注册相关路由。
//
// 路由分层：
//   - `/v1/adminext/clusters`（精确）→ 注册/列表（挂管理面会话中间件）；
//   - `/v1/adminext/clusters/`（子树）→ 审批/摘除（挂管理面会话中间件）；
//   - `POST /v1/adminext/clusters/{id}/heartbeat`（方法化，更具体）→ 心跳，
//     **不挂管理面会话中间件**：调用方是集群自身，凭集群身份凭证认证。
func registerClusterRoutes(mux *http.ServeMux, cfg *config, api *clusterAPI) {
	if api == nil {
		return
	}
	mux.HandleFunc("/v1/adminext/clusters", authMiddleware(cfg, api.handleClusters))
	mux.HandleFunc("/v1/adminext/clusters/", authMiddleware(cfg, api.handleClusterSubtree))
	mux.HandleFunc("POST /v1/adminext/clusters/{id}/heartbeat", api.handleHeartbeatByPath)
}

// handleClusters 精确路径分发：POST 注册 / GET 列表。
func (a *clusterAPI) handleClusters(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		a.handleRegister(w, r)
	case http.MethodGet:
		a.handleList(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET/POST")
	}
}

// clusterIDFromPath 从 `/v1/adminext/clusters/{id}[/...]` 中取出集群 ID。
func clusterIDFromPath(r *http.Request) string {
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/adminext/clusters/"), "/")
	if p == "" {
		return ""
	}
	parts := strings.Split(p, "/")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	return parts[0]
}

// handleHeartbeatByPath 方法化路由入口（PathValue 取 ID）。
func (a *clusterAPI) handleHeartbeatByPath(w http.ResponseWriter, r *http.Request) {
	a.handleHeartbeat(w, r, r.PathValue("id"))
}

// handleClusterSubtree 处理 /v1/adminext/clusters/ 子树：审批（POST）与摘除（DELETE）。
func (a *clusterAPI) handleClusterSubtree(w http.ResponseWriter, r *http.Request) {
	p := strings.Trim(strings.TrimPrefix(r.URL.Path, "/v1/adminext/clusters/"), "/")
	parts := strings.Split(p, "/")
	switch {
	case len(parts) == 1 && parts[0] != "" && r.Method == http.MethodDelete:
		a.handleRemove(w, r, parts[0])
	case len(parts) == 1 && parts[0] != "":
		writeError(w, http.StatusMethodNotAllowed, "仅支持 DELETE")
	case len(parts) == 2 && parts[1] == "approval" && r.Method == http.MethodPost:
		a.handleApproval(w, r, parts[0])
	case len(parts) == 2 && parts[1] == "heartbeat" && r.Method == http.MethodPost:
		a.handleHeartbeat(w, r, parts[0])
	default:
		writeError(w, http.StatusNotFound, "端点不存在")
	}
}
