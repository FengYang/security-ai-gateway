// Package main — 租户账号目录反查（§6.11 / §8 依赖 4，M8 Go 侧）。
//
// 端点（管理面 listener，authMiddleware；Console 内部专用，非租户直连）：
//
//	GET /v1/adminext/tenant-directory/lookup?email=<归一化邮箱>
//	  命中    → 200 {tenant_id, status, tenant_role:"tenant_user"}
//	  未命中  → 404（**禁止 Console 兜底 admin**，C-14）
//	  邮箱非法 → 400
//
// 定位：Console 登录时 `AdminExtUserStore.resolveRole` 依此反查租户目录
// （单一真源 = Go tenant store，禁止 Console 复制账号表，C-14）；
// 未命中不得回退 admin；目录不可达（本服务 5xx / 网络故障）→ Console 登录失败（不放行）。
package main

import (
	"log"
	"net/http"
)

const tenantDirectoryLookupPath = "/v1/adminext/tenant-directory/lookup"

// tenantDirectoryView 目录反查响应（§6.11）。
type tenantDirectoryView struct {
	TenantID   string `json:"tenant_id"`
	Status     string `json:"status"`      // 账号状态：active | pending | locked
	TenantRole string `json:"tenant_role"` // 恒 "tenant_user"
}

// registerTenantDirectory 注册目录反查端点（管理面 authMiddleware；Console 内部端点）。
func (h *tenantHandler) registerTenantDirectory(mux *http.ServeMux, cfg *config) {
	mux.HandleFunc(tenantDirectoryLookupPath, authMiddleware(cfg, h.handleTenantDirectoryLookup))
}

// handleTenantDirectoryLookup 按邮箱反查租户账号（命中/未命中/非法三分支）。
func (h *tenantHandler) handleTenantDirectoryLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		tenantWriteError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	email := normalizeEmail(r.URL.Query().Get("email"))
	if !validEmail(email) {
		tenantWriteError(w, http.StatusBadRequest, "email 非法")
		return
	}
	user, err := h.store.GetUserByEmail(email)
	if err != nil {
		// 目录不可达 → 503（Console 侧据此判登录失败，不放行；不静默 404）
		log.Printf("[tenant-directory] 目录查询失败: %v", err)
		tenantWriteError(w, http.StatusServiceUnavailable, "目录不可达")
		return
	}
	if user == nil {
		tenantWriteError(w, http.StatusNotFound, "not found")
		return
	}
	tenantWriteJSON(w, http.StatusOK, tenantDirectoryView{
		TenantID:   user.TenantID,
		Status:     user.Status,
		TenantRole: tenantRole,
	})
}
