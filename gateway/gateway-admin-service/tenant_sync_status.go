// Package main — P2-4 T-3.3 收敛核对 API（§6.2 T-3④）。
//
// GET /v1/adminext/clusters/sync-status 输出各租户 × 各集群「期望版本 vs 实际版本」
// 差异表。实际版本取自集群上报的 applied_config_version（心跳落库）；未上报标记
// unknown 并置 alert（禁止以"未见差异"默认收敛，RSK-3 / §6.2）。
package main

import (
	"log"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// syncStatusPath 收敛核对端点（§6.2）：GET /v1/adminext/clusters/sync-status。
const syncStatusPath = "/v1/adminext/clusters/sync-status"

// syncStatusEntry 单条「期望版本 vs 实际版本」差异记录。
type syncStatusEntry struct {
	TenantID        string `json:"tenant_id"`
	TenantName      string `json:"tenant_name,omitempty"`
	ClusterID       string `json:"cluster_id"` // "" = 全局（全部集群）
	ClusterName     string `json:"cluster_name,omitempty"`
	ExpectedVersion string `json:"expected_version"` // 期望 config_version（期望下发的版本）
	ActualVersion   string `json:"actual_version"`   // 集群上报 applied_config_version；未上报="unknown"
	DispatchStatus  string `json:"dispatch_status"`  // 该 pair 的下发状态机状态
	Converged       bool   `json:"converged"`        // actual==expected（仅 actual 已知时可为 true）
}

// syncStatusResponse 收敛核对总览。
type syncStatusResponse struct {
	GeneratedAt            int64             `json:"generated_at"`
	ClusterRegistryEnabled bool              `json:"cluster_registry_enabled"`
	Total                  int               `json:"total"`
	Converged              int               `json:"converged"`
	Diverged               int               `json:"diverged"` // actual 已知但 != expected
	Unknown                int               `json:"unknown"`  // 未上报 / 注册表未启用
	Alert                  bool              `json:"alert"`    // Diverged>0 或 Unknown>0
	Entries                []syncStatusEntry `json:"entries"`
}

// registerSyncStatus 在管理面 mux 注册收敛核对端点（admin-only）。
func (h *tenantHandler) registerSyncStatus(mux *http.ServeMux, cfg *config) {
	mux.HandleFunc(syncStatusPath, authMiddleware(cfg, h.handleSyncStatus))
}

// handleSyncStatus GET /v1/adminext/clusters/sync-status：
// 遍历租户 × 各集群下发行，比对期望 config_version 与集群上报 applied_config_version；
// 未上报标记 unknown 并置 alert（禁止以"未见差异"默认收敛，RSK-3 / §6.2 T-3④）。
func (h *tenantHandler) handleSyncStatus(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, roleAdmin) {
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()

	// 1. 集群注册表（nil = 未启用 ⇒ 全部 actual=unknown，fail-closed）。
	var clusterByID map[string]*ClusterRecord
	registryEnabled := false
	if h.clusterStore != nil {
		recs, err := h.clusterStore.List(ctx)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "列出集群失败: " + err.Error()})
			return
		}
		clusterByID = make(map[string]*ClusterRecord, len(recs))
		for _, rec := range recs {
			if !rec.RemovedAt.IsZero() {
				continue // 已摘除 ⇒ 不再作为目标
			}
			clusterByID[rec.ID] = rec
		}
		registryEnabled = true
	}

	// 2. 全部租户（取名称 + 枚举基数）。
	tenants, err := h.store.ListAllTenants()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "列出租户失败: " + err.Error()})
		return
	}
	tenantName := make(map[string]string, len(tenants))
	for _, t := range tenants {
		tenantName[t.ID] = t.Name
	}

	// 3. 枚举每个租户的下发行，构造 (tenant, cluster) 管理对。
	type managedPair struct {
		clusterID string
		expected  int64
		status    string
	}
	var entries []syncStatusEntry
	for _, t := range tenants {
		rows, err := h.store.ListDispatchStatesByTenant(t.ID)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "列出下发行失败: " + err.Error()})
			return
		}
		if len(rows) == 0 {
			continue
		}
		var globalRow *TenantDispatchState
		perCluster := make(map[string]*TenantDispatchState)
		for _, row := range rows {
			if row.ClusterID == dispatchClusterGlobal {
				globalRow = row
			} else {
				perCluster[row.ClusterID] = row
			}
		}

		var pairs []managedPair
		if registryEnabled {
			// 全局行 ⇒ 所有已注册（未摘除）集群；具体集群行覆盖期望值/状态。
			if globalRow != nil {
				for cid := range clusterByID {
					exp, st := globalRow.ConfigVersion, globalRow.Status
					if pr, ok := perCluster[cid]; ok {
						exp, st = pr.ConfigVersion, pr.Status
					}
					pairs = append(pairs, managedPair{clusterID: cid, expected: exp, status: st})
				}
			}
			// 具体集群行：仅当未被全局扇出覆盖（无全局行，或集群不在注册表）时才独立核对；
			// 在注册表内且已有全局行覆盖的，跳过以避免重复条目。
			for cid, pr := range perCluster {
				if globalRow != nil {
					if _, ok := clusterByID[cid]; ok {
						continue
					}
				}
				pairs = append(pairs, managedPair{clusterID: cid, expected: pr.ConfigVersion, status: pr.Status})
			}
		} else {
			// 注册表未启用：全局行以 cluster_id="" 代表"全部集群"，actual=unknown；
			// 具体集群行同样 unknown（无法取 actual）。
			if globalRow != nil {
				pairs = append(pairs, managedPair{clusterID: dispatchClusterGlobal, expected: globalRow.ConfigVersion, status: globalRow.Status})
			}
			for cid, pr := range perCluster {
				pairs = append(pairs, managedPair{clusterID: cid, expected: pr.ConfigVersion, status: pr.Status})
			}
		}
		sort.Slice(pairs, func(i, j int) bool { return pairs[i].clusterID < pairs[j].clusterID })

		for _, p := range pairs {
			actual := "unknown"
			if p.clusterID != dispatchClusterGlobal {
				if rec, ok := clusterByID[p.clusterID]; ok && rec.Applied != "" {
					actual = rec.Applied
				}
			}
			converged := false
			if actual != "unknown" {
				if av, perr := strconv.ParseInt(actual, 10, 64); perr == nil {
					converged = (av == p.expected)
				}
			}
			entries = append(entries, syncStatusEntry{
				TenantID:        t.ID,
				TenantName:      tenantName[t.ID],
				ClusterID:       p.clusterID,
				ClusterName:     clusterName(clusterByID, p.clusterID),
				ExpectedVersion: strconv.FormatInt(p.expected, 10),
				ActualVersion:   actual,
				DispatchStatus:  p.status,
				Converged:       converged,
			})
		}
	}

	resp := syncStatusResponse{
		GeneratedAt:            time.Now().Unix(),
		ClusterRegistryEnabled: registryEnabled,
		Entries:                entries,
	}
	for i := range entries {
		resp.Total++
		switch {
		case entries[i].Converged:
			resp.Converged++
		case entries[i].ActualVersion == "unknown":
			resp.Unknown++
		default:
			resp.Diverged++
		}
	}
	// 禁止以"未见差异"默认收敛（§6.2 T-3④）：差异>0 或 未上报>0 ⇒ 告警（非阻断）。
	resp.Alert = resp.Diverged > 0 || resp.Unknown > 0
	if resp.Alert {
		log.Printf("[sync-status] 收敛核对告警：total=%d converged=%d diverged=%d unknown=%d",
			resp.Total, resp.Converged, resp.Diverged, resp.Unknown)
	}
	writeJSON(w, http.StatusOK, resp)
}

// clusterName 取集群显示名（注册表未启用 / 未知集群返回空）。
func clusterName(byID map[string]*ClusterRecord, id string) string {
	if id == dispatchClusterGlobal {
		return ""
	}
	if rec, ok := byID[id]; ok {
		return rec.Name
	}
	return ""
}
