package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
)

// 本文件实现方案 §4.1 的路由配置管理 API（P0 必做 11 个）：
//   GET    /routes                  拉取当前完整路由表（含签名，数据面拉路径）
//   GET    /routes/{tenant}/{model} 查询单条路由配置
//   PUT    /routes/{tenant}/{model} 创建/更新单条路由（upsert）
//   DELETE /routes/{tenant}/{model} 删除单条路由
//   POST   /routes/dry-run          预演配置变更（校验+diff，不生效）
//   GET    /routes/endpoints/status 端点状态查询（P0 仅配置静态视图）
//   POST   /routes/rollback         按 version 回滚
//   GET    /routes/history          版本历史 + 审计链查询
//   POST   /routes/push             配置推送（P0 空实现，数据面主动拉取）
//   GET    /routes/audit            路由变更审计日志查询
//
// 请求体上限由 main.go 的 limitBody 中间件统一约束（4MiB）。

// ============================================================
// 单条路由：查询 / 更新 / 删除
// ============================================================

// handleGetRoute 查询单条路由配置。
func (s *Server) handleGetRoute(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	model := r.PathValue("model")
	tbl := s.store.GetRouteTable()
	if tbl == nil {
		writeError(w, http.StatusNotFound, "not_found", "路由表不存在")
		return
	}
	rt := tbl.Lookup(tenant, model)
	if rt == nil {
		writeError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("路由 tenant=%q model=%q 不存在", tenant, model))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version": tbl.Version,
		"route":   rt,
	})
}

// handleUpsertRoute 创建或更新单条路由（按 tenant+model 定位）。
// 整体版本号递增 + 重新签名 + 落审计链。
func (s *Server) handleUpsertRoute(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	model := r.PathValue("model")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	var rt route.TableRoute
	if err := json.Unmarshal(body, &rt); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("请求体 JSON 解析失败: %v", err))
		return
	}
	// 路径参数覆盖 body 中的 tenant/model（防路径与 body 不一致）
	rt.Tenant = tenant
	rt.Model = model
	if err := rt.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_route", err.Error())
		return
	}

	tbl := s.store.GetRouteTable()
	if tbl == nil {
		tbl = route.NewRouteTable(0, 0)
	}
	nextVer := tbl.Version + 1

	// 深拷贝 + upsert
	newTbl := tbl.Clone()
	newTbl.Version = nextVer
	newTbl.UpdatedAt = time.Now().Unix()
	found := false
	for i := range newTbl.Routes {
		if newTbl.Routes[i].Tenant == tenant && newTbl.Routes[i].Model == model {
			newTbl.Routes[i] = rt
			found = true
			break
		}
	}
	if !found {
		newTbl.Routes = append(newTbl.Routes, rt)
	}

	// 整体校验
	if err := newTbl.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_route_table", err.Error())
		return
	}

	s.applyRouteTable(w, r, newTbl, policyaudit.ActionApply, tbl.Version)
}

// handleDeleteRoute 删除单条路由。
func (s *Server) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	tenant := r.PathValue("tenant")
	model := r.PathValue("model")
	tbl := s.store.GetRouteTable()
	if tbl == nil {
		writeError(w, http.StatusNotFound, "not_found", "路由表不存在")
		return
	}
	if tbl.Lookup(tenant, model) == nil {
		writeError(w, http.StatusNotFound, "not_found",
			fmt.Sprintf("路由 tenant=%q model=%q 不存在", tenant, model))
		return
	}

	nextVer := tbl.Version + 1
	newTbl := tbl.Clone()
	newTbl.Version = nextVer
	newTbl.UpdatedAt = time.Now().Unix()
	newRoutes := make([]route.TableRoute, 0, len(newTbl.Routes)-1)
	for _, r := range newTbl.Routes {
		if r.Tenant == tenant && r.Model == model {
			continue
		}
		newRoutes = append(newRoutes, r)
	}
	newTbl.Routes = newRoutes

	s.applyRouteTable(w, r, newTbl, policyaudit.ActionApply, tbl.Version)
}

// ============================================================
// Dry-run：预演配置变更（校验+diff，不生效）
// ============================================================

// dryRunReq 预演请求体：传入待变更的路由表，返回校验结果与差异。
type dryRunReq struct {
	Routes []route.TableRoute `json:"routes"`
}

// handleDryRun 预演配置变更（方案 §4.1.2）。
// 校验通过返回 diff 摘要；校验失败返回具体错误。
func (s *Server) handleDryRun(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	var req dryRunReq
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Sprintf("请求体 JSON 解析失败: %v", err))
		return
	}

	candidate := &route.RouteTable{
		Version:   0, // dry-run 不计版本
		UpdatedAt: time.Now().Unix(),
		Routes:    req.Routes,
	}
	if err := candidate.Validate(); err != nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	cur := s.store.GetRouteTable()
	changes := route.DiffRoutes(cur, candidate)
	added, updated, removed := 0, 0, 0
	for _, c := range changes {
		switch c.Change {
		case "add":
			added++
		case "modify":
			updated++
		case "remove":
			removed++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"valid":        true,
		"route_count":  len(req.Routes),
		"changes":      changes,
		"changes_summary": map[string]int{
			"added":   added,
			"updated": updated,
			"removed": removed,
		},
		"note": "仅预演校验与差异对比，未实际生效。需生效请调用 PUT /routes/{tenant}/{model}。",
	})
}

// ============================================================
// 端点状态查询（P0 仅配置静态视图）
// ============================================================

// handleEndpointStatus 返回所有端点的配置层面状态（方案 §4.1.4）。
// P0 限制：仅返回配置层面的静态状态（enabled/priority/weight）；
// 运行时实时状态（健康度/失败率/熔断状态）通过 §10 可观测性指标获取。
func (s *Server) handleEndpointStatus(w http.ResponseWriter, r *http.Request) {
	tbl := s.store.GetRouteTable()
	if tbl == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"endpoints": []any{},
			"note":      "当前无路由配置",
		})
		return
	}

	type epStatus struct {
		Tenant   string  `json:"tenant"`
		Model    string  `json:"model"`
		Name     string  `json:"name"`
		URL      string  `json:"url"`
		Weight   float64 `json:"weight"`
		Priority int     `json:"priority"`
		Enabled  bool    `json:"enabled"`
		HasAuth  bool    `json:"has_auth"`
	}

	result := []epStatus{}
	for _, rt := range tbl.Routes {
		for _, ep := range rt.Endpoints {
			result = append(result, epStatus{
				Tenant:   rt.Tenant,
				Model:    rt.Model,
				Name:     ep.Name,
				URL:      ep.URL,
				Weight:   ep.Weight,
				Priority: ep.Priority,
				Enabled:  ep.Enabled,
				HasAuth:  ep.Auth.SecretRef != "",
			})
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version":   tbl.Version,
		"endpoints": result,
		"total":     len(result),
		"note":      "P0 仅返回配置静态视图；运行时健康度/失败率/熔断状态请通过 Prometheus 指标查看（otpmask_route_*）",
	})
}

// ============================================================
// 回滚 + 历史
// ============================================================

// routeRollbackReq 回滚请求体。
type routeRollbackReq struct {
	Version int `json:"version"`
}

// handleRouteRollback 按版本回滚路由表（以历史版本构造新版本，保持版本单调）。
func (s *Server) handleRouteRollback(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "请求体读取失败")
		return
	}
	var req routeRollbackReq
	if err := json.Unmarshal(body, &req); err != nil || req.Version <= 0 {
		writeError(w, http.StatusBadRequest, "invalid_request",
			"请求体须为 JSON 且含正整数 version")
		return
	}
	cur := s.store.GetRouteTable()
	if cur == nil {
		writeError(w, http.StatusConflict, "no_table", "当前无生效路由表，无可回滚")
		return
	}
	src := s.findRouteHistory(req.Version)
	if src == nil {
		writeError(w, http.StatusBadRequest, "version_not_in_history",
			fmt.Sprintf("历史中无版本 %d（仅保留最近 %d 版，进程重启后仅剩当前版本）",
				req.Version, policyHistoryLimit))
		return
	}
	next := src.Clone()
	next.Version = cur.Version + 1
	next.UpdatedAt = time.Now().Unix()
	s.applyRouteTable(w, r, next, policyaudit.ActionRollback, cur.Version)
}

// handleRouteHistory 返回路由表变更历史 + 审计链校验结果。
func (s *Server) handleRouteHistory(w http.ResponseWriter, r *http.Request) {
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
	tbl := s.store.GetRouteTable()
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

// ============================================================
// 配置推送（P0 空实现）
// ============================================================

// handleRoutePush 配置推送触发（P0 空实现）。
// P0 数据面采用主动拉取模式（pull），本接口仅返回当前版本号，
// 便于管理面确认"配置已在控制面生效"。
func (s *Server) handleRoutePush(w http.ResponseWriter, r *http.Request) {
	tbl := s.store.GetRouteTable()
	ver := 0
	if tbl != nil {
		ver = tbl.Version
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"version":   ver,
		"pushed":    false,
		"note":      "P0 数据面采用主动拉取模式（GET /routes），无主动推送通道。数据面下次拉取将获得最新版本。",
		"pull_path": "/routes",
	})
}

// ============================================================
// 审计日志查询
// ============================================================

// handleRouteAudit 路由变更审计日志查询（与 history 同源，独立路径便于权限划分）。
func (s *Server) handleRouteAudit(w http.ResponseWriter, r *http.Request) {
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
	writeJSON(w, http.StatusOK, map[string]any{
		"chain_ok":        ok,
		"chain_broken_at": brokenAt,
		"events":          s.audit.List(limit),
		"events_total":    s.audit.Len(),
	})
}

// ============================================================
// 内部：apply + 历史 + 审计
// ============================================================

// applyRouteTable 统一的路由表生效路径（upsert / delete / rollback 共用）：
// 差异计算 → 签名 → 落库 → 变更审计落链 → 返回结果。
func (s *Server) applyRouteTable(w http.ResponseWriter, r *http.Request,
	tbl *route.RouteTable, action string, fromVersion int) {

	prev := s.store.GetRouteTable()
	changes := route.DiffRoutes(prev, tbl)

	// 签名
	if err := s.signer.SignTable(tbl); err != nil {
		writeError(w, http.StatusInternalServerError, "sign_failed", "路由表签名失败")
		return
	}
	// 落库
	s.store.SaveRouteTable(tbl)
	s.recordRouteHistory(tbl)

	// 变更审计落链（fail-closed：落链失败即拒绝 2xx）
	if err := s.appendRouteAudit(r, action, fromVersion, tbl.Version, changes); err != nil {
		writeError(w, http.StatusInternalServerError, "audit_failed",
			fmt.Sprintf("路由已在控制面生效但变更审计写入失败（fail-closed；请人工核查审计文件后决定是否重试）: %v", err))
		return
	}

	added, updated, removed := 0, 0, 0
	for _, c := range changes {
		switch c.Change {
		case "add":
			added++
		case "modify":
			updated++
		case "remove":
			removed++
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"version": tbl.Version,
		"action":  action,
		"routes":  len(tbl.Routes),
		"changes_summary": map[string]int{
			"added":   added,
			"updated": updated,
			"removed": removed,
		},
		"changes": changes,
	})
}

// appendRouteAudit 路由变更审计落链（逐条路由差异 = 一条链上事件）。
func (s *Server) appendRouteAudit(r *http.Request, action string, from, to int,
	changes []route.RouteChange) error {

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
		ev.RuleID = "route_table"
		_, err := s.audit.Append(ev)
		return err
	}
	for _, c := range changes {
		ev := base
		ev.RuleID = c.Tenant + "/" + c.Model
		ev.Change = c.Change
		ev.Field = c.Field
		ev.OldValue = c.Old
		ev.NewValue = c.New
		if _, err := s.audit.Append(ev); err != nil {
			return err
		}
	}
	return nil
}

// routeHistory 路由表历史版本（与 ratelimit 的 history 分开存储，避免互串）。
// 为保持简洁，复用同一 histMu 互斥锁（两者都是配置面操作，并发度低）。
//
// 注：Server.history 字段原用于 ratelimit.Table；路由历史另行存储。
// 为最小化改动，路由历史存在独立切片中。
var routeHistoryStore []*route.RouteTable

// recordRouteHistory 记录路由表历史版本（保留最近 policyHistoryLimit 版）。
func (s *Server) recordRouteHistory(t *route.RouteTable) {
	if t == nil {
		return
	}
	s.histMu.Lock()
	defer s.histMu.Unlock()
	routeHistoryStore = append(routeHistoryStore, t.Clone())
	if len(routeHistoryStore) > policyHistoryLimit {
		routeHistoryStore = routeHistoryStore[len(routeHistoryStore)-policyHistoryLimit:]
	}
}

// findRouteHistory 按 version 查找路由表历史版本。
func (s *Server) findRouteHistory(version int) *route.RouteTable {
	s.histMu.Lock()
	defer s.histMu.Unlock()
	for i := len(routeHistoryStore) - 1; i >= 0; i-- {
		if routeHistoryStore[i].Version == version {
			return routeHistoryStore[i].Clone()
		}
	}
	return nil
}
