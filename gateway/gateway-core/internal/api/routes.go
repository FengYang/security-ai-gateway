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
		"valid":       true,
		"route_count": len(req.Routes),
		"changes":     changes,
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

// ============================================================
// P1-6 M3.4：TTFT 上报端点（数据面 → 控制面，§6.2）
// ============================================================

// ttftReportRequest 上报报文（§6.2，数据面 M2.3 构造）。
type ttftReportRequest struct {
	Node       string             `json:"node"`
	Worker     int                `json:"worker"`
	BatchID    string             `json:"batch_id"`
	ReportedAt int64              `json:"reported_at"` // 毫秒时间戳
	Samples    []ttftReportSample `json:"samples"`
}

type ttftReportSample struct {
	Tenant   string   `json:"tenant"`
	Model    string   `json:"model"`
	Endpoint string   `json:"endpoint"`
	Cache    string   `json:"cache"`
	Buckets  []uint64 `json:"buckets"`
}

// ttftReportMaxSamples 单批 samples 条目数上限（§6.2 TT2-08，与下发侧对称；超限 400 too_many_samples）。
const ttftReportMaxSamples = 1000

// handleTTFTReport POST /routes/ttft/report（至少一次 + 按 batch_id 去重，§6.2）。
//
// 处理序（全或无；400 拒绝不消耗 batch_id）：
//  1. 结构校验（JSON / batch_id / reported_at / samples 非空与条数上限）；
//  2. 逐样本值域校验（tenant/model/endpoint/cache、buckets 长度 11 与单桶上限、
//     reported_at 时间窗——窗口取该 (tenant,model) 路由 latency 配置）+ 白名单（TT2-08）；
//  3. 单批总样本上限；
//  4. batch_id 去重：重复 → 200 result=duplicate（ACK 丢弃，数据面据此清待确认队列）；
//  5. 聚合条目容量预检（超限 503 source_unavailable）→ 落片 → 200 result=ok。
func (s *Server) handleTTFTReport(w http.ResponseWriter, r *http.Request) {
	reject := func(msg string) {
		s.metrics.incReportResult("reject")
		writeError(w, http.StatusBadRequest, "invalid_request", msg)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		reject("请求体读取失败")
		return
	}
	var req ttftReportRequest
	if err := json.Unmarshal(body, &req); err != nil {
		reject(fmt.Sprintf("请求体 JSON 解析失败: %v", err))
		return
	}
	if req.BatchID == "" {
		reject("batch_id 不能为空（去重键）")
		return
	}
	if req.ReportedAt <= 0 {
		reject("reported_at 必须为毫秒时间戳")
		return
	}
	if len(req.Samples) == 0 {
		reject("samples 不能为空")
		return
	}
	if len(req.Samples) > ttftReportMaxSamples {
		reject(fmt.Sprintf("samples 条目数 %d 超出上限 %d（too_many_samples）", len(req.Samples), ttftReportMaxSamples))
		return
	}

	tbl := s.store.GetRouteTable()
	nowSec := time.Now().Unix()
	reportedAtSec := req.ReportedAt / 1000

	type landing struct {
		key       route.TTFTKey
		buckets   [route.TTFTBucketCount]uint64
		windowSec int
	}
	landings := make([]landing, 0, len(req.Samples))
	var total uint64
	for i := range req.Samples {
		sm := &req.Samples[i]
		if sm.Tenant == "" || sm.Model == "" || sm.Endpoint == "" {
			reject(fmt.Sprintf("samples[%d] tenant/model/endpoint 不能为空", i))
			return
		}
		if sm.Cache != "hit" && sm.Cache != "miss" {
			reject(fmt.Sprintf("samples[%d] cache 须为 hit/miss，got %q", i, sm.Cache))
			return
		}
		if len(sm.Buckets) != route.TTFTBucketCount {
			reject(fmt.Sprintf("samples[%d] buckets 长度须为 %d，got %d", i, route.TTFTBucketCount, len(sm.Buckets)))
			return
		}
		var b [route.TTFTBucketCount]uint64
		copy(b[:], sm.Buckets)
		if err := route.ValidateTTFTBucketCounts(&b); err != nil {
			reject(fmt.Sprintf("samples[%d] %v", i, err))
			return
		}
		// 该 (tenant,model) 生效窗口（路由 latency 配置；缺省 300s）
		win := route.TTFTDefaultWindowSec
		if rt := tbl.Lookup(sm.Tenant, sm.Model); rt != nil && rt.Latency != nil && rt.Latency.WindowSec > 0 {
			win = rt.Latency.WindowSec
		}
		if !route.TTFTReportedAtInWindow(reportedAtSec, nowSec, win) {
			reject(fmt.Sprintf("samples[%d] reported_at 越窗（now=%d window=%ds，TT2-03）", i, nowSec, win))
			return
		}
		if !tbl.KnowsEndpoint(sm.Tenant, sm.Model, sm.Endpoint) {
			reject(fmt.Sprintf("samples[%d] 未知端点 (%s,%s,%s) 不在当前路由表（TT2-08）", i, sm.Tenant, sm.Model, sm.Endpoint))
			return
		}
		for _, c := range b {
			total += c
		}
		landings = append(landings, landing{
			key:       route.TTFTKey{Tenant: sm.Tenant, Model: sm.Model, Endpoint: sm.Endpoint, Cache: sm.Cache},
			buckets:   b,
			windowSec: win,
		})
	}
	if err := route.ValidateTTFTBatchTotal(total); err != nil {
		reject(err.Error())
		return
	}

	// batch_id 去重：重复批次 ACK 丢弃（验证通过后才登记，400 拒绝不消耗 batch_id）
	if s.ttftDedup.Seen(req.BatchID, nowSec) {
		s.metrics.incReportResult("duplicate")
		writeJSON(w, http.StatusOK, map[string]string{"result": "duplicate"})
		return
	}
	// 容量预检（TT2-08：条目数上限；整体拒绝避免部分落片）
	keys := make([]route.TTFTKey, 0, len(landings))
	for _, ld := range landings {
		keys = append(keys, ld.key)
	}
	if !s.ttftRing.HasRoomFor(keys) {
		s.metrics.incReportResult("reject")
		writeError(w, http.StatusServiceUnavailable, "source_unavailable",
			"TTFT 聚合条目数已达上限（TT2-08；需运维 reset 或扩容）")
		return
	}
	for _, ld := range landings {
		if res := s.ttftRing.Record(ld.key, &ld.buckets, reportedAtSec, ld.windowSec); res != route.TTFTIngestOK {
			// 防御路径（预检后仅并发竞态可触达）；batch_id 已登记，重试将按 duplicate ACK
			s.metrics.incReportResult("reject")
			writeError(w, http.StatusServiceUnavailable, "source_unavailable", "TTFT 聚合器拒绝落片")
			return
		}
	}
	s.metrics.incReportResult("ok")
	writeJSON(w, http.StatusOK, map[string]string{"result": "ok"})
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
