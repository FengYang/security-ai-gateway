// Package main — P1-2 排障查询 API（M6，§6.3 / §7.7）。
//
// 端点（统一前缀 /v1/adminext，鉴权 authMiddleware，auditor/admin 均可读）：
//
//	GET /v1/adminext/trace/search                 多维检索（映射 Tempo Search API）
//	GET /v1/adminext/trace/{request_id}           单请求全链路聚合（span 树 + 审计 + 耗时分解）
//	GET /v1/adminext/trace/{request_id}/report   导出排障报告（application/json | text/csv）
//
// 数据源与 503 语义（对齐 sec_center.go：不静默返回空）：
//   - Tempo 查询地址未配置（ADMIN_TEMPO_URL）→ 503；
//   - Tempo 不可达 → 503；
//   - tee-infer 审计代理不可达 → 审计段降级为空并如实标注（audit.available=false），
//     span 段仍返回（排障以 trace 为主，审计为佐证）。
//
// 安全约束（§6.3）：
//   - 响应仅含 §6.2 白名单属性与审计元数据；无原文、无金额（C-1/C-5）；
//   - 租户隔离：非 admin 会话仅可访问本声明租户；跨租户/缺省 tenant → 403（fail-closed）；
//   - CSV 导出防公式注入：以 = + - @ \t \r 开头的字段值前置单引号（'）。
package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	traceSearchPath     = "/v1/adminext/trace/search"
	traceBasePath       = "/v1/adminext/trace/"
	traceReportSuffix   = "/report"
	traceQueryTimeout   = 5 * time.Second
	traceSearchMaxLimit = 200
	traceSearchDefLimit = 50
)

// traceAllowedAttrs 允许出现在响应中的 span 属性键（§6.2 白名单 + §7.4 M3 扩展）。
// 白名单外一律丢弃（纵深防御：即便 Tempo 侧存在残留属性也不外泄）。
var traceAllowedAttrs = map[string]struct{}{
	"tenant.id": {}, "request.id": {}, "model.id": {}, "engine.type": {},
	"cache.hit": {}, "cache.mode": {}, "tokens.in": {}, "tokens.out": {},
	"result": {}, "deny.reason": {}, "og.category": {}, "og.mode": {},
	"is.retry": {}, "http.status_code": {}, "ttft.ms": {},
	"input.digest": {}, "output.digest": {},
	// M3 控制面/管理面（§7.4）
	"http.method": {}, "http.request.method": {}, "http.route": {}, "url.path": {},
	"user.role": {}, "route.name": {}, "change.type": {},
}

// traceStatusEnum 检索端点 status 枚举（§6.3：枚举外值 → 400）。
var traceStatusEnum = map[string]struct{}{
	"ok": {}, "client_error": {}, "server_error": {}, "denied": {},
}

// traceHandler 排障查询 handler。
type traceHandler struct {
	tempoURL string // Tempo 查询 API 基地址（空 = 未配置 → 503）
	settings *usageSettings
	client   *http.Client
}

// newTraceHandler 装配排障查询 handler（恒注册；数据源缺失时按 503 语义返回）。
func newTraceHandler(tempoURL string, s *usageSettings) *traceHandler {
	return &traceHandler{
		tempoURL: strings.TrimRight(tempoURL, "/"),
		settings: s,
		client:   &http.Client{Timeout: traceQueryTimeout},
	}
}

// ---- 响应模型（§6.3 单请求聚合示例） ----

type traceSpanView struct {
	Name    string         `json:"name"`
	StartMs float64        `json:"start_ms"`
	DurMs   float64        `json:"dur_ms"`
	Attrs   map[string]any `json:"attrs"`
}

type traceDenyView struct {
	Reason string `json:"reason"`
	Result string `json:"result"`
}

type traceAuditView struct {
	Available bool            `json:"available"` // 审计数据源是否可用（tee-infer 可达）
	Action    string          `json:"action"`
	Result    string          `json:"result"`
	CacheHit  bool            `json:"cache_hit"`
	IsRetry   bool            `json:"is_retry"`
	Denies    []traceDenyView `json:"denies"`
}

type traceBreakdownView struct {
	IngressMs     float64 `json:"ingress_ms"`
	TEEOverheadMs float64 `json:"tee_overhead_ms"`
	UpstreamMs    float64 `json:"upstream_ms"`
}

type traceAggregateView struct {
	RequestID string             `json:"request_id"`
	TraceID   string             `json:"trace_id"`
	Tenant    string             `json:"tenant"`
	Spans     []traceSpanView    `json:"spans"`
	Audit     traceAuditView     `json:"audit"`
	Breakdown traceBreakdownView `json:"breakdown"`
}

// handle trace 路由分发：/v1/adminext/trace/{request_id} 与 /report。
// 由 mux 注册在 traceBasePath+"{request_id}" 与 traceBasePath+"{request_id}/report"。
func (h *traceHandler) handleTraceByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epTraceFamilyRead) {
		return
	}
	rid := strings.TrimSpace(r.PathValue("request_id"))
	if rid == "" {
		writeError(w, http.StatusBadRequest, "request_id 必填")
		return
	}
	agg, code, errMsg := h.aggregate(r, rid)
	if errMsg != "" {
		writeError(w, code, errMsg)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(agg)
}

// handleTraceReport 导出排障报告：?format=json|csv（缺省 json）。
func (h *traceHandler) handleTraceReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epTraceFamilyRead) {
		return
	}
	rid := strings.TrimSpace(r.PathValue("request_id"))
	if rid == "" {
		writeError(w, http.StatusBadRequest, "request_id 必填")
		return
	}
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	agg, code, errMsg := h.aggregate(r, rid)
	if errMsg != "" {
		writeError(w, code, errMsg)
		return
	}
	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "trace-"+rid+".json"))
		_ = json.NewEncoder(w).Encode(agg)
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "trace-"+rid+".csv"))
		if err := writeTraceCSV(w, agg); err != nil {
			// 头已发出无法改状态码；尽力终止（客户端可据内容判定）
			return
		}
	default:
		writeError(w, http.StatusBadRequest, "format 仅支持 json|csv")
	}
}

// handleTraceSearch 多维检索（映射 Tempo Search API）。
// 参数：tenant/from/to/model/status/category/limit/offset（status 枚举外值 → 400）。
func (h *traceHandler) handleTraceSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epTraceFamilyRead) {
		return
	}
	if h.tempoURL == "" {
		writeError(w, http.StatusServiceUnavailable, "Tempo 查询地址未配置（ADMIN_TEMPO_URL）")
		return
	}
	q := r.URL.Query()
	// status 枚举校验（§6.3）
	if s := q.Get("status"); s != "" {
		if _, ok := traceStatusEnum[s]; !ok {
			writeError(w, http.StatusBadRequest, "status 枚举非法（ok|client_error|server_error|denied）")
			return
		}
	}
	// 租户隔离：非 admin 强制收敛为自身租户（传入不一致值即 403，不静默改写）
	c := claimsFrom(r.Context())
	tenant := strings.TrimSpace(q.Get("tenant"))
	if c != nil && !roleUnrestricted(c) {
		if c.Tenant == "" || (tenant != "" && tenant != c.Tenant) {
			writeError(w, http.StatusForbidden, "跨租户访问被拒绝")
			return
		}
		tenant = c.Tenant
	}
	limit := clampQueryInt(q.Get("limit"), traceSearchDefLimit, 1, traceSearchMaxLimit)
	offset := clampQueryInt(q.Get("offset"), 0, 0, 1<<30)

	// 组装 Tempo search 查询串（tags 过滤 + 时间窗 + 分页）
	v := url.Values{}
	v.Set("limit", strconv.Itoa(limit))
	var tags []string
	if tenant != "" {
		tags = append(tags, "tenant.id="+tenant)
	}
	if model := strings.TrimSpace(q.Get("model")); model != "" {
		tags = append(tags, "model.id="+model)
	}
	if cat := strings.TrimSpace(q.Get("category")); cat != "" {
		tags = append(tags, "og.category="+cat)
	}
	if len(tags) > 0 {
		v.Set("tags", strings.Join(tags, " "))
	}
	if status := strings.TrimSpace(q.Get("status")); status != "" {
		v.Set("status", status) // 透传供 Collector/网关侧扩展；Tempo 侧按需识别
	}
	if from := strings.TrimSpace(q.Get("from")); from != "" {
		v.Set("start", from) // Unix 秒
	}
	if to := strings.TrimSpace(q.Get("to")); to != "" {
		v.Set("end", to)
	}
	// Tempo 无 offset（分页用 start/end）；offset>0 时以 limit+offset 拉取后在响应标注，
	// 不静默丢参（审计可核对）。
	if offset > 0 {
		v.Set("limit", strconv.Itoa(limit+offset))
	}

	target := h.tempoURL + "/api/search?" + v.Encode()
	body, status, err := h.get(r, target)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "Tempo 不可达")
		return
	}
	if status != http.StatusOK {
		writeError(w, http.StatusServiceUnavailable, fmt.Sprintf("Tempo 返回 %d", status))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(body)
}

// aggregate 单请求全链路聚合：Tempo 查 trace → 解析 span → 审计关联 → 租户隔离。
// 返回 (视图, httpCode, errMsg)；errMsg 非空时按 (code) 返回错误。
func (h *traceHandler) aggregate(r *http.Request, rid string) (*traceAggregateView, int, string) {
	if h.tempoURL == "" {
		return nil, http.StatusServiceUnavailable, "Tempo 查询地址未配置（ADMIN_TEMPO_URL）"
	}
	// 1) 按 request.id 检索 traceID
	traceID, status, err := h.searchByRequestID(r, rid)
	if err != nil {
		return nil, http.StatusServiceUnavailable, "Tempo 不可达"
	}
	if status != http.StatusOK {
		return nil, http.StatusServiceUnavailable, fmt.Sprintf("Tempo 返回 %d", status)
	}
	if traceID == "" {
		return nil, http.StatusNotFound, "未找到该 request_id 对应的 trace"
	}
	// 2) 拉取 trace 明细
	raw, status, err := h.get(r, h.tempoURL+"/api/traces/"+url.PathEscape(traceID))
	if err != nil {
		return nil, http.StatusServiceUnavailable, "Tempo 不可达"
	}
	if status != http.StatusOK {
		return nil, http.StatusServiceUnavailable, fmt.Sprintf("Tempo 返回 %d", status)
	}
	td, perr := parseTempoTrace(raw)
	if perr != nil {
		return nil, http.StatusBadGateway, "trace 解析失败"
	}
	spans := td.views()
	tenant := td.tenantID()

	// 3) 租户隔离（fail-closed）：非 admin 仅本租户；tenant 未知亦拒绝
	c := claimsFrom(r.Context())
	if c != nil && !roleUnrestricted(c) {
		if c.Tenant == "" || tenant == "" || tenant != c.Tenant {
			return nil, http.StatusForbidden, "跨租户访问被拒绝"
		}
	}

	// 4) 审计关联（tee-infer /audit?tenant=，客户端按 request_id 过滤）
	audit := h.fetchAudit(r, tenant, rid)

	agg := &traceAggregateView{
		RequestID: rid,
		TraceID:   traceID,
		Tenant:    tenant,
		Spans:     spans,
		Audit:     audit,
		Breakdown: computeBreakdown(spans),
	}
	return agg, http.StatusOK, ""
}

// searchByRequestID 用 request.id 标签检索 traceID（取首条）。
func (h *traceHandler) searchByRequestID(r *http.Request, rid string) (string, int, error) {
	v := url.Values{}
	v.Set("tags", "request.id="+rid)
	v.Set("limit", "1")
	body, status, err := h.get(r, h.tempoURL+"/api/search?"+v.Encode())
	if err != nil {
		return "", 0, err
	}
	if status != http.StatusOK {
		return "", status, nil
	}
	var resp struct {
		Traces []struct {
			TraceID string `json:"traceID"`
		} `json:"traces"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", status, nil
	}
	if len(resp.Traces) == 0 {
		return "", status, nil
	}
	return resp.Traces[0].TraceID, status, nil
}

// fetchAudit 从 tee-infer 拉取租户审计事件并按 request_id 过滤，构造审计视图。
// tee-infer 不可达 → Available=false（不阻断 trace 返回，但如实标注）。
func (h *traceHandler) fetchAudit(r *http.Request, tenant, rid string) traceAuditView {
	view := traceAuditView{Available: false, Denies: []traceDenyView{}}
	if h.settings == nil || h.settings.url == "" || tenant == "" {
		return view
	}
	target := h.settings.url + "/audit?" + url.Values{"tenant": {tenant}}.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		return view
	}
	req.Header.Set(teeAdminHeader, h.settings.token)
	resp, err := h.client.Do(req)
	if err != nil {
		return view
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return view
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return view
	}
	var events []struct {
		RequestID string `json:"request_id"`
		Action    string `json:"action"`
		Result    string `json:"result"`
		CacheHit  bool   `json:"cache_hit"`
		IsRetry   bool   `json:"is_retry"`
	}
	if err := json.Unmarshal(body, &events); err != nil {
		return view
	}
	view.Available = true
	for _, e := range events {
		if e.RequestID != rid {
			continue
		}
		if e.Action == "infer" || e.Action == "cache_negative_hit" {
			view.Action, view.Result, view.CacheHit, view.IsRetry = e.Action, e.Result, e.CacheHit, e.IsRetry
		}
		if e.Action == "deny" || e.Action == "output_blocked" || strings.HasPrefix(e.Result, "blocked_") {
			view.Denies = append(view.Denies, traceDenyView{Reason: e.Result, Result: e.Action})
		}
	}
	return view
}

// get 发起 Tempo 查询请求，返回 body / 状态码 / 网络错误。
func (h *traceHandler) get(r *http.Request, target string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// computeBreakdown 由 span 列表推导耗时分解。
// ingress_ms = envoy.ingress span 时长；upstream_ms = upstream.model.call 时长；
// tee_overhead_ms = tee.infer 时长 − upstream 时长（clamp ≥ 0）。
func computeBreakdown(spans []traceSpanView) traceBreakdownView {
	var b traceBreakdownView
	var teeDur, upDur float64
	for _, s := range spans {
		switch s.Name {
		case "envoy.ingress":
			b.IngressMs = s.DurMs
		case "upstream.model.call":
			upDur = s.DurMs
		case "tee.infer":
			teeDur = s.DurMs
		}
	}
	b.UpstreamMs = upDur
	if teeDur-upDur > 0 {
		b.TEEOverheadMs = teeDur - upDur
	}
	return b
}

// writeTraceCSV 以 CSV 导出排障报告（含公式注入防护，§6.3）。
func writeTraceCSV(w io.Writer, agg *traceAggregateView) error {
	cw := csv.NewWriter(w)
	rows := [][]string{
		{"section", "name", "start_ms", "dur_ms", "attr_key", "attr_value"},
	}
	for _, s := range agg.Spans {
		keys := make([]string, 0, len(s.Attrs))
		for k := range s.Attrs {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			rows = append(rows, []string{"span", s.Name, ftoa(s.StartMs), ftoa(s.DurMs), "", ""})
			continue
		}
		for _, k := range keys {
			rows = append(rows, []string{
				"span", s.Name, ftoa(s.StartMs), ftoa(s.DurMs),
				csvEscape(k), csvEscape(fmt.Sprint(s.Attrs[k])),
			})
		}
	}
	rows = append(rows,
		[]string{"audit", "action", "", "", "action", csvEscape(agg.Audit.Action)},
		[]string{"audit", "result", "", "", "result", csvEscape(agg.Audit.Result)},
	)
	for _, d := range agg.Audit.Denies {
		rows = append(rows, []string{"audit", "deny", "", "", csvEscape(d.Result), csvEscape(d.Reason)})
	}
	rows = append(rows,
		[]string{"breakdown", "ingress_ms", "", ftoa(agg.Breakdown.IngressMs), "", ""},
		[]string{"breakdown", "tee_overhead_ms", "", ftoa(agg.Breakdown.TEEOverheadMs), "", ""},
		[]string{"breakdown", "upstream_ms", "", ftoa(agg.Breakdown.UpstreamMs), "", ""},
	)
	if err := cw.WriteAll(rows); err != nil {
		return err
	}
	cw.Flush()
	return cw.Error()
}

// ftoa 浮点转字符串（固定 3 位小数，避免科学计数法干扰表格）。
func ftoa(f float64) string { return strconv.FormatFloat(f, 'f', 3, 64) }

// csvEscape 对 CSV 单元格值进行公式注入防护（§6.3）。
// 以 = + - @ \t \r 开头 → 前置单引号。
func csvEscape(val string) string {
	if len(val) == 0 {
		return val
	}
	switch val[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + val
	default:
		return val
	}
}
