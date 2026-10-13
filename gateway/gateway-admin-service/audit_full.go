// Package main — P1-7 T8/T9（MOD6/MOD7）：审计温/冷层检索·导出 与 留存声明读写。
//
// 设计：docs/详细设计/P1/GA-AI网关能力补齐方案--P1--全流量审计改造.md §6.2/§6.3/§6.4、§7.7/§7.8。
//
// 端点：
//
//	GET  /v1/adminext/audit-full/search   温/冷层归档检索（多维过滤 + {items,page,chain}）
//	GET  /v1/adminext/audit-full/export   流式 NDJSON 导出 + 链尾摘要响应头（+ 可选读取侧降采样）
//	GET  /v1/adminext/audit-retention      读取留存/分层声明（只读快照）
//	PUT  /v1/adminext/audit-retention      更新留存声明（落 G1 链，fail-closed；≥180 天）
//
// 数据源：归档后端抽象 archiveStore。默认 localArchiveStore 读取本地归档根目录
// （env ADMIN_AUDIT_ARCHIVE_ROOT；布局 <root>/<tier>/<tenant>/<yyyy-mm-dd>/part-*.jsonl，
// 与 tee-infer T6 归档器 localFSArchiveSink 一致）。对象存储为可插拔后端（生产装配，W0 复核）。
// 归档根未配置 → 503（不静默返回空，§6.6）。
//
// 安全：复用 authMiddleware + requireRule；`tenant` 非本租户 → 403，admin 可跨租户（V-7）。
// 导出仅含 §6.1(A) 白名单字段（归档落盘已由 T4 脱敏，读侧为透传二次裁剪）。
package main

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	auditFullSearchPath   = "/v1/adminext/audit-full/search"
	auditFullExportPath   = "/v1/adminext/audit-full/export"
	auditRetentionPath    = "/v1/adminext/audit-retention"
	auditFullQueryDefault = 50
	auditFullQueryMax     = 200
	auditFullOffsetMax    = 10000
	auditFullMultiMax     = 5 // status/action 多值上限
)

// auditRetentionEnv 缺省留存声明（env 可覆盖；与 tee-infer RetentionPolicy 同口径）。
const (
	envArchiveRoot      = "ADMIN_AUDIT_ARCHIVE_ROOT"
	envRetentionDays    = "ADMIN_AUDIT_RETENTION_DAYS"
	envRetentionHotDays = "ADMIN_AUDIT_RETENTION_HOT_DAYS"
	envRetentionWarm    = "ADMIN_AUDIT_RETENTION_WARM_DAYS"
	envRetentionCold    = "ADMIN_AUDIT_RETENTION_COLD_DAYS"
	envRetentionSample  = "ADMIN_AUDIT_RETENTION_SAMPLE_MISS_RATE"
)

// ---- 归档后端抽象 ----

// archiveStore 温/冷层归档只读后端（可插拔：本地文件系统 / 对象存储）。
type archiveStore interface {
	// readEvents 返回指定 tier 下 tenant 在 [fromDate,toDate]（yyyy-mm-dd，含端点）的归档事件。
	readEvents(ctx context.Context, tier, tenant, fromDate, toDate string) ([]auditRecord, error)
}

// auditRecord 归档事件（§6.1(A) 白名单字段 + 常用过滤维度；已由写入侧脱敏）。
type auditRecord struct {
	EventID     string `json:"event_id"`
	Timestamp   int64  `json:"timestamp"`
	TenantID    string `json:"tenant_id"`
	UserID      string `json:"user_id,omitempty"`
	RequestID   string `json:"request_id"`
	Action      string `json:"action"`
	TokensIn    int    `json:"tokens_in,omitempty"`
	TokensOut   int    `json:"tokens_out,omitempty"`
	Result      string `json:"result"`
	PayloadSHA  string `json:"payload_hash"`
	Model       string `json:"model,omitempty"`
	Path        string `json:"path,omitempty"`
	PathMode    string `json:"path_mode,omitempty"`
	TTFTMs      int    `json:"ttft_ms,omitempty"`
	DurMS       int    `json:"dur_ms,omitempty"`
	HTTPStatus  int    `json:"http_status,omitempty"`
	HitPolicies string `json:"hit_policies,omitempty"`
	Origin      string `json:"origin,omitempty"`
	TraceID     string `json:"trace_id,omitempty"`
	PrevHash    string `json:"prev_hash,omitempty"`
}

// isHit 命中判定式（§3.4 注）：hit ≡ result != ok 或 hit_policies 非空。
func (r auditRecord) isHit() bool {
	return (r.Result != "ok" && r.Result != "") || r.HitPolicies != ""
}

// localArchiveStore 本地文件系统归档后端（布局与 tee-infer localFSArchiveSink 一致）。
type localArchiveStore struct {
	root string
}

// readEvents 扫描 <root>/<tier>/<tenant>/<date>/part-*.jsonl（仅 [fromDate,toDate] 内日期分区）。
func (s *localArchiveStore) readEvents(_ context.Context, tier, tenant, fromDate, toDate string) ([]auditRecord, error) {
	if !isSafeArchiveSegment(tier) || !isSafeArchiveSegment(tenant) {
		return nil, fmt.Errorf("archive: 非法分段 %q/%q", tier, tenant)
	}
	base := filepath.Join(s.root, tier, tenant)
	entries, err := os.ReadDir(base)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // 分区不存在 = 无数据（非错误）
		}
		return nil, err
	}
	var out []auditRecord
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		date := ent.Name()
		if date < fromDate || date > toDate {
			continue // 按日期分区裁剪（前缀定位）
		}
		files, err := filepath.Glob(filepath.Join(base, date, "part-*.jsonl"))
		if err != nil {
			return nil, err
		}
		for _, fp := range files {
			recs, err := readJSONL(fp)
			if err != nil {
				return nil, err
			}
			out = append(out, recs...)
		}
	}
	return out, nil
}

// readJSONL 逐行解析 JSONL 归档文件。
func readJSONL(path string) ([]auditRecord, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []auditRecord
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var r auditRecord
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			return nil, fmt.Errorf("archive: %s 解析失败: %w", path, err)
		}
		out = append(out, r)
	}
	return out, nil
}

// isSafeArchiveSegment 校验归档路径分段（防路径穿越；与 tee-infer isSafeSegment 同规则）。
func isSafeArchiveSegment(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// ---- T8/T9 handler ----

// auditFullHandler 温/冷层检索·导出（T8）与留存声明（T9）。
type auditFullHandler struct {
	store     archiveStore     // nil = 归档后端未配置（503）
	chain     *adminAuditChain // G1 链（留存变更落链；nil = 未启用）
	settings  *usageSettings   // tee-infer 地址（留存下发）
	client    *http.Client
	retention retentionState // 留存声明（内存态，T9 GET 源）
}

// retentionState 留存/分层声明（§6.4 视图口径，与服务不删除数据的声明式纪律一致）。
type retentionState struct {
	DeclaredDays   int  `json:"declared_days"`
	HotDays        int  `json:"hot_days"`
	WarmDays       int  `json:"warm_days"`
	ColdDays       int  `json:"cold_days"`
	SampleMissRate int  `json:"sample_miss_rate"`
	Enabled        bool `json:"enabled"`
}

// loadRetentionState 读取留存声明（env 覆盖；缺省 365/7/30/180/0，与 tee-infer 对齐）。
func loadRetentionState() retentionState {
	return retentionState{
		DeclaredDays:   envInt(envRetentionDays, 365),
		HotDays:        envInt(envRetentionHotDays, 7),
		WarmDays:       envInt(envRetentionWarm, 30),
		ColdDays:       envInt(envRetentionCold, 180),
		SampleMissRate: envInt(envRetentionSample, 0),
		Enabled:        true,
	}
}

// newAuditFullHandler 装配 T8/T9 handler。
func newAuditFullHandler(s *usageSettings, chain *adminAuditChain) *auditFullHandler {
	h := &auditFullHandler{
		chain:     chain,
		settings:  s,
		client:    &http.Client{Timeout: usageProxyTimeout},
		retention: loadRetentionState(),
	}
	if root := strings.TrimSpace(os.Getenv(envArchiveRoot)); root != "" {
		h.store = &localArchiveStore{root: root}
	}
	return h
}

// ---- 查询参数解析与校验（§6.2） ----

// auditQuery 解析后的多维查询参数。
type auditQuery struct {
	Tenant    string
	FromNano  int64
	ToNano    int64
	Tier      string
	Model     string
	Statuses  []int
	Actions   []string
	Hit       string // "" | hit | miss
	PathMode  string
	RequestID string
	Limit     int
	Offset    int
	Sort      string // timestamp | dur_ms
	SortDesc  bool
	Sample    int // 导出用：sample_miss_rate（0–100）
}

// paramError 参数校验错误（首错返回，§6.2：400 逐字段首错）。
type paramError struct{ field, reason string }

func (e *paramError) Error() string { return e.field + ": " + e.reason }

// parseAuditQuery 解析并校验查询参数（首错返回 *paramError；enablePaging=false 时不校验 limit/offset）。
func parseAuditQuery(q map[string][]string, forExport bool) (*auditQuery, error) {
	get := func(k string) string {
		if v, ok := q[k]; ok && len(v) > 0 {
			return strings.TrimSpace(v[0])
		}
		return ""
	}
	out := &auditQuery{
		Tenant:    get("tenant"),
		Tier:      strings.ToLower(get("tier")),
		Model:     get("model"),
		RequestID: get("request_id"),
		PathMode:  get("path_mode"),
		Hit:       strings.ToLower(get("hit")),
		Limit:     auditFullQueryDefault,
		Offset:    0,
		Sort:      "timestamp",
		SortDesc:  true,
	}
	if out.Tier == "" {
		out.Tier = "warm" // 缺省温层（§6.2）
	}
	if out.Tier != "warm" && out.Tier != "cold" && out.Tier != "hot" {
		return nil, &paramError{"tier", "须为 warm|cold|hot"}
	}
	if out.PathMode != "" && out.PathMode != "plain" && out.PathMode != "encrypted" {
		return nil, &paramError{"path_mode", "须为 plain|encrypted"}
	}
	if out.Hit != "" && out.Hit != "hit" && out.Hit != "miss" {
		return nil, &paramError{"hit", "须为 hit|miss"}
	}
	// from/to（缺省 to=now、from=to−24h；from>to → 400）
	now := time.Now()
	to, err := parseNanoOrRFC3339(get("to"), now)
	if err != nil {
		return nil, &paramError{"to", "非法时间（RFC3339 或纳秒）"}
	}
	from, err := parseNanoOrRFC3339(get("from"), to.Add(-24*time.Hour))
	if err != nil {
		return nil, &paramError{"from", "非法时间（RFC3339 或纳秒）"}
	}
	if from.After(to) {
		return nil, &paramError{"from", "from 不得晚于 to"}
	}
	out.FromNano, out.ToNano = from.UnixNano(), to.UnixNano()

	// status 多值 OR（≤5，100–599）
	for _, raw := range splitMulti(q["status"]) {
		v, err := strconv.Atoi(raw)
		if err != nil || v < 100 || v > 599 {
			return nil, &paramError{"status", "须为 100–599 整数（逗号多值上限 5）"}
		}
		out.Statuses = append(out.Statuses, v)
	}
	if len(out.Statuses) > auditFullMultiMax {
		return nil, &paramError{"status", "多值上限 5"}
	}
	// action 多值 OR（≤5）
	for _, raw := range splitMulti(q["action"]) {
		if raw == "" {
			continue
		}
		out.Actions = append(out.Actions, raw)
	}
	if len(out.Actions) > auditFullMultiMax {
		return nil, &paramError{"action", "多值上限 5"}
	}
	// sort
	if s := get("sort"); s != "" {
		parts := strings.SplitN(s, ":", 2)
		switch parts[0] {
		case "timestamp":
			out.Sort = "timestamp"
		case "dur_ms":
			out.Sort = "dur_ms"
		default:
			return nil, &paramError{"sort", "字段须为 timestamp|dur_ms"}
		}
		if len(parts) == 2 {
			switch parts[1] {
			case "asc":
				out.SortDesc = false
			case "desc":
				out.SortDesc = true
			default:
				return nil, &paramError{"sort", "方向须为 asc|desc"}
			}
		}
	}
	if !forExport {
		limit := clampQueryInt(get("limit"), auditFullQueryDefault, 1, auditFullQueryMax)
		off, err := strconv.Atoi(get("offset"))
		if get("offset") != "" && (err != nil || off < 0 || off > auditFullOffsetMax) {
			return nil, &paramError{"offset", fmt.Sprintf("须为 0–%d 整数", auditFullOffsetMax)}
		}
		out.Limit, out.Offset = limit, off
	} else if get("sample_miss_rate") != "" {
		v, err := strconv.Atoi(get("sample_miss_rate"))
		if err != nil || v < 0 || v > 100 {
			return nil, &paramError{"sample_miss_rate", "须为 0–100 整数"}
		}
		out.Sample = v
	}
	return out, nil
}

// splitMulti 拆分逗号多值（去空、去重保序）。
func splitMulti(vals []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range vals {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p == "" || seen[p] {
				continue
			}
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// parseNanoOrRFC3339 解析 RFC3339 或 Unix 纳秒；空值回退 def。
func parseNanoOrRFC3339(raw string, def time.Time) (time.Time, error) {
	if raw == "" {
		return def, nil
	}
	if n, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(0, n), nil
	}
	return time.Parse(time.RFC3339, raw)
}

// ---- 跨度上限（§6.2） ----

// maxSpanFor 返回端点/tier 的单次最大跨度；-1 = 不支持。
func maxSpanFor(endpoint, tier string) time.Duration {
	day := 24 * time.Hour
	switch endpoint {
	case "search":
		switch tier {
		case "warm":
			return 30 * day
		case "cold":
			return 90 * day
		}
		return -1
	case "export":
		switch tier {
		case "hot":
			return 7 * day
		case "warm":
			return 30 * day
		}
		return -1
	}
	return -1
}

// requireTenantScoped 租户作用域校验（V-7）：非 admin 强制收敛为自身租户；跨租户 → 403。
// 返回 (生效租户, ok)。
func requireTenantScoped(w http.ResponseWriter, r *http.Request, requested string) (string, bool) {
	c := claimsFrom(r.Context())
	if c == nil {
		writeError(w, http.StatusForbidden, "需要已认证会话")
		return "", false
	}
	if roleUnrestricted(c) {
		return requested, true // admin 可跨租户（空 = 全租户）
	}
	if c.Tenant == "" || (requested != "" && requested != c.Tenant) {
		writeError(w, http.StatusForbidden, "跨租户访问被拒绝")
		return "", false
	}
	return c.Tenant, true
}

// ---- T8：检索 ----

// auditChainSummary 链尾摘要（§6.2，供判截断）。
type auditChainSummary struct {
	Schema   string `json:"schema"`
	Tier     string `json:"tier"`
	Events   int    `json:"events"`
	LastHash string `json:"last_hash"`
}

// auditPage 分页视图。
type auditPage struct {
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	Total   int  `json:"total"`
	HasMore bool `json:"has_more"`
}

// handleAuditFullSearch GET /v1/adminext/audit-full/search?...（§6.2 → {items,page,chain}）。
func (h *auditFullHandler) handleAuditFullSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epAuditFullSearch) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "归档后端未配置（ADMIN_AUDIT_ARCHIVE_ROOT）")
		return
	}
	query, err := parseAuditQuery(r.URL.Query(), false)
	if err != nil {
		writeParamError(w, err)
		return
	}
	if query.Tenant == "" {
		writeParamError(w, &paramError{"tenant", "必填（归档按 tenant/日期 分区）"})
		return
	}
	tenant, ok := requireTenantScoped(w, r, query.Tenant)
	if !ok {
		return
	}
	query.Tenant = tenant
	if span := maxSpanFor("search", query.Tier); span < 0 {
		writeParamError(w, &paramError{"tier", "search 仅支持 warm|cold"})
		return
	} else if time.Duration(query.ToNano-query.FromNano) > span {
		writeParamError(w, &paramError{"from/to", fmt.Sprintf("跨度超上限（%s 最大 %s）", query.Tier, span)})
		return
	}

	recs, err := h.store.readEvents(r.Context(), query.Tier, query.Tenant, dateOf(query.FromNano), dateOf(query.ToNano))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "归档后端不可达")
		return
	}
	total := len(recs) // 链窗口事件数（扫描后、过滤前）
	filtered := filterRecords(recs, query)
	sortRecords(filtered, query)
	matched := len(filtered)
	pageRecs := paginate(filtered, query.Offset, query.Limit)

	view := map[string]interface{}{
		"items": pageRecs,
		"page": auditPage{
			Limit:   query.Limit,
			Offset:  query.Offset,
			Total:   matched,
			HasMore: query.Offset+len(pageRecs) < matched,
		},
		"chain": auditChainSummary{
			Schema:   "tee",
			Tier:     query.Tier,
			Events:   total,
			LastHash: windowLastHash(recs),
		},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// ---- T8：导出 ----

// handleAuditFullExport GET /v1/adminext/audit-full/export?...（流式 NDJSON + 链尾摘要头 + 可选降采样）。
func (h *auditFullHandler) handleAuditFullExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epAuditFullExport) {
		return
	}
	if h.store == nil {
		writeError(w, http.StatusServiceUnavailable, "归档后端未配置（ADMIN_AUDIT_ARCHIVE_ROOT）")
		return
	}
	query, err := parseAuditQuery(r.URL.Query(), true)
	if err != nil {
		writeParamError(w, err)
		return
	}
	if query.Tier == "" || query.Tier == "warm" {
		// 缺省 warm（parseAuditQuery 已置 warm）；若显式 hot 亦允许（7d）
	}
	if query.Tenant == "" {
		writeParamError(w, &paramError{"tenant", "必填"})
		return
	}
	tenant, ok := requireTenantScoped(w, r, query.Tenant)
	if !ok {
		return
	}
	query.Tenant = tenant
	span := maxSpanFor("export", query.Tier)
	if span < 0 {
		writeParamError(w, &paramError{"tier", "export 仅支持 hot|warm"})
		return
	}
	if time.Duration(query.ToNano-query.FromNano) > span {
		writeParamError(w, &paramError{"from/to", fmt.Sprintf("跨度超上限（%s 最大 %s）", query.Tier, span)})
		return
	}

	recs, err := h.store.readEvents(r.Context(), query.Tier, query.Tenant, dateOf(query.FromNano), dateOf(query.ToNano))
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "归档后端不可达")
		return
	}
	filtered := filterRecords(recs, query)
	sortRecords(filtered, query)
	if query.Sample > 0 {
		filtered = sampleMiss(filtered, query.Sample)
	}

	// 链尾摘要响应头（§6.3）：供第三方判截断，复用 audit-verify -anchor。
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="audit-full.jsonl"`)
	w.Header().Set("X-Audit-Chain-Events", strconv.Itoa(len(recs)))
	w.Header().Set("X-Audit-Chain-Last-Hash", windowLastHash(recs))
	if query.Sample > 0 {
		w.Header().Set("X-Audit-Sample-Rate", strconv.Itoa(query.Sample))
		// 包内抽样说明（算法/比率/可重现性）：以注释行前置（NDJSON 消费方可跳过以 '#' 开头行）。
		_, _ = fmt.Fprintf(w, "# sample_notice algorithm=sha256(request_id)%%100<rate rate=%d reproducible=true scope=miss_only\n", query.Sample)
	}
	enc := json.NewEncoder(w)
	for _, rec := range filtered {
		_ = enc.Encode(rec) // 流式：边读边写，不限内存
	}
}

// ---- T9：留存声明 ----

// handleAuditRetention GET（读声明）/ PUT（更新，落链 fail-closed）。
func (h *auditFullHandler) handleAuditRetention(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getRetention(w, r)
	case http.MethodPut:
		h.putRetention(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET/PUT")
	}
}

func (h *auditFullHandler) getRetention(w http.ResponseWriter, r *http.Request) {
	if !requireRule(w, r, epAuditRetentionRead) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(h.retention)
}

// auditRetentionRequest PUT 请求体（declared_days=0 表示不声明；见 §6.4）。
type auditRetentionRequest struct {
	DeclaredDays   int   `json:"declared_days"`
	HotDays        int   `json:"hot_days"`
	WarmDays       int   `json:"warm_days"`
	ColdDays       int   `json:"cold_days"`
	SampleMissRate int   `json:"sample_miss_rate"`
	Enabled        *bool `json:"enabled,omitempty"`
}

// validateRetention 校验留存声明（§6.4/§7.5：declared_days=0 不声明；(0,180) 拒绝；分层合计 ≥180）。
func validateRetention(req auditRetentionRequest) error {
	if req.DeclaredDays < 0 {
		return &paramError{"declared_days", "不可为负（0=不声明）"}
	}
	if req.DeclaredDays > 0 && req.DeclaredDays < 180 {
		return &paramError{"declared_days", "低于法定硬底 180 天（C-8）"}
	}
	if req.HotDays < 1 {
		return &paramError{"hot_days", "须 ≥ 1"}
	}
	if req.WarmDays <= req.HotDays {
		return &paramError{"warm_days", "须 > hot_days"}
	}
	if req.ColdDays < req.WarmDays {
		return &paramError{"cold_days", "须 ≥ warm_days"}
	}
	if req.HotDays+req.WarmDays+req.ColdDays < 180 {
		return &paramError{"cold_days", "分层合计低于法定硬底 180 天（C-8）"}
	}
	if req.SampleMissRate < 0 || req.SampleMissRate > 100 {
		return &paramError{"sample_miss_rate", "须 ∈ [0,100]"}
	}
	return nil
}

func (h *auditFullHandler) putRetention(w http.ResponseWriter, r *http.Request) {
	if !requireRule(w, r, epAuditRetentionWrite) {
		return
	}
	var req auditRetentionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		writeParamError(w, &paramError{"body", "非法 JSON"})
		return
	}
	if err := validateRetention(req); err != nil {
		writeParamError(w, err)
		return
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	next := retentionState{
		DeclaredDays: req.DeclaredDays, HotDays: req.HotDays, WarmDays: req.WarmDays,
		ColdDays: req.ColdDays, SampleMissRate: req.SampleMissRate, Enabled: enabled,
	}
	// ① 落 G1 链（fail-closed：链写失败 → 500，不下发半生效配置）。
	if h.chain != nil {
		c := claimsFrom(r.Context())
		detail, _ := json.Marshal(req)
		if err := h.chain.append(adminAuditEvent{
			Actor:     c.Sub,
			Action:    auditActionAuditRetentionChange,
			Result:    "ok",
			Detail:    string(detail),
			RequestID: r.Header.Get("X-Request-ID"),
		}); err != nil {
			writeError(w, http.StatusInternalServerError, "审计链写入失败（fail-closed，配置未变更）")
			return
		}
	}
	// ② 下发 tee-infer（PUT /audit/retention；未配置地址则跳过下发，仅本地声明生效）。
	if h.settings != nil && h.settings.url != "" {
		if err := h.dispatchRetention(r.Context(), req); err != nil {
			writeError(w, http.StatusServiceUnavailable, "留存配置下发 tee-infer 失败（fail-closed）")
			return
		}
	}
	// ③ 更新本地声明（仅在链写 + 下发均成功后）。
	h.retention = next
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(next)
}

// dispatchRetention 下发留存声明到 tee-infer。
func (h *auditFullHandler) dispatchRetention(ctx context.Context, req auditRetentionRequest) error {
	body, _ := json.Marshal(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPut, h.settings.url+"/audit/retention", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set(teeAdminHeader, h.settings.token)
	resp, err := h.client.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("tee-infer 返回 %d", resp.StatusCode)
	}
	return nil
}

// ---- 过滤 / 排序 / 分页 / 采样（纯函数，便于单测） ----

// filterRecords 应用多维过滤（§6.2；hit 与 result/hit_policies 同给时以 hit 为准）。
func filterRecords(recs []auditRecord, q *auditQuery) []auditRecord {
	out := make([]auditRecord, 0, len(recs))
	for _, r := range recs {
		if r.Timestamp < q.FromNano || r.Timestamp > q.ToNano {
			continue
		}
		if q.Model != "" && r.Model != q.Model {
			continue
		}
		if q.PathMode != "" && r.PathMode != q.PathMode {
			continue
		}
		if q.RequestID != "" && r.RequestID != q.RequestID {
			continue
		}
		if len(q.Statuses) > 0 && !containsInt(q.Statuses, r.HTTPStatus) {
			continue
		}
		if len(q.Actions) > 0 && !containsStr(q.Actions, r.Action) {
			continue
		}
		switch q.Hit {
		case "hit":
			if !r.isHit() {
				continue
			}
		case "miss":
			if r.isHit() {
				continue
			}
		}
		out = append(out, r)
	}
	return out
}

// sortRecords 排序（timestamp 缺省 desc；dur_ms 可选）。
func sortRecords(recs []auditRecord, q *auditQuery) {
	sort.SliceStable(recs, func(i, j int) bool {
		var less bool
		if q.Sort == "dur_ms" {
			less = recs[i].DurMS < recs[j].DurMS
		} else {
			less = recs[i].Timestamp < recs[j].Timestamp
		}
		if q.SortDesc {
			return !less
		}
		return less
	})
}

// paginate 分页切片。
func paginate(recs []auditRecord, offset, limit int) []auditRecord {
	if offset >= len(recs) {
		return []auditRecord{}
	}
	end := offset + limit
	if end > len(recs) {
		end = len(recs)
	}
	return recs[offset:end]
}

// sampleMiss 仅对未命中事件按确定性算法降采样（§3.4 R-采样-2；命中事件恒保留，D-16）。
func sampleMiss(recs []auditRecord, rate int) []auditRecord {
	out := make([]auditRecord, 0, len(recs))
	for _, r := range recs {
		if r.isHit() || sampleShouldKeep(r.RequestID, rate) {
			out = append(out, r)
		}
	}
	return out
}

// sampleShouldKeep 确定性采样判定：sha256(request_id)%100 < rate（同 request_id 可重现，A3-08）。
func sampleShouldKeep(requestID string, rate int) bool {
	if rate <= 0 {
		return true // rate<=0 表示不采样（保留）——调用方已在外层判空
	}
	if rate >= 100 {
		return true
	}
	sum := sha256.Sum256([]byte(requestID))
	return int(binary.BigEndian.Uint32(sum[:4])%100) < rate
}

// windowLastHash 取扫描窗口内时间最晚事件的 prev_hash 作窗口链锚（判截断用）。
func windowLastHash(recs []auditRecord) string {
	if len(recs) == 0 {
		return ""
	}
	max := recs[0]
	for _, r := range recs {
		if r.Timestamp > max.Timestamp {
			max = r
		}
	}
	return max.PrevHash
}

// dateOf 纳秒 → yyyy-mm-dd（UTC，与归档分区一致）。
func dateOf(nano int64) string {
	return time.Unix(0, nano).UTC().Format("2006-01-02")
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// writeParamError 参数校验失败 → 400（§6.2：{"code":"invalid_argument","message":"<字段>: <原因>"}）。
func writeParamError(w http.ResponseWriter, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"code":    "invalid_argument",
		"message": err.Error(),
	})
}
