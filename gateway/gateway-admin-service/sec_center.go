// Package main — M3-B 安全中心数据端点（密态链路状态 / Guardrail 策略 / 审计链）。
//
// 设计：docs/管理门户-细化方案.md §5「安全中心」（密态链路状态 / Guardrail 策略 / 审计链）。
//
// 端点：
//
//	GET /v1/adminext/sec-status           密态链路状态聚合（tee-infer healthz+config + G1 链状态）
//	GET /v1/adminext/audit-chain          G1 链事件查询（分页，倒序）
//	GET /v1/adminext/audit-chain/verify   G1 链完整性校验（重算）
//	GET /v1/adminext/audit-chain/export   G1 链导出（JSONL 附件）
//	GET /v1/adminext/audit-tee            tee-infer 审计链查询/校验代理（?verify=1 走 /audit/verify）
//
// 权限：全部要求已认证会话（admin 与 auditor 均可读，auditor 的只读定位见 D10）。
//
// 503 语义（不静默给假数据）：
//   - G1 链未启用（ADMIN_AUDIT_FILE 未配置）→ 链查询/校验/导出 503；
//   - tee-infer 地址未配置（ADMIN_TEE_INFER_URL）→ 审计代理 503；
//   - 例外：sec-status 对 tee 不可达**如实标注** tee_health=unreachable 并返回 200——
//     该页面的语义就是"展示链路健康"，链路断了正是要展示的状态，非静默降级。
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	secStatusPath        = "/v1/adminext/sec-status"
	auditChainPath       = "/v1/adminext/audit-chain"
	auditChainVerifyPath = auditChainPath + "/verify"
	auditChainExportPath = auditChainPath + "/export"
	teeAuditPath         = "/v1/adminext/audit-tee"

	secCenterTimeout = 5 * time.Second

	auditQueryDefaultLimit = 50
	auditQueryMaxLimit     = 200

	// P2-4 T-4.1：审计跨集群聚合查询。
	auditChainQueryPath         = auditChainPath + "/query"
	auditChainQueryTimeout      = 10 * time.Second
	auditChainQueryDefaultLimit = 200
	auditChainQueryMaxLimit     = 100000
)

// secCenterHandler 安全中心数据端点集合。
type secCenterHandler struct {
	chain    *adminAuditChain // nil = G1 链未启用
	settings *usageSettings   // 复用 tee-infer 地址/令牌配置
	client   *http.Client
	full     *auditFullHandler // P1-7 T8/T9：温/冷层检索·导出 + 留存声明（恒装配）

	// P2-4 T-4.1：跨集群聚合查询依赖项（缺省 nil/false ⇒ 降级语义如实反映）。
	clusterStore  ClusterStore        // nil = 集群注册表未启用（core/tee 卷标 disabled）
	dispatchToken string              // 拉取 core/tee 导出端点的 Bearer 令牌（复用 GATEWAY_CORE_DISPATCH_TOKEN）
	fetcher       clusterChainFetcher // 跨集群链拉取（默认 httpClusterChainFetcher；单测可注入）
}

// newSecCenterHandler 装配安全中心 handler（恒注册；数据源缺失时按上述 503 语义返回）。
func newSecCenterHandler(chain *adminAuditChain, s *usageSettings) *secCenterHandler {
	return &secCenterHandler{
		chain:    chain,
		settings: s,
		client:   &http.Client{Timeout: secCenterTimeout},
		full:     newAuditFullHandler(s, chain),
		fetcher:  &httpClusterChainFetcher{client: &http.Client{Timeout: auditChainQueryTimeout}},
	}
}

// setClusterStore 注入集群注册表句柄（P2-4 T-4.1：core/tee 卷按 cluster 定位导出端点）。
// nil = 注册表未启用 ⇒ 所有 core/tee 卷标 disabled（fail-closed，不臆造集群）。
func (h *secCenterHandler) setClusterStore(cs ClusterStore) { h.clusterStore = cs }

// setDispatchToken 注入跨集群拉取令牌（P2-4 T-4.1：复用 GATEWAY_CORE_DISPATCH_TOKEN）。
func (h *secCenterHandler) setDispatchToken(tok string) { h.dispatchToken = tok }

// registerAuditChainQuery 注册审计跨集群聚合查询端点（P2-4 T-4.1）。
// 独立于 buildAdminMux 注册（与其余 admin 端点同法，保持 buildAdminMux 签名不变）。
func (h *secCenterHandler) registerAuditChainQuery(mux *http.ServeMux, cfg *config) {
	mux.HandleFunc(auditChainQueryPath, authMiddleware(cfg, h.handleAuditChainQuery))
}

// requireChain G1 链已启用方可查询（否则 503，不静默返回空链）。
func (h *secCenterHandler) requireChain(w http.ResponseWriter) bool {
	if h.chain == nil {
		writeError(w, http.StatusServiceUnavailable,
			"审计链未启用（ADMIN_AUDIT_FILE 未配置）")
		return false
	}
	return true
}

// handleAuditChain G1 链查询：GET /v1/adminext/audit-chain?limit&offset（auditor 可读）。
func (h *secCenterHandler) handleAuditChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epAuditChain) || !h.requireChain(w) {
		return
	}
	limit := clampQueryInt(r.URL.Query().Get("limit"), auditQueryDefaultLimit, 1, auditQueryMaxLimit)
	offset := clampQueryInt(r.URL.Query().Get("offset"), 0, 0, 1<<30)

	events, total := h.chain.list(limit, offset)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"total":  total,
		"limit":  limit,
		"offset": offset,
	})
}

// auditChainVerifyView G1 链校验视图。
type auditChainVerifyView struct {
	OK       bool `json:"ok"`
	Events   int  `json:"events"`
	BrokenAt int  `json:"broken_at,omitempty"` // 断裂位置索引（仅 ok=false 时有效）
}

// handleAuditChainVerify G1 链完整性校验：GET /v1/adminext/audit-chain/verify。
func (h *secCenterHandler) handleAuditChainVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epAuditChainVerify) || !h.requireChain(w) {
		return
	}
	ok, n := h.chain.verify()
	view := auditChainVerifyView{OK: ok, Events: n}
	if !ok {
		// 既有 verify 在失败时返回断裂位置（i），成功时返回事件总数。
		view.BrokenAt = n
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// handleAuditChainExport G1 链导出：GET /v1/adminext/audit-chain/export（JSONL 附件）。
func (h *secCenterHandler) handleAuditChainExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epAuditChainExport) || !h.requireChain(w) {
		return
	}
	// 导出全部：limit 给足够大值（list 内部按实际条数分配容量，无预分配风险）。
	events, total := h.chain.list(1<<30, 0)
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Content-Disposition", `attachment; filename="admin-audit-chain.jsonl"`)
	// 独立验证增强（Phase 2 门禁 #4）：随导出附「链尾摘要」，使**拿到导出包的第三方**
	// 也能判定截断（否则导出包只能自证内部自洽）。校验器：gateway/audit-verify。
	w.Header().Set("X-Audit-Chain-Events", strconv.Itoa(total))
	w.Header().Set("X-Audit-Chain-Last-Hash", h.chain.lastHash())
	enc := json.NewEncoder(w)
	for i := len(events) - 1; i >= 0; i-- { // 倒序取回后按链序输出
		_ = enc.Encode(events[i])
	}
}

// handleTeeAudit tee-infer 审计链代理：GET /v1/adminext/audit-tee[?tenant=&verify=1]。
func (h *secCenterHandler) handleTeeAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epAuditTee) {
		return
	}
	if h.settings.url == "" {
		writeError(w, http.StatusServiceUnavailable, "tee-infer 地址未配置（ADMIN_TEE_INFER_URL）")
		return
	}
	target := h.settings.url + "/audit"
	q := r.URL.Query()
	if q.Get("verify") == "1" {
		target += "/verify"
	} else {
		// P1-7 T8（§7.7）：热层查询透传 §6.2 多维参数（hit/path_mode/request_id/sort/...）。
		pass := url.Values{}
		for _, k := range []string{"tenant", "from", "to", "model", "status", "action",
			"hit", "path_mode", "request_id", "limit", "offset", "sort"} {
			if v := q.Get(k); v != "" {
				pass.Set(k, v)
			}
		}
		if enc := pass.Encode(); enc != "" {
			target += "?" + enc
		}
	}
	body, status, err := h.fetchTee(r, target, true)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "tee-infer 不可达")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// secStatusView 密态链路状态视图（安全中心首屏）。
type secStatusView struct {
	TEEURL        string          `json:"tee_url"`
	TEEHealth     string          `json:"tee_health"` // ok | attestation_required | unreachable
	TEEHTTPStatus int             `json:"tee_http_status"`
	TEEConfig     json.RawMessage `json:"tee_config,omitempty"`
	AuditChain    auditChainView  `json:"audit_chain"`
	FetchedAt     int64           `json:"fetched_at"`
}

// auditChainView G1 链状态摘要。
type auditChainView struct {
	Enabled  bool   `json:"enabled"`
	Events   int    `json:"events"`
	Verified bool   `json:"verified"`
	LastHash string `json:"last_hash"` // 前 8 位（最小披露）
}

// handleSecStatus 密态链路状态聚合：GET /v1/adminext/sec-status。
func (h *secCenterHandler) handleSecStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epSecStatus) {
		return
	}
	view := secStatusView{
		TEEURL:    h.settings.url,
		TEEHealth: "unreachable",
		FetchedAt: time.Now().UnixNano(),
		AuditChain: auditChainView{
			Enabled: h.chain != nil,
		},
	}
	if h.chain != nil {
		ok, n := h.chain.verify()
		view.AuditChain.Verified = ok
		view.AuditChain.Events = n
		if last := h.chain.lastHash(); len(last) >= 8 {
			view.AuditChain.LastHash = last[:8] // 最小披露：只给链尾前 8 位
		} else {
			view.AuditChain.LastHash = last
		}
	}

	if h.settings.url != "" {
		if _, status, err := h.fetchTee(r, h.settings.url+"/healthz", false); err == nil {
			view.TEEHTTPStatus = status
			switch status {
			case http.StatusOK:
				view.TEEHealth = "ok"
			case http.StatusServiceUnavailable:
				view.TEEHealth = "attestation_required"
			}
		}
		if cfg, status, err := h.fetchTee(r, h.settings.url+"/config", true); err == nil && status == http.StatusOK {
			view.TEEConfig = json.RawMessage(cfg)
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// fetchTee 调用 tee-infer 端点；withToken = 是否带管理令牌头。
// 返回 body、HTTP 状态码与网络错误（状态码非 2xx 不算错误，由调用方判定语义）。
func (h *secCenterHandler) fetchTee(r *http.Request, target string, withToken bool) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	if withToken {
		req.Header.Set(teeAdminHeader, h.settings.token)
	}
	resp, err := h.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return body, resp.StatusCode, nil
}

// clampQueryInt 解析查询参数为整数并夹在 [min, max]，非法/缺省回退 def。
func clampQueryInt(raw string, def, min, max int) int {
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// ============================================================================
// P2-4 T-4.1：审计跨集群聚合查询（只读分卷视图，R-5/D-7）。
//
// 契约（§6.3）：聚合层是**查询视图**，**不重算哈希、不混合链**——
//   - admin 链：直查 admin-service 自身审计库（G1 链），与集群无关；
//   - core/tee 链：按 cluster 从其导出端点 `GET /v1/internal/audit/chain/export`
//     拉取 NDJSON，**原样透传**，不拼接单链语义；
//   - 降级语义：单集群拉取失败/离线 ⇒ 该卷标注 status=error|offline，**不影响其他
//     集群**返回，且不为空链（R-5/R-1）；集群注册表禁用 ⇒ core/tee 卷标 disabled。
//
// 鉴权：audit:read（audit_admin / auditor / sec_admin），与 audit-chain 同口径。
// ============================================================================

// 分卷状态（每卷独立标注，互不影响）。
const (
	auditVolOK       = "ok"        // 正常取数
	auditVolError    = "error"     // 集群返回非 2xx（4xx/5xx）
	auditVolOffline  = "offline"   // 集群不可达（网络错误/超时）
	auditVolDisabled = "disabled"  // 集群注册表未启用 / 集群未配置端点
	auditVolNotFound = "not_found" // 指定 cluster 不存在或已摘除
)

// auditChainVolume 单个集群指定链的分卷（不跨集群拼接）。
//
// 事件序列原样透传（json.RawMessage），聚合层**不重算哈希、不混合链**（R-5）；
// last_hash 取自集群导出端点的链尾哈希响应头（只读呈现，供 audit-verify 比对）。
type auditChainVolume struct {
	ClusterID   string            `json:"cluster_id"` // admin 卷 = ""（管理面全局，非集群维度）
	ClusterName string            `json:"cluster_name,omitempty"`
	Schema      string            `json:"schema"` // admin | core | tee
	Status      string            `json:"status"` // ok | error | offline | disabled | not_found
	Error       string            `json:"error,omitempty"`
	Events      []json.RawMessage `json:"events,omitempty"` // 分卷事件序列（原样透传，不重算哈希）
	EventCount  int               `json:"event_count"`
	Total       int               `json:"total,omitempty"`     // 链总长度（admin=内存总数；core/tee=导出端点 X-Audit-Export-Total）
	LastHash    string            `json:"last_hash,omitempty"` // 链尾哈希（最小披露：哈希本身非敏感，供独立验证比对）
	FetchedAt   int64             `json:"fetched_at"`
}

// auditChainQueryResponse 聚合查询响应（volumes 为分卷数组；cluster 缺省 ⇒ 所有注册集群）。
type auditChainQueryResponse struct {
	Schema                 string             `json:"schema"`
	GeneratedAt            int64              `json:"generated_at"`
	ClusterRegistryEnabled bool               `json:"cluster_registry_enabled"`
	Volumes                []auditChainVolume `json:"volumes"`
}

// clusterChainFetcher 按 cluster 拉取 core/tee 链导出（聚合层只读，不重算哈希）。
// 接口化便于单测注入；生产默认 httpClusterChainFetcher。
type clusterChainFetcher interface {
	FetchClusterChain(ctx context.Context, endpoint, schema, token string, limit int) (*auditChainVolume, error)
}

// fetchHTTPError 集群导出端点返回非 2xx（调用方据此标 status=error，区别于网络错误 offline）。
type fetchHTTPError struct{ Code int }

func (e *fetchHTTPError) Error() string { return fmt.Sprintf("cluster export HTTP %d", e.Code) }

// httpClusterChainFetcher 生产用跨集群链拉取：GET <endpoint>/v1/internal/audit/chain/export?schema=<s>。
//
// 鉴权：复用 admin→数据面内部服务令牌（Bearer，与 T-3.2b 推式下发同法）。
// 响应：body = 纯 NDJSON（逐字节同 WORM 行），元信息经 X-Audit-Export-* 响应头下发。
type httpClusterChainFetcher struct {
	client *http.Client
}

func (f *httpClusterChainFetcher) FetchClusterChain(ctx context.Context, endpoint, schema, token string, limit int) (*auditChainVolume, error) {
	u := strings.TrimRight(endpoint, "/") + "/v1/internal/audit/chain/export?schema=" + url.QueryEscape(schema)
	if limit > 0 {
		u += "&limit=" + strconv.Itoa(limit)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err // 网络错误/超时 ⇒ 调用方映射为 offline
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &fetchHTTPError{Code: resp.StatusCode}
	}
	events, perr := parseNDJSONLines(body)
	if perr != nil {
		return nil, perr
	}
	vol := &auditChainVolume{
		Schema:     schema,
		Status:     auditVolOK,
		Events:     events,
		EventCount: len(events),
		FetchedAt:  time.Now().UnixNano(),
	}
	if v := resp.Header.Get("X-Audit-Export-Tail-Hash"); v != "" {
		vol.LastHash = v
	}
	if v := resp.Header.Get("X-Audit-Export-Total"); v != "" {
		if n, e := strconv.Atoi(v); e == nil {
			vol.Total = n
		}
	}
	return vol, nil
}

// parseNDJSONLines 将 NDJSON body 解析为逐行 RawMessage（不重算哈希，仅透传 + 合法性校验）。
// 非法行 ⇒ 返回 error（该卷标 error，暴露导出损坏，不静默透传脏数据）。
func parseNDJSONLines(b []byte) ([]json.RawMessage, error) {
	var out []json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, fmt.Errorf("audit: 集群导出 NDJSON 含非法行（导出损坏）")
		}
		out = append(out, json.RawMessage(append([]byte(nil), line...)))
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// handleAuditChainQuery 审计跨集群聚合查询：GET /v1/adminext/audit-chain/query?cluster=&schema=&limit。
//
// 逻辑：先 RBAC（requireRule，audit:read）；解析 schema（缺省 admin，须 ∈ {admin,core,tee}）；
// schema=admin ⇒ 直查本服务 G1 链（单卷，cluster 参数被忽略——admin 链为管理面全局，非集群维度）；
// schema=core|tee ⇒ 按 cluster 拉取（cluster 缺省 ⇒ 所有已注册且未摘除集群各自一卷）。
// 逐卷独立标状态，单卷失败不影响其他卷（R-5/R-1）。
func (h *secCenterHandler) handleAuditChainQuery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireRule(w, r, epAuditChainQuery) {
		return
	}
	q := r.URL.Query()
	schema := q.Get("schema")
	if schema == "" {
		schema = "admin"
	}
	switch schema {
	case "admin", "core", "tee":
	default:
		writeError(w, http.StatusBadRequest, "schema 必须为 admin|core|tee")
		return
	}
	limit := clampQueryInt(q.Get("limit"), auditChainQueryDefaultLimit, 1, auditChainQueryMaxLimit)
	clusterID := strings.TrimSpace(q.Get("cluster"))

	resp := &auditChainQueryResponse{
		Schema:                 schema,
		GeneratedAt:            time.Now().UnixNano(),
		ClusterRegistryEnabled: h.clusterStore != nil,
	}
	switch schema {
	case "admin":
		resp.Volumes = []auditChainVolume{h.adminVolume(limit)}
	case "core", "tee":
		resp.Volumes = h.clusterVolumes(r.Context(), schema, clusterID, limit)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// adminVolume 读取本服务 G1 链分卷（只读，不重算哈希）。
func (h *secCenterHandler) adminVolume(limit int) auditChainVolume {
	v := auditChainVolume{Schema: "admin", ClusterID: "", Status: auditVolOK, FetchedAt: time.Now().UnixNano()}
	if h.chain == nil {
		v.Status = auditVolDisabled
		v.Error = "审计链未启用（ADMIN_AUDIT_FILE 未配置）"
		return v
	}
	events, total := h.chain.list(limit, 0)
	raw := make([]json.RawMessage, 0, len(events))
	for i := range events {
		b, err := json.Marshal(events[i])
		if err != nil {
			v.Status = auditVolError
			v.Error = "管理面审计事件序列化失败"
			return v
		}
		raw = append(raw, b)
	}
	v.Events = raw
	v.EventCount = len(raw)
	v.Total = total
	v.LastHash = h.chain.lastHash()
	return v
}

// clusterVolumes 构造 core/tee 的各集群分卷（逐卷独立，互不影响）。
//
//   - 注册表禁用（clusterStore=nil）：cluster 缺省 ⇒ 空卷集；指定 cluster ⇒ 单卷 disabled；
//   - 指定 cluster：不存在/已摘除 ⇒ not_found；否则拉取该卷；
//   - cluster 缺省：列举所有注册集群，跳过已摘除/已隔离，逐卷拉取。
func (h *secCenterHandler) clusterVolumes(ctx context.Context, schema, clusterID string, limit int) []auditChainVolume {
	now := time.Now().UnixNano()
	if h.clusterStore == nil {
		if clusterID == "" {
			return nil // 注册表未启用且无指定集群 ⇒ 无卷（cluster_registry_enabled=false 已在响应层标注）
		}
		return []auditChainVolume{{
			Schema: schema, ClusterID: clusterID, Status: auditVolDisabled,
			Error: "集群注册表未启用（无法定位集群导出端点）", FetchedAt: now,
		}}
	}
	if clusterID != "" {
		rec, err := h.clusterStore.Get(ctx, clusterID)
		if err != nil || rec.Status == ClusterStatusRemoved || rec.Status == ClusterStatusQuarantined {
			return []auditChainVolume{{
				Schema: schema, ClusterID: clusterID, Status: auditVolNotFound,
				Error: "集群不存在或已摘除", FetchedAt: now,
			}}
		}
		return []auditChainVolume{h.fetchOne(ctx, rec, schema, limit)}
	}
	recs, err := h.clusterStore.List(ctx)
	if err != nil {
		return []auditChainVolume{{
			Schema: schema, ClusterID: "", Status: auditVolError,
			Error: "集群注册表列举失败", FetchedAt: now,
		}}
	}
	out := make([]auditChainVolume, 0, len(recs))
	for _, rec := range recs {
		if rec.Status == ClusterStatusRemoved || rec.Status == ClusterStatusQuarantined {
			continue
		}
		out = append(out, h.fetchOne(ctx, rec, schema, limit))
	}
	return out
}

// fetchOne 拉取单集群 core/tee 分卷（失败降级为 error|offline，不影响其他卷）。
func (h *secCenterHandler) fetchOne(ctx context.Context, rec *ClusterRecord, schema string, limit int) auditChainVolume {
	v := auditChainVolume{Schema: schema, ClusterID: rec.ID, ClusterName: rec.Name, FetchedAt: time.Now().UnixNano()}
	if rec.Endpoint == "" {
		v.Status = auditVolError
		v.Error = "集群未配置数据面端点"
		return v
	}
	vol, err := h.fetcher.FetchClusterChain(ctx, rec.Endpoint, schema, h.dispatchToken, limit)
	if err != nil {
		var httpErr *fetchHTTPError
		if errors.As(err, &httpErr) {
			v.Status = auditVolError
			v.Error = fmt.Sprintf("集群返回 HTTP %d", httpErr.Code)
		} else {
			v.Status = auditVolOffline
			v.Error = "集群不可达（离线）"
		}
		return v
	}
	vol.ClusterID = rec.ID
	vol.ClusterName = rec.Name
	vol.Schema = schema
	return *vol
}
