// Package main — A-2' 用量看板与配额端点（管理门户 M2）。
//
// 设计：docs/管理门户-M2剩余项重排计划.md §3 A-2'。
//
// 定位：**代理层**。计量唯一真源 = tee-infer 审计链（Higress 只见密文无法计量），
// 本服务不落任何用量数据，仅将门户请求转发至 tee-infer（/usage 与 /usage/quota），
// 注入服务间令牌（前端不可见），并补齐角色授权与审计留痕。
//
// 端点：
//
//	GET  /v1/adminext/usage         用量查询（auditor/admin 可读；透传 from/to/tenant）
//	                                 → tee-infer GET /usage（增量聚合，含模型维度与配额视图）
//	POST /v1/adminext/usage/quota    配额设置（**admin**）
//	                                 → tee-infer POST /usage/quota；成功后落 G1 审计链 quota_set
//	GET  /v1/adminext/metering/reconcile  审计-计量对账快照（auditor/admin 可读；S5 判据 6）
//	                                 → tee-infer GET /reconcile（容差 0/差异分类/出账是否被阻断）
//
// 503 语义（完成定义③：不静默返回 0/空数据）：
//   - ADMIN_TEE_INFER_URL / ADMIN_TEE_INFER_TOKEN 未配置 → 503；
//   - tee-infer 不可达（网络错误）→ 503；
//   - tee-infer 返回 5xx 或 401/403/404（数据源/配置异常）→ 503；
//   - tee-infer 返回 400（调用方参数错误）→ 透传 400。
//
// 安全约束：金额列不出现（现仅计量无单价，项目硬约束）；配额写操作先在数据源
// 生效再落 G1 审计链，落链失败拒绝 2xx（fail-closed，与凭据写一致）。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// usageAPIBase 用量端点前缀；usageQuotaPath 配额子路径；meteringReconcilePath 对账快照。
const (
	usageAPIBase          = "/v1/adminext/usage"
	usageQuotaPath        = usageAPIBase + "/quota"
	meteringReconcilePath = "/v1/adminext/metering/reconcile"
)

// teeAdminHeader tee-infer 管理端点认证头（服务间令牌，前端不可见）。
const teeAdminHeader = "X-Admin-Token"

// usageProxyTimeout 代理 tee-infer 的超时（管理面查询，非推理热路径）。
const usageProxyTimeout = 10 * time.Second

// usageSettings 用量代理配置（ADMIN_TEE_INFER_URL / ADMIN_TEE_INFER_TOKEN）。
type usageSettings struct {
	url   string // tee-infer 基址，如 http://127.0.0.1:19090（尾斜杠归一）
	token string // X-Admin-Token 值（tee-infer 管理令牌或计量令牌）
}

// loadUsageSettings 读取用量代理配置。
// token 缺省允许为空（tee-infer 开发模式可能不校验），但 url 未配置即视为特性关闭。
func loadUsageSettings() *usageSettings {
	return &usageSettings{
		url:   strings.TrimRight(os.Getenv("ADMIN_TEE_INFER_URL"), "/"),
		token: os.Getenv("ADMIN_TEE_INFER_TOKEN"),
	}
}

// quotaSetRequest 配额设置请求体（与 tee-infer /usage/quota 契约一致）。
type quotaSetRequest struct {
	Tenant    string `json:"tenant"`
	MaxTokens int64  `json:"max_tokens"` // <=0 = 解除限制
}

// usageHandler 用量代理端点集合。
type usageHandler struct {
	settings *usageSettings
	audit    *adminAuditChain // G1：quota_set 落链（nil = 未启用）
	client   *http.Client
}

// newUsageHandler 装配用量代理 handler（恒注册；数据源未配置时端点返回 503）。
func newUsageHandler(s *usageSettings, audit *adminAuditChain) *usageHandler {
	return &usageHandler{
		settings: s,
		audit:    audit,
		client:   &http.Client{Timeout: usageProxyTimeout},
	}
}

// requireDataSource 数据源已配置方可代理（否则 503，不静默返回空数据）。
func (h *usageHandler) requireDataSource(w http.ResponseWriter) bool {
	if h.settings.url == "" {
		writeError(w, http.StatusServiceUnavailable, "usage 数据源未配置（ADMIN_TEE_INFER_URL）")
		return false
	}
	return true
}

// handleUsage 用量查询：GET /v1/adminext/usage?from&to&tenant（auditor 可读）。
func (h *usageHandler) handleUsage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireReadAccess(w, r) {
		return
	}
	if !h.requireDataSource(w) {
		return
	}

	// 白名单透传查询参数（from/to/tenant），防任意参数注入数据源。
	q := url.Values{}
	for _, k := range []string{"from", "to", "tenant"} {
		if v := r.URL.Query().Get(k); v != "" {
			q.Set(k, v)
		}
	}
	target := h.settings.url + "/usage"
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "usage 请求构造失败")
		return
	}
	req.Header.Set(teeAdminHeader, h.settings.token)

	resp, err := h.client.Do(req)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "usage 数据源不可达")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.relayError(w, resp, "usage 数据源")
		return
	}
	h.relay(w, resp)
}

// handleQuota 配额设置：POST /v1/adminext/usage/quota（**admin**）。
// 先在 tee-infer 生效，再落 G1 审计链 quota_set；落链失败拒绝 2xx（fail-closed）。
func (h *usageHandler) handleQuota(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRole(w, r, roleAdmin) {
		return
	}
	if !h.requireDataSource(w) {
		return
	}

	var req quotaSetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Tenant == "" {
		writeError(w, http.StatusBadRequest, "请求体须为 JSON 且含 tenant")
		return
	}
	body, err := json.Marshal(req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "请求体编码失败")
		return
	}

	proxyReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost,
		h.settings.url+"/usage/quota", strings.NewReader(string(body)))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "配额请求构造失败")
		return
	}
	proxyReq.Header.Set("Content-Type", "application/json")
	proxyReq.Header.Set(teeAdminHeader, h.settings.token)

	resp, err := h.client.Do(proxyReq)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "配额数据源不可达")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.relayError(w, resp, "配额数据源")
		return
	}

	// G1 审计落链：配额已在数据源生效，落链失败无法回滚 → 拒绝 2xx（fail-closed）。
	if h.audit != nil {
		if err := h.audit.append(adminAuditEvent{
			Actor:     operationSub(r),
			Action:    auditActionQuotaSet,
			Tenant:    req.Tenant,
			MaxTokens: req.MaxTokens,
			RequestID: r.Header.Get("X-Request-ID"),
			Result:    "ok",
		}); err != nil {
			metrics.incBrokerAuditWriteFailed()
			writeError(w, http.StatusInternalServerError,
				"配额已在数据源生效但审计链写入失败（fail-closed；请人工核查审计文件后再决定是否重试）")
			return
		}
	}
	h.relay(w, resp)
}

// handleMeteringReconcile 审计-计量对账快照：GET /v1/adminext/metering/reconcile（auditor 可读）。
// → tee-infer GET /reconcile（S5 判据 6：容差/差异分类/对外出账是否被阻断）。
// 定位同 /usage：**只读代理**，本服务不自算、不落库；作为控制台看板的数据源。
func (h *usageHandler) handleMeteringReconcile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireReadAccess(w, r) {
		return
	}
	if !h.requireDataSource(w) {
		return
	}
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, h.settings.url+"/reconcile", nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "对账请求构造失败")
		return
	}
	req.Header.Set(teeAdminHeader, h.settings.token)

	resp, err := h.client.Do(req)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, "对账数据源不可达")
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		h.relayError(w, resp, "对账数据源")
		return
	}
	h.relay(w, resp)
}

// relay 透传数据源 2xx 响应（Content-Type + body 原样）。
func (h *usageHandler) relay(w http.ResponseWriter, resp *http.Response) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// relayError 透传数据源错误：400（调用方参数错）原样透传，其余视为数据源异常 → 503。
// label 用于错误文案（区分用量/对账两类数据源）。
func (h *usageHandler) relayError(w http.ResponseWriter, resp *http.Response, label string) {
	if resp.StatusCode == http.StatusBadRequest {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		writeError(w, http.StatusBadRequest, fmt.Sprintf("参数错误: %s", strings.TrimSpace(string(msg))))
		return
	}
	writeError(w, http.StatusServiceUnavailable,
		fmt.Sprintf("%s返回异常（HTTP %d）", label, resp.StatusCode))
}
