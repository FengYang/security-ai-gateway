// Package main — 租户用量与账单查询（F3，§6.4，M4）。
//
// 端点（租户会话前缀：TenantAuthMiddleware）：
//
//	GET /v1/adminext/tenant/usage               日/月聚合（透传 tee-infer，强制本租户，无金额）
//	GET /v1/adminext/tenant/bills               账单列表（租户固定）
//	GET /v1/adminext/tenant/bills/{id}          明细；归属校验失败 → 404（不泄露他租户存在性）
//	GET /v1/adminext/tenant/bills/{id}/export   明细导出（CSV，含公式注入防护）
//
// 硬约束（§6.4）：
//   - 租户身份注入（C-15）：**强制丢弃**客户端 tenant 参数，以令牌 tenant 声明替换后再转发；
//   - 窗口 from/to ≤ 92 天；limit ≤ 500；
//   - tee-infer 不可达 → 503；billing 域未启用 → bills 503（C-12，不静默返回空数据）；
//   - 金额列不出现（C-10）。
package main

import (
	"io"
	"net/http"
	"net/url"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
)

const (
	tenantUsagePath = tenantSessionBase + "/usage"
	tenantBillsPath = tenantSessionBase + "/bills"

	// 查询上限（§6.4：窗口 ≤ 92 天；列表 limit ≤ 500）。
	tenantUsageMaxWindowDays = 92
	tenantQueryMaxLimit      = 500
)

// registerTenantUsageMux 注册租户用量/账单端点（租户令牌；只读，无需 CSRF）。
func (h *tenantHandler) registerTenantUsageMux(mux *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.HandlerFunc { return tenantAuthMiddleware(h.cfg, fn) }
	mux.HandleFunc("GET "+tenantUsagePath, wrap(h.handleTenantUsage))
	mux.HandleFunc("GET "+tenantBillsPath, wrap(h.handleTenantBills))
	mux.HandleFunc("GET "+tenantBillsPath+"/{id}", wrap(h.handleTenantBillItem))
	mux.HandleFunc("GET "+tenantBillsPath+"/{id}/export", wrap(h.handleTenantBillExport))
}

// ---------- 用量 ----------

// handleTenantUsage 用量聚合：透传 tee-infer /usage（强制本租户，丢弃客户端 tenant）。
func (h *tenantHandler) handleTenantUsage(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.usage == nil || h.usage.settings.url == "" {
		tenantWriteError(w, http.StatusServiceUnavailable, "用量数据源未配置")
		return
	}
	q := r.URL.Query()
	if _, _, ok := parseUsageWindow(q.Get("from"), q.Get("to")); !ok {
		tenantWriteError(w, http.StatusBadRequest, "from/to 非法或窗口超过 92 天")
		return
	}
	// 强制租户（C-15）：仅转发 from/to，tenant 用令牌声明
	fwd := url.Values{}
	fwd.Set("tenant", tenantID)
	if v := q.Get("from"); v != "" {
		fwd.Set("from", v)
	}
	if v := q.Get("to"); v != "" {
		fwd.Set("to", v)
	}
	if g := q.Get("granularity"); g == "day" || g == "month" {
		fwd.Set("granularity", g)
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet,
		h.usage.settings.url+"/usage?"+fwd.Encode(), nil)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "usage 请求构造失败")
		return
	}
	req.Header.Set(teeAdminHeader, h.usage.settings.token)
	resp, err := h.usage.client.Do(req)
	if err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "用量数据源不可达")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		tenantWriteError(w, http.StatusServiceUnavailable, "用量数据源异常")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 4<<20))
}

// parseUsageWindow 校验窗口：空值合法（沿用上游缺省）；两者均给定时须合规且跨度 ≤ 92 天。
func parseUsageWindow(from, to string) (string, string, bool) {
	if from == "" || to == "" {
		return from, to, true
	}
	f, err1 := time.Parse("2006-01-02", from)
	t, err2 := time.Parse("2006-01-02", to)
	if err1 != nil || err2 != nil || t.Before(f) {
		return "", "", false
	}
	if t.Sub(f) > time.Duration(tenantUsageMaxWindowDays)*24*time.Hour {
		return "", "", false
	}
	return from, to, true
}

// ---------- 账单列表 ----------

// handleTenantBills 账单列表（租户固定）。
func (h *tenantHandler) handleTenantBills(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.billing == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "账单功能未启用")
		return
	}
	q := r.URL.Query()
	bills, err := h.billing.store.Bills().List(billing.BillQuery{
		TenantID: tenantID, // 恒定租户（忽略客户端传入）
		Kind:     q.Get("kind"),
		From:     q.Get("from"),
		To:       q.Get("to"),
		Limit:    clampTenantLimit(q.Get("limit"), 100),
	})
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "账单查询失败")
		return
	}
	tenantWriteJSON(w, http.StatusOK, map[string]any{"bills": bills})
}

// ---------- 账单明细 ----------

// handleTenantBillItem 账单明细；归属校验失败 → 404（不泄露存在性）。
func (h *tenantHandler) handleTenantBillItem(w http.ResponseWriter, r *http.Request) {
	bill, tenantID, ok := h.loadTenantBill(w, r)
	if !ok {
		return
	}
	_ = tenantID
	tenantWriteJSON(w, http.StatusOK, bill)
}

// ---------- 账单导出 ----------

// handleTenantBillExport 账单明细导出（CSV；复用 billing.ExportCSV 的公式注入防护）。
func (h *tenantHandler) handleTenantBillExport(w http.ResponseWriter, r *http.Request) {
	bill, tenantID, ok := h.loadTenantBill(w, r)
	if !ok {
		return
	}
	data, mime, err := billing.ExportCSV(bill)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "导出失败")
		return
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Disposition", `attachment; filename="bill-`+bill.ID+`.csv"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
	_ = tenantID
}

// loadTenantBill 取账单并校验归属（跨租户/不存在 → 404，不泄露存在性）。
func (h *tenantHandler) loadTenantBill(w http.ResponseWriter, r *http.Request) (*billing.Bill, string, bool) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return nil, "", false
	}
	if h.billing == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "账单功能未启用")
		return nil, "", false
	}
	billID := r.PathValue("id")
	if billID == "" {
		tenantWriteError(w, http.StatusBadRequest, "账单 id 缺失")
		return nil, "", false
	}
	bill, err := h.billing.store.Bills().Get(billID)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "账单查询失败")
		return nil, "", false
	}
	// 归属校验失败 → 404（不泄露他租户账单存在性）
	if bill == nil || bill.TenantID != tenantID {
		tenantWriteError(w, http.StatusNotFound, "账单不存在")
		return nil, "", false
	}
	return bill, tenantID, true
}

// clampTenantLimit 归一化分页 limit（≤ tenantQueryMaxLimit）。
func clampTenantLimit(raw string, def int) int {
	v := atoiDefault(raw, def)
	if v <= 0 {
		return def
	}
	if v > tenantQueryMaxLimit {
		return tenantQueryMaxLimit
	}
	return v
}
