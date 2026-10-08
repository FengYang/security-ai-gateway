// Package main — P1-2 SLA 报表端点（M6，§6.3 / §7.8）。
//
//	GET /v1/adminext/sla/summary   从 Prometheus 聚合可用性 / P50/P95/P99 / 错误率
//
// 数据源与 503 语义（对齐 sec_center.go：不静默返回空）：
//   - Prometheus 地址未配置（ADMIN_PROMETHEUS_URL）→ 503；
//   - Prometheus 不可达 / 查询失败 → 503。
//
// 租户作用域（§6.3）：非 admin 会话强制收敛为自身租户；admin 可跨租户。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	slaSummaryPath   = "/v1/adminext/sla/summary"
	slaPromTimeout   = 5 * time.Second
	slaDefaultWindow = "5m"
)

// slaHandler SLA 报表 handler。
type slaHandler struct {
	promURL string // Prometheus 地址（空 = 未配置 → 503）
	client  *http.Client
}

// newSLAHandler 装配 SLA 报表 handler（恒注册；数据源缺失时 503）。
func newSLAHandler(promURL string) *slaHandler {
	return &slaHandler{
		promURL: strings.TrimRight(promURL, "/"),
		client:  &http.Client{Timeout: slaPromTimeout},
	}
}

// slaSummaryView SLA 汇总视图。
type slaSummaryView struct {
	Tenant       string  `json:"tenant"` // 空 = 全租户（admin）
	Window       string  `json:"window"`
	Availability float64 `json:"availability"`
	ErrorRate    float64 `json:"error_rate"`
	P50Ms        float64 `json:"p50_ms"`
	P95Ms        float64 `json:"p95_ms"`
	P99Ms        float64 `json:"p99_ms"`
	FetchedAt    int64   `json:"fetched_at"`
}

// handleSLASummary GET /v1/adminext/sla/summary?window=5m[&tenant=]
func (h *slaHandler) handleSLASummary(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireReadAccess(w, r) {
		return
	}
	if h.promURL == "" {
		writeError(w, http.StatusServiceUnavailable, "Prometheus 地址未配置（ADMIN_PROMETHEUS_URL）")
		return
	}
	// 租户作用域：非 admin 强制收敛为自身租户
	c := claimsFrom(r.Context())
	tenant := strings.TrimSpace(r.URL.Query().Get("tenant"))
	if c != nil && c.Role != roleAdmin {
		if c.Tenant == "" || (tenant != "" && tenant != c.Tenant) {
			writeError(w, http.StatusForbidden, "跨租户访问被拒绝")
			return
		}
		tenant = c.Tenant
	}
	window := strings.TrimSpace(r.URL.Query().Get("window"))
	if window == "" {
		window = slaDefaultWindow
	}
	sel := promTenantSelector(tenant)

	view := slaSummaryView{Tenant: tenant, Window: window, FetchedAt: time.Now().UnixNano()}
	var err error
	if view.Availability, err = h.queryScalar(r, fmt.Sprintf(
		`sum(rate(otpmask_inference_requests_total{result="ok"%s}[%s])) / clamp_min(sum(rate(otpmask_inference_requests_total{%s}[%s])), 1)`,
		sel, window, promTrimBrace(sel), window)); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Prometheus 查询失败（可用性）")
		return
	}
	view.ErrorRate = 1 - view.Availability
	if view.P50Ms, err = h.queryScalar(r, fmt.Sprintf(
		`histogram_quantile(0.50, sum by (le) (rate(otpmask_ttft_seconds_bucket{%s}[%s]))) * 1000`,
		promTrimBrace(sel), window)); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Prometheus 查询失败（P50）")
		return
	}
	if view.P95Ms, err = h.queryScalar(r, fmt.Sprintf(
		`histogram_quantile(0.95, sum by (le) (rate(otpmask_ttft_seconds_bucket{%s}[%s]))) * 1000`,
		promTrimBrace(sel), window)); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Prometheus 查询失败（P95）")
		return
	}
	if view.P99Ms, err = h.queryScalar(r, fmt.Sprintf(
		`histogram_quantile(0.99, sum by (le) (rate(otpmask_ttft_seconds_bucket{%s}[%s]))) * 1000`,
		promTrimBrace(sel), window)); err != nil {
		writeError(w, http.StatusServiceUnavailable, "Prometheus 查询失败（P99）")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(view)
}

// promTenantSelector 生成租户标签选择器（空租户 = 空串 = 全租户）。
func promTenantSelector(tenant string) string {
	if tenant == "" {
		return ""
	}
	return fmt.Sprintf(`,tenant=%q`, tenant)
}

// promTrimBrace 把 ",tenant=\"x\"" 转为 "tenant=\"x\""（用于 {…} 内首位指标选择器）。
func promTrimBrace(sel string) string { return strings.TrimPrefix(sel, ",") }

// promQueryScalar 执行 Prometheus 瞬时查询并取首个结果的数值（无结果视为 0）。
// 供 SLA 报表与 SLO 错误预算共用（同一口径）。
func promQueryScalar(r *http.Request, client *http.Client, promURL, expr string) (float64, error) {
	v := url.Values{}
	v.Set("query", expr)
	target := promURL + "/api/v1/query?" + v.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("prometheus 返回 %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return 0, err
	}
	var out struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Value []json.RawMessage `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return 0, err
	}
	if out.Status != "success" || len(out.Data.Result) == 0 || len(out.Data.Result[0].Value) < 2 {
		return 0, nil // 无数据 = 0（不视为错误）
	}
	raw := strings.Trim(string(out.Data.Result[0].Value[1]), `"`)
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return 0, nil
	}
	return f, nil
}

// queryScalar slaHandler 便捷封装。
func (h *slaHandler) queryScalar(r *http.Request, expr string) (float64, error) {
	return promQueryScalar(r, h.client, h.promURL, expr)
}
