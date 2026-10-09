// Package main — 租户审计摘要视图（F6，§6.7，M6）。
//
// 端点（租户会话前缀：TenantAuthMiddleware）：
//
//	GET /v1/adminext/tenant/audit?from&to&action&result&limit&offset
//
// 硬约束（§6.7 / D-10 / C-3）：
//   - **强制租户过滤**：tenant 恒为令牌声明（不接受客户端覆盖）；对 tee-infer 亦以本租户拉取，
//     返回前再按 tenant_id 二次确认（纵深防御）；
//   - **仅摘要字段白名单**：timestamp/action/result/model/tokens_in/out/cache_hit/is_retry/request_id；
//   - **显式剔除**：payload_hash、transformed_hash、key_fp 等可关联原文/内部链路字段；
//   - from/to 缺省近 30 天、最大 92 天；action 须在附录 D 枚举内（含 infer）；result ∈ success/denied/error；
//     limit 缺省 50、上限 200；offset ≥ 0；
//   - 数据源 tee-infer `/audit` 不可达 → 503（C-12）。
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	tenantAuditPath = tenantSessionBase + "/audit"

	tenantAuditDefaultDays  = 30
	tenantAuditMaxDays      = 92
	tenantAuditDefaultLimit = 50
	tenantAuditMaxLimit     = 200
)

// tenantAuditItem 审计摘要项（字段白名单，§6.7；绝不包含 payload_hash 等）。
type tenantAuditItem struct {
	Timestamp int64  `json:"timestamp"`
	Action    string `json:"action"`
	Result    string `json:"result"` // success | denied | error
	Model     string `json:"model,omitempty"`
	TokensIn  int    `json:"tokens_in"`
	TokensOut int    `json:"tokens_out"`
	CacheHit  bool   `json:"cache_hit"`
	IsRetry   bool   `json:"is_retry"`
	RequestID string `json:"request_id"`
}

// tenantAuditResponse 审计摘要响应（§6.7）。
type tenantAuditResponse struct {
	Total  int               `json:"total"`
	Limit  int               `json:"limit"`
	Offset int               `json:"offset"`
	Items  []tenantAuditItem `json:"items"`
}

// teeAuditEvent tee-infer 审计事件（仅解析摘要所需字段；其余（含 payload_hash）不进入本结构）。
type teeAuditEvent struct {
	Timestamp int64  `json:"timestamp"` // UTC 纳秒
	TenantID  string `json:"tenant_id"`
	RequestID string `json:"request_id"`
	Action    string `json:"action"`
	Result    string `json:"result"`
	Model     string `json:"model,omitempty"`
	TokensIn  int    `json:"tokens_in"`
	TokensOut int    `json:"tokens_out"`
	CacheHit  bool   `json:"cache_hit"`
	IsRetry   bool   `json:"is_retry"`
}

// tenantAuditActions 允许的 action 枚举（§6.7：附录 D 13 动作 + 数据面 infer/deny/key_issue）。
var tenantAuditActions = map[string]struct{}{
	"tenant_register": {}, "tenant_login": {}, "tenant_logout": {}, "password_reset": {},
	"api_key_create": {}, "api_key_rotate": {}, "api_key_revoke": {},
	"policy_update": {}, "policy_apply": {}, "model_config_update": {},
	"plan_upgrade": {}, "plan_downgrade": {}, "plan_bind": {},
	"infer": {}, "deny": {}, "key_issue": {},
}

// registerTenantAuditMux 注册租户审计端点（租户令牌；只读）。
func (h *tenantHandler) registerTenantAuditMux(mux *http.ServeMux) {
	mux.HandleFunc("GET "+tenantAuditPath,
		tenantAuthMiddleware(h.jwtSecret, h.handleTenantAudit))
}

// handleTenantAudit 本租户审计摘要（强制租户 + 白名单 + 过滤分页）。
func (h *tenantHandler) handleTenantAudit(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.usage == nil || h.usage.settings.url == "" {
		tenantWriteError(w, http.StatusServiceUnavailable, "审计数据源未配置")
		return
	}
	q := r.URL.Query()
	fromSec, toSec, ok := parseAuditWindow(q.Get("from"), q.Get("to"))
	if !ok {
		tenantWriteError(w, http.StatusBadRequest, "from/to 非法或窗口超过 92 天")
		return
	}
	action := q.Get("action")
	if action != "" {
		if _, ok := tenantAuditActions[action]; !ok {
			tenantWriteError(w, http.StatusBadRequest, "unknown action")
			return
		}
	}
	result := q.Get("result")
	if result != "" && result != "success" && result != "denied" && result != "error" {
		tenantWriteError(w, http.StatusBadRequest, "result 须为 success/denied/error")
		return
	}
	limit := clampQueryInt(q.Get("limit"), tenantAuditDefaultLimit, 1, tenantAuditMaxLimit)
	offset := clampQueryInt(q.Get("offset"), 0, 0, 1<<30)

	// 数据源：强制本租户（D-10；tee 侧亦按 tenant 过滤，此处不传客户端值）
	target := h.usage.settings.url + "/audit?" + url.Values{"tenant": {tenantID}}.Encode()
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "审计请求构造失败")
		return
	}
	req.Header.Set(teeAdminHeader, h.usage.settings.token)
	resp, err := h.usage.client.Do(req)
	if err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "审计数据源不可达")
		return
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		tenantWriteError(w, http.StatusServiceUnavailable, "审计数据源异常")
		return
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	var events []teeAuditEvent
	if err := json.Unmarshal(raw, &events); err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "审计数据源响应异常")
		return
	}

	// 过滤（租户/窗口/action/result）+ 摘要映射
	items := make([]tenantAuditItem, 0, len(events))
	for _, e := range events {
		if e.TenantID != tenantID { // 纵深防御：二次确认本租户
			continue
		}
		tsSec := e.Timestamp / 1e9 // 纳秒 → 秒
		if tsSec < fromSec || tsSec > toSec {
			continue
		}
		if action != "" && e.Action != action {
			continue
		}
		mapped := mapAuditResult(e.Result)
		if result != "" && mapped != result {
			continue
		}
		items = append(items, tenantAuditItem{
			Timestamp: tsSec,
			Action:    e.Action,
			Result:    mapped,
			Model:     e.Model,
			TokensIn:  e.TokensIn,
			TokensOut: e.TokensOut,
			CacheHit:  e.CacheHit,
			IsRetry:   e.IsRetry,
			RequestID: e.RequestID,
		})
	}

	total := len(items)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	tenantWriteJSON(w, http.StatusOK, tenantAuditResponse{
		Total: total, Limit: limit, Offset: offset, Items: items[offset:end],
	})
}

// parseAuditWindow 解析 from/to（YYYY-MM-DD）；缺省近 30 天，跨度上限 92 天。返回 unix 秒。
func parseAuditWindow(fromStr, toStr string) (int64, int64, bool) {
	now := time.Now()
	var from, to int64
	if toStr != "" {
		t, err := time.Parse("2006-01-02", toStr)
		if err != nil {
			return 0, 0, false
		}
		to = t.Add(24*time.Hour - time.Second).Unix() // 含当日
	} else {
		to = now.Unix()
	}
	if fromStr != "" {
		f, err := time.Parse("2006-01-02", fromStr)
		if err != nil {
			return 0, 0, false
		}
		from = f.Unix()
	} else {
		from = now.AddDate(0, 0, -tenantAuditDefaultDays).Unix()
	}
	if to < from {
		return 0, 0, false
	}
	if to-from > int64(tenantAuditMaxDays)*86400 {
		return 0, 0, false
	}
	return from, to, true
}

// mapAuditResult 归一化结果口径（tee-infer ok/deny → §6.7 success/denied；其余 error）。
func mapAuditResult(r string) string {
	switch r {
	case "ok", "success":
		return "success"
	case "deny", "denied":
		return "denied"
	default:
		return "error"
	}
}
