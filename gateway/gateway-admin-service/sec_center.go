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
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
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
)

// secCenterHandler 安全中心数据端点集合。
type secCenterHandler struct {
	chain    *adminAuditChain // nil = G1 链未启用
	settings *usageSettings   // 复用 tee-infer 地址/令牌配置
	client   *http.Client
	full     *auditFullHandler // P1-7 T8/T9：温/冷层检索·导出 + 留存声明（恒装配）
}

// newSecCenterHandler 装配安全中心 handler（恒注册；数据源缺失时按上述 503 语义返回）。
func newSecCenterHandler(chain *adminAuditChain, s *usageSettings) *secCenterHandler {
	return &secCenterHandler{
		chain:    chain,
		settings: s,
		client:   &http.Client{Timeout: secCenterTimeout},
		full:     newAuditFullHandler(s, chain),
	}
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
