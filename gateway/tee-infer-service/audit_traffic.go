package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// P1-7 T2a（MOD2）：数据面未达 TEE 流量上报端点 POST /audit/report（§6.5 / D-2 / D-13）。
//
// 语义与既有 /audit/shadow 一致（整批先校验→非法整批 400、窗口内幂等、fail-closed），
// 但为**逐笔请求**事件：action=request、origin=data-plane。
//
// 上报安全（D-13，纵深防御）：
//   - 独立只读上报令牌（X-Admin-Token，仅可达本端点；不回落 -admin-token，A3-11）；
//   - 请求体 HMAC-SHA256 签名（头 X-Audit-Report-Sig），防篡改；
//   - timestamp_ns 5 分钟时间窗防重放；
//   - 租户归属校验（A3-10 / D-18 分型）：插件侧令牌绑定 tenant 集合、越界整批 400；
//     回灌侧（网关级）租户由服务端解析、不信任自报；
//   - 窗口内 request_id 幂等（复用 shadowReportState 机制，独立键命名空间）。
//
// 落链通道选型裁决（A3-03 / A4-01）：统一经 auditChain.append()，与 TEE 侧既有落链点
// 同通道（D-17 后 append 经 fileWorm 落盘），不引入 appendOrFail 双通道。

// auditReportItem 单条数据面上报（字段与 §6.5 请求体一一对应）。
type auditReportItem struct {
	RequestID   string `json:"request_id"`
	TenantID    string `json:"tenant_id,omitempty"` // 插件侧必填且须∈令牌绑定集合；回灌侧由服务端解析（不取自报）
	Path        string `json:"path,omitempty"`
	PathMode    string `json:"path_mode,omitempty"` // plain | encrypted
	HTTPStatus  int    `json:"http_status,omitempty"`
	Result      string `json:"result"` // 6 项白名单（见 auditReportResultWhitelist）
	HitPolicies string `json:"hit_policies,omitempty"`
	TimestampNS int64  `json:"timestamp_ns,omitempty"` // 上报时刻（数据面时钟，Unix 纳秒）；用于 5 分钟重放窗校验
	DurMS       int    `json:"dur_ms,omitempty"`
	Model       string `json:"model,omitempty"`
}

// auditReport 上报请求体（批量）。
type auditReport struct {
	Reports []auditReportItem `json:"reports"`
}

// auditReportResultWhitelist 上报侧 result 严格白名单（§6.5，冻结全集，实施时不得新增）。
var auditReportResultWhitelist = map[string]bool{
	"rate_limited":        true, // 限流拒绝（D-15，→ hit）
	"auth_failed":         true, // 鉴权失败 401（D-15，→ hit）
	"ip_blocked":          true, // IP 封禁 403（D-15，→ hit）
	"cache_hit_dataplane": true, // 数据面缓存命中（→ miss）
	"non_infer":           true, // 非推理请求（→ miss）
	"ok":                  true, // 正常到达 TEE 前的补充上报（→ miss）
}

// auditReportMaxBatch 单批条数上限（§6.5 validate）。
const auditReportMaxBatch = 500

// auditReportTimeWindow 重放防护时间窗（§6.5 D-13）。
const auditReportTimeWindow = 5 * time.Minute

// sentinelTenant 回灌侧（无服务端可解析身份时）的哨兵租户（D-18 未归属标记）。
const auditReportSentinelTenant = "_unauthenticated"

// validate 整批校验：任一非法 → error（调用方整批 400，不做部分接受）。
// now 为服务端当前时间（Unix 纳秒）。pluginMode=true 时 tenant_id 必填且须∈令牌绑定集合
// （该项集合成员校验在调用方完成，此处仅校验非空）；否则为网关/回灌侧（tenant 由服务端解析）。
func (r *auditReport) validate(now int64, pluginMode bool) error {
	if len(r.Reports) == 0 {
		return fmt.Errorf("reports 不得为空")
	}
	if len(r.Reports) > auditReportMaxBatch {
		return fmt.Errorf("reports 条数超上限 %d，实际 %d", auditReportMaxBatch, len(r.Reports))
	}
	for i := range r.Reports {
		it := &r.Reports[i]
		if strings.TrimSpace(it.RequestID) == "" {
			return fmt.Errorf("第 %d 条：request_id 必填", i)
		}
		if pluginMode && strings.TrimSpace(it.TenantID) == "" {
			return fmt.Errorf("第 %d 条：插件侧上报 tenant_id 必填", i)
		}
		if !auditReportResultWhitelist[it.Result] {
			return fmt.Errorf("第 %d 条：result 非法（%q 不在白名单）", i, it.Result)
		}
		if it.TimestampNS != 0 {
			delta := time.Duration(absInt64(now - it.TimestampNS))
			if delta > auditReportTimeWindow {
				return fmt.Errorf("第 %d 条：timestamp_ns 超出 ±5 分钟重放窗（差 %s）", i, delta)
			}
		}
		switch it.PathMode {
		case "", "plain", "encrypted":
		default:
			return fmt.Errorf("第 %d 条：path_mode 非法（须 plain|encrypted），实际 %q", i, it.PathMode)
		}
	}
	return nil
}

// absInt64 取绝对值（time.Duration 底层为 int64 纳秒）。
func absInt64(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// auditReportModeLabel 返回上报端点运行模式标签（用于启动日志）。
func auditReportModeLabel(tenants string) string {
	if parseTenantSet(tenants) != nil {
		return "plugin(tenant-bound)"
	}
	return "gateway(server-resolved)"
}

// parseTenantSet 解析逗号分隔的 tenant_id 集合（trim + 去空）。空串返回 nil（网关级模式）。
func parseTenantSet(s string) map[string]bool {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	set := make(map[string]bool)
	for _, t := range strings.Split(s, ",") {
		t = strings.TrimSpace(t)
		if t != "" {
			set[t] = true
		}
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

// reporterHash8 由上报令牌派生稳定的上报端标识（前 8 hex），用于 reporter_id：
// 标识"持有该令牌的上报端"，不泄露令牌明文（A3-10 审计投毒溯源）。
func reporterHash8(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])[:8]
}

// checkReportAuth 校验上报令牌（独立只读令牌，不回落 -admin-token，A3-11）。
// 与 checkAdmin 隔离：本端点只用 auditReportToken，绝不接受管理令牌。
func (s *teeServer) checkReportAuth(r *http.Request) bool {
	if s.auditReportToken == "" {
		return false // 端点未注册时不该到达；防御性拒绝
	}
	token := r.Header.Get(adminHeader)
	if token == "" {
		return false
	}
	a := sha256.Sum256([]byte(token))
	b := sha256.Sum256([]byte(s.auditReportToken))
	return subtle.ConstantTimeCompare(a[:], b[:]) == 1
}

// handleAuditReport POST /audit/report：接收数据面未达 TEE 的流量并逐条落链
// （action=request、origin=data-plane），完整实现 §6.5 语义。
func (s *teeServer) handleAuditReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		recordExemptExit("handleAuditReport", "method_not_allowed")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !s.checkReportAuth(r) {
		s.auditDenyExitReq(r, "-", "", "report_auth_failed", "", http.StatusUnauthorized)
		http.Error(w, "上报认证失败", http.StatusUnauthorized)
		return
	}
	// 先读原始 body（用于 HMAC 校验），再解析 JSON。
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	if err != nil {
		s.auditDenyExitReq(r, "-", "", "report_read_failed", "", http.StatusBadRequest)
		http.Error(w, "读取请求体失败", http.StatusBadRequest)
		return
	}
	sig := r.Header.Get("X-Audit-Report-Sig")
	if sig == "" {
		s.auditDenyExitReq(r, "-", "", "report_missing_sig", "", http.StatusUnauthorized)
		http.Error(w, "缺少 X-Audit-Report-Sig", http.StatusUnauthorized)
		return
	}
	mac := hmac.New(sha256.New, []byte(s.auditReportToken))
	mac.Write(raw)
	expected := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(expected), []byte(sig)) {
		s.auditDenyExitReq(r, "-", "", "report_bad_sig", "", http.StatusUnauthorized)
		http.Error(w, "上报签名校验失败", http.StatusUnauthorized)
		return
	}
	var req auditReport
	if err := json.Unmarshal(raw, &req); err != nil {
		s.auditDenyExitReq(r, "-", "", "report_bad_json", "", http.StatusBadRequest)
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}

	pluginMode := len(s.auditReportTenants) > 0
	if err := req.validate(time.Now().UnixNano(), pluginMode); err != nil {
		s.auditDenyExitReq(r, "-", "", "report_validate_failed", "", http.StatusBadRequest)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// 租户归属校验（A3-10 / D-18 分型①）：插件侧令牌绑定集合，越界整批 400。
	if pluginMode {
		for i := range req.Reports {
			if !s.auditReportTenants[req.Reports[i].TenantID] {
				s.auditDenyExitReq(r, "-", "", "report_tenant_unauthorized", "", http.StatusBadRequest)
				http.Error(w, fmt.Sprintf("第 %d 条：tenant_id %q 不在本令牌授权集合", i, req.Reports[i].TenantID), http.StatusBadRequest)
				return
			}
		}
	}

	// 回灌侧（D-18）：读取数据面经 key-auth 注入的 consumer 标识，作为租户解析线索
	// （真实 consumer→tenant 映射表由 T2c deliverable deploy/logging/consumer-tenant-map.yaml 落地；
	// 本任务未装配映射表，故暂落哨兵租户 + TenantIDResolution 标记，待 T2c 接入后改为真实解析）。
	consumer := r.Header.Get("X-Mse-Consumer")

	now := time.Now()
	reporterID := "tok-" + reporterHash8(s.auditReportToken)
	newly := 0
	deduped := 0

	// 持 s.mu 跨 admit+append，保证窗口内 request_id 幂等（避免并发双写）。
	s.mu.Lock()
	for i := range req.Reports {
		it := &req.Reports[i]
		if !s.auditReports.admit(it.RequestID, now) {
			deduped++
			continue
		}
		ev := AuditEvent{
			TenantID:    it.TenantID,
			RequestID:   it.RequestID,
			Action:      "request",
			Origin:      "data-plane",
			Result:      it.Result,
			Path:        it.Path,
			PathMode:    it.PathMode,
			HTTPStatus:  it.HTTPStatus,
			DurMS:       it.DurMS,
			Model:       it.Model,
			HitPolicies: it.HitPolicies,
			ReporterID:  reporterID, // 服务端按令牌绑定身份写入，不取自报值（A3-10）
		}
		// payload_hash = sha256(request_id)（进 hash 字段，§6.5；非明文、可复算）。
		sum := sha256.Sum256([]byte(it.RequestID))
		ev.PayloadSHA = hex.EncodeToString(sum[:])
		// timestamp_ns 有效则保留原始上报时刻（取证用）；否则 append() 取落链时刻。
		if it.TimestampNS != 0 {
			ev.Timestamp = it.TimestampNS
		}
		// 网关/回灌侧：服务端解析租户，不信任自报（D-18 分型②）。
		if !pluginMode {
			if consumer != "" {
				ev.TenantIDResolution = "consumer_map" // T2c 映射表将据此解析真实租户
			} else {
				ev.TenantIDResolution = "unauthenticated"
			}
			ev.TenantID = auditReportSentinelTenant
		}
		s.audit.append(ev)
		newly++
	}
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"accepted":   newly,
		"duplicates": deduped,
	})
}
