// Package main — P1-2 SLO 定义与租户 tracing 灰度开关（M7，§6.3 / §7.9）。
//
//	GET  /v1/adminext/slo               SLO 定义 + 当前错误预算余量（Prometheus 聚合）
//	POST /v1/adminext/slo          admin 创建/更新 SLO（落审计链，fail-closed）
//	POST /v1/adminext/tracing/tenant admin 租户级 tracing 灰度开关（落审计链，fail-closed）
//
// 存储：ADMIN_SLO_FILE（JSON 文件；未配置 = 内存模式，重启丢失，如实日志）。
// 审计：POST 端点在审计链未启用（ADMIN_AUDIT_FILE 未配置）时返回 503（不静默落空）。
//
// C-4/C-8：tracing 默认关闭；本端点仅维护「期望 allow-list」，实际执行点在
// Collector tail_sampling（§6.4 租户开关执行点）——Collector 侧热更属运维动作，
// 本端点持久化期望状态并落审计，供 Collector 侧同步（待实机验证 wiring）。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	sloPath           = "/v1/adminext/slo"
	tracingTenantPath = "/v1/adminext/tracing/tenant"
)

// 支持的 SLO 类型（§7.9 冻结：availability / latency_p99）。
const (
	sliTypeAvailability = "availability"
	sliTypeLatencyP99   = "latency_p99"
)

// sliDef 服务级指标定义（§7.9 冻结 schema）。
type sliDef struct {
	Type   string `json:"type"` // availability | latency_p99
	Metric string `json:"metric"`
	Filter string `json:"filter,omitempty"`
}

// sloAlerting 燃尽率告警参数（§7.9 冻结 schema）。
type sloAlerting struct {
	FastBurnRate float64 `json:"fast_burn_rate"`
	SlowBurnRate float64 `json:"slow_burn_rate"`
	Enabled      bool    `json:"enabled"`
}

// sloDef 单条 SLO 定义（§7.9 冻结 schema）。
type sloDef struct {
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	SLI         sliDef      `json:"sli"`
	Target      float64     `json:"target"` // 目标（0,1），如 0.999
	Window      string      `json:"window"` // 统计窗口，如 "30d"
	Alerting    sloAlerting `json:"alerting"`
	TenantID    string      `json:"tenant_id,omitempty"`
	Enabled     bool        `json:"enabled"`
}

// sloStoreState 持久化状态。
type sloStoreState struct {
	SLOS []sloDef `json:"slos"`
	// TracingTenants tracing allow-list 的**本地缓存**。
	// 事实源为 Collector ConfigMap（见 tracing_allowlist.go）；本字段仅作
	// 未接线（非集群内）时的只读回显与最近一次成功应用的回执。
	TracingTenants []string `json:"tracing_tenants"`
}

// sloHandler SLO 与 tracing 灰度端点集合。
type sloHandler struct {
	mu      sync.Mutex
	path    string // 空 = 内存模式
	state   sloStoreState
	promURL string
	client  *http.Client
	chain   *adminAuditChain
	// applier Collector allow-list 应用器（事实源 = ConfigMap）。
	// nil = 未接线（非 in-cluster 或初始化失败）→ 写端点 503 fail-closed。
	applier *allowlistApplier
}

// newSLOHandler 装配 handler：加载持久化状态（文件损坏 → 空状态并告警，不拒绝启动）。
// 同时尽力装配 Collector allow-list 应用器：非 in-cluster → applier 为 nil（写端点 503）。
func newSLOHandler(file, promURL string, chain *adminAuditChain) *sloHandler {
	h := &sloHandler{
		path:    file,
		promURL: strings.TrimRight(promURL, "/"),
		client:  &http.Client{Timeout: 5 * time.Second},
		chain:   chain,
	}
	if file != "" {
		if raw, err := os.ReadFile(file); err == nil {
			if err := json.Unmarshal(raw, &h.state); err != nil {
				log.Printf("[adminext] SLO 状态文件损坏（按空状态处理）：%v", err)
			}
		}
	}
	if a, err := newAllowlistApplierFromEnv(); err != nil {
		log.Printf("[adminext] Collector allow-list 未接线（%v）：POST /tracing/tenant 将返回 503", err)
	} else {
		h.applier = a
	}
	return h
}

// persist 落盘（内存模式为空操作）；调用方须持锁。
func (h *sloHandler) persist() error {
	if h.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(h.state, "", "  ")
	if err != nil {
		return err
	}
	tmp := h.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, h.path)
}

// handleSLO 分发 GET（读取）/ POST（写，admin）。
func (h *sloHandler) handleSLO(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getSLO(w, r)
	case http.MethodPost:
		h.postSLO(w, r)
	default:
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET/POST")
	}
}

// getSLO GET /v1/adminext/slo：定义 + 错误预算余量（Prometheus；未配置则仅返回定义）。
func (h *sloHandler) getSLO(w http.ResponseWriter, r *http.Request) {
	if !requireReadAccess(w, r) {
		return
	}
	h.mu.Lock()
	state := h.state
	h.mu.Unlock()

	// tracing allow-list：已接线 → 读事实源（Collector ConfigMap）；未接线 → 本地缓存回显并如实标注。
	tenants := state.TracingTenants
	source := "local-cache"
	wired := h.applier != nil
	if h.applier != nil {
		if cur, err := h.applier.current(r.Context()); err != nil {
			log.Printf("[adminext] 读取 Collector allow-list 失败（回退本地缓存）：%v", err)
			source = "local-cache(read-failed)"
		} else {
			tenants = cur
			source = "collector-configmap"
		}
	}

	out := map[string]any{
		"slos":            state.SLOS,
		"tracing_tenants": tenants,
		"tracing_wired":   wired,
		"tracing_source":  source,
		"fetched_at":      time.Now().UnixNano(),
	}
	// 错误预算余量：按调用者租户作用域（admin = 全租户）
	c := claimsFrom(r.Context())
	tenant := ""
	if c != nil && c.Role != roleAdmin {
		tenant = c.Tenant
	}
	if h.promURL != "" && len(state.SLOS) > 0 {
		slo := state.SLOS[0] // 当前生效 SLO（单条起步）
		sel := promTenantSelector(tenant)
		budget, err := promQueryScalar(r, h.client, h.promURL, fmt.Sprintf(
			`sum(rate(otpmask_inference_requests_total{result="ok"%s}[%s])) / clamp_min(sum(rate(otpmask_inference_requests_total{%s}[%s])), 1)`,
			sel, "30m", promTrimBrace(sel), "30m"))
		if err != nil {
			writeError(w, http.StatusServiceUnavailable, "Prometheus 查询失败（错误预算）")
			return
		}
		total := 1 - slo.Target
		remaining := 0.0
		if total > 0 {
			// 错误预算余量 = (可用性 − 目标) / (1 − 目标)，clamp 到 [0,1]
			remaining = (budget - slo.Target) / total
			if remaining < 0 {
				remaining = 0
			}
			if remaining > 1 {
				remaining = 1
			}
		}
		out["budget"] = map[string]any{
			"tenant":             tenant,
			"slo_name":           slo.Name,
			"target":             slo.Target,
			"availability":       budget,
			"remaining_fraction": remaining,
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// postSLO POST /v1/adminext/slo：创建/更新 SLO（admin，落审计链）。
func (h *sloHandler) postSLO(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, roleAdmin) {
		return
	}
	if h.chain == nil {
		writeError(w, http.StatusServiceUnavailable, "审计链未启用（ADMIN_AUDIT_FILE 未配置），SLO 变更拒绝")
		return
	}
	var body sloDef
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10))
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if err := validateSLO(body); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	h.mu.Lock()
	replaced := false
	for i := range h.state.SLOS {
		if h.state.SLOS[i].Name == body.Name {
			h.state.SLOS[i] = body
			replaced = true
			break
		}
	}
	if !replaced {
		h.state.SLOS = append(h.state.SLOS, body)
	}
	err := h.persist()
	h.mu.Unlock()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "SLO 持久化失败")
		return
	}
	h.audit(r, "slo_update", body.Name)
	log.Printf("[adminext] SLO 更新：name=%s type=%s target=%v window=%s",
		body.Name, body.SLI.Type, body.Target, body.Window)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}`))
}

// handleTracingTenant POST /v1/adminext/tracing/tenant：租户级 tracing 灰度开关（admin）。
//
// 方案 B3（2026-10-08）：事实源 = Collector ConfigMap。流程为
// 「读 ConfigMap → 增/删租户 → 渲染 → PATCH ConfigMap → 触发 otel-collector 滚动」，
// **任一步失败即 503（fail-closed），不改本地缓存**——保证「返回 200 即代表已生效」。
func (h *sloHandler) handleTracingTenant(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRole(w, r, roleAdmin) {
		return
	}
	if h.chain == nil {
		writeError(w, http.StatusServiceUnavailable, "审计链未启用（ADMIN_AUDIT_FILE 未配置），tracing 开关变更拒绝")
		return
	}
	if h.applier == nil {
		writeError(w, http.StatusServiceUnavailable,
			"tracing 灰度未接线（非 in-cluster 或 K8s 客户端初始化失败）；Collector allow-list 无法应用")
		return
	}
	var body struct {
		Tenant  string `json:"tenant"`
		Enabled bool   `json:"enabled"`
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	if err := dec.Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	body.Tenant = strings.TrimSpace(body.Tenant)
	if body.Tenant == "" {
		writeError(w, http.StatusBadRequest, "tenant 必填")
		return
	}

	rev, restarted, tenants, err := h.applier.apply(r.Context(), body.Tenant, body.Enabled)
	if err != nil {
		log.Printf("[adminext] tracing 灰度开关应用失败：tenant=%s enabled=%v err=%v", body.Tenant, body.Enabled, err)
		writeError(w, http.StatusServiceUnavailable, "Collector allow-list 应用失败（未生效）: "+err.Error())
		return
	}

	// 本地缓存仅作回执（事实源为 ConfigMap）；持久化失败不掩盖已生效结果，仅告警。
	h.mu.Lock()
	h.state.TracingTenants = append([]string(nil), tenants...)
	perr := h.persist()
	h.mu.Unlock()
	if perr != nil {
		log.Printf("[adminext] tracing allow-list 本地缓存写入失败（不影响已生效结果）：%v", perr)
	}

	h.audit(r, "tracing_tenant_update", body.Tenant)
	log.Printf("[adminext] tracing 灰度开关已应用：tenant=%s enabled=%v rev=%s restarted=%v tenants=%v",
		body.Tenant, body.Enabled, rev, restarted, tenants)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":    "ok",
		"applied":   true,
		"rev":       rev,
		"restarted": restarted,
		"tenants":   tenants,
	})
}

// audit 落审计链（action/target 留痕）。
func (h *sloHandler) audit(r *http.Request, action, target string) {
	c := claimsFrom(r.Context())
	actor := "unknown"
	if c != nil {
		actor = c.Sub
	}
	if err := h.chain.append(adminAuditEvent{
		Actor:     actor,
		Action:    action,
		Target:    target,
		RequestID: r.Header.Get("X-Request-ID"),
		Result:    "ok",
	}); err != nil {
		log.Printf("[adminext] 审计落链失败（action=%s target=%s）: %v", action, target, err)
	}
}

// setAllowList 增删 allow-list 条目（去重、稳定排序由调用方按需处理）。
func setAllowList(list []string, tenant string, enabled bool) []string {
	out := make([]string, 0, len(list)+1)
	found := false
	for _, t := range list {
		if t == tenant {
			found = true
			if enabled {
				out = append(out, t)
			}
			continue
		}
		out = append(out, t)
	}
	if enabled && !found {
		out = append(out, tenant)
	}
	return out
}

// validateSLO 校验 SLO 定义（§7.9 冻结 schema）。
func validateSLO(d sloDef) error {
	if strings.TrimSpace(d.Name) == "" {
		return errors.New("name 必填")
	}
	switch d.SLI.Type {
	case sliTypeAvailability, sliTypeLatencyP99:
	case "":
		return errors.New("sli.type 必填（availability|latency_p99）")
	default:
		return errors.New("sli.type 非法（availability|latency_p99）")
	}
	if d.Target <= 0 || d.Target >= 1 {
		return errors.New("target 须在 (0,1) 区间")
	}
	if strings.TrimSpace(d.Window) == "" {
		return errors.New("window 必填（如 30d）")
	}
	return nil
}
