// Package main — N5 · 数据面策略下发通道（§4.3.5，V-S6，硬约束 C-20）。
//
// 端点（租户会话前缀：TenantAuthMiddleware 双策略 + 写 CSRF）：
//
//	GET  /v1/adminext/tenant/dispatch/status   本租户下发状态（源：表 ⑩）
//	POST /v1/adminext/tenant/dispatch/replay   运维手动重放（admin + target_tenant，附录 D）
//
// 通道定档（D-12）：经 gateway-core 处方 API（mTLS + 内部服务令牌）下发，
// 门户不持 k8s RBAC；私有化无 gateway-core 的受限 ServiceAccount 直写为后续形态开关。
//
// 时序（§4.3.5 item 2）：租户写操作在 handler 内**同事务**更新表 ⑩（config_version+1、
// status='pending'），handler 返回后投递进程内 dispatch 任务（带缓冲；**每租户单飞 worker**）；
// worker：status='applying' → BuildDispatch（纯函数）→ ApplyDispatch → status='applied'。
// 失败重试 3 次（指数退避 1s/4s/16s）→ status='failed' + last_error（脱敏）。
//
// fail-closed（C-20）：下发失败/超时/返回非预期 → **数据面保留上一版生效配置**，
// 不回退"无策略"开放态、不静默成功；applied_version 与 config_version 不一致即漂移并告警；
// 重启后扫描 pending/applying 自动重放（幂等，按 config_version）。
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ---------- 常量 ----------

const (
	tenantDispatchPath       = tenantSessionBase + "/dispatch"
	tenantDispatchStatusPath = tenantDispatchPath + "/status"
	tenantDispatchReplayPath = tenantDispatchPath + "/replay"

	// dispatchPrescriptionPath gateway-core 处方 API 路径。
	dispatchPrescriptionPath = "/v1/prescription"

	// 下发目标类型（Higress CRD / Consumer / 处方）。
	dispatchTargetWasmPlugin          = "wasm_plugin"
	dispatchTargetConsumerCredentials = "consumer_credentials"
	dispatchTargetConsumerQuota       = "consumer_quota"
	dispatchTargetPrescription        = "gateway_core_prescription"

	// dispatchApplyTimeout 单次 Apply 超时（超时 = 保留旧版，C-20）。
	dispatchApplyTimeout = 20 * time.Second
	// defaultDispatchTimeoutSec 单次 Apply 超时秒数（env 缺省，供 config 侧引用）。
	defaultDispatchTimeoutSec = 20
	// dispatchMaxErrorLen last_error 脱敏后长度上限（禁含配置内容）。
	dispatchMaxErrorLen = 200
)

// dispatchBackoff 失败重试退避（§4.3.5 item 2：1s/4s/16s）。
var dispatchBackoff = []time.Duration{time.Second, 4 * time.Second, 16 * time.Second}

// ---------- 数据结构 ----------

// DispatchTarget 单条下发目标（Higress CRD / Consumer / gateway-core 处方）。
type DispatchTarget struct {
	Kind string         `json:"kind"`
	Name string         `json:"name"`
	Spec map[string]any `json:"spec"`
}

// DispatchPlan 一次下发的完整计划（BuildDispatch 纯函数产物，可单测）。
type DispatchPlan struct {
	TenantID      string           `json:"tenant_id"`
	ConfigVersion int64            `json:"config_version"`
	Targets       []DispatchTarget `json:"targets"`
}

// dispatchQuota 套餐配额维度（billing 域；nil = 未知，不下发配额目标）。
type dispatchQuota struct {
	PlanID        string
	MonthlyTokens int64
	Concurrency   int
	CacheTier     string
}

// DispatchInput BuildDispatch 的输入快照（由 store 当前态聚合而来）。
type DispatchInput struct {
	TenantID      string
	ConfigVersion int64
	Provisioning  *TenantProvisioning
	Keys          []*APIKey
	Policy        *PolicyOverlay
	Models        *ModelConfig
	Quota         *dispatchQuota
}

// dispatchStatusView GET /dispatch/status 响应（§6.12）。
type dispatchStatusView struct {
	ConfigVersion  int64  `json:"config_version"`
	Status         string `json:"status"`
	AppliedVersion int64  `json:"applied_version"`
	LastError      string `json:"last_error,omitempty"`
	UpdatedAt      int64  `json:"updated_at"`
	Drift          bool   `json:"drift"`
}

// ---------- BuildDispatch（纯函数）----------

// BuildDispatch 由租户当前配置快照生成下发计划（纯函数：无 IO、无副作用，可单测）。
// 输出目标：N6 插件组合（WasmPlugin）/ key-auth Consumer 凭证 / ai-quota Consumer 配额 /
// gateway-core 处方（策略 overlay + 模型 ACL，经 X-Otp-Route）。
func BuildDispatch(in DispatchInput) (*DispatchPlan, error) {
	plan := &DispatchPlan{TenantID: in.TenantID, ConfigVersion: in.ConfigVersion, Targets: []DispatchTarget{}}

	// 1) N6 插件组合（WasmPlugin）+ 场景/段①② 参数
	if in.Provisioning != nil {
		chain, err := unmarshalPluginSet(in.Provisioning.PluginSetJSON)
		if err != nil {
			return nil, fmt.Errorf("tenant: dispatch 解析 plugin_set: %w", err)
		}
		plan.Targets = append(plan.Targets, DispatchTarget{
			Kind: dispatchTargetWasmPlugin,
			Name: "tenant-plugins-" + in.TenantID,
			Spec: map[string]any{
				"scenario":         in.Provisioning.Scenario,
				"trust_tier":       in.Provisioning.TrustTier,
				"access_mode":      in.Provisioning.AccessMode,
				"segment1_enabled": in.Provisioning.Segment1Enabled,
				"segment2_mode":    in.Provisioning.Segment2Mode,
				"template_version": in.Provisioning.TemplateVersion,
				"chain":            chain,
			},
		})
	}

	// 2) key-auth Consumer 凭证（仅元数据；绝不含 Key 明文——门户不持有明文）
	creds := make([]map[string]any, 0, len(in.Keys))
	for _, k := range in.Keys {
		if k.Status != apiKeyStatusActive {
			continue
		}
		creds = append(creds, map[string]any{
			"name": k.Name, "jti": k.JTI, "expires_at": k.ExpiresAt, "created_at": k.CreatedAt,
		})
	}
	if len(creds) > 0 {
		plan.Targets = append(plan.Targets, DispatchTarget{
			Kind: dispatchTargetConsumerCredentials,
			Name: "tenant-consumer-" + in.TenantID,
			Spec: map[string]any{"consumer": in.TenantID, "credentials": creds},
		})
	}

	// 3) 配额（ai-quota / ai-token-ratelimit；Consumer 维度天然隔离）
	if in.Quota != nil {
		plan.Targets = append(plan.Targets, DispatchTarget{
			Kind: dispatchTargetConsumerQuota,
			Name: "tenant-quota-" + in.TenantID,
			Spec: map[string]any{
				"consumer":       in.TenantID,
				"plan_id":        in.Quota.PlanID,
				"monthly_tokens": in.Quota.MonthlyTokens,
				"concurrency":    in.Quota.Concurrency,
				"cache_tier":     in.Quota.CacheTier,
			},
		})
	}

	// 4) gateway-core 处方（策略 overlay → request-validation；模型 ACL → ai-proxy allowlist）
	presc := map[string]any{"route": otpRouteForTenant(in.TenantID)}
	if in.Policy != nil {
		presc["policy"] = policyPrescription(in.Policy)
	}
	if in.Models != nil {
		presc["models"] = modelsPrescription(in.Models)
	}
	plan.Targets = append(plan.Targets, DispatchTarget{
		Kind: dispatchTargetPrescription,
		Name: "tenant-prescription-" + in.TenantID,
		Spec: presc,
	})

	return plan, nil
}

// otpRouteForTenant 处方路由（X-Otp-Route，§4.3.5 映射表）。
func otpRouteForTenant(tenantID string) string { return "tenant/" + tenantID }

// policyPrescription 策略 overlay 处方体（含条目清单，供 request-validation schema 渲染）。
func policyPrescription(p *PolicyOverlay) map[string]any {
	var wl, bl map[string]any
	var cat map[string]string
	_ = json.Unmarshal([]byte(p.WhitelistJSON), &wl)
	_ = json.Unmarshal([]byte(p.BlacklistJSON), &bl)
	_ = json.Unmarshal([]byte(p.CategoryActionsJSON), &cat)
	return map[string]any{
		"version":          p.Version,
		"whitelist":        wl,
		"blacklist":        bl,
		"category_actions": cat,
	}
}

// modelsPrescription 模型 ACL 处方体（ai-proxy allowlist + 默认模型）。
func modelsPrescription(m *ModelConfig) map[string]any {
	var allowed []string
	_ = json.Unmarshal([]byte(m.AllowedModelsJSON), &allowed)
	if allowed == nil {
		allowed = []string{}
	}
	return map[string]any{
		"version":        m.Version,
		"allowed_models": allowed,
		"default_model":  m.DefaultModel,
	}
}

// ---------- ApplyDispatch（下发通道）----------

// dispatchApplyError 下发失败分类（用于脱敏 last_error 与告警）。
type dispatchApplyError struct {
	Class  string // rejected | unreachable | timeout | unexpected | unauthorized | channel_unconfigured
	Status int    // HTTP 状态码（无则 0）
	Msg    string
}

func (e *dispatchApplyError) Error() string {
	if e.Status > 0 {
		return fmt.Sprintf("dispatch: %s(status=%d) %s", e.Class, e.Status, e.Msg)
	}
	return fmt.Sprintf("dispatch: %s %s", e.Class, e.Msg)
}

// dispatchApplier 下发执行通道（真实实现 = gateway-core 处方 API；测试注入 fake）。
// 返回数据面回执的生效版本（<=0 = 视同请求版本）。
type dispatchApplier interface {
	Apply(ctx context.Context, plan *DispatchPlan) (int64, error)
}

// dispatchAlarm 漂移/失败告警回调（接管理面告警通道；nil = 仅日志）。
type dispatchAlarm func(tenantID, kind, detail string)

// httpDispatchApplier 经 HTTP 调 gateway-core 处方 API（mTLS + 内部服务令牌）。
type httpDispatchApplier struct {
	baseURL string
	token   string
	client  *http.Client
}

// newHTTPDispatchApplier 构造下发客户端；baseURL 为空 → nil（通道未配置，fail-closed）。
func newHTTPDispatchApplier(baseURL, token string, timeout time.Duration) *httpDispatchApplier {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = dispatchApplyTimeout
	}
	return &httpDispatchApplier{baseURL: baseURL, token: token, client: &http.Client{Timeout: timeout}}
}

// Apply 提交下发计划；返回数据面回执的 applied_version。
func (a *httpDispatchApplier) Apply(ctx context.Context, plan *DispatchPlan) (int64, error) {
	if a == nil || a.baseURL == "" {
		return 0, &dispatchApplyError{Class: "channel_unconfigured"}
	}
	// 内部服务令牌必填（mTLS + 鉴权，§4.3.5 可信域约束）；缺失即 fail-closed
	if a.token == "" {
		return 0, &dispatchApplyError{Class: "unauthorized", Msg: "内部服务令牌未配置"}
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return 0, &dispatchApplyError{Class: "unexpected", Msg: "plan 序列化失败"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+dispatchPrescriptionPath, bytes.NewReader(body))
	if err != nil {
		return 0, &dispatchApplyError{Class: "unexpected", Msg: "构造请求失败"}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+a.token)
	req.Header.Set("X-Otp-Route", otpRouteForTenant(plan.TenantID))

	resp, err := a.client.Do(req)
	if err != nil {
		class := "unreachable"
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			class = "timeout"
		}
		return 0, &dispatchApplyError{Class: class, Msg: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	switch {
	case resp.StatusCode == http.StatusOK:
	case resp.StatusCode >= 400 && resp.StatusCode < 500:
		return 0, &dispatchApplyError{Class: "rejected", Status: resp.StatusCode}
	default:
		return 0, &dispatchApplyError{Class: "unexpected", Status: resp.StatusCode}
	}
	var out struct {
		AppliedVersion int64 `json:"applied_version"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return 0, &dispatchApplyError{Class: "unexpected", Status: resp.StatusCode, Msg: "回执解析失败"}
	}
	return out.AppliedVersion, nil
}

// sanitizeDispatchError 把下发错误收敛为脱敏短码（**禁含配置内容**，§3.5 表 ⑩ last_error）。
func sanitizeDispatchError(err error) string {
	if err == nil {
		return ""
	}
	var ae *dispatchApplyError
	var s string
	if errors.As(err, &ae) {
		s = ae.Class
		if ae.Status > 0 {
			s = fmt.Sprintf("%s(status=%d)", ae.Class, ae.Status)
		}
	} else {
		s = err.Error()
	}
	s = strings.NewReplacer("\n", " ", "\r", " ", "\t", " ").Replace(s)
	if len(s) > dispatchMaxErrorLen {
		s = s[:dispatchMaxErrorLen]
	}
	return s
}

// ---------- dispatcher（每租户单飞 worker）----------

// dispatcher 下发调度器：每租户单飞串行 worker + 重启幂等重放（§4.3.5）。
type dispatcher struct {
	store   TenantStore
	applier dispatchApplier
	quotaFn func(tenantID string) *dispatchQuota
	alarm   dispatchAlarm
	now     func() int64
	sleep   func(time.Duration)
	backoff []time.Duration

	mu      sync.Mutex
	running map[string]bool // 租户 → worker 在跑
	rerun   map[string]bool // 租户 → 执行期间又收到触发
	wg      sync.WaitGroup
}

// newDispatcher 构造调度器（applier 为 nil = 通道未配置，仍保持 fail-closed 状态可观测）。
func newDispatcher(store TenantStore, applier dispatchApplier) *dispatcher {
	return &dispatcher{
		store:   store,
		applier: applier,
		now:     func() int64 { return time.Now().Unix() },
		sleep:   time.Sleep,
		backoff: append([]time.Duration(nil), dispatchBackoff...),
		running: map[string]bool{},
		rerun:   map[string]bool{},
	}
}

// BumpInTx 同事务把表 ⑩ config_version+1、status='pending'（§4.3.5 item 2）。
func (d *dispatcher) BumpInTx(tx TenantTx, tenantID string) error {
	if d == nil || d.store == nil {
		return nil
	}
	_, err := d.store.BumpDispatchVersion(tx, tenantID, d.now())
	return err
}

// Enqueue 投递下发任务（幂等；每租户单飞，执行期间重复触发合并为一次重跑）。
func (d *dispatcher) Enqueue(tenantID string) {
	if d == nil || d.store == nil || tenantID == "" {
		return
	}
	d.mu.Lock()
	if d.running[tenantID] {
		d.rerun[tenantID] = true
		d.mu.Unlock()
		return
	}
	d.running[tenantID] = true
	d.wg.Add(1)
	d.mu.Unlock()
	go d.worker(tenantID)
}

// ReplayPending 重启重放：扫描 status ∈ {pending, applying} 并重新入队（幂等）。
func (d *dispatcher) ReplayPending() (int, error) {
	if d == nil || d.store == nil {
		return 0, nil
	}
	rows, err := d.store.ListDispatchStatesByStatus(dispatchStatusPending, dispatchStatusApplying)
	if err != nil {
		return 0, err
	}
	for _, r := range rows {
		d.Enqueue(r.TenantID)
	}
	return len(rows), nil
}

// Wait 等待所有单飞 worker 结束（测试与优雅停机用）。
func (d *dispatcher) Wait() {
	if d == nil {
		return
	}
	d.wg.Wait()
}

// worker 每租户单飞串行循环：执行一次后若期间有新触发则合并重跑。
func (d *dispatcher) worker(tenantID string) {
	defer d.wg.Done()
	for {
		d.runOnce(tenantID)
		d.mu.Lock()
		if d.rerun[tenantID] {
			d.rerun[tenantID] = false
			d.mu.Unlock()
			continue
		}
		delete(d.running, tenantID)
		d.mu.Unlock()
		return
	}
}

// runOnce 单次下发：applying → BuildDispatch → ApplyDispatch（重试 3 次）→ applied/failed。
func (d *dispatcher) runOnce(tenantID string) {
	st, err := d.store.GetDispatchState(tenantID)
	if err != nil {
		log.Printf("[dispatch] 读取状态失败 tenant=%s: %v", tenantID, err)
		return
	}
	if st == nil || st.ConfigVersion <= st.AppliedVersion {
		return // 无新版本，幂等跳过（重放不产生重复副作用）
	}
	targetVersion := st.ConfigVersion

	if err := d.markApplying(tenantID); err != nil {
		log.Printf("[dispatch] 置 applying 失败 tenant=%s: %v", tenantID, err)
		return
	}

	plan, err := d.buildPlan(tenantID, targetVersion)
	if err != nil {
		d.markFailed(tenantID, sanitizeDispatchError(err), 0)
		d.raise(tenantID, "build_failed", sanitizeDispatchError(err))
		return
	}

	var lastErr error
	attempts := len(d.backoff) + 1
	for attempt := 1; attempt <= attempts; attempt++ {
		applied, err := d.applier.Apply(context.Background(), plan)
		if err == nil {
			if applied <= 0 || applied > targetVersion {
				applied = targetVersion
			}
			d.markApplied(tenantID, applied)
			if applied < targetVersion {
				// 数据面回执版本落后 → 漂移告警（以数据面生效版本为准，C-20）
				d.raise(tenantID, "version_drift",
					fmt.Sprintf("config=%d applied=%d", targetVersion, applied))
			}
			return
		}
		lastErr = err
		if attempt <= len(d.backoff) {
			d.sleep(d.backoff[attempt-1])
		}
	}
	msg := sanitizeDispatchError(lastErr)
	d.markFailed(tenantID, msg, int64(len(d.backoff)))
	log.Printf("[dispatch] 下发失败（已重试 %d 次，保留旧版）tenant=%s: %s", len(d.backoff), tenantID, msg)
	d.raise(tenantID, "dispatch_failed", msg)
}

func (d *dispatcher) buildPlan(tenantID string, configVersion int64) (*DispatchPlan, error) {
	in := DispatchInput{TenantID: tenantID, ConfigVersion: configVersion}
	var err error
	if in.Provisioning, err = d.store.GetProvisioning(tenantID); err != nil {
		return nil, err
	}
	if in.Keys, err = d.store.ListAPIKeysByTenant(tenantID); err != nil {
		return nil, err
	}
	if in.Policy, err = d.store.GetPolicyOverlay(tenantID); err != nil {
		return nil, err
	}
	if in.Models, err = d.store.GetModelConfig(tenantID); err != nil {
		return nil, err
	}
	if d.quotaFn != nil {
		in.Quota = d.quotaFn(tenantID)
	}
	return BuildDispatch(in)
}

func (d *dispatcher) markApplying(tenantID string) error {
	return d.withTx(func(tx TenantTx) error {
		return d.store.MarkDispatchApplying(tx, tenantID, d.now())
	})
}

func (d *dispatcher) markApplied(tenantID string, version int64) {
	if err := d.withTx(func(tx TenantTx) error {
		return d.store.MarkDispatchApplied(tx, tenantID, version, d.now())
	}); err != nil {
		log.Printf("[dispatch] 置 applied 失败 tenant=%s: %v", tenantID, err)
	}
}

func (d *dispatcher) markFailed(tenantID, lastError string, retryCount int64) {
	if err := d.withTx(func(tx TenantTx) error {
		return d.store.MarkDispatchFailed(tx, tenantID, lastError, retryCount, d.now())
	}); err != nil {
		log.Printf("[dispatch] 置 failed 失败 tenant=%s: %v", tenantID, err)
	}
}

func (d *dispatcher) withTx(fn func(tx TenantTx) error) error {
	tx, err := d.store.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (d *dispatcher) raise(tenantID, kind, detail string) {
	if d.alarm != nil {
		d.alarm(tenantID, kind, detail)
		return
	}
	log.Printf("[dispatch][alarm] tenant=%s kind=%s detail=%s", tenantID, kind, detail)
}

// ---------- 端点 ----------

// registerTenantDispatchMux 注册下发状态/重放端点（租户令牌 + 写 CSRF）。
func (h *tenantHandler) registerTenantDispatchMux(mux *http.ServeMux) {
	mux.HandleFunc("GET "+tenantDispatchStatusPath, tenantAuthMiddleware(h.cfg, h.handleDispatchStatus))
	mux.HandleFunc("POST "+tenantDispatchReplayPath,
		tenantAuthMiddleware(h.cfg, csrfCheck(h.handleDispatchReplay)))
}

// handleDispatchStatus 本租户下发状态（源：表 ⑩；未建行 → idle 默认视图）。
func (h *tenantHandler) handleDispatchStatus(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	st, err := h.store.GetDispatchState(tenantID)
	if err != nil {
		log.Printf("[dispatch] 读取状态失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	tenantWriteJSON(w, http.StatusOK, dispatchStatusViewOf(st))
}

// handleDispatchReplay 运维手动重放下发（仅 admin 接管；附录 D `dispatch_replay`）。
func (h *tenantHandler) handleDispatchReplay(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	adminSub, isAdmin := tenantTakeoverFromCtx(r)
	if !isAdmin {
		tenantWriteError(w, http.StatusForbidden, "下发重放仅管理员可执行")
		return
	}
	if h.dispatch == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "下发通道未就绪")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	req.Reason = strings.TrimSpace(req.Reason)
	if req.Reason == "" || len(req.Reason) > 256 {
		tenantWriteError(w, http.StatusBadRequest, "reason 长度须为 1-256")
		return
	}
	st, err := h.store.GetDispatchState(tenantID)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	curVersion := int64(0)
	if st != nil {
		curVersion = st.ConfigVersion
	}
	h.dispatch.Enqueue(tenantID)
	h.auditAppendDetail(adminSub, auditActionDispatchReplay, tenantID,
		fmt.Sprintf("reason=%s config_version=%d", req.Reason, curVersion))
	log.Printf("[dispatch] 手动重放 tenant=%s by=%s config_version=%d reason=%s",
		tenantID, adminSub, curVersion, req.Reason)
	tenantWriteJSON(w, http.StatusOK, map[string]any{
		"tenant": tenantID, "config_version": curVersion, "enqueued": true,
	})
}

// dispatchStatusViewOf 把存储行映射为视图（nil → idle 默认）。
func dispatchStatusViewOf(st *TenantDispatchState) dispatchStatusView {
	if st == nil {
		return dispatchStatusView{Status: dispatchStatusIdle}
	}
	return dispatchStatusView{
		ConfigVersion:  st.ConfigVersion,
		Status:         st.Status,
		AppliedVersion: st.AppliedVersion,
		LastError:      st.LastError,
		UpdatedAt:      st.UpdatedAt,
		Drift:          st.ConfigVersion != st.AppliedVersion,
	}
}
