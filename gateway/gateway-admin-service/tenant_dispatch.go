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

	// dispatchCacheKeyPrefix 语义缓存键前缀（N7，§4.3.7 item 1：`tenant_id+model`）。
	dispatchCacheKeyPrefix = "tenant_id+model"

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
	// Scope 计划级作用域（P2-4 T-3.1，§6.2）：由三张表的 scope **交集**得出。
	// global = 不限定集群；clusters 非空 = 定向集群集合；clusters 为空且 global=false
	// = **不下发**（交集为空，fail-closed，不退化为 global）。
	Scope DispatchScope `json:"scope"`
	// TargetClusterID 本次下发的目标集群（P2-4 T-3.2b）：'' = 本地默认端点。
	TargetClusterID string `json:"target_cluster_id,omitempty"`
	// TargetEndpoint 目标数据面端点（内部路由信息；**不随载荷下发**，
	// 避免把集群内部地址带给数据面）。
	TargetEndpoint string `json:"-"`
}

// ForTarget 返回按目标集群裁定的计划副本（每个目标集群一份，内容一致、路由不同）。
func (p *DispatchPlan) ForTarget(clusterID, endpoint string) *DispatchPlan {
	if p == nil {
		return nil
	}
	cp := *p
	cp.TargetClusterID = clusterID
	cp.TargetEndpoint = endpoint
	return &cp
}

// TargetClusters 返回该计划的目标集群集合。
//
// 返回 (集合, 是否下发)：global → (nil, true)；clusters 非空 → (集合, true)；
// 空交集 → (nil, false)——调用方必须跳过投递（不得退化为 global）。
func (p *DispatchPlan) TargetClusters() ([]string, bool) {
	if p == nil {
		return nil, false
	}
	return scopeTargetClusters(p.Scope)
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

	// 0) 计划级作用域（P2-4 T-3.1，§6.2）：三张表的 scope 取**交集**。
	// global 视为全集（不收窄）；任一 cluster 作用域收窄目标集群集合；
	// 交集为空 ⇒ 不下发（fail-closed，不退化为 global）。
	scope, err := effectiveDispatchScope(
		provisioningScopeRaw(in.Provisioning),
		policyScopeRaw(in.Policy),
		modelsScopeRaw(in.Models),
	)
	if err != nil {
		return nil, fmt.Errorf("tenant: dispatch 解析作用域: %w", err)
	}
	plan.Scope = scope

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
				// N7：跨租户隔离（语义缓存命名空间 + tenant 解析一致性处方）。
				"cache_namespace":   cacheNamespaceForTenant(in.TenantID),
				"cache_key_prefix":  dispatchCacheKeyPrefix,
				"tenant_resolution": tenantResolutionSpec(in.TenantID),
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
				// N7：配额隔离（consumer 维度天然隔离 + 防伪造 X-Tenant-ID）。
				"isolation": consumerIsolationSpec(in.TenantID),
			},
		})
	}

	// 4) gateway-core 处方（策略 overlay → request-validation；模型 ACL → ai-proxy allowlist）
	presc := map[string]any{
		"route":             otpRouteForTenant(in.TenantID),
		"tenant_resolution": tenantResolutionSpec(in.TenantID),
	}
	if in.Policy != nil {
		presc["policy"] = policyPrescription(in.Policy)
	}
	if in.Models != nil {
		presc["models"] = modelsPrescription(in.Models)
	}
	// N7 密态轨（S2/S3/S4）：段① 解密后的 JWT 声明租户须与声明租户一致（§4.3.7 S1–S5 差异）。
	if requiresDecryptTenantBinding(in.Provisioning) {
		presc["decrypt_tenant_binding"] = decryptTenantBindingSpec(in.TenantID)
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

// ---------- N7 · 多租户隔离增强（§4.3.7，V-S7）----------

// cacheNamespaceForTenant 语义缓存命名空间（§4.3.7 item 1：跨租户不误命中）。
// 键 = `tenant_id+model`（键前缀见 dispatchCacheKeyPrefix），命名空间按租户前缀隔离。
func cacheNamespaceForTenant(tenantID string) string { return "tenant:" + tenantID }

// consumerIsolationSpec ai-quota/ai-token-ratelimit 的 consumer 维度隔离参数（§4.3.7 item 2）。
// reject_self_declared_tenant_header：数据面以 JWT 真值覆盖自声明 X-Tenant-ID，防伪造越权。
func consumerIsolationSpec(tenantID string) map[string]any {
	return map[string]any{
		"scope":                              "consumer",
		"consumer":                           consumerForTenant(tenantID),
		"isolate":                            true,
		"reject_self_declared_tenant_header": true,
	}
}

// tenantResolutionSpec tenant 解析一致性处方（§4.3.7 item 3/4）：
// 租户由 auth-service JWT 派生、插件校验后**覆盖自声明头**；缺消费者落哨兵租户
// （审计侧以 `tenant_id_resolution` 做一致性裁决）。
func tenantResolutionSpec(tenantID string) map[string]any {
	return map[string]any{
		"mode":            "jwt_override",
		"header":          "X-Tenant-ID",
		"authority":       "auth-service",
		"audit_field":     "tenant_id_resolution",
		"consumer":        consumerForTenant(tenantID),
		"sentinel_tenant": sentinelTenant,
	}
}

// decryptTenantBindingSpec 密态轨（S2/S3/S4）段① 解密租户绑定校验（§4.3.7 S1–S5 差异）：
// 段① 解密出的 JWT 声明租户须与声明租户一致，防"解密方≠声明租户"跨租户串味。
func decryptTenantBindingSpec(tenantID string) map[string]any {
	return map[string]any{
		"require":       true,
		"segment":       1,
		"invariant":     "decrypted_jwt.tenant == declared.tenant",
		"target_tenant": tenantID,
	}
}

// requiresDecryptTenantBinding 是否需要段① 解密租户绑定校验（A 型分段密态 + 段① 启用）。
func requiresDecryptTenantBinding(p *TenantProvisioning) bool {
	return p != nil && p.Segment1Enabled && p.AccessMode == accessModeASegmented
}

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
	// 目标端点：计划指定了集群端点则按集群投递（P2-4 T-3.2b），否则用配置的默认端点。
	baseURL := a.baseURL
	if plan != nil && plan.TargetEndpoint != "" {
		baseURL = strings.TrimRight(strings.TrimSpace(plan.TargetEndpoint), "/")
	}
	body, err := json.Marshal(plan)
	if err != nil {
		return 0, &dispatchApplyError{Class: "unexpected", Msg: "plan 序列化失败"}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+dispatchPrescriptionPath, bytes.NewReader(body))
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

// ---------- dispatcher（每租户×每集群单飞 worker）----------

// dispatchTarget 一个下发目标集群（cluster_id + 数据面端点）。
type dispatchTarget struct {
	// ClusterID 目标集群 ID；'' = 本地默认端点（注册表未启用/无集群时的既有
	// 单集群行为，V-7「单集群行为不变」）。
	ClusterID string
	// Endpoint 数据面端点（空 = 用配置的默认端点）。
	Endpoint string
}

// clusterTargetResolver 目标集群解析（集群注册表）。
type clusterTargetResolver interface {
	// ListTargets 列出可下发集群（active/degraded）。
	ListTargets(ctx context.Context) ([]dispatchTarget, error)
}

// registryTargetResolver 基于集群注册表的目标解析器。
type registryTargetResolver struct {
	store ClusterStore
}

// ListTargets 列出可用集群（active/degraded；removed/quarantined/unreachable 排除）。
func (r *registryTargetResolver) ListTargets(ctx context.Context) ([]dispatchTarget, error) {
	if r == nil || r.store == nil {
		return nil, errScopeNoRegistry
	}
	recs, err := r.store.List(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]dispatchTarget, 0, len(recs))
	for _, rec := range recs {
		if rec == nil {
			continue
		}
		if rec.Status != ClusterStatusActive && rec.Status != ClusterStatusDegraded {
			continue
		}
		out = append(out, dispatchTarget{ClusterID: rec.ID, Endpoint: rec.Endpoint})
	}
	return out, nil
}

// dispatchKey 下发单飞键（租户 × 集群）。
type dispatchKey struct {
	TenantID  string
	ClusterID string
}

// dispatcher 下发调度器：每租户×每集群单飞串行 worker + 重启幂等重放
// （§4.3.5；P2-4 T-3.2b 起单飞粒度 = 租户 × 集群）。
type dispatcher struct {
	store   TenantStore
	applier dispatchApplier
	quotaFn func(tenantID string) *dispatchQuota
	alarm   dispatchAlarm
	now     func() int64
	sleep   func(time.Duration)
	backoff []time.Duration

	// targetMu 保护目标解析器（懒加载共享注册表句柄；装配层可注入）。
	targetMu  sync.Mutex
	targets   clusterTargetResolver
	targetErr error

	mu      sync.Mutex
	running map[dispatchKey]bool // 租户×集群 → worker 在跑
	rerun   map[dispatchKey]bool // 租户×集群 → 执行期间又收到触发
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
		running: map[dispatchKey]bool{},
		rerun:   map[dispatchKey]bool{},
	}
}

// SetTargetResolver 注入目标集群解析器（装配层可选；未注入时按环境变量懒加载
// 集群注册表；注册表不可用 ⇒ 只用本地默认端点）。
func (d *dispatcher) SetTargetResolver(r clusterTargetResolver) {
	if d == nil {
		return
	}
	d.targetMu.Lock()
	defer d.targetMu.Unlock()
	d.targets = r
	d.targetErr = nil
}

// resolver 返回目标集群解析器（懒加载进程内共享的注册表句柄）。
func (d *dispatcher) resolver() (clusterTargetResolver, error) {
	d.targetMu.Lock()
	defer d.targetMu.Unlock()
	if d.targets != nil {
		return d.targets, nil
	}
	if d.targetErr != nil {
		return nil, d.targetErr
	}
	st, err := sharedClusterRegistryStore()
	if err != nil {
		d.targetErr = err
		return nil, err
	}
	d.targets = &registryTargetResolver{store: st}
	return d.targets, nil
}

// BumpInTx 同事务把表 ⑩ config_version+1、status='pending'（§4.3.5 item 2）。
func (d *dispatcher) BumpInTx(tx TenantTx, tenantID string) error {
	if d == nil || d.store == nil {
		return nil
	}
	_, err := d.store.BumpDispatchVersion(tx, tenantID, d.now())
	return err
}

// Enqueue 投递下发任务（幂等；每租户×每集群单飞，执行期间重复触发合并为一次重跑）。
//
// 目标集群集合由租户的生效作用域决定（§6.2）：
//   - 定向作用域（cluster[]）→ 精确投递这些集群；解析不出目标 ⇒ **不下发**
//     （fail-closed，避免把定向配置投到不该收的集群）；
//   - 全局作用域 → 注册表中所有可用集群；注册表未启用/为空 → 本地默认端点
//     （既有单集群行为）。
//
// 解析失败（定向目标不可用 / 作用域交集为空）⇒ 不下发 + 告警 + 租户级全局行置
// failed（**可观测**，fail-closed：绝不静默通过）。
func (d *dispatcher) Enqueue(tenantID string) {
	if d == nil || d.store == nil || tenantID == "" {
		return
	}
	tgts, err := d.resolveTargets(tenantID)
	if err != nil {
		log.Printf("[dispatch] 目标解析失败（不下发）tenant=%s: %v", tenantID, err)
		d.markGlobalFailed(tenantID, sanitizeDispatchError(err))
		d.raise(tenantID, "target_resolve_failed", sanitizeDispatchError(err))
		return
	}
	for _, t := range tgts {
		d.enqueueKey(dispatchKey{TenantID: tenantID, ClusterID: t.ClusterID})
	}
}

// resolveTargets 解析租户本次下发的目标集群集合（见 Enqueue 的口径说明）。
func (d *dispatcher) resolveTargets(tenantID string) ([]dispatchTarget, error) {
	sc, err := d.tenantScope(tenantID)
	if err != nil {
		return nil, err
	}
	if !sc.Global && len(sc.Clusters) == 0 {
		// 作用域交集为空 ⇒ 不下发（fail-closed，不退化为 global）。
		// 显式报错以便**可观测**（告警 + 全局行 failed），而不是静默无事发生。
		return nil, errScopeEmptyIntersection
	}
	resolver, rerr := d.resolver()
	var avail []dispatchTarget
	if rerr == nil {
		avail, rerr = resolver.ListTargets(context.Background())
	}
	if !sc.Global {
		// 定向作用域：目标必须解析得到（不可用 ⇒ fail-closed 不下发）。
		if rerr != nil {
			return nil, fmt.Errorf("定向作用域无法解析目标集群（fail-closed）: %w", rerr)
		}
		byID := make(map[string]dispatchTarget, len(avail))
		for _, t := range avail {
			byID[t.ClusterID] = t
		}
		out := make([]dispatchTarget, 0, len(sc.Clusters))
		for _, id := range sc.Clusters {
			t, ok := byID[id]
			if !ok {
				return nil, fmt.Errorf("目标集群 %q 不可用（fail-closed，不下发）", id)
			}
			out = append(out, t)
		}
		return out, nil
	}
	if rerr != nil || len(avail) == 0 {
		// 注册表未启用/无集群/查询失败 → 本地默认端点（既有单集群行为）。
		// 全局作用域下这是"少发"而非"错发"：其余集群待注册表恢复后由重放补齐。
		if rerr != nil {
			log.Printf("[dispatch] 集群注册表不可用，回退本地默认端点 tenant=%s: %v", tenantID, rerr)
		}
		return []dispatchTarget{{ClusterID: dispatchClusterGlobal}}, nil
	}
	return avail, nil
}

// tenantScope 读取租户的生效作用域（三表交集；与 BuildDispatch 同口径）。
func (d *dispatcher) tenantScope(tenantID string) (DispatchScope, error) {
	prov, err := d.store.GetProvisioning(tenantID)
	if err != nil {
		return DispatchScope{}, err
	}
	pol, err := d.store.GetPolicyOverlay(tenantID)
	if err != nil {
		return DispatchScope{}, err
	}
	mdl, err := d.store.GetModelConfig(tenantID)
	if err != nil {
		return DispatchScope{}, err
	}
	return effectiveDispatchScope(provisioningScopeRaw(prov), policyScopeRaw(pol), modelsScopeRaw(mdl))
}

// endpointFor 取目标集群的数据面端点（空 = 用配置的默认端点）。
func (d *dispatcher) endpointFor(key dispatchKey) string {
	if key.ClusterID == dispatchClusterGlobal {
		return ""
	}
	resolver, err := d.resolver()
	if err != nil {
		return ""
	}
	tgts, err := resolver.ListTargets(context.Background())
	if err != nil {
		return ""
	}
	for _, t := range tgts {
		if t.ClusterID == key.ClusterID {
			return t.Endpoint
		}
	}
	return ""
}

// ReplayPending 重启重放：扫描 status ∈ {pending, applying} 并重新入队（幂等）。
//
// 语义（T-3.2b「每租户×每集群单飞」）：
//   - 集群行（cluster_id ≠ ”）→ **精确重放**该 (租户×集群)；
//   - 租户级全局行（cluster_id=”）→ 承载租户级"期望版本"与聚合状态；
//     status=pending 表示"尚未全部收敛" ⇒ 按生效作用域**扇出**到目标集群，
//     补齐"从未收到过配置"（无行）的集群——否则一次崩溃会让该集群静默缺配置；
//   - 两者按 (租户×集群) **去重**：同一键只入队一次（全局行扇出与集群行精确
//     重放可能命中同一集群，去重后仍满足单飞；重复入队只会触发一次额外重跑）。
func (d *dispatcher) ReplayPending() (int, error) {
	if d == nil || d.store == nil {
		return 0, nil
	}
	rows, err := d.store.ListDispatchStatesByStatus(dispatchStatusPending, dispatchStatusApplying)
	if err != nil {
		return 0, err
	}
	keys := make(map[dispatchKey]bool, len(rows))
	order := make([]dispatchKey, 0, len(rows))
	var globalTenants []string
	seenTenant := make(map[string]bool)
	for _, r := range rows {
		if r.ClusterID != dispatchClusterGlobal {
			key := dispatchKey{TenantID: r.TenantID, ClusterID: r.ClusterID}
			if !keys[key] {
				keys[key] = true
				order = append(order, key)
			}
			continue
		}
		if !seenTenant[r.TenantID] {
			seenTenant[r.TenantID] = true
			globalTenants = append(globalTenants, r.TenantID)
		}
	}
	// 全局行扇出：按生效作用域解析目标集群（定向作用域 ⇒ 只到定向集群）。
	for _, tenantID := range globalTenants {
		tgts, terr := d.resolveTargets(tenantID)
		if terr != nil {
			log.Printf("[dispatch] 重放目标解析失败（该租户本次不重放）tenant=%s: %v", tenantID, terr)
			d.raise(tenantID, "target_resolve_failed", sanitizeDispatchError(terr))
			continue
		}
		for _, t := range tgts {
			key := dispatchKey{TenantID: tenantID, ClusterID: t.ClusterID}
			if !keys[key] {
				keys[key] = true
				order = append(order, key)
			}
		}
	}
	for _, key := range order {
		d.enqueueKey(key)
	}
	return len(order), nil
}

// Wait 等待所有单飞 worker 结束（测试与优雅停机用）。
func (d *dispatcher) Wait() {
	if d == nil {
		return
	}
	d.wg.Wait()
}

// enqueueKey 投递单飞任务（同一租户×集群合并为一次重跑）。
func (d *dispatcher) enqueueKey(key dispatchKey) {
	d.mu.Lock()
	if d.running[key] {
		d.rerun[key] = true
		d.mu.Unlock()
		return
	}
	d.running[key] = true
	d.wg.Add(1)
	d.mu.Unlock()
	go d.worker(key)
}

// worker 每租户×集群单飞串行循环：执行一次后若期间有新触发则合并重跑。
func (d *dispatcher) worker(key dispatchKey) {
	defer d.wg.Done()
	for {
		d.runOnce(key)
		d.mu.Lock()
		if d.rerun[key] {
			d.rerun[key] = false
			d.mu.Unlock()
			continue
		}
		delete(d.running, key)
		d.mu.Unlock()
		return
	}
}

// runOnce 单次下发：applying → BuildDispatch → ApplyDispatch（重试 3 次）→ applied/failed。
func (d *dispatcher) runOnce(key dispatchKey) {
	// 租户级目标版本（全局行 tenant/'' 承载期望版本；写路径 bump）。
	global, err := d.store.GetDispatchState(key.TenantID)
	if err != nil {
		log.Printf("[dispatch] 读取状态失败 tenant=%s: %v", key.TenantID, err)
		return
	}
	if global == nil {
		return
	}
	targetVersion := global.ConfigVersion
	// 该集群行的进度：已收敛则幂等跳过（重放不产生重复副作用）。
	row, err := d.store.GetDispatchStateForCluster(key.TenantID, key.ClusterID)
	if err != nil {
		log.Printf("[dispatch] 读取集群状态失败 tenant=%s cluster=%s: %v", key.TenantID, key.ClusterID, err)
		return
	}
	if row != nil && row.ConfigVersion >= targetVersion && row.AppliedVersion >= targetVersion {
		return
	}
	// 把租户级目标版本投影到该集群行（不递增版本号）。
	if err := d.withTx(func(tx TenantTx) error {
		return d.store.MarkDispatchPendingForCluster(tx, key.TenantID, key.ClusterID, targetVersion, d.now())
	}); err != nil {
		log.Printf("[dispatch] 标记待下发失败 tenant=%s cluster=%s: %v", key.TenantID, key.ClusterID, err)
		return
	}
	if d.applier == nil {
		d.markFailed(key, "channel_unconfigured", 0)
		d.raise(key.TenantID, "dispatch_failed", "channel_unconfigured")
		return
	}
	if err := d.markApplying(key); err != nil {
		log.Printf("[dispatch] 置 applying 失败 tenant=%s cluster=%s: %v", key.TenantID, key.ClusterID, err)
		return
	}

	plan, err := d.buildPlan(key.TenantID, targetVersion)
	if err != nil {
		d.markFailed(key, sanitizeDispatchError(err), 0)
		d.raise(key.TenantID, "build_failed", sanitizeDispatchError(err))
		return
	}

	// P2-4 T-3.1（§6.2）：作用域交集为空 ⇒ **不下发**（fail-closed，不退化为 global）。
	// 此时"下发到哪个集群"无解，硬发会把配置投递到不该收的集群（V-3 串扰）。
	if _, ok := plan.TargetClusters(); !ok {
		d.markFailed(key, "scope 交集为空，不下发", 0)
		d.raise(key.TenantID, "scope_empty", "配置作用域交集为空，已跳下发")
		return
	}
	// 按目标集群裁定计划（内容一致、路由到该集群的数据面端点）。
	plan = plan.ForTarget(key.ClusterID, d.endpointFor(key))

	var lastErr error
	attempts := len(d.backoff) + 1
	for attempt := 1; attempt <= attempts; attempt++ {
		applied, err := d.applier.Apply(context.Background(), plan)
		if err == nil {
			if applied <= 0 || applied > targetVersion {
				applied = targetVersion
			}
			d.markApplied(key, applied)
			if applied < targetVersion {
				// 数据面回执版本落后 → 漂移告警（以数据面生效版本为准，C-20）
				d.raise(key.TenantID, "version_drift",
					fmt.Sprintf("config=%d applied=%d cluster=%s", targetVersion, applied, key.ClusterID))
			}
			return
		}
		lastErr = err
		if attempt <= len(d.backoff) {
			d.sleep(d.backoff[attempt-1])
		}
	}
	msg := sanitizeDispatchError(lastErr)
	d.markFailed(key, msg, int64(len(d.backoff)))
	log.Printf("[dispatch] 下发失败（已重试 %d 次，保留旧版）tenant=%s cluster=%s: %s",
		len(d.backoff), key.TenantID, key.ClusterID, msg)
	d.raise(key.TenantID, "dispatch_failed", msg)
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

func (d *dispatcher) markApplying(key dispatchKey) error {
	return d.withTx(func(tx TenantTx) error {
		return d.store.MarkDispatchApplyingForCluster(tx, key.TenantID, key.ClusterID, d.now())
	})
}

func (d *dispatcher) markApplied(key dispatchKey, appliedVersion int64) {
	if err := d.withTx(func(tx TenantTx) error {
		return d.store.MarkDispatchAppliedForCluster(tx, key.TenantID, key.ClusterID, appliedVersion, d.now())
	}); err != nil {
		log.Printf("[dispatch] 置 applied 失败 tenant=%s cluster=%s: %v", key.TenantID, key.ClusterID, err)
	}
	// 租户级聚合：全部目标集群收敛后，全局行才置 applied（未全收敛保持 pending，
	// 漂移在 /dispatch/status 与 T-3.3 核对中可见）。
	d.refreshGlobalState(key.TenantID)
}

func (d *dispatcher) markFailed(key dispatchKey, lastError string, retryCount int64) {
	if err := d.withTx(func(tx TenantTx) error {
		return d.store.MarkDispatchFailedForCluster(tx, key.TenantID, key.ClusterID, lastError, retryCount, d.now())
	}); err != nil {
		log.Printf("[dispatch] 置 failed 失败 tenant=%s cluster=%s: %v", key.TenantID, key.ClusterID, err)
	}
}

// markGlobalFailed 把**租户级全局行**置 failed（脱敏 last_error + 重试计数）。
//
// 用于租户级失败（目标解析失败 / 作用域交集为空 / 目标集群不可用）——这类失败
// 不落在任何集群行上，必须让全局行显式可见（fail-closed：不静默保持 pending）。
//
// 全局行可能尚不存在（未 bump 过就入队）⇒ 先按需建行再置 failed（建行只在
// 缺失时进行，避免覆盖既有 config_version）。
//
// ⚠️ 读全局行必须在**事务外**做：事务内用独立连接读 sqlite 会在写事务需要把
// 共享锁升级为独占锁时自锁（database is locked 忙等 ⇒ 挂起）。
func (d *dispatcher) markGlobalFailed(tenantID, lastError string) {
	global, err := d.store.GetDispatchState(tenantID)
	if err != nil {
		log.Printf("[dispatch] 读取全局状态失败 tenant=%s: %v", tenantID, err)
		return
	}
	if err := d.withTx(func(tx TenantTx) error {
		if global == nil {
			// 建行（version=0：无写路径 bump ⇒ 无期望版本）。
			if err := d.store.MarkDispatchPendingForCluster(tx, tenantID, dispatchClusterGlobal, 0, d.now()); err != nil {
				return err
			}
		}
		return d.store.MarkDispatchFailed(tx, tenantID, lastError, int64(len(d.backoff)), d.now())
	}); err != nil {
		log.Printf("[dispatch] 置全局 failed 失败 tenant=%s: %v", tenantID, err)
	}
}

// refreshGlobalState 租户级聚合：全部目标集群收敛后把全局行（tenant/”）置 applied。
//
// 全局行承载"期望版本"与租户级状态；各集群行承载实际进度。
// 缺行/未收敛 ⇒ 不改全局行（保持 pending，漂移可见）。
func (d *dispatcher) refreshGlobalState(tenantID string) {
	global, err := d.store.GetDispatchState(tenantID)
	if err != nil || global == nil {
		return
	}
	tgts, err := d.resolveTargets(tenantID)
	if err != nil {
		return
	}
	for _, t := range tgts {
		row, err := d.store.GetDispatchStateForCluster(tenantID, t.ClusterID)
		if err != nil || row == nil {
			return // 缺行 = 未收敛
		}
		if row.AppliedVersion < global.ConfigVersion {
			return
		}
	}
	if err := d.withTx(func(tx TenantTx) error {
		return d.store.MarkDispatchApplied(tx, tenantID, global.ConfigVersion, d.now())
	}); err != nil {
		log.Printf("[dispatch] 聚合全局状态失败 tenant=%s: %v", tenantID, err)
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
