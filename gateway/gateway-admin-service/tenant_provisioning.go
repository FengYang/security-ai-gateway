// Package main — N1 · 场景化开通向导（§4.3.1，V-S1/V-S2/V-S11）。
//
// 端点（租户会话前缀：TenantAuthMiddleware 双策略 + CSRF（写））：
//
//	GET /v1/adminext/tenant/provisioning   本租户开通配置只读视图（源：表 ⑧）
//	PUT /v1/adminext/tenant/provisioning   开通/变更场景
//
// 约束（§4.3.1 / §6.12）：
//   - 接入形态场景推导（access_mode 恒 a_segmented、段①/段② 由场景唯一推导），UI 只读，禁改选；
//   - 租户仅 status≠active 时可自助首开；active 租户变更属高敏操作，仅 admin（target_tenant）+ 二次确认；
//   - 变更成功联动 N4 重签声明 + N5 下发（config_version+1，同事务）；
//   - 审计 `provisioning_update` 记录场景/可信域档/接入形态变更前后（diff 摘要，C-5）。
package main

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// tenantProvisioningPath 开通配置端点路径。
const tenantProvisioningPath = tenantSessionBase + "/provisioning"

// trustTier* 轴 A：客户可信域 / 非可信基础设施。
const (
	trustTierTrusted   = "trusted"
	trustTierUntrusted = "untrusted"
)

// provisioningRequest PUT 请求体（向导第 1/2 步；access_mode/段①② 为服务端推导，不接收）。
type provisioningRequest struct {
	Scenario  string `json:"scenario"`
	TrustTier string `json:"trust_tier"`
	// Confirm 二次确认（active 租户高敏变更必填 true，§4.3.1）。
	Confirm bool `json:"confirm"`
	// ProviderCredRefs provider 凭据引用（N2；仅 vault 句柄 + 元数据，禁明文）。
	// nil = 保持既有引用不变；非 nil = 全量替换。
	ProviderCredRefs *[]providerCredRef `json:"provider_cred_refs,omitempty"`
	// Scope 策略作用域（P2-4 T-3.1，§6.2）：nil = 保持既有 scope 不变更。
	Scope *scopeWriteRequest `json:"scope,omitempty"`
}

// provisioningView 开通配置视图（GET/PUT 响应，§6.12）。
type provisioningView struct {
	Scenario        string        `json:"scenario"`
	TrustTier       string        `json:"trust_tier"`
	AccessMode      string        `json:"access_mode"`
	PluginSet       []pluginEntry `json:"plugin_set"`
	Segment1Enabled int           `json:"segment1_enabled"`
	Segment2Mode    string        `json:"segment2_mode"`
	TemplateVersion string        `json:"template_version"`
	Provisioned     bool          `json:"provisioned"`
	// Scope 策略作用域（P2-4 T-3.1，§6.2）：回显当前生效作用域。
	Scope *scopeWriteRequest `json:"scope,omitempty"`
}

// provisioningEffects 开通变更后的联动副作用（N4 重签声明 / N5 下发）。
//
// 由后续子任务注入真实实现（D=N5、F=N4）；未注入 = 空操作，保证各阶段可独立编译/测试。
// 最终形态：bumpDispatchVersion 在同事务内把表 ⑩ config_version+1、status=pending；
// enqueueDispatch 在事务提交后投递进程内下发任务（每租户单飞）；
// reissueStatement 在提交后按 supersedes 链重签承诺边界声明。
type provisioningEffects struct {
	bumpDispatchVersion func(tx TenantTx, tenantID string) error
	enqueueDispatch     func(tenantID string)
	reissueStatement    func(tenantID string) error
}

// dispatchBumpInTx 同事务推进下发版本（未接线 = 空操作）。
func (h *tenantHandler) dispatchBumpInTx(tx TenantTx, tenantID string) error {
	if h.effects.bumpDispatchVersion == nil {
		return nil
	}
	return h.effects.bumpDispatchVersion(tx, tenantID)
}

// dispatchEnqueue 提交后投递下发任务（未接线 = 空操作）。
func (h *tenantHandler) dispatchEnqueue(tenantID string) {
	if h.effects.enqueueDispatch != nil {
		h.effects.enqueueDispatch(tenantID)
	}
}

// registerTenantProvisioningMux 注册开通配置端点（租户令牌 + CSRF（写））。
func (h *tenantHandler) registerTenantProvisioningMux(mux *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.HandlerFunc {
		return tenantAuthMiddleware(h.cfg, csrfCheck(fn))
	}
	mux.HandleFunc("GET "+tenantProvisioningPath, tenantAuthMiddleware(h.cfg, h.handleTenantProvisioningGet))
	mux.HandleFunc("PUT "+tenantProvisioningPath, wrap(h.handleTenantProvisioningPut))
}

// handleTenantProvisioningGet 本租户开通配置只读视图（未开通 → provisioned=false 默认视图）。
func (h *tenantHandler) handleTenantProvisioningGet(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	p, err := h.store.GetProvisioning(tenantID)
	if err != nil {
		log.Printf("[tenant-provisioning] 读取失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	// P2-4 T-3.1：回显策略作用域（存量数据 = global；数据非法 → fail-closed 500）。
	sc, err := parseDispatchScope(scopeRawOfProvisioning(p))
	if err != nil {
		log.Printf("[tenant-provisioning] 作用域数据非法 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	view := provisioningViewOf(p)
	view.Scope = scopeResponseOf(sc)
	tenantWriteJSON(w, http.StatusOK, view)
}

// handleTenantProvisioningPut 开通/变更场景。
func (h *tenantHandler) handleTenantProvisioningPut(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	_, isAdmin := tenantTakeoverFromCtx(r)

	var req provisioningRequest
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	scenario := strings.ToLower(strings.TrimSpace(req.Scenario))
	spec, ok := lookupScenario(scenario)
	if !ok {
		tenantWriteError(w, http.StatusBadRequest, "未知或不支持的场景（S5 暂缓不可选）")
		return
	}
	trust := strings.TrimSpace(req.TrustTier)
	if trust != trustTierTrusted && trust != trustTierUntrusted {
		tenantWriteError(w, http.StatusBadRequest, "trust_tier 须为 trusted 或 untrusted")
		return
	}

	// 开通约束：active 租户变更场景/可信域档属高敏操作，仅 admin + 二次确认（§4.3.1 item 5）。
	tenant, err := h.store.GetTenantByID(tenantID)
	if err != nil {
		log.Printf("[tenant-provisioning] 读取租户失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if tenant == nil {
		tenantWriteError(w, http.StatusNotFound, "租户不存在")
		return
	}
	if tenant.Status == tenantStatusActive {
		if !isAdmin {
			tenantWriteError(w, http.StatusForbidden, "active 租户的场景变更仅管理员可执行")
			return
		}
		if !req.Confirm {
			tenantWriteError(w, http.StatusBadRequest, "高敏变更须二次确认（confirm=true）")
			return
		}
	}

	// 渲染插件组合（N6；预检失败 = 服务端模板缺陷）。
	chain, ver, err := renderPluginSet(scenario)
	if err != nil {
		log.Printf("[tenant-provisioning] 插件组合渲染失败 scenario=%s: %v", scenario, err)
		tenantWriteError(w, http.StatusInternalServerError, "插件组合渲染失败")
		return
	}
	pluginJSON, err := marshalPluginSet(chain)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "插件组合序列化失败")
		return
	}

	cur, err := h.store.GetProvisioning(tenantID)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	now := time.Now().Unix()
	provisionedAt := now
	credRefs := "[]"
	if cur != nil {
		provisionedAt = cur.ProvisionedAt
		if cur.ProviderCredRefsJSON != "" {
			credRefs = cur.ProviderCredRefsJSON
		}
	}
	// N2：provider 凭据引用（仅句柄 + 元数据）；提供则全量替换，否则保持既有。
	if req.ProviderCredRefs != nil {
		if msg, ok := validateProviderCredRefs(*req.ProviderCredRefs); !ok {
			tenantWriteError(w, http.StatusBadRequest, msg)
			return
		}
		refsJSON, err := marshalProviderCredRefs(normalizeProviderCredRefs(*req.ProviderCredRefs, now))
		if err != nil {
			tenantWriteError(w, http.StatusInternalServerError, "provider 凭据引用序列化失败")
			return
		}
		credRefs = refsJSON
	}

	// P2-4 T-3.1：策略作用域（缺省 = 保持既有；非法取值 / 集群未注册 → 拒绝写入）。
	// cluster[] 作用域**仅管理面可写**（P2-4 主理人裁定）：租户自助面写 cluster[]
	// ⇒ 403；global 两侧皆可写。
	scope, _, err := h.resolveScopeWrite(r.Context(), req.Scope, scopeRawOfProvisioning(cur), isAdmin)
	if err != nil {
		tenantWriteError(w, scopeWriteStatus(err), scopeWriteMessage(err))
		return
	}

	p := &TenantProvisioning{
		TenantID:             tenantID,
		Scenario:             scenario,
		TrustTier:            trust,
		AccessMode:           spec.AccessMode,
		PluginSetJSON:        pluginJSON,
		Segment1Enabled:      spec.Segment1,
		Segment2Mode:         spec.Segment2Mode,
		TemplateVersion:      ver,
		ProviderCredRefsJSON: credRefs,
		ProvisionedAt:        provisionedAt,
		UpdatedAt:            now,
		ScopeJSON:            marshalDispatchScope(scope),
	}

	// 同事务：写表 ⑧ + 联动 N5 下发（config_version+1，表 ⑩）——保证"配置已存、待下发"原子性。
	tx, err := h.store.Begin()
	if err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "开通配置保存失败")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.store.UpsertProvisioning(tx, p); err != nil {
		log.Printf("[tenant-provisioning] 保存失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "开通配置保存失败")
		return
	}
	if h.effects.bumpDispatchVersion != nil {
		if err := h.effects.bumpDispatchVersion(tx, tenantID); err != nil {
			log.Printf("[tenant-provisioning] N5 下发入队失败 tenant=%s: %v", tenantID, err)
			tenantWriteError(w, http.StatusServiceUnavailable, "配置下发入队失败")
			return
		}
	}
	if err := tx.Commit(); err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "开通配置保存失败")
		return
	}

	// 提交后投递 N5 下发任务（每租户单飞）。
	h.dispatchEnqueue(tenantID)

	// 联动 N4 重签承诺边界声明（supersedes 链）。声明重签失败不回滚配置（配置已存），仅告警。
	if h.effects.reissueStatement != nil {
		if err := h.effects.reissueStatement(tenantID); err != nil {
			log.Printf("[tenant-provisioning] N4 声明重签失败 tenant=%s: %v", tenantID, err)
		}
	}

	// 审计：记录场景/可信域档/接入形态变更前后（diff 摘要，不落敏感值）。
	h.auditAppendDetail(tenantActor(r), auditActionProvisioningUpdate, tenantID,
		provisioningDiffDetail(cur, scenario, trust))

	tenantWriteJSON(w, http.StatusOK, provisioningViewOf(p))
}

// provisioningViewOf 把存储行映射为视图（nil → 未开通默认视图）。
func provisioningViewOf(p *TenantProvisioning) provisioningView {
	if p == nil {
		return provisioningView{
			AccessMode:      accessModeASegmented,
			PluginSet:       []pluginEntry{},
			Segment2Mode:    segment2None,
			TemplateVersion: "",
			Provisioned:     false,
			Scope:           &scopeWriteRequest{Global: true},
		}
	}
	chain, _ := unmarshalPluginSet(p.PluginSetJSON)
	if chain == nil {
		chain = []pluginEntry{}
	}
	seg1 := 0
	if p.Segment1Enabled {
		seg1 = 1
	}
	v := provisioningView{
		Scenario:        p.Scenario,
		TrustTier:       p.TrustTier,
		AccessMode:      p.AccessMode,
		PluginSet:       chain,
		Segment1Enabled: seg1,
		Segment2Mode:    p.Segment2Mode,
		TemplateVersion: p.TemplateVersion,
		Provisioned:     true,
	}
	// P2-4 T-3.1：回显作用域（解析失败时留空，由调用方 fail-closed 处理）。
	if sc, err := parseDispatchScope(p.ScopeJSON); err == nil {
		v.Scope = scopeResponseOf(sc)
	}
	return v
}

// provisioningDiffDetail 生成场景/可信域档变更摘要（不含敏感值）。
func provisioningDiffDetail(cur *TenantProvisioning, scenario, trust string) string {
	oldScenario, oldTrust := "(none)", "(none)"
	if cur != nil {
		oldScenario, oldTrust = cur.Scenario, cur.TrustTier
	}
	spec, _ := lookupScenario(scenario)
	return fmt.Sprintf("scenario=%s->%s trust_tier=%s->%s access_mode=%s segment1=%v segment2=%s",
		oldScenario, scenario, oldTrust, trust, spec.AccessMode, spec.Segment1, spec.Segment2Mode)
}
