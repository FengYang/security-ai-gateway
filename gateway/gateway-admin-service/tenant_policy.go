// Package main — 租户策略 overlay 与模型配置（F4/F5，§6.5/§6.6，M5）。
//
// 端点（租户会话前缀：TenantAuthMiddleware + CSRF（写））：
//
//	GET  /v1/adminext/tenant/policy            本租户 overlay（只读视图）
//	PUT  /v1/adminext/tenant/policy            更新（受限子集 + If-Match 乐观锁）
//	POST /v1/adminext/tenant/policy/apply      提交生效（依赖未就绪 → 503，不伪造生效）
//	GET  /v1/adminext/tenant/models            可用模型（目录 ∩ 套餐 ModelScopes）
//	GET  /v1/adminext/tenant/models/config     当前模型配置
//	PUT  /v1/adminext/tenant/models/config     设置（交集校验 + 默认模型校验）
//
// 受限范围（§6.5）：条目 value ≤256 字节；白/黑名单条数 ≤ 套餐上限（TENANT_POLICY_LIMITS）；
// regex 须 RE2 编译通过（100ms 预算）；类目动作须在内置类目集合内。
//
// 审计（附录 D）：`policy_update` 仅存条目数/类目数摘要（不存具体词）；
// `policy_apply` 仅存申请状态；`model_config_update` 记模型 ID（非敏感）。
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	tenantPolicyPath       = tenantSessionBase + "/policy"
	tenantPolicyApplyPath  = tenantPolicyPath + "/apply"
	tenantModelsPath       = tenantSessionBase + "/models"
	tenantModelsConfigPath = tenantModelsPath + "/config"

	// 条目约束（§6.5）：单条目 value 长度上限。
	maxPolicyEntryValueLen = 256
	// regex 编译/求值预算（§6.5）。
	policyRegexBudget = 100 * time.Millisecond
	// 缺省条目上限（billing 未启用或套餐未列时）。
	defaultPolicyEntryLimit = 50
)

// tenantBuiltinCategories 内置类目集合（§6.5：类目键须在内置集合，不允许新增类目）。
// 说明：本体未逐条枚举，此处按 §6.5 示例 + 常见 PII/安全类目定义；新增须改此表（评审门禁）。
var tenantBuiltinCategories = map[string]struct{}{
	"pii_id_card": {}, "pii_phone": {}, "pii_email": {}, "pii_bank_card": {}, "pii_address": {},
	"violence": {}, "hate": {}, "self_harm": {}, "sexual": {}, "illegal": {},
}

// tenantCategoryActionSet 允许的类目动作。
var tenantCategoryActionSet = map[string]struct{}{"block": {}, "mask": {}, "allow": {}}

// ---------- 结构与路由 ----------

// policyEntry 策略条目（§6.5）。
type policyEntry struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"` // literal | regex
	Value     string `json:"value"`
	CreatedAt int64  `json:"created_at,omitempty"`
}

// policyListView 白/黑名单视图。
type policyListView struct {
	Entries []policyEntry `json:"entries"`
}

// policyView 策略响应/请求体（同一结构，§6.5）。
type policyView struct {
	Version         int64             `json:"version"`
	Whitelist       policyListView    `json:"whitelist"`
	Blacklist       policyListView    `json:"blacklist"`
	CategoryActions map[string]string `json:"category_actions"`
	// Scope 策略作用域（P2-4 T-3.1，§6.2）。
	// 请求侧：缺省（nil）= 保持既有 scope 不变更；响应侧：回显当前生效作用域。
	Scope *scopeWriteRequest `json:"scope,omitempty"`
}

// modelsConfigView 模型配置响应/请求体（§6.6）。
type modelsConfigView struct {
	Version       int64    `json:"version"`
	AllowedModels []string `json:"allowed_models"`
	DefaultModel  string   `json:"default_model"`
	// Scope 策略作用域（P2-4 T-3.1，§6.2）；语义同 policyView.Scope。
	Scope *scopeWriteRequest `json:"scope,omitempty"`
}

// registerTenantPolicyMux 注册策略/模型端点（租户令牌 + CSRF（写））。
func (h *tenantHandler) registerTenantPolicyMux(mux *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.HandlerFunc {
		return tenantAuthMiddleware(h.cfg, csrfCheck(fn))
	}
	mux.HandleFunc("GET "+tenantPolicyPath, wrap(h.handleTenantPolicyGet))
	mux.HandleFunc("PUT "+tenantPolicyPath, wrap(h.handleTenantPolicyPut))
	mux.HandleFunc("POST "+tenantPolicyApplyPath, wrap(h.handleTenantPolicyApply))
	mux.HandleFunc("GET "+tenantModelsPath, wrap(h.handleTenantModels))
	mux.HandleFunc("GET "+tenantModelsConfigPath, wrap(h.handleTenantModelsConfigGet))
	mux.HandleFunc("PUT "+tenantModelsConfigPath, wrap(h.handleTenantModelsConfigPut))
}

// ---------- 策略：读 ----------

// handleTenantPolicyGet 本租户 overlay 只读视图（未初始化 → version=0 + 空结构）。
func (h *tenantHandler) handleTenantPolicyGet(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	po, err := h.store.GetPolicyOverlay(tenantID)
	if err != nil {
		log.Printf("[tenant-policy] 读取失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	view := policyView{
		Whitelist:       policyListView{Entries: []policyEntry{}},
		Blacklist:       policyListView{Entries: []policyEntry{}},
		CategoryActions: map[string]string{},
	}
	if po != nil {
		view.Version = po.Version
		_ = json.Unmarshal([]byte(po.WhitelistJSON), &view.Whitelist)
		_ = json.Unmarshal([]byte(po.BlacklistJSON), &view.Blacklist)
		_ = json.Unmarshal([]byte(po.CategoryActionsJSON), &view.CategoryActions)
		if view.Whitelist.Entries == nil {
			view.Whitelist.Entries = []policyEntry{}
		}
		if view.Blacklist.Entries == nil {
			view.Blacklist.Entries = []policyEntry{}
		}
		if view.CategoryActions == nil {
			view.CategoryActions = map[string]string{}
		}
	}
	// P2-4 T-3.1：回显策略作用域（存量数据 = global）。
	sc, err := parseDispatchScope(scopeRawOfPolicy(po))
	if err != nil {
		log.Printf("[tenant-policy] 作用域数据非法 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	view.Scope = scopeResponseOf(sc)
	tenantWriteJSON(w, http.StatusOK, view)
}

// ---------- 策略：写 ----------

// handleTenantPolicyPut 更新 overlay（受限子集 + If-Match 乐观锁 + 全量替换）。
func (h *tenantHandler) handleTenantPolicyPut(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	cur, err := h.store.GetPolicyOverlay(tenantID)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	curVersion := int64(0)
	if cur != nil {
		curVersion = cur.Version
	}
	reqVersion, ok := parseIfMatch(r.Header.Get("If-Match"))
	if !ok {
		tenantWriteError(w, http.StatusBadRequest, "缺少或非法的 If-Match 版本头")
		return
	}
	if reqVersion != curVersion {
		tenantWriteJSON(w, http.StatusConflict, map[string]any{"error": "version_conflict", "current": curVersion})
		return
	}

	var req policyView
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if msg, ok := h.validatePolicy(tenantID, req); !ok {
		tenantWriteError(w, http.StatusBadRequest, msg)
		return
	}

	// P2-4 T-3.1：策略作用域（缺省 = 保持既有；非法取值 / 集群未注册 → 拒绝写入）。
	// cluster[] 作用域**仅管理面可写**（P2-4 主理人裁定）：租户自助面写 cluster[]
	// ⇒ 403（越权：影响其它集群的数据面投递）；global 两侧皆可写。
	_, isAdmin := tenantTakeoverFromCtx(r)
	scope, _, err := h.resolveScopeWrite(r.Context(), req.Scope, scopeRawOfPolicy(cur), isAdmin)
	if err != nil {
		tenantWriteError(w, scopeWriteStatus(err), scopeWriteMessage(err))
		return
	}

	wl := normalizePolicyEntries(req.Whitelist)
	bl := normalizePolicyEntries(req.Blacklist)
	wlJSON, _ := json.Marshal(wl)
	blJSON, _ := json.Marshal(bl)
	caJSON, _ := json.Marshal(req.CategoryActions)

	po := &PolicyOverlay{
		TenantID: tenantID, Version: curVersion,
		WhitelistJSON: string(wlJSON), BlacklistJSON: string(blJSON),
		CategoryActionsJSON: string(caJSON), UpdatedAt: time.Now().Unix(),
		ScopeJSON: marshalDispatchScope(scope),
	}
	tx, err := h.store.Begin()
	if err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "策略保存失败")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.store.UpsertPolicyOverlay(tx, po); err != nil {
		if errors.Is(err, errTenantVersionConflict) {
			tenantWriteJSON(w, http.StatusConflict, map[string]any{"error": "version_conflict", "current": curVersion})
			return
		}
		log.Printf("[tenant-policy] 保存失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "策略保存失败")
		return
	}
	// N5：同事务 config_version+1，保证「配置已存、待下发」原子性（C-20）。
	if err := h.dispatchBumpInTx(tx, tenantID); err != nil {
		log.Printf("[tenant-policy] N5 下发入队失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "策略保存失败")
		return
	}
	if err := tx.Commit(); err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "策略保存失败")
		return
	}
	h.dispatchEnqueue(tenantID)

	// 审计：Target=policy_overlay（附录 D）、Tenant 标注归属；仅条目数/类目数摘要（不存具体词）
	h.auditAppendTenantDetail(tenantActor(r), auditActionPolicyUpdate, tenantID, "policy_overlay",
		fmt.Sprintf("wl=%d bl=%d cat=%d", len(wl.Entries), len(bl.Entries), len(req.CategoryActions)))

	// 返回更新后完整结构（version+1）
	tenantWriteJSON(w, http.StatusOK, policyView{
		Version:         curVersion + 1,
		Whitelist:       wl,
		Blacklist:       bl,
		CategoryActions: req.CategoryActions,
		Scope:           scopeResponseOf(scope),
	})
}

// handleTenantPolicyApply 提交生效；§8 依赖 1（tee-infer/P0-1 租户限域端点）未就绪 → 503。
func (h *tenantHandler) handleTenantPolicyApply(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	// 如实登记：租户级策略限域生效判据尚未实现，不伪造生效
	// 审计：Target=policy_overlay（附录 D），detail 记"未就绪"（不落全量枚举）
	h.auditAppendTenantDetail(tenantActor(r), auditActionPolicyApply, tenantID, "policy_overlay", "unavailable")
	tenantWriteJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "tenant_scope_unavailable"})
}

// validatePolicy 受限范围校验（§6.5）；返回 (错误信息, 是否通过)。
func (h *tenantHandler) validatePolicy(tenantID string, v policyView) (string, bool) {
	limit := h.policyEntryLimit(tenantID)
	for _, side := range []struct {
		name string
		list policyListView
	}{{"whitelist", v.Whitelist}, {"blacklist", v.Blacklist}} {
		if len(side.list.Entries) > limit {
			return fmt.Sprintf("%s 条目数超过套餐上限（%d）", side.name, limit), false
		}
		for _, e := range side.list.Entries {
			if e.Value == "" || len(e.Value) > maxPolicyEntryValueLen {
				return "条目 value 长度须为 1-256 字节", false
			}
			switch e.Kind {
			case "literal":
			case "regex":
				if !regexCompilesWithin(e.Value) {
					return "regex 条目编译失败或超出预算: " + e.Value, false
				}
			default:
				return "条目 kind 须为 literal 或 regex", false
			}
		}
	}
	for cat, act := range v.CategoryActions {
		if _, ok := tenantBuiltinCategories[cat]; !ok {
			return "未知类目（不允许新增类目）: " + cat, false
		}
		if _, ok := tenantCategoryActionSet[act]; !ok {
			return "非法类目动作（须为 block/mask/allow）: " + act, false
		}
	}
	return "", true
}

// policyEntryLimit 返回本租户套餐的条目上限（billing 未启用/未列 → 缺省 50）。
func (h *tenantHandler) policyEntryLimit(tenantID string) int {
	planID := "free"
	if h.billing != nil {
		if plan, err := h.billing.store.Plans().Resolve(tenantID, time.Now().UnixNano()); err == nil && plan != nil {
			planID = plan.ID
		}
	}
	if v, ok := h.cfg.policyLimits[planID]; ok && v > 0 {
		return v
	}
	return defaultPolicyEntryLimit
}

// ---------- 模型 ----------

// handleTenantModels 可用模型列表（目录 ∩ 套餐 ModelScopes）。
func (h *tenantHandler) handleTenantModels(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.billing == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "计费域未启用")
		return
	}
	catalog := h.catalogModelIDs()
	scopes := h.planModelScopes(tenantID)
	selected := h.selectedModels(tenantID)

	out := make([]map[string]any, 0, len(catalog))
	for _, id := range catalog {
		allowedByPlan := len(scopes) == 0 || containsStr(scopes, id)
		out = append(out, map[string]any{
			"id":                 id,
			"name":               id,
			"enabled_in_catalog": true,
			"allowed_by_plan":    allowedByPlan,
			"selected":           containsStr(selected, id),
		})
	}
	tenantWriteJSON(w, http.StatusOK, map[string]any{"models": out})
}

// handleTenantModelsConfigGet 当前模型配置。
func (h *tenantHandler) handleTenantModelsConfigGet(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	mc, err := h.store.GetModelConfig(tenantID)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	view := modelsConfigView{AllowedModels: []string{}}
	if mc != nil {
		view.Version = mc.Version
		view.DefaultModel = mc.DefaultModel
		_ = json.Unmarshal([]byte(mc.AllowedModelsJSON), &view.AllowedModels)
		if view.AllowedModels == nil {
			view.AllowedModels = []string{}
		}
	}
	// P2-4 T-3.1：回显策略作用域（存量数据 = global）。
	sc, err := parseDispatchScope(modelsScopeRaw(mc))
	if err != nil {
		log.Printf("[tenant-models] 作用域数据非法 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	view.Scope = scopeResponseOf(sc)
	tenantWriteJSON(w, http.StatusOK, view)
}

// handleTenantModelsConfigPut 设置模型集合与默认模型（交集校验 + 乐观锁）。
func (h *tenantHandler) handleTenantModelsConfigPut(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.billing == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "计费域未启用")
		return
	}
	cur, err := h.store.GetModelConfig(tenantID)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	curVersion := int64(0)
	if cur != nil {
		curVersion = cur.Version
	}
	reqVersion, ok := parseIfMatch(r.Header.Get("If-Match"))
	if !ok {
		tenantWriteError(w, http.StatusBadRequest, "缺少或非法的 If-Match 版本头")
		return
	}
	if reqVersion != curVersion {
		tenantWriteJSON(w, http.StatusConflict, map[string]any{"error": "version_conflict", "current": curVersion})
		return
	}

	var req modelsConfigView
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}

	// 交集校验：每个 ID ∈ 目录 ∩ 套餐 ModelScopes；去重
	catalog := h.catalogModelIDs()
	catalogSet := sliceSet(catalog)
	scopes := h.planModelScopes(tenantID)
	scopeSet := sliceSet(scopes)
	seen := map[string]struct{}{}
	allowed := make([]string, 0, len(req.AllowedModels))
	rejected := make([]string, 0)
	for _, id := range req.AllowedModels {
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		_, inCatalog := catalogSet[id]
		allowedByPlan := len(scopes) == 0 || scopeSet[id]
		if !inCatalog || !allowedByPlan {
			rejected = append(rejected, id)
			continue
		}
		allowed = append(allowed, id)
	}
	if len(rejected) > 0 {
		tenantWriteJSON(w, http.StatusBadRequest, map[string]any{
			"error": "models_not_allowed", "rejected": rejected,
		})
		return
	}
	// 默认模型须 ∈ 提交后的 allowed_models；空 allowed 须同时清空 default
	if req.DefaultModel != "" {
		if !containsStr(allowed, req.DefaultModel) {
			tenantWriteError(w, http.StatusBadRequest, "default_model 必须属于 allowed_models")
			return
		}
	} else if len(allowed) == 0 {
		req.DefaultModel = ""
	}

	// P2-4 T-3.1：策略作用域（缺省 = 保持既有；非法取值 / 集群未注册 → 拒绝写入）。
	// cluster[] 作用域**仅管理面可写**（P2-4 主理人裁定）；global 两侧皆可写。
	_, isAdmin := tenantTakeoverFromCtx(r)
	scope, _, err := h.resolveScopeWrite(r.Context(), req.Scope, modelsScopeRaw(cur), isAdmin)
	if err != nil {
		tenantWriteError(w, scopeWriteStatus(err), scopeWriteMessage(err))
		return
	}

	allowedJSON, _ := json.Marshal(allowed)
	mc := &ModelConfig{
		TenantID: tenantID, AllowedModelsJSON: string(allowedJSON),
		DefaultModel: req.DefaultModel, Version: curVersion, UpdatedAt: time.Now().Unix(),
		ScopeJSON: marshalDispatchScope(scope),
	}
	tx, err := h.store.Begin()
	if err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "模型配置保存失败")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.store.UpsertModelConfig(tx, mc); err != nil {
		if errors.Is(err, errTenantVersionConflict) {
			tenantWriteJSON(w, http.StatusConflict, map[string]any{"error": "version_conflict", "current": curVersion})
			return
		}
		log.Printf("[tenant-models] 保存失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "模型配置保存失败")
		return
	}
	// N5：同事务 config_version+1（C-20）。
	if err := h.dispatchBumpInTx(tx, tenantID); err != nil {
		log.Printf("[tenant-models] N5 下发入队失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "模型配置保存失败")
		return
	}
	if err := tx.Commit(); err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "模型配置保存失败")
		return
	}
	h.dispatchEnqueue(tenantID)

	// 审计：Target=default_model（附录 D），Detail 记模型 ID 列表与默认模型（非敏感）
	h.auditAppendTenantDetail(tenantActor(r), auditActionModelConfigUpdate, tenantID, req.DefaultModel,
		fmt.Sprintf("allowed=%s default=%s", strings.Join(allowed, ","), req.DefaultModel))

	tenantWriteJSON(w, http.StatusOK, modelsConfigView{
		Version: curVersion + 1, AllowedModels: allowed, DefaultModel: req.DefaultModel,
		Scope: scopeResponseOf(scope),
	})
}

// ---------- 工具 ----------

// parseIfMatch 解析 If-Match 头（整数版本；允许 ETag 风格引号）。
func parseIfMatch(v string) (int64, bool) {
	v = strings.TrimSpace(v)
	v = strings.Trim(v, `"`)
	if v == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

// normalizePolicyEntries 补齐缺省 id 与 created_at（服务端生成；不改变 value）。
func normalizePolicyEntries(l policyListView) policyListView {
	now := time.Now().Unix()
	out := policyListView{Entries: make([]policyEntry, 0, len(l.Entries))}
	for _, e := range l.Entries {
		if e.ID == "" {
			if id, err := randomToken(4); err == nil {
				e.ID = "e-" + id
			}
		}
		if e.CreatedAt == 0 {
			e.CreatedAt = now
		}
		out.Entries = append(out.Entries, e)
	}
	return out
}

// regexCompilesWithin 在预算内编译 RE2（Go regexp 即 RE2；超时即拒）。
func regexCompilesWithin(pattern string) bool {
	done := make(chan bool, 1)
	go func() {
		_, err := regexp.Compile(pattern)
		done <- err == nil
	}()
	select {
	case ok := <-done:
		return ok
	case <-time.After(policyRegexBudget):
		return false
	}
}

// catalogModelIDs 模型目录中的模型 ID 集合（去重排序）。
func (h *tenantHandler) catalogModelIDs() []string {
	if h.catalog == nil {
		return nil
	}
	routes := loadAIRoutes(h.catalog.settings.routesDir)
	seen := map[string]struct{}{}
	var out []string
	for _, rt := range routes {
		for _, mp := range rt.ModelPredicates {
			if mp.MatchValue == "" {
				continue
			}
			if _, ok := seen[mp.MatchValue]; ok {
				continue
			}
			seen[mp.MatchValue] = struct{}{}
			out = append(out, mp.MatchValue)
		}
	}
	sort.Strings(out)
	return out
}

// planModelScopes 当前套餐的模型范围（空 = 全部；billing 未启用/无订阅 → 空）。
func (h *tenantHandler) planModelScopes(tenantID string) []string {
	if h.billing == nil {
		return nil
	}
	plan, err := h.billing.store.Plans().Resolve(tenantID, time.Now().UnixNano())
	if err != nil || plan == nil {
		return nil
	}
	return plan.ModelScopes
}

// selectedModels 当前已选模型（模型配置的 allowed_models）。
func (h *tenantHandler) selectedModels(tenantID string) []string {
	mc, err := h.store.GetModelConfig(tenantID)
	if err != nil || mc == nil {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(mc.AllowedModelsJSON), &out)
	return out
}

// sliceSet 构建集合。
func sliceSet(items []string) map[string]bool {
	out := make(map[string]bool, len(items))
	for _, s := range items {
		out[s] = true
	}
	return out
}

// containsStr 判断字符串是否在切片中。
func containsStr(items []string, target string) bool {
	for _, s := range items {
		if s == target {
			return true
		}
	}
	return false
}

// auditAppendDetail 落审计（detail 为变更摘要；不进 hash，见 adminAuditEvent.Detail）。
func (h *tenantHandler) auditAppendDetail(actor, action, target, detail string) {
	if h.audit == nil {
		return
	}
	if err := h.audit.append(adminAuditEvent{
		Actor: actor, Action: action, Target: target, Detail: detail, Result: "ok",
	}); err != nil {
		log.Printf("[tenant-policy] 审计落链失败 action=%s: %v", action, err)
	}
}

// auditAppendTenantDetail 落审计，同时标注 Tenant（归属）与 Target（目标资源，附录 D）：
// policy_update / policy_apply → Target=policy_overlay；model_config_update → Target=default_model。
// Target 不再复用 tenant_id，租户归属由 Tenant 字段承载（哈希链含两字段）。
func (h *tenantHandler) auditAppendTenantDetail(actor, action, tenantID, target, detail string) {
	if h.audit == nil {
		return
	}
	if err := h.audit.append(adminAuditEvent{
		Actor: actor, Action: action, Tenant: tenantID, Target: target, Detail: detail, Result: "ok",
	}); err != nil {
		log.Printf("[tenant-policy] 审计落链失败 action=%s: %v", action, err)
	}
}
