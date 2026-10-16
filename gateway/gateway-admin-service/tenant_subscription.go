// Package main — 租户套餐自助（F7，§6.8，M7）。
//
// 端点（租户会话前缀：TenantAuthMiddleware + CSRF（写））：
//
//	GET  /v1/adminext/tenant/plans                     套餐列表（读 billing/plan_store）
//	GET  /v1/adminext/tenant/subscription              当前订阅（自助语义）
//	POST /v1/adminext/tenant/subscription/upgrade      发起升级/降级请求 → 待确认单（D-9）
//
// 前置（§6.8）：要求 BILLING_ENABLED=true；billing 域关闭 → 一律 503（C-12，不返回空列表）。
// D-9：升级/降级需**管理员确认**（复用 handleBindSubscription：升级立即生效、降级次月 1 日）；
// 免费版不可降级；审计 `plan_upgrade` / `plan_downgrade`（附录 D）。金额列不出现（C-10）。
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
)

const (
	tenantPlansPath        = tenantSessionBase + "/plans"
	tenantSubscriptionPath = tenantSessionBase + "/subscription"
)

// tenantPlanView 套餐视图（金额/价格列不出现，C-10）。
type tenantPlanView struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	MonthlyTokens int64    `json:"monthly_tokens"`
	Concurrency   int      `json:"concurrency"`
	CacheTier     string   `json:"cache_tier"`
	OverQuota     string   `json:"over_quota"`
	ModelScopes   []string `json:"model_scopes,omitempty"`
}

// registerTenantSubscriptionMux 注册套餐自助端点（租户令牌 + CSRF（写））。
func (h *tenantHandler) registerTenantSubscriptionMux(mux *http.ServeMux) {
	wrap := func(fn http.HandlerFunc) http.HandlerFunc {
		return tenantAuthMiddleware(h.cfg, csrfCheck(fn))
	}
	mux.HandleFunc("GET "+tenantPlansPath, wrap(h.handleTenantPlans))
	mux.HandleFunc("GET "+tenantSubscriptionPath, wrap(h.handleTenantSubscription))
	mux.HandleFunc("POST "+tenantSubscriptionPath+"/upgrade", wrap(h.handleTenantSubscriptionUpgrade))
}

// handleTenantPlans 套餐列表（billing 未启用 → 503）。
func (h *tenantHandler) handleTenantPlans(w http.ResponseWriter, r *http.Request) {
	if _, err := requireTenantScope(r); err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.billing == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "计费域未启用")
		return
	}
	plans, err := h.billing.store.Plans().ListPlans()
	if err != nil {
		log.Printf("[tenant-plans] 列表失败: %v", err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	out := make([]tenantPlanView, 0, len(plans))
	for _, p := range plans {
		out = append(out, tenantPlanView{
			ID: p.ID, Name: p.Name, MonthlyTokens: p.MonthlyTokens,
			Concurrency: p.Concurrency, CacheTier: p.CacheTier,
			OverQuota: p.OverQuota, ModelScopes: p.ModelScopes,
		})
	}
	tenantWriteJSON(w, http.StatusOK, map[string]any{"plans": out})
}

// handleTenantSubscription 当前订阅（最新未过期；自助按令牌内租户）。
func (h *tenantHandler) handleTenantSubscription(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.billing == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "计费域未启用")
		return
	}
	sub, err := h.currentSubscription(tenantID)
	if err != nil {
		log.Printf("[tenant-subscription] 查询失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	tenantWriteJSON(w, http.StatusOK, map[string]any{"tenant": tenantID, "subscription": sub})
}

// handleTenantSubscriptionUpgrade 发起升级/降级请求（生成待确认单，D-9）。
func (h *tenantHandler) handleTenantSubscriptionUpgrade(w http.ResponseWriter, r *http.Request) {
	tenantID, err := requireTenantScope(r)
	if err != nil {
		tenantWriteError(w, http.StatusForbidden, "forbidden")
		return
	}
	if h.billing == nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "计费域未启用")
		return
	}
	var req struct {
		PlanID string `json:"plan_id"`
	}
	if err := decodeJSONBody(r, &req); err != nil {
		tenantWriteError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.PlanID == "" {
		tenantWriteError(w, http.StatusBadRequest, "plan_id 必填")
		return
	}
	target, err := h.billing.store.Plans().GetPlan(req.PlanID)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if target == nil {
		tenantWriteError(w, http.StatusBadRequest, "套餐不存在")
		return
	}
	curPlanID := h.currentPlanID(tenantID)
	if curPlanID == req.PlanID {
		tenantWriteError(w, http.StatusBadRequest, "已是当前套餐")
		return
	}
	direction := "upgrade"
	if planRank(req.PlanID) < planRank(curPlanID) {
		direction = "downgrade"
	}
	// D-9：免费版不可降级
	if direction == "downgrade" && curPlanID == "free" {
		tenantWriteError(w, http.StatusBadRequest, "免费版不可降级")
		return
	}

	rid, err := randomToken(8)
	if err != nil {
		tenantWriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	requestID := "req-" + rid
	actor := tenantActor(r)
	tx, err := h.store.Begin()
	if err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "请求创建失败")
		return
	}
	defer func() { _ = tx.Rollback() }()
	if err := h.store.CreateSubscriptionRequest(tx, &SubscriptionRequest{
		RequestID: requestID, TenantID: tenantID, FromPlan: curPlanID, ToPlan: req.PlanID,
		Direction: direction, Status: "pending", CreatedBy: actor, CreatedAt: time.Now().Unix(),
	}); err != nil {
		log.Printf("[tenant-subscription] 待确认单落库失败 tenant=%s: %v", tenantID, err)
		tenantWriteError(w, http.StatusServiceUnavailable, "请求创建失败")
		return
	}
	if err := tx.Commit(); err != nil {
		tenantWriteError(w, http.StatusServiceUnavailable, "请求创建失败")
		return
	}

	action := auditActionPlanUpgrade
	if direction == "downgrade" {
		action = auditActionPlanDowngrade
	}
	// 附录 D：Target=plan_id；降级须记录生效日（次月 1 日，D-9），升级立即生效。
	detail := fmt.Sprintf("%s->%s req=%s", curPlanID, req.PlanID, requestID)
	if direction == "downgrade" {
		now := time.Now()
		eff := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
		detail += " eff=" + eff.Format("2006-01-02")
	}
	h.auditAppendTenantDetail(actor, action, tenantID, req.PlanID, detail)
	log.Printf("[tenant-subscription] %s 请求已登记 tenant=%s %s→%s req=%s",
		direction, tenantID, curPlanID, req.PlanID, requestID)
	tenantWriteJSON(w, http.StatusOK, map[string]any{"request_id": requestID, "status": "pending"})
}

// currentSubscription 取本租户最新未过期订阅（无 → nil）。
func (h *tenantHandler) currentSubscription(tenantID string) (*billing.Subscription, error) {
	now := time.Now().UnixNano()
	subs, err := h.billing.store.Plans().ListSubscriptions(now)
	if err != nil {
		return nil, err
	}
	var cur *billing.Subscription
	for i := range subs {
		s := subs[i]
		if s.TenantID != tenantID {
			continue
		}
		if s.ExpiresAt != 0 && s.ExpiresAt <= now {
			continue
		}
		if cur == nil || s.EffectiveAt >= cur.EffectiveAt {
			cp := s
			cur = &cp
		}
	}
	return cur, nil
}

// currentPlanID 取本租户当前生效套餐 ID（无订阅 → free）。
func (h *tenantHandler) currentPlanID(tenantID string) string {
	if h.billing == nil {
		return "free"
	}
	plan, err := h.billing.store.Plans().Resolve(tenantID, time.Now().UnixNano())
	if err != nil || plan == nil {
		return "free"
	}
	return plan.ID
}

// planRank 套餐档位（用于判定升级/降级方向；未知档视为最高 → 保守按升级）。
func planRank(id string) int {
	switch id {
	case "free":
		return 0
	case "basic":
		return 1
	case "pro":
		return 2
	case "enterprise":
		return 3
	default:
		return 99
	}
}
