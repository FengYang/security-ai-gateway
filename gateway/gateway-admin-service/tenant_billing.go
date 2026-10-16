// Package main — 租户免费版自动绑定（G-2/V-1）+ 配额未确认补偿任务（§7.2/§3.2）。
//
// 绑定流程对齐 billing 既有 handleBindSubscription（M6「受理 → 回读确认」）：
// 绑定 free → QuotaCompiler 编译 → QuotaApplier 下发 → ConfirmQuotaApplied 回读确认。
// 回读未通过不回滚套餐，但租户保持 quota_pending（不得对外宣称 active），由补偿任务重放。
package main

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
)

// freePlanID 注册验证通过后自动绑定的套餐（§6.2）。
const freePlanID = "free"

// bindResult 绑定结果（status + 套餐配额摘要，供 verify 响应）。
type bindResult struct {
	Status        string // tenantStatusActive / tenantStatusQuotaPending
	MonthlyTokens int64
	Concurrency   int
}

// quotaBinder 免费版绑定器（nil = billing 域未启用 → verify 返回 503）。
type quotaBinder interface {
	// BindFree 绑定 free 套餐并完成配额编译/下发/回读确认。
	BindFree(ctx context.Context, tenantID, actor string) (bindResult, error)
}

// BindFree 复用 billing 域的 store/compiler/applier/回读确认（单一真源，C-9）。
func (h *billingHandler) BindFree(ctx context.Context, tenantID, actor string) (bindResult, error) {
	plan, err := h.store.Plans().GetPlan(freePlanID)
	if err != nil {
		return bindResult{}, fmt.Errorf("tenant: get free plan: %w", err)
	}
	if plan == nil {
		return bindResult{}, fmt.Errorf("tenant: free 套餐未初始化（InitDefaultPlans）")
	}
	res := bindResult{MonthlyTokens: plan.MonthlyTokens, Concurrency: plan.Concurrency}

	now := time.Now().UnixNano()
	if err := h.store.Plans().Bind(billing.Subscription{
		TenantID:    tenantID,
		PlanID:      freePlanID,
		EffectiveAt: now,
		BoundBy:     actor,
		BoundAt:     now,
	}); err != nil {
		return res, fmt.Errorf("tenant: bind free plan: %w", err)
	}

	// 配额编译 → 下发 → 回读确认；任一环节失败 → quota_pending（不回滚，等补偿）
	updates, err := h.compiler.Compile(tenantID, plan)
	if err != nil {
		log.Printf("[tenant-billing] 配额编译失败 tenant=%s: %v", tenantID, err)
		res.Status = tenantStatusQuotaPending
		return res, nil
	}
	if h.applier == nil {
		log.Printf("[tenant-billing] 配额下发器未配置 tenant=%s（标记 quota_pending）", tenantID)
		res.Status = tenantStatusQuotaPending
		return res, nil
	}
	if err := h.applier.ApplyQuota(ctx, updates); err != nil {
		log.Printf("[tenant-billing] 配额下发失败 tenant=%s: %v", tenantID, err)
		res.Status = tenantStatusQuotaPending
		return res, nil
	}
	rd, ok := h.applier.(billing.QuotaReader)
	if !ok {
		log.Printf("[tenant-billing] 下发器不支持回读 tenant=%s（标记 quota_pending）", tenantID)
		res.Status = tenantStatusQuotaPending
		return res, nil
	}
	budget := h.quotaApplyBudget
	if budget <= 0 {
		budget = m6ApplyWithin
	}
	if err := billing.ConfirmQuotaApplied(ctx, rd, tenantID, updates, budget, m6ApplyPoll); err != nil {
		log.Printf("[tenant-billing] 配额生效未确认 tenant=%s: %v", tenantID, err)
		res.Status = tenantStatusQuotaPending
		return res, nil
	}

	if h.audit != nil {
		// 附录 D：Target=plan_id（对齐既有 auditActionPlanBind），Tenant 承载租户归属。
		// 审计绝不落明文邮箱：actor 为邮箱时仅存哈希前缀（与 register/login 同法）。
		auditActor := actor
		if strings.Contains(auditActor, "@") {
			auditActor = emailFingerprint(auditActor)
		}
		if err := h.audit.append(adminAuditEvent{
			Actor:  auditActor,
			Action: auditActionPlanBind,
			Tenant: tenantID,
			Target: freePlanID,
			Result: "ok",
		}); err != nil {
			log.Printf("[tenant-billing] 审计落链失败 tenant=%s: %v", tenantID, err)
		}
	}
	res.Status = tenantStatusActive
	return res, nil
}

// startQuotaCompensator 启动配额未确认补偿任务（§7.2 step3；间隔见 TENANT_COMPENSATE_INTERVAL_MIN）。
// 仅由 main 调用；测试不启动（避免后台 goroutine 干扰断言）。
func (h *tenantHandler) startQuotaCompensator(ctx context.Context, interval time.Duration) {
	if h.binder == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				h.compensateOnce(ctx)
			}
		}
	}()
	log.Printf("[tenant] 配额补偿任务已启动：间隔 %s", interval)
}

// compensateOnce 扫描 quota_pending 租户并重试绑定/配额下发；成功后置 active。
func (h *tenantHandler) compensateOnce(ctx context.Context) {
	if h.binder == nil {
		return
	}
	tenants, err := h.store.ListTenantsByStatus(tenantStatusQuotaPending)
	if err != nil {
		log.Printf("[tenant] 补偿扫描失败: %v", err)
		return
	}
	for _, t := range tenants {
		res, err := h.binder.BindFree(ctx, t.ID, "system")
		if err != nil {
			log.Printf("[tenant] 补偿绑定失败 tenant=%s: %v", t.ID, err)
			continue
		}
		if res.Status != tenantStatusActive {
			continue
		}
		tx, err := h.store.Begin()
		if err != nil {
			log.Printf("[tenant] 补偿更新状态开事务失败 tenant=%s: %v", t.ID, err)
			continue
		}
		if err := h.store.UpdateTenantStatus(tx, t.ID, tenantStatusActive); err != nil {
			_ = tx.Rollback()
			log.Printf("[tenant] 补偿更新状态失败 tenant=%s: %v", t.ID, err)
			continue
		}
		if err := tx.Commit(); err != nil {
			log.Printf("[tenant] 补偿提交失败 tenant=%s: %v", t.ID, err)
			continue
		}
		log.Printf("[tenant] 配额补偿完成 tenant=%s → active", t.ID)
	}
}
