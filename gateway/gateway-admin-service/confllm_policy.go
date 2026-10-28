// Package main — /v1/confllm/* 策略链统一收口（D3 parity，K8 风险 = 新入口旁路）。
//
// 职责：把密态推理数据面全部路由包进与主链路**同一套**安全中间件，保证模型 ACL /
// 配额 / 脱敏 / 审计不因新入口被绕过（单一事实源，绝不复制第二套安全实现）：
//
//	认证（authMiddleware）→ 授权（requireRule 端点规则表）→ 配额（quotaGate，billing）
//	→ 审计（auditWrap，adminAuditChain）→ 业务 handler
//
// 红线（P0-4）：审计事件与日志**绝不**含请求/响应体、prompt、凭据。
package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	confllm "security-ai-gateway/gateway/confllm-adapter"
)

// confllmQuotaChecker 配额检查（D3 parity）。唯一实现 = billing（AnomalyDetector.QuotaRemaining）；
// nil = 未启用（放行 + 可观测，绝不静默）。
type confllmQuotaChecker interface {
	QuotaRemaining(tenant, day string) (float64, bool)
}

// confllm 审计动作常量（D3 parity；只记调用元数据，绝不记请求/响应体）。
const (
	auditActionConfllmChat        = "confllm_chat"
	auditActionConfllmStream      = "confllm_stream"
	auditActionConfllmGraphSubmit = "confllm_graph_submit"
	auditActionConfllmGraphPoll   = "confllm_graph_poll"
	auditActionConfllmModels      = "confllm_models"
	auditActionConfllmHealth      = "confllm_health"
)

// confllmPolicy /v1/confllm/* 统一策略链（D3 parity）：一个入口包全部路由，
// 顺序固定：认证（authMiddleware）→ 授权（requireRule）→ 配额（quotaGate）
// → 审计（auditWrap）→ 业务 handler。
//
// 授权复用端点规则表（authz.go requireRule，授权唯一事实源）；配额复用 billing
// 配额查询（confllmQuotaChecker）；审计复用 adminAuditChain（G1 链）。
func confllmPolicy(cfg *config, rule endpointRule, action string, audit *adminAuditChain, quota confllmQuotaChecker, next http.HandlerFunc) http.HandlerFunc {
	return authMiddleware(cfg, func(w http.ResponseWriter, r *http.Request) {
		if !requireRule(w, r, rule) {
			return
		}
		if !confllmQuotaGate(w, r, quota) {
			return
		}
		confllmAuditWrap(action, audit, next)(w, r)
	})
}

// confllmQuotaGate 配额门禁（D3 parity）。三种状态都可观测，绝不静默：
//
//  1. checker 非 nil 且 tenant 非空且返回 ok 且 ratio<=0 → 429（quota_exceeded，
//     响应体与库侧错误形态一致 {"error":{"code","message"}}）；
//  2. checker nil / tenant 空 / ok=false → 放行 + quota_unenforced 计数
//     （gateway_admin_confllm_quota_unenforced_total{reason}，见 metrics.go）；
//  3. 放行路径不影响业务响应（仅推进计数，不改写任何响应字节）。
//
// day 取当日（YYYY-MM-DD，billing.QuotaRemaining 语义 = 当月截至 day 的剩余比）。
func confllmQuotaGate(w http.ResponseWriter, r *http.Request, quota confllmQuotaChecker) bool {
	tenant := ""
	if c := claimsFrom(r.Context()); c != nil {
		tenant = c.Tenant
	}
	if quota == nil {
		metrics.incConfllmQuotaUnenforced("checker_disabled")
		return true
	}
	if tenant == "" {
		metrics.incConfllmQuotaUnenforced("tenant_empty")
		return true
	}
	ratio, ok := quota.QuotaRemaining(tenant, time.Now().Format("2006-01-02"))
	if !ok {
		// 无套餐 / 不限量 / 无账本数据 → billing 语义不告警，此处同样放行但留痕。
		metrics.incConfllmQuotaUnenforced("no_quota_data")
		return true
	}
	if ratio <= 0 {
		pe := confllm.NewProviderError(confllm.CodeQuotaExceeded, http.StatusTooManyRequests,
			fmt.Sprintf("租户配额已用尽（剩余比 %.6f ≤ 0），本次推理调用被拒绝", ratio))
		writeJSON(w, http.StatusTooManyRequests, pe.SanitizedBody())
		return false
	}
	return true
}

// confllmAuditWrap 审计包装（D3 parity）：请求完成后向 adminAuditChain 追加一条事件
// （参照 broker_secret.go 的 auditAppend 模式）。
//
// 事件只记：action / sub / role / tenant / 方法 + 路径 / HTTP 状态码 / X-Request-ID。
// **绝不**记录请求体、响应体、prompt、凭据（P0-4 红线）。
//
// 与凭据写路径（G1 fail-closed：审计写失败拒绝变更）不同：推理调用在 handler 返回后
// 已成既成事实，无法回滚响应，故写失败仅告警留痕（事件本身 Result 恒 "ok" =
// 链上事件完整，调用结果状态码在 Detail 中如实记录）。
func confllmAuditWrap(action string, audit *adminAuditChain, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w}
		next(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		confllmAuditAppend(audit, confllmInferAuditEvent(r, action, status))
	}
}

// confllmInferAuditEvent 构造推理调用审计事件（字段映射见 adminAuditEvent）：
// Actor=sub、Action=动作常量、Tenant=令牌租户、RequestID=X-Request-ID；
// 方法+路径+状态码+角色进 Detail（证据字段，不进 hash()，旧链逐字节不变）。
func confllmInferAuditEvent(r *http.Request, action string, status int) adminAuditEvent {
	c := claimsFrom(r.Context())
	e := adminAuditEvent{
		Action:    action,
		RequestID: r.Header.Get("X-Request-ID"),
		Result:    "ok",
	}
	if c != nil {
		e.Actor = c.Sub
		e.Tenant = c.Tenant
		e.Detail = fmt.Sprintf("role=%s %s %s status=%d", c.Role, r.Method, r.URL.Path, status)
	} else {
		e.Detail = fmt.Sprintf("role=- %s %s status=%d", r.Method, r.URL.Path, status)
	}
	return e
}

// confllmAuditAppend 落链推理调用事件；audit 未启用（nil）→ 跳过（与 broker_secret.go 同口径）。
func confllmAuditAppend(audit *adminAuditChain, e adminAuditEvent) {
	if audit == nil {
		return
	}
	if err := audit.append(e); err != nil {
		log.Printf("[confllm] 审计链写入失败（仅告警：推理响应已发出，无法回滚）action=%s rid=%s: %v",
			e.Action, e.RequestID, err)
	}
}
