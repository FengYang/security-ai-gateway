// billing_api.go — P0-3 Token 计费体系：管理面 HTTP 端点（§4.3.2）。
//
// 默认关闭：BILLING_ENABLED!=true 时不构造本 handler、不注册任何 /billing 端点，
// /usage 等既有端点逐字节不变（R-1/M10）。
//
// 路由（全部经 authMiddleware；读写权限见各 handler）：
//
//	GET  /v1/adminext/billing/plans                   套餐列表（读）
//	POST /v1/adminext/billing/plans                   套餐 upsert（admin）
//	POST /v1/adminext/billing/subscription            租户绑定套餐（admin）
//	GET  /v1/adminext/billing/bills                   账单列表（读）
//	GET  /v1/adminext/billing/bills/{id}              账单详情（读）
//	GET  /v1/adminext/billing/bills/{id}/verify       账单验签（读）
//	GET  /v1/adminext/billing/bills/{id}/export       账单导出 CSV（读）
//	GET  /v1/adminext/billing/ledger                  账本用量查询（读）
//	POST /v1/adminext/billing/close-daily             日结（admin）
//	POST /v1/adminext/billing/close-monthly           月结（admin）
//	POST /v1/adminext/billing/freeze                  冻结租户（admin）
//	POST /v1/adminext/billing/unfreeze                解冻租户（admin）
//
// 跨租户隔离（§7.4）：读端点（plans/bills/ledger）按令牌 `tenant` 声明强制隔离——
// admin 可跨租户；非 admin 仅限自身租户，声明缺失或不符一律 403（fail-closed）。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"security-ai-gateway/gateway/gateway-admin-service/billing"
)

const billingAPIBase = "/v1/adminext/billing"

// billingHandler 计费域 HTTP 处理器。
type billingHandler struct {
	store          billing.Store
	svc            *billing.BillingService
	compiler       billing.QuotaCompiler
	applier        billing.QuotaApplier
	freeze         *billing.FreezeController
	signer         billing.BillSigner
	pricePublicURL string
	audit          *adminAuditChain
	sched          *billing.Scheduler // nil = 后台调度未启用
	backfillDays   int                // S-8 回看窗口（日志用）
}

// StartSchedulers 启动后台任务（S-8 缺口扫描：启动时立即一次 + 每日一次）。
// **仅由 main 调用**；测试不启动（避免后台 goroutine 干扰断言）。
func (h *billingHandler) StartSchedulers(ctx context.Context) {
	if h == nil || h.sched == nil {
		return
	}
	h.sched.Start(ctx)
	log.Printf("[billing] 后台调度已启动：S-3 月结 + S-5 异常扫描 + S-6 链校验 + S-7 余额告警 + S-8 缺口扫描（回看 %d 天，启动即执行一次 + 每 24h）+ S-9 到期扫描 + S-10 关联校验", h.backfillDays)
}

// Close 停止后台任务（幂等；不关闭 store——store 生命周期由调用方管理）。
func (h *billingHandler) Close() {
	if h == nil || h.sched == nil {
		return
	}
	h.sched.Stop()
}

// newBillingHandler 依配置构造计费 handler；enabled=false 返回 (nil,nil)。
func newBillingHandler(cfg *billing.BillingConfig, audit *adminAuditChain) (*billingHandler, error) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}

	// 存储
	store, err := billing.OpenSQLiteStore(cfg.Store.DSN, cfg.Store.WAL)
	if err != nil {
		return nil, fmt.Errorf("billing: open store: %w", err)
	}
	if err := billing.InitDefaultPlans(store); err != nil {
		return nil, fmt.Errorf("billing: init default plans: %w", err)
	}

	// 价格表（SC-2：不可读 → 报错，由 main 决定降级/拒绝）
	tbl, err := billing.LoadPriceTable(cfg.Rating.PriceTable)
	if err != nil {
		return nil, fmt.Errorf("billing: load price table: %w", err)
	}

	// 计价引擎（A-37：月累计缓存加速；缓存句柄注入服务以便补账失效）
	ledger := store.Ledger().(billing.MonthStdSource)
	eng, monthCache := billing.NewRatingEngineWithCache(cfg.Rating.Rounding, ledger)
	priceProvider := billing.NewStaticPriceTable(tbl) // 供计价与 S-5 单价缺失检测共用
	svc := billing.NewBillingService(store, eng, priceProvider, nil, store.Freezes())
	svc.SetMonthStdCache(monthCache)

	h := &billingHandler{
		store:          store,
		svc:            svc,
		compiler:       billing.NewQuotaCompiler(),
		freeze:         billing.NewFreezeController(store.Freezes(), nil, func() int64 { return time.Now().UnixNano() }),
		pricePublicURL: cfg.API.PricePublicURL,
		audit:          audit,
		backfillDays:   cfg.Schedule.BackfillLookbackDays,
	}

	// 后台调度（T8）：
	//   S-3  月结（每月 monthly_close_day @ monthly_close_at；结算"上月"，幂等）
	//   S-5  异常扫描（每 anomaly_scan_interval；四类规则 → 指标 #10/#12）
	//   S-6  链校验（每 verify_interval；断裂 → 停出账，fail-closed）
	//   S-7  余额告警（每 quota_scan_interval；低于阈值 → 通知，periodKey 幂等）
	//   S-8  缺口扫描（启动即一次 + 每日；补齐漏跑日账 + 日结后预热 A-37）
	//   S-9  到期扫描（每 expiry_scan_interval；T-30/7/0 提醒 → 指标 #21，不自动降级）
	//   S-10 关联校验（每 verify_assoc_interval；不符 → 标记 assoc_mismatch，不阻断）
	// 说明：S-2「日结」由 S-8 覆盖（缺口扫描每日执行，等价于"确保截至昨日已出账"）；
	// S-1 的接线见进度跟踪文档"剩余项"。L2 对账（reconciler）当前未接线，
	// 故 S-5 规则② 在现状下为空操作（nil 跳过），规则①③④ 生效。
	if cfg.Schedule.Enabled {
		det := billing.NewAnomalyDetectorForStore(store, priceProvider, nil, cfg.Anomaly,
			func() int64 { return time.Now().UnixNano() })
		notifier := billing.NewQuotaNotifier(store.AlertDedup(), nil,
			func() int64 { return time.Now().UnixNano() })
		h.sched = billing.NewScheduler(cfg.Schedule, billing.SchedulerTasks{
			CloseMonthly:  billing.CloseMonthlyTask(svc),
			ScanAnomalies: billing.ScanAnomaliesTask(det),
			CheckQuota:    billing.CheckQuotaTask(det, notifier),
			VerifyChain:   billing.VerifyChainTask(svc),
			Backfill:      billing.BackfillTask(svc, cfg.Schedule.BackfillLookbackDays),
			ScanExpiries:  billing.ScanExpiriesTask(svc),
			VerifyAssoc:   billing.VerifyAssocTask(svc, cfg.Schedule.BackfillLookbackDays),
		})
	}

	// 签名器（引用式密钥；未配置 = 不签名）
	if key, ok := resolveSecretRef(cfg.Secrets.SigningKeyRef); ok {
		h.signer = billing.NewBillSigner(key)
		svc.SetSigner(h.signer)
	}

	// 配额下发器（经 tee-infer）
	if tok, ok := resolveSecretRef(cfg.Source.AdminTokenRef); ok {
		h.applier = billing.NewHTTPQuotaApplier(cfg.Source.TEEURL, string(tok), 10*time.Second)
	}

	return h, nil
}

// register 注册计费端点（经 authMiddleware 鉴权）。
func (h *billingHandler) register(mux *http.ServeMux, cfg *config) {
	wrap := func(fn http.HandlerFunc) http.HandlerFunc {
		return authMiddleware(cfg, h.withMetrics(fn))
	}
	mux.HandleFunc(billingAPIBase+"/plans", wrap(h.handlePlans))
	mux.HandleFunc(billingAPIBase+"/subscription", wrap(h.handleSubscription))
	mux.HandleFunc(billingAPIBase+"/bills", wrap(h.handleBills))
	mux.HandleFunc(billingAPIBase+"/bills/", wrap(h.handleBillItem))
	mux.HandleFunc(billingAPIBase+"/ledger", wrap(h.handleLedger))
	mux.HandleFunc(billingAPIBase+"/close-daily", wrap(h.handleCloseDaily))
	mux.HandleFunc(billingAPIBase+"/close-monthly", wrap(h.handleCloseMonthly))
	mux.HandleFunc(billingAPIBase+"/freeze", wrap(h.handleFreeze))
	mux.HandleFunc(billingAPIBase+"/unfreeze", wrap(h.handleUnfreeze))
}

// billingStatus 捕获响应码（用于指标 #1）。
type billingStatus struct {
	http.ResponseWriter
	code int
}

func (s *billingStatus) WriteHeader(code int) {
	s.code = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *billingStatus) Write(b []byte) (int, error) {
	if s.code == 0 {
		s.code = http.StatusOK
	}
	return s.ResponseWriter.Write(b)
}

// withMetrics 计费 API 请求计数（指标 #1；method/code）。
func (h *billingHandler) withMetrics(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rec := &billingStatus{ResponseWriter: w}
		next(rec, r)
		code := rec.code
		if code == 0 {
			code = http.StatusOK
		}
		billing.IncBillingRequests(r.Method, strconv.Itoa(code))
	}
}

// ---------- 套餐 ----------

func (h *billingHandler) handlePlans(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireReadAccess(w, r) {
			return
		}
		plans, err := h.store.Plans().ListPlans()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "套餐列表查询失败")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"plans": plans})
	case http.MethodPost:
		if !requireRole(w, r, "admin") {
			return
		}
		var p billing.Plan
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&p); err != nil {
			writeError(w, http.StatusBadRequest, "请求体解析失败")
			return
		}
		if err := billing.ValidatePlan(&p); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if err := h.store.Plans().PutPlan(&p); err != nil {
			writeError(w, http.StatusInternalServerError, "套餐写入失败")
			return
		}
		h.auditAction(r, auditActionPlanUpsert, p.ID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "id": p.ID})
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET/POST")
	}
}

// ---------- 订阅绑定 ----------

func (h *billingHandler) handleSubscription(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	var req struct {
		Tenant      string `json:"tenant"`
		PlanID      string `json:"plan_id"`
		EffectiveAt int64  `json:"effective_at"`
		ExpiresAt   int64  `json:"expires_at"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.Tenant == "" || req.PlanID == "" {
		writeError(w, http.StatusBadRequest, "tenant 与 plan_id 必填")
		return
	}
	// 套餐必须存在（T-6.4-1）
	plan, err := h.store.Plans().GetPlan(req.PlanID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "套餐查询失败")
		return
	}
	if plan == nil {
		writeError(w, http.StatusNotFound, "套餐不存在")
		return
	}
	c := claimsFrom(r.Context())
	sub := billing.Subscription{
		TenantID:    req.Tenant,
		PlanID:      req.PlanID,
		EffectiveAt: req.EffectiveAt,
		ExpiresAt:   req.ExpiresAt,
		BoundBy:     c.Sub,
		BoundAt:     time.Now().UnixNano(),
	}
	if err := h.store.Plans().Bind(sub); err != nil {
		writeError(w, http.StatusInternalServerError, "套餐绑定失败")
		return
	}
	// 配额编译 + 下发（M6）
	updates, err := h.compiler.Compile(req.Tenant, plan)
	if err == nil && h.applier != nil {
		if err := h.applier.ApplyQuota(r.Context(), updates); err != nil {
			log.Printf("[billing] quota apply failed tenant=%s: %v", req.Tenant, err)
		}
	}
	h.auditAction(r, auditActionPlanBind, req.Tenant)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tenant": req.Tenant, "plan_id": req.PlanID})
}

// ---------- 账单 ----------

func (h *billingHandler) handleBills(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireReadAccess(w, r) {
		return
	}
	q := r.URL.Query()
	tenant := q.Get("tenant")
	if !h.tenantAllowed(r, tenant) {
		writeError(w, http.StatusForbidden, "跨租户访问被拒绝")
		return
	}
	limit := atoiDefault(q.Get("limit"), 100)
	bills, err := h.store.Bills().List(billing.BillQuery{
		TenantID: tenant, Kind: q.Get("kind"),
		From: q.Get("from"), To: q.Get("to"), Limit: limit,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "账单查询失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bills": bills})
}

// handleBillItem 处理 /bills/{id}、/bills/{id}/verify、/bills/{id}/export。
func (h *billingHandler) handleBillItem(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireReadAccess(w, r) {
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, billingAPIBase+"/bills/")
	parts := strings.Split(rest, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "账单 id 缺失")
		return
	}
	billID := parts[0]
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}

	bill, err := h.store.Bills().Get(billID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "账单查询失败")
		return
	}
	if bill == nil {
		writeError(w, http.StatusNotFound, "账单不存在")
		return
	}
	if !h.tenantAllowed(r, bill.TenantID) {
		writeError(w, http.StatusForbidden, "跨租户访问被拒绝")
		return
	}

	switch sub {
	case "verify":
		valid := h.signer != nil && h.signer.Verify(bill)
		if valid {
			billing.IncSignatureVerify("valid") // 指标 #16（M8）
		} else {
			billing.IncSignatureVerify("invalid")
		}
		resp := map[string]any{
			"valid":         valid,
			"sig_alg":       "hmac-sha256",
			"price_version": bill.PriceVersion,
			"ledger_head":   bill.LedgerHead,
			"audit_head":    bill.AuditHead,
		}
		if err := h.svc.VerifyBillingChain(bill); err != nil {
			resp["assoc"] = err.Error()
			billing.IncAssocVerify("fail") // 指标 #22（A-34；不阻断）
		} else {
			billing.IncAssocVerify("pass")
		}
		h.auditAction(r, auditActionBillVerify, billID)
		writeJSON(w, http.StatusOK, resp)
	case "export":
		data, mime, err := billing.ExportCSV(bill)
		if err != nil {
			billing.IncExport("csv", "error")
			writeError(w, http.StatusInternalServerError, "导出失败")
			return
		}
		billing.IncExport("csv", "ok") // 指标 #15
		h.auditAction(r, auditActionBillExport, billID)
		w.Header().Set("Content-Type", mime)
		w.Header().Set("Content-Disposition", `attachment; filename="`+billID+`.csv"`)
		_, _ = w.Write(data)
	case "":
		writeJSON(w, http.StatusOK, bill)
	default:
		writeError(w, http.StatusNotFound, "未知子资源")
	}
}

// ---------- 账本用量 ----------

func (h *billingHandler) handleLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
		return
	}
	if !requireReadAccess(w, r) {
		return
	}
	q := r.URL.Query()
	tenant := q.Get("tenant")
	if !h.tenantAllowed(r, tenant) {
		writeError(w, http.StatusForbidden, "跨租户访问被拒绝")
		return
	}
	entries, err := h.store.Ledger().Range(billing.LedgerQuery{
		TenantID: tenant, DayFrom: q.Get("from"), DayTo: q.Get("to"),
		Limit: atoiDefault(q.Get("limit"), 1000),
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "账本查询失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": entries})
}

// ---------- 出账 ----------

func (h *billingHandler) handleCloseDaily(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	var req struct {
		Tenant string `json:"tenant"`
		Day    string `json:"day"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.Tenant == "" || req.Day == "" {
		writeError(w, http.StatusBadRequest, "tenant 与 day 必填")
		return
	}
	bill, err := h.svc.CloseDaily(r.Context(), req.Tenant, req.Day)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	h.auditAction(r, auditActionBillIssue, bill.ID)
	writeJSON(w, http.StatusOK, bill)
}

func (h *billingHandler) handleCloseMonthly(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	var req struct {
		Tenant string `json:"tenant"`
		Month  string `json:"month"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.Tenant == "" || req.Month == "" {
		writeError(w, http.StatusBadRequest, "tenant 与 month 必填")
		return
	}
	bill, err := h.svc.CloseMonthly(r.Context(), req.Tenant, req.Month)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	h.auditAction(r, auditActionBillIssue, bill.ID)
	writeJSON(w, http.StatusOK, bill)
}

// ---------- 冻结 / 解冻 ----------

func (h *billingHandler) handleFreeze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	var req struct {
		Tenant   string `json:"tenant"`
		Reason   string `json:"reason"`
		Severity string `json:"severity"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.Tenant == "" {
		writeError(w, http.StatusBadRequest, "tenant 必填")
		return
	}
	if req.Reason == "" {
		req.Reason = "manual"
	}
	if req.Severity == "" {
		req.Severity = string(billing.SeverityCritical)
	}
	c := claimsFrom(r.Context())
	if err := h.freeze.Freeze(req.Tenant, req.Reason, req.Severity, c.Sub); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	h.auditAction(r, auditActionBillFreeze, req.Tenant)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tenant": req.Tenant})
}

func (h *billingHandler) handleUnfreeze(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	var req struct {
		Tenant string `json:"tenant"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "请求体解析失败")
		return
	}
	if req.Tenant == "" {
		writeError(w, http.StatusBadRequest, "tenant 必填")
		return
	}
	c := claimsFrom(r.Context())
	if err := h.freeze.Unfreeze(req.Tenant, c.Sub); err != nil {
		writeError(w, http.StatusInternalServerError, "解冻失败")
		return
	}
	h.auditAction(r, auditActionBillUnfreeze, req.Tenant)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "tenant": req.Tenant})
}

// ---------- 辅助 ----------

// tenantAllowed 跨租户读隔离（§7.4）：
//   - admin：可跨租户（运营/财务口径）；
//   - 非 admin（auditor 等）：仅允许访问令牌 `tenant` 声明所指租户；
//     声明缺失或与目标不符 → 拒绝（fail-closed）；
//   - tenant 为空（意图全量列举）→ 非 admin 一律拒绝（禁止越权全量读取）。
func (h *billingHandler) tenantAllowed(r *http.Request, tenant string) bool {
	c := claimsFrom(r.Context())
	if c == nil {
		return false
	}
	if c.Role == roleAdmin {
		return true
	}
	return tenant != "" && c.Tenant != "" && c.Tenant == tenant
}

// auditAction 落管理面审计链（best-effort；失败仅记日志）。
func (h *billingHandler) auditAction(r *http.Request, action, target string) {
	if h.audit == nil {
		return
	}
	c := claimsFrom(r.Context())
	actor := ""
	if c != nil {
		actor = c.Sub
	}
	if err := h.audit.append(adminAuditEvent{
		Actor:     actor,
		Action:    action,
		Target:    target,
		RequestID: r.Header.Get("X-Request-ID"),
		Result:    "ok",
	}); err != nil {
		log.Printf("[billing] audit append failed action=%s: %v", action, err)
	}
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

// resolveSecretRef 解析引用式密钥（env:NAME / file:PATH，R-5/R-9/R-27）。
func resolveSecretRef(ref string) ([]byte, bool) {
	if ref == "" {
		return nil, false
	}
	switch {
	case strings.HasPrefix(ref, "env:"):
		v := os.Getenv(strings.TrimPrefix(ref, "env:"))
		if v == "" {
			return nil, false
		}
		return []byte(v), true
	case strings.HasPrefix(ref, "file:"):
		b, err := os.ReadFile(strings.TrimPrefix(ref, "file:"))
		if err != nil {
			return nil, false
		}
		return b, true
	default:
		return nil, false
	}
}
