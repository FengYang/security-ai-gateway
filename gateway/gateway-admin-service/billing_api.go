// billing_api.go — P0-3 Token 计费体系：管理面 HTTP 端点（§4.3.2）。
//
// 默认关闭：BILLING_ENABLED!=true 时不构造本 handler、不注册任何 /billing 端点，
// /usage 等既有端点逐字节不变（R-1/M10）。
//
// 路由（全部经 authMiddleware；读写权限见各 handler）：
//
//	GET  /v1/adminext/billing/plans                   套餐列表（读）
//	POST /v1/adminext/billing/plans                   套餐 upsert（admin）
//	GET  /v1/adminext/billing/subscription            当前租户套餐（读；自助按 token 内租户）
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
//	POST /v1/adminext/billing/events                  推送事件消费（HMAC 鉴权，非 JWT；§6.3.1）
//
// 跨租户隔离（§7.4）：读端点（plans/bills/ledger）按令牌 `tenant` 声明强制隔离——
// admin 可跨租户；非 admin 仅限自身租户，声明缺失或不符一律 403（fail-closed）。
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
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
	store            billing.Store
	svc              *billing.BillingService
	compiler         billing.QuotaCompiler
	applier          billing.QuotaApplier
	freeze           *billing.FreezeController
	signer           billing.BillSigner
	pricePublicURL   string
	audit            *adminAuditChain
	eventsSecret     []byte             // 推送 webhook HMAC 验签密钥（events_secret_ref 优先，回退 push_secret_ref；空 = 一律 401）
	quotaApplyBudget time.Duration      // M6 回读确认预算（零值 = m6ApplyWithin；测试可缩短）
	sched            *billing.Scheduler // nil = 后台调度未启用
	backfillDays     int                // S-8 回看窗口（日志用）
}

// StartSchedulers 启动后台任务（S-8 缺口扫描：启动时立即一次 + 每日一次）。
// **仅由 main 调用**；测试不启动（避免后台 goroutine 干扰断言）。
func (h *billingHandler) StartSchedulers(ctx context.Context) {
	if h == nil || h.sched == nil {
		return
	}
	h.sched.Start(ctx)
	log.Printf("[billing] 后台调度已启动：S-1 增量拉取 + S-3 月结 + S-5 异常扫描 + S-6 链校验 + S-7 余额告警 + S-8 缺口扫描（回看 %d 天，启动即执行一次 + 每 24h）+ S-9 到期扫描 + S-10 关联校验", h.backfillDays)
}

// Close 停止后台任务（幂等；不关闭 store——store 生命周期由调用方管理）。
func (h *billingHandler) Close() {
	if h == nil || h.sched == nil {
		return
	}
	h.sched.Stop()
}

// freezeAuditSink 把计费域冻结/解冻落管理面审计链（§6.10.2；系统自动冻结 actor="system"）。
type freezeAuditSink struct{ chain *adminAuditChain }

func (s freezeAuditSink) RecordFreeze(action, tenant, reason, severity, by string) {
	if s.chain == nil {
		return
	}
	if err := s.chain.append(adminAuditEvent{
		Actor:  by,
		Action: action,
		Target: tenant,
		Result: "ok",
	}); err != nil {
		log.Printf("[billing] freeze audit append failed action=%s tenant=%s: %v", action, tenant, err)
	}
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

	// 计量令牌（引用式；未配置 → 拉取与 L2 对账降级）
	token, hasToken := resolveSecretRef(cfg.Source.AdminTokenRef)

	// 计价引擎（A-37：月累计缓存加速；缓存句柄注入服务以便补账失效）
	ledger := store.Ledger().(billing.MonthStdSource)
	eng, monthCache := billing.NewRatingEngineWithCache(cfg.Rating.Rounding, ledger)
	priceProvider := billing.NewStaticPriceTable(tbl) // 供计价、S-5 单价缺失、L2 共用

	// L2 对账器（S-4：每次出账前 + 拉取后门禁；计量侧 reader 复用 tee-infer 拉取源）
	var pullSrc billing.PullSource
	var rec *billing.Reconciler
	if hasToken {
		pullSrc = billing.NewTEEPullSource(cfg.Source.TEEURL, string(token), 30*time.Second)
		rec = billing.NewReconcilerForStore(store, billing.NewPullNetReader(pullSrc), cfg.Anomaly.ReconcileAlertRatio)
	}

	svc := billing.NewBillingService(store, eng, priceProvider, rec, store.Freezes())
	svc.SetMonthStdCache(monthCache)
	// 单写者模式（A-12/R-30）与回补窗口为**非密钥配置** → 无条件注入；
	// 拉取源依赖计量令牌（未配置 → nil，pullOnce no-op，但推送消费仍按 sync_mode 生效）
	svc.SetMeteringSource(pullSrc, cfg.Source.PullLookback, cfg.Source.SyncMode)

	// REC-6 审计链校验器（tee-infer /audit/verify；断裂 → 全局停出账，B-6.12-4）。
	// 端点为只读校验；令牌可选（无令牌时省略管理头）。
	svc.SetAuditChainVerifier(billing.NewTEEAuditVerifier(cfg.Source.TEEURL, string(token), 10*time.Second))

	// 推送 webhook 验签密钥（§4.2/R-27 独立事件密钥域）：
	//   优先 `secrets.events_secret_ref`；未配置 → 回退 `source.push_secret_ref`（向后兼容）；
	//   两者皆缺 → 端点一律 401（fail-closed）。
	eventsSecret, _ := resolveSecretRef(cfg.Secrets.EventsSecretRef)
	if len(eventsSecret) == 0 {
		eventsSecret, _ = resolveSecretRef(cfg.Source.PushSecretRef)
	}

	h := &billingHandler{
		store:          store,
		svc:            svc,
		compiler:       billing.NewQuotaCompiler(),
		freeze:         billing.NewFreezeController(store.Freezes(), freezeAuditSink{audit}, func() int64 { return time.Now().UnixNano() }),
		pricePublicURL: cfg.API.PricePublicURL,
		audit:          audit,
		eventsSecret:   eventsSecret,
		backfillDays:   cfg.Schedule.BackfillLookbackDays,
	}

	// 后台调度（T8）：
	//   S-1  增量拉取（每 source.pull_interval；入账受 sync_mode 单写者门控）
	//   S-3  月结（每月 monthly_close_day @ monthly_close_at；结算"上月"，幂等）
	//   S-5  异常扫描（每 anomaly_scan_interval；四类规则 → 指标 #10/#12；critical → 冻结 §6.10.1）
	//   S-6  链校验（每 verify_interval；断裂 → 停出账，fail-closed）
	//   S-7  余额告警（每 quota_scan_interval；低于阈值 → 通知，periodKey 幂等）
	//   S-8  缺口扫描（启动即一次 + 每日；补齐漏跑日账 + 日结后预热 A-37）
	//   S-9  到期扫描（每 expiry_scan_interval；T-30/7/0 提醒 → 指标 #21，不自动降级）
	//   S-10 关联校验（每 verify_assoc_interval；不符 → 标记 assoc_mismatch，不阻断）
	// 说明：S-2「日结」由 S-8 覆盖（缺口扫描每日执行，等价于"确保截至昨日已出账"）。
	// L2 对账（reconciler）在配置了计量令牌时激活：出账门禁（diff>0 → 不出账，fail-closed）+
	// S-5 规则②（reconcile_diff）；未配置令牌时降级为 nil（门禁与规则②跳过）。
	if cfg.Schedule.Enabled {
		det := billing.NewAnomalyDetectorForStore(store, priceProvider, rec, cfg.Anomaly,
			func() int64 { return time.Now().UnixNano() })
		det.SetFreezeLinker(h.freeze) // S-5 critical 异常 → 冻结（§6.10.1）
		// 告警外部交付（Webhook；空 URL → nil 降级）：S-7 余额 + S-9 到期共用
		alertSink := billing.NewWebhookAlertSink(cfg.Secrets.AlertWebhookURL, 10*time.Second)
		svc.SetAlertSink(alertSink)
		notifier := billing.NewQuotaNotifier(store.AlertDedup(), alertSink,
			func() int64 { return time.Now().UnixNano() })
		h.sched = billing.NewScheduler(cfg.Schedule, billing.SchedulerTasks{
			Pull:          billing.PullTask(svc),
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

	// 配额下发器（经 tee-infer；复用同一计量令牌）
	if hasToken {
		h.applier = billing.NewHTTPQuotaApplier(cfg.Source.TEEURL, string(token), 10*time.Second)
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
	mux.HandleFunc(billingAPIBase+"/verify-chain", wrap(h.handleVerifyChain))
	// 推送消费（§6.3.1）：由 HMAC（X-Signature）鉴权——推送方无管理面 JWT，故**不经** authMiddleware
	mux.HandleFunc(billingAPIBase+"/events", h.withMetrics(h.handleBillingEvents))
}

// billingEventsMaxBytes 推送事件体上限（1 MiB；事件级载荷远小于此）。
const billingEventsMaxBytes = 1 << 20

// M6 回读确认预算与轮询间隔（§6.4.1 2c / A-14；POST 2xx ≠ 生效，以回读为准）。
const (
	m6ApplyWithin = 60 * time.Second
	m6ApplyPoll   = time.Second
)

// handleBillingEvents POST /v1/adminext/billing/events（§6.3.1）。
//
// 流程：HMAC 验签（X-Signature: sha256=<hex>，密钥 = source.push_secret_ref）→ JSON 反序列化
// → 委托 `ConsumePush`（幂等入账 + 冻结计数均在服务内；账本无第二写入路径 INV-8）。
// 鉴权：不经 authMiddleware（推送方无管理面 JWT），由 HMAC 承担（B-6.3-1：未验签 → 401）。
func (h *billingHandler) handleBillingEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, billingEventsMaxBytes))
	if err != nil {
		writeError(w, http.StatusBadRequest, "bad_body")
		return
	}
	if !h.verifyEventsHMAC(r.Header.Get("X-Signature"), body) {
		writeError(w, http.StatusUnauthorized, "signature_invalid") // B-6.3-1
		return
	}
	var ev billing.PushEvent
	if err := json.Unmarshal(body, &ev); err != nil {
		writeError(w, http.StatusBadRequest, "bad_json")
		return
	}
	if err := h.svc.ConsumePush(ev); err != nil {
		writeError(w, http.StatusInternalServerError, "ledger_error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "accepted"})
}

// verifyEventsHMAC 校验推送签名（§6.3.1）。
// 密钥未配置 / 头缺失或非 `sha256=<hex>` / 常量时间不等 → false（fail-closed）。
// ★ SEC-001：委托 billing.VerifyEventMAC 做 **intl↔sm 双算法**兼容校验（解耦两端 CRYPTO_PROFILE）。
func (h *billingHandler) verifyEventsHMAC(sig string, body []byte) bool {
	return billing.VerifyEventMAC(h.eventsSecret, body, sig)
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

// withMetrics 计费 API 观测：请求计数（#1；path,code）+ 查询耗时（#9；path，M5）。
//
// ★ MET-001/002：标签统一为 `path`（低基数路由模板），与详设 §9.1 契约一致；
// 同时**接通 #9 `billing_api_duration_seconds` 生产者**（此前 `ObserveAPI` 无调用点 → M5 不可观测）。
func (h *billingHandler) withMetrics(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &billingStatus{ResponseWriter: w}
		next(rec, r)
		code := rec.code
		if code == 0 {
			code = http.StatusOK
		}
		route := billingRouteLabel(r.URL.Path)
		billing.IncBillingRequests(route, strconv.Itoa(code))  // 指标 #1
		billing.ObserveAPI(route, time.Since(start).Seconds()) // 指标 #9
	}
}

// billingRouteLabel 把 /billing 请求路径归一为**低基数**路由标签
// （避免 `/bills/{id}` 含真实账单 id 造成指标基数爆炸）。
func billingRouteLabel(p string) string {
	rest := strings.TrimPrefix(p, billingAPIBase)
	switch rest {
	case "/plans", "/subscription", "/bills", "/ledger", "/close-daily",
		"/close-monthly", "/freeze", "/unfreeze", "/verify-chain", "/events":
		return rest
	}
	if strings.HasPrefix(rest, "/bills/") {
		parts := strings.Split(strings.TrimPrefix(rest, "/bills/"), "/")
		if len(parts) >= 2 && parts[1] != "" {
			return "/bills/{id}/" + parts[1] // /verify | /export
		}
		return "/bills/{id}"
	}
	return rest
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
		// R-29 交叉约束：charge 套餐须非免费档且单价非全 0（防免费版产出金额账单）
		if h.svc != nil {
			if err := h.svc.ValidatePlanPricing(&p); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
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
	switch r.Method {
	case http.MethodGet:
		h.handleGetSubscription(w, r)
	case http.MethodPost:
		h.handleBindSubscription(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 GET/POST")
	}
}

// handleGetSubscription GET /v1/adminext/billing/subscription（§4.3.2）：当前租户套餐查询。
//
// 角色：读端点（`billing_reader`/`auditor`/`admin`；`billing_reader` 未放行时退用 auditor）。
// 自助场景：`tenant` 缺省取令牌内 `tenant` 声明；非 admin 跨租户 → 403（§7.4，fail-closed）。
// 返回当前生效订阅（最新 `effective_at` 且未过期）；无绑定 → `subscription=null`。
func (h *billingHandler) handleGetSubscription(w http.ResponseWriter, r *http.Request) {
	if !requireReadAccess(w, r) {
		return
	}
	c := claimsFrom(r.Context())
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" && c != nil {
		tenant = c.Tenant // 自助：按 token 内租户
	}
	if !h.tenantAllowed(r, tenant) {
		writeError(w, http.StatusForbidden, "跨租户访问被拒绝")
		return
	}
	if tenant == "" {
		writeError(w, http.StatusBadRequest, "tenant 必填（自助会话需令牌内携带 tenant 声明）")
		return
	}
	now := time.Now().UnixNano()
	subs, err := h.store.Plans().ListSubscriptions(now)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "订阅查询失败")
		return
	}
	var cur *billing.Subscription
	for i := range subs {
		s := subs[i]
		if s.TenantID != tenant {
			continue
		}
		if s.ExpiresAt != 0 && s.ExpiresAt <= now {
			continue // 已过期
		}
		if cur == nil || s.EffectiveAt >= cur.EffectiveAt {
			cp := s
			cur = &cp
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tenant": tenant, "subscription": cur})
}

// handleBindSubscription POST /v1/adminext/billing/subscription（**admin**）：绑定/升降级。
func (h *billingHandler) handleBindSubscription(w http.ResponseWriter, r *http.Request) {
	start := time.Now() // ★ A-14：M6 计时起点（套餐变更**受理** → 回读确认）
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
	// 配额编译 + 下发 + 回读确认（P-1/M6：受理 → 回读确认 ≤ 60s）
	if updates, cerr := h.compiler.Compile(req.Tenant, plan); cerr != nil {
		log.Printf("[billing] 配额编译失败 tenant=%s: %v", req.Tenant, cerr)
	} else if h.applier != nil {
		if err := h.applier.ApplyQuota(r.Context(), updates); err != nil {
			log.Printf("[billing] quota apply failed tenant=%s: %v", req.Tenant, err)
		} else {
			// 2c 回读确认：POST 2xx ≠ 已生效；确认失败仅告警不回滚（TEE 已生效为准，§6.4.1）
			if rd, ok := h.applier.(billing.QuotaReader); ok {
				budget := h.quotaApplyBudget
				if budget <= 0 {
					budget = m6ApplyWithin
				}
				if err := billing.ConfirmQuotaApplied(r.Context(), rd, req.Tenant, updates,
					budget, m6ApplyPoll); err != nil {
					log.Printf("[billing] M6 配额生效未确认 tenant=%s: %v", req.Tenant, err)
				}
			}
			billing.ObserveQuotaApply(time.Since(start).Seconds()) // 指标 #13（M6）
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

// ---------- 完整性校验（手动触发） ----------

// handleVerifyChain 手动触发全量完整性校验：账本哈希链（S-6，§7.1.2）+ tee-infer 审计链
// （REC-6/B-6.12-4，§6.12.4）。
//
// 定位：调度器按 `verify_interval` 周期执行同一逻辑（`VerifyChainTask`）；本端点供运维/测试
// **即时**核对，断裂即置链标志并停出账（fail-closed）。返回账本断链位置（-1 = 完好）。
func (h *billingHandler) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
		return
	}
	if !requireRole(w, r, "admin") {
		return
	}
	if h.svc == nil {
		writeError(w, http.StatusServiceUnavailable, "计费服务未就绪")
		return
	}
	brokenAt, err := h.svc.VerifyLedgerChain()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	auditErr := h.svc.VerifyAuditChain(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"ledger_broken_at": brokenAt,      // -1 = 完好
		"ledger_broken":    brokenAt >= 0, // 已停出账（fail-closed）
		"audit_chain_ok":   auditErr == nil,
	})
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
