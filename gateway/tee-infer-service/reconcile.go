// reconcile.go - 审计-计量对账（S5；设计《GA-控制面限流与计量设计》§5/§8 判据 6）
//
// 口径：计量唯一真源 = tee-infer 审计链。内存用量计数器（usageRecord）与审计事件在
// **同一请求路径**内同步更新——reserveQuota 计输入、recordUsage 计输出与请求数、
// audit.append 落链——故二者**同源**，对账容差为 **0 token**（判据 6）。
// 聚合复用计费拉取的同一函数 aggregateUsage（口径单一，不引入第二套账）。
//
// **对账窗口 = [本进程启动时刻, now)**：usage 是内存态，重启即归零；若按累计口径对账，
// 任何一次重启都会造成"审计累计 > 用量累计"的**永久**差异（并据此永久阻断出账），
// 这是假阳性。故主对账只比对**本进程窗口内**的审计事件与用量计数（两侧都只反映本进程
// 活动，理应逐 token 相等）。链中早于启动时刻的事件作为**重启基线**在快照中如实暴露
// （restart_detected / events_before_start），供看板标注"累计视图口径差异"，**不阻断**。
//
// 差异分类（按**可判定信号**归类，不猜测原因）：
//
//	chain_broken   审计链断裂（截断/篡改）——verify() 失败 ⇒ 审计完整性不成立
//	multi_instance 链中出现异实例事件（instance_id ≠ 本实例）——多实例共写同一链
//	usage_reset    窗口内审计多于用量，且链中存在启动前事件（重启已发生）⇒ 重启期间计数丢失
//	               （含滚动重启时旧进程未标实例的事件）
//	audit_behind   用量多于审计 ⇒ 存在已计费但未落链的推理（审计写入失败/丢失）
//	unknown        其余偏差——如实标注，不归因
//
// 阻断对外出账（判据 6）：任一分类命中即置位 billingWebhook.blocked（暂停推送）；
// 计费侧由 from/to 拉取兜底——推送可丢可补，**阻断不丢账**；恢复一致后自动解除。
package main

import (
	"fmt"
	"log"
	"math"
	"sort"
	"sync"
	"time"
)

// reconcileInterval 定时对账周期。
const reconcileInterval = 5 * time.Minute

// 差异分类（reconcile_mismatch_total 的 reason 标签值）；"" = 一致。
const (
	reconcileReasonChainBroken   = "chain_broken"
	reconcileReasonMultiInstance = "multi_instance"
	reconcileReasonUsageReset    = "usage_reset"
	reconcileReasonAuditBehind   = "audit_behind"
	reconcileReasonUnknown       = "unknown"
)

// tenantDiff 单租户偏差（窗口内：审计 − 用量），仅记录不一致租户。
type tenantDiff struct {
	Tenant        string `json:"tenant"`
	AuditRequests int64  `json:"audit_requests"`
	UsageRequests int64  `json:"usage_requests"`
	AuditTokensIn int64  `json:"audit_tokens_in"`
	UsageTokensIn int64  `json:"usage_tokens_in"`
	DiffTokensIn  int64  `json:"diff_tokens_in"`
	DiffTokensOut int64  `json:"diff_tokens_out"`
	DiffRequests  int64  `json:"diff_requests"`
}

// reconcileStatus 对账快照（GET /reconcile 返回；控制面看板数据源）。
type reconcileStatus struct {
	OK              bool   `json:"ok"`
	Reason          string `json:"reason,omitempty"`
	ToleranceTokens int64  `json:"tolerance_tokens"` // 0（同源）
	InstanceID      string `json:"instance_id"`
	WindowStartAt   int64  `json:"window_start_at"` // 本进程启动时刻（UTC 纳秒）= 对账窗口起点
	ChainIntact     bool   `json:"chain_intact"`
	ChainBrokenAt   int    `json:"chain_broken_at,omitempty"`
	// 重启基线（信息项，不参与一致性判定、不阻断）
	RestartDetected   bool `json:"restart_detected"`
	EventsBeforeStart int  `json:"events_before_start"`
	// 窗口内口径
	AuditInferEvents int          `json:"audit_infer_events"`
	UsageRequests    int          `json:"usage_requests"`
	DiffTokensIn     int64        `json:"diff_tokens_in"`
	DiffTokensOut    int64        `json:"diff_tokens_out"`
	DiffRequests     int64        `json:"diff_requests"`
	Tenants          []tenantDiff `json:"tenants,omitempty"`
	ForeignInstances []string     `json:"foreign_instances,omitempty"`
	BillingBlocked   bool         `json:"billing_blocked"`
	LastRunAt        int64        `json:"last_run_at"` // UTC 纳秒
	Detail           string       `json:"detail,omitempty"`
}

// reconciler 对账器。usage/mu 与 teeServer 共享（同一把锁保护用量计数）。
type reconciler struct {
	audit     *auditChain
	usage     map[string]*usageRecord
	mu        *sync.Mutex
	metrics   *otpmaskMetrics
	billing   *billingWebhook
	startedAt int64 // 本进程启动时刻（UTC 纳秒），用于识别"重启导致的用量丢失"
	statusMu  sync.Mutex
	last      *reconcileStatus
}

func newReconciler(a *auditChain, usage map[string]*usageRecord, mu *sync.Mutex,
	m *otpmaskMetrics, b *billingWebhook, startedAt int64) *reconciler {
	return &reconciler{audit: a, usage: usage, mu: mu, metrics: m, billing: b, startedAt: startedAt}
}

// status 返回最近一次对账快照（未对账过 → nil）。
func (r *reconciler) status() *reconcileStatus {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	if r.last == nil {
		return nil
	}
	cp := *r.last
	return &cp
}

// setStatus 保存快照。
func (r *reconciler) setStatus(st reconcileStatus) {
	r.statusMu.Lock()
	r.last = &st
	r.statusMu.Unlock()
}

// usageTotals 用量侧三元组快照。
type usageTotals struct {
	in       int64
	out      int64
	requests int64
}

// reconcileOnce 执行一次对账；返回是否一致（窗口内容差 0）。
// 副作用：不一致时置位出账阻断并计数；恢复一致时解除阻断。
func (r *reconciler) reconcileOnce(now time.Time) bool {
	chainOK, brokenAt := r.audit.verify()
	events := r.audit.query("")
	// 与计费拉取同一聚合函数（同源口径）：仅统计 action=infer 的事件。
	// 主对账窗口 = [本进程启动时刻, now)；启动前事件单列（重启基线，不参与判定）。
	auditAgg := aggregateUsage(events, r.startedAt, math.MaxInt64)
	beforeAgg := aggregateUsage(events, 0, r.startedAt)
	beforeEvents := 0
	for _, inc := range beforeAgg {
		beforeEvents += inc.Requests
	}
	foreign := r.audit.foreignInstances(r.startedAt)

	r.mu.Lock()
	usageSide := make(map[string]usageTotals, len(r.usage))
	for t, rec := range r.usage {
		if rec == nil {
			continue
		}
		usageSide[t] = usageTotals{in: int64(rec.TokensIn), out: int64(rec.TokensOut), requests: int64(rec.Requests)}
	}
	r.mu.Unlock()

	tenants := make(map[string]bool, len(auditAgg)+len(usageSide))
	for t := range auditAgg {
		tenants[t] = true
	}
	for t := range usageSide {
		tenants[t] = true
	}
	names := make([]string, 0, len(tenants))
	for t := range tenants {
		names = append(names, t)
	}
	sort.Strings(names)

	st := reconcileStatus{
		ToleranceTokens:   0,
		InstanceID:        r.audit.instanceIDOf(),
		WindowStartAt:     r.startedAt,
		ChainIntact:       chainOK,
		ChainBrokenAt:     brokenAt,
		RestartDetected:   beforeEvents > 0,
		EventsBeforeStart: beforeEvents,
		ForeignInstances:  foreign,
		LastRunAt:         now.UnixNano(),
	}
	// S2-6：输出侧审查重启检测 gauge 置位（1=检测到启动前事件=发生过重启）
	if r.metrics != nil {
		if beforeEvents > 0 {
			r.metrics.setOGRestartDetected(1)
		} else {
			r.metrics.setOGRestartDetected(0)
		}
	}
	auditAhead, usageAhead := false, false
	for _, t := range names {
		var aIn, aOut, aReq int64
		if inc := auditAgg[t]; inc != nil {
			aIn, aOut, aReq = int64(inc.TokensIn), int64(inc.TokensOut), int64(inc.Requests)
		}
		u := usageSide[t]
		st.AuditInferEvents += int(aReq)
		st.UsageRequests += int(u.requests)
		dIn, dOut, dReq := aIn-u.in, aOut-u.out, aReq-u.requests
		st.DiffTokensIn += dIn
		st.DiffTokensOut += dOut
		st.DiffRequests += dReq
		if dIn == 0 && dOut == 0 && dReq == 0 {
			continue
		}
		if dIn > 0 || dOut > 0 || dReq > 0 {
			auditAhead = true
		}
		if dIn < 0 || dOut < 0 || dReq < 0 {
			usageAhead = true
		}
		st.Tenants = append(st.Tenants, tenantDiff{
			Tenant: t, AuditRequests: aReq, UsageRequests: u.requests,
			AuditTokensIn: aIn, UsageTokensIn: u.in,
			DiffTokensIn: dIn, DiffTokensOut: dOut, DiffRequests: dReq,
		})
	}

	if chainOK && len(st.Tenants) == 0 {
		st.OK = true
		if st.RestartDetected {
			st.Detail = fmt.Sprintf("窗口内一致；链中存在启动前事件 %d 条（重启基线，累计视图口径差异，不阻断）", beforeEvents)
		}
	} else {
		st.OK = false
		switch {
		case !chainOK:
			st.Reason = reconcileReasonChainBroken
			st.Detail = fmt.Sprintf("审计链在 #%d 处断裂（截断/篡改）：审计完整性不成立，出账不可信", brokenAt)
		case len(foreign) > 0:
			st.Reason = reconcileReasonMultiInstance
			st.Detail = fmt.Sprintf("审计链出现异实例事件 %v（多实例共写同一链）：用量计数器为各实例内存态，无法与本链对账", foreign)
		case auditAhead && !usageAhead && st.RestartDetected:
			st.Reason = reconcileReasonUsageReset
			st.Detail = fmt.Sprintf("窗口内审计多于用量且存在启动前事件 %d 条（重启已发生）⇒ 重启期间计数丢失（含滚动重启时旧进程未标实例的事件）", beforeEvents)
		case usageAhead && !auditAhead:
			st.Reason = reconcileReasonAuditBehind
			st.Detail = "用量多于审计：存在已计费但未落链的推理（审计写入失败/丢失）"
		default:
			st.Reason = reconcileReasonUnknown
			st.Detail = "偏差方向混合或无可判定信号：如实标注，不猜测归因（需人工核对 /audit 逐事件）"
		}
	}

	// 阻断联动 + 指标
	magnitude := abs64(st.DiffTokensIn) + abs64(st.DiffTokensOut)
	if st.OK {
		if r.billing.unblock() {
			log.Printf("[reconcile] 对账恢复一致（实例 %s）：解除对外出账阻断", st.InstanceID)
		}
		st.BillingBlocked = false
	} else {
		r.billing.block(st.Reason)
		st.BillingBlocked = true
		r.metrics.incReconcileMismatch(st.Reason, magnitude)
		log.Printf("[reconcile] 对账不一致 reason=%s 窗口[%s,+] 审计(infer=%d) 用量(requests=%d) 偏差(in=%d out=%d req=%d) 已阻断对外出账：%s",
			st.Reason, time.Unix(0, r.startedAt).UTC().Format(time.RFC3339), st.AuditInferEvents, st.UsageRequests,
			st.DiffTokensIn, st.DiffTokensOut, st.DiffRequests, st.Detail)
	}
	r.metrics.setReconcileRun(now.UnixNano(), st.BillingBlocked)
	r.setStatus(st)
	return st.OK
}

// abs64 绝对值。
func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

// run 定时对账：启动即跑一次（状态/阻断立即可见），随后按周期执行。
func (r *reconciler) run() {
	r.reconcileOnce(time.Now())
	ticker := time.NewTicker(reconcileInterval)
	defer ticker.Stop()
	for range ticker.C {
		r.reconcileOnce(time.Now())
	}
}
