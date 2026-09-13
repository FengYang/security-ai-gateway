// reconcile_test.go - S5（判据 6）审计-计量对账测试：
// 窗口口径一致性、差异分类（重启/截断/多实例/用量多于审计）、出账阻断与恢复解阻断、
// 以及 /reconcile 与 /reconcile/run 端点契约。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// newTestWebhook 起本地 mock 计费接收端，返回推送器与"已收到推送数"读取函数。
func newTestWebhook(t *testing.T) (*billingWebhook, func() int) {
	t.Helper()
	var n int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&n, 1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(ts.Close)
	return newBillingWebhook(ts.URL, ""), func() int { return int(atomic.LoadInt64(&n)) }
}

// inferEvent 构造计费口径的 infer 事件。
func inferEvent(id, tenant string, in, out int) AuditEvent {
	return AuditEvent{EventID: id, TenantID: tenant, RequestID: id, Action: "infer",
		Result: "ok", TokensIn: in, TokensOut: out}
}

// injectRecoveredEvent 直接注入一条"上一次进程写入、由 WORM 恢复"的链上事件
// （时间戳显式取 1 小时前），用于构造重启基线——不依赖系统时钟粒度。
func injectRecoveredEvent(a *auditChain, ev AuditEvent) {
	ev.Timestamp = time.Now().Add(-time.Hour).UnixNano()
	a.mu.Lock()
	ev.PrevHash = a.lastHex
	a.events = append(a.events, ev)
	a.lastHex = ev.hash()
	a.mu.Unlock()
}

// TestReconcileWindowConsistentWithRestartBaseline 窗口内一致 → ok；
// 链中启动前事件只作重启基线（不阻断），推送不受影响。
func TestReconcileWindowConsistentWithRestartBaseline(t *testing.T) {
	audit := newAuditChain()
	usage := map[string]*usageRecord{}
	m := newMetrics()
	wh, received := newTestWebhook(t)
	wh.metrics = m

	// 上一次进程写入的事件（窗口之外，WORM 恢复语义）
	injectRecoveredEvent(audit, inferEvent("old", "t1", 5, 7))
	startedAt := time.Now().UnixNano() // 本进程窗口起点
	rec := newReconciler(audit, usage, &audit.mu, m, wh, startedAt)

	// 窗口内：审计 1 条 infer，用量同口径
	audit.append(inferEvent("new1", "t1", 3, 4))
	usage["t1"] = &usageRecord{TokensIn: 3, TokensOut: 4, Requests: 1}

	if !rec.reconcileOnce(time.Now()) {
		t.Fatalf("窗口内一致应返回 true：%+v", rec.status())
	}
	st := rec.status()
	if !st.OK || st.Reason != "" || st.BillingBlocked {
		t.Fatalf("快照不符: %+v", st)
	}
	if !st.RestartDetected || st.EventsBeforeStart != 1 {
		t.Fatalf("重启基线应被识别且不参与判定: %+v", st)
	}
	if st.AuditInferEvents != 1 || st.UsageRequests != 1 ||
		st.DiffTokensIn != 0 || st.DiffTokensOut != 0 || st.DiffRequests != 0 {
		t.Fatalf("窗口口径不符: %+v", st)
	}
	if st.ToleranceTokens != 0 || st.ChainIntact != true || st.WindowStartAt != startedAt {
		t.Fatalf("基础字段不符: %+v", st)
	}
	// 一致时推送正常（未被抑制）
	wh.notify(inferEvent("e1", "t1", 1, 1))
	if received() != 1 || m.billingSuppressed[reconcileReasonUsageReset] != 0 {
		t.Fatalf("一致时不应抑制推送：received=%d suppressed=%+v", received(), m.billingSuppressed)
	}
}

// TestReconcileUsageResetBlockedThenUnblocked 窗口内审计多于用量且已发生重启
// → usage_reset + 阻断出账（推送被抑制）；补齐用量后自动解阻断。
func TestReconcileUsageResetBlockedThenUnblocked(t *testing.T) {
	audit := newAuditChain()
	usage := map[string]*usageRecord{}
	m := newMetrics()
	wh, received := newTestWebhook(t)
	wh.metrics = m

	injectRecoveredEvent(audit, inferEvent("old", "t1", 1, 1)) // 重启基线
	startedAt := time.Now().UnixNano()
	rec := newReconciler(audit, usage, &audit.mu, m, wh, startedAt)
	audit.append(inferEvent("new1", "t1", 3, 4)) // 窗口内事件
	// 用量计数丢失（重启期间未累计）

	if rec.reconcileOnce(time.Now()) {
		t.Fatal("存在偏差应返回 false")
	}
	st := rec.status()
	if st.OK || st.Reason != reconcileReasonUsageReset || !st.BillingBlocked {
		t.Fatalf("应分类 usage_reset 并阻断: %+v", st)
	}
	if st.DiffTokensIn != 3 || st.DiffTokensOut != 4 || st.DiffRequests != 1 {
		t.Fatalf("偏差量不符: %+v", st)
	}
	if m.reconcile[reconcileReasonUsageReset] != 1 || m.billingBlocked != 1 {
		t.Fatalf("指标不符: mismatch=%+v blocked=%d", m.reconcile, m.billingBlocked)
	}
	// 阻断期间推送被抑制
	wh.notify(inferEvent("sup", "t1", 1, 1))
	if received() != 0 || m.billingSuppressed[reconcileReasonUsageReset] != 1 {
		t.Fatalf("阻断期间应抑制推送：received=%d suppressed=%+v", received(), m.billingSuppressed)
	}
	// 补齐用量 → 恢复一致 → 解阻断 + 恢复推送
	usage["t1"] = &usageRecord{TokensIn: 3, TokensOut: 4, Requests: 1}
	if !rec.reconcileOnce(time.Now()) {
		t.Fatal("补齐后应一致")
	}
	if wh.blocked() || rec.status().BillingBlocked || m.billingBlocked != 0 {
		t.Fatalf("应解除阻断: %+v", rec.status())
	}
	wh.notify(inferEvent("resumed", "t1", 1, 1))
	if received() != 1 {
		t.Fatalf("解阻断后应恢复推送：received=%d", received())
	}
}

// TestReconcileAuditBehindBlocked 用量多于窗口内审计（计费未落链）→ audit_behind + 阻断。
func TestReconcileAuditBehindBlocked(t *testing.T) {
	audit := newAuditChain()
	usage := map[string]*usageRecord{}
	m := newMetrics()
	wh, _ := newTestWebhook(t)
	wh.metrics = m
	rec := newReconciler(audit, usage, &audit.mu, m, wh, time.Now().UnixNano())

	audit.append(inferEvent("only", "t1", 1, 1)) // 窗口内仅 1 条
	usage["t1"] = &usageRecord{TokensIn: 2, TokensOut: 2, Requests: 2}

	if rec.reconcileOnce(time.Now()) {
		t.Fatal("用量多于审计应返回 false")
	}
	st := rec.status()
	if st.Reason != reconcileReasonAuditBehind || !st.BillingBlocked {
		t.Fatalf("应分类 audit_behind 并阻断: %+v", st)
	}
	if st.DiffTokensIn != -1 || st.DiffRequests != -1 {
		t.Fatalf("偏差方向不符: %+v", st)
	}
}

// TestReconcileMultiInstanceBlocked 窗口内出现异实例事件（多实例共写）→ multi_instance + 阻断。
func TestReconcileMultiInstanceBlocked(t *testing.T) {
	audit := newAuditChain()
	usage := map[string]*usageRecord{}
	m := newMetrics()
	wh, _ := newTestWebhook(t)
	wh.metrics = m
	rec := newReconciler(audit, usage, &audit.mu, m, wh, time.Now().UnixNano())

	ev := inferEvent("foreign", "t1", 2, 2)
	ev.InstanceID = "inst-other" // 异实例写入
	audit.append(ev)

	if rec.reconcileOnce(time.Now()) {
		t.Fatal("异实例共写应返回 false")
	}
	st := rec.status()
	if st.Reason != reconcileReasonMultiInstance || !st.BillingBlocked {
		t.Fatalf("应分类 multi_instance 并阻断: %+v", st)
	}
	if len(st.ForeignInstances) != 1 || st.ForeignInstances[0] != "inst-other" {
		t.Fatalf("异实例清单不符: %+v", st.ForeignInstances)
	}
}

// TestReconcileChainBrokenBlocked 审计链断裂（截断/篡改）→ chain_broken + 阻断。
func TestReconcileChainBrokenBlocked(t *testing.T) {
	audit := newAuditChain()
	usage := map[string]*usageRecord{}
	m := newMetrics()
	wh, _ := newTestWebhook(t)
	wh.metrics = m
	rec := newReconciler(audit, usage, &audit.mu, m, wh, time.Now().UnixNano())

	audit.append(inferEvent("a", "t1", 1, 1))
	audit.append(inferEvent("b", "t1", 1, 1))
	usage["t1"] = &usageRecord{TokensIn: 2, TokensOut: 2, Requests: 2}
	if !rec.reconcileOnce(time.Now()) {
		t.Fatal("未被篡改时应一致")
	}

	// 篡改历史行 → 链断裂
	audit.events[0].PayloadSHA = "tampered"
	if rec.reconcileOnce(time.Now()) {
		t.Fatal("链断裂应返回 false")
	}
	st := rec.status()
	if st.Reason != reconcileReasonChainBroken || st.ChainIntact || !st.BillingBlocked {
		t.Fatalf("应分类 chain_broken 并阻断: %+v", st)
	}
	if st.ChainBrokenAt != 1 {
		t.Fatalf("断裂位置不符: %+v", st)
	}
}

// TestReconcileEndpoints /reconcile（只读）与 /reconcile/run（管理令牌）契约。
func TestReconcileEndpoints(t *testing.T) {
	srv, _ := newM9Server(t)

	// 对账器未启动 → 503
	rec := httptest.NewRecorder()
	srv.handleReconcile(rec, httptest.NewRequest(http.MethodGet, "/reconcile", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("未启动对账器应 503，got %d", rec.Code)
	}
	// 非 GET → 405
	srv.reconciler = newReconciler(srv.audit, srv.usage, &srv.mu, srv.metrics, nil, time.Now().UnixNano())
	rec = httptest.NewRecorder()
	srv.handleReconcile(rec, httptest.NewRequest(http.MethodPost, "/reconcile", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET 应 405，got %d", rec.Code)
	}

	// 一致快照 → 200 + 契约字段
	rec = httptest.NewRecorder()
	srv.handleReconcile(rec, httptest.NewRequest(http.MethodGet, "/reconcile", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("未对账时应 503，got %d", rec.Code)
	}
	if !srv.reconciler.reconcileOnce(time.Now()) {
		t.Fatal("空链空用量应一致")
	}
	req := httptest.NewRequest(http.MethodGet, "/reconcile", nil)
	rec = httptest.NewRecorder()
	srv.handleReconcile(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /reconcile 应 200，got %d（body=%s）", rec.Code, rec.Body.String())
	}
	var st reconcileStatus
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("快照解析失败: %v", err)
	}
	if !st.OK || st.ToleranceTokens != 0 || st.BillingBlocked || st.InstanceID == "" {
		t.Fatalf("快照契约不符: %+v", st)
	}

	// 鉴权：配置管理令牌后无令牌 → 401（/reconcile 只读端点同样受保护）
	srv.adminToken = "admin-tok"
	rec = httptest.NewRecorder()
	srv.handleReconcile(rec, httptest.NewRequest(http.MethodGet, "/reconcile", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("缺令牌应 401，got %d", rec.Code)
	}
	// 计量只读令牌可通过（与 /usage 一致）
	srv.meterToken = "meter-tok"
	req = httptest.NewRequest(http.MethodGet, "/reconcile", nil)
	req.Header.Set(adminHeader, "meter-tok")
	rec = httptest.NewRecorder()
	srv.handleReconcile(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("计量令牌应可读，got %d", rec.Code)
	}

	// /reconcile/run：POST 即时对账
	req = httptest.NewRequest(http.MethodPost, "/reconcile/run", nil)
	req.Header.Set(adminHeader, "admin-tok")
	rec = httptest.NewRecorder()
	srv.handleReconcileRun(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /reconcile/run 应 200，got %d（body=%s）", rec.Code, rec.Body.String())
	}
	var out struct {
		OK     bool             `json:"ok"`
		Status *reconcileStatus `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("即时对账响应解析失败: %v", err)
	}
	if !out.OK || out.Status == nil || !out.Status.OK {
		t.Fatalf("即时对账结果不符: %+v", out)
	}
}
