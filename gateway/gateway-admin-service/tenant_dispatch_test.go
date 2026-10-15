package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------- 测试辅助 ----------

// fakeDispatchApplier 可编程下发通道（测试注入）。
type fakeDispatchApplier struct {
	mu     sync.Mutex
	calls  int
	cur    int
	maxCur int
	plans  []*DispatchPlan

	applyFn func(call int, plan *DispatchPlan) (int64, error)
	block   chan struct{}
	entered chan struct{}
}

func (f *fakeDispatchApplier) Apply(_ context.Context, plan *DispatchPlan) (int64, error) {
	f.mu.Lock()
	f.calls++
	n := f.calls
	f.cur++
	if f.cur > f.maxCur {
		f.maxCur = f.cur
	}
	f.plans = append(f.plans, plan)
	fn := f.applyFn
	block := f.block
	entered := f.entered
	f.mu.Unlock()

	if entered != nil {
		select {
		case entered <- struct{}{}:
		default:
		}
	}
	if block != nil {
		<-block
	}

	var res int64
	var err error
	if fn != nil {
		res, err = fn(n, plan)
	}
	f.mu.Lock()
	f.cur--
	f.mu.Unlock()
	return res, err
}

func (f *fakeDispatchApplier) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// newTestDispatcher 构造无退避、无 sleep 的调度器（测试避免真实等待）。
func newTestDispatcher(store *sqliteTenantStore, applier dispatchApplier) *dispatcher {
	d := newDispatcher(store, applier)
	d.sleep = func(time.Duration) {}
	d.backoff = []time.Duration{0, 0, 0}
	return d
}

// bump 同事务推进表 ⑩ 版本。
func bump(t *testing.T, store *sqliteTenantStore, tenantID string) {
	t.Helper()
	tx, err := store.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := store.BumpDispatchVersion(tx, tenantID, time.Now().Unix()); err != nil {
		t.Fatalf("bump: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

// ---------- BuildDispatch（纯函数）----------

func TestBuildDispatch_TargetsAndNoPlaintext(t *testing.T) {
	chain, _ := marshalPluginSet([]pluginEntry{{Name: "ai-proxy", Order: 1}})
	in := DispatchInput{
		TenantID:      "t_1",
		ConfigVersion: 3,
		Provisioning: &TenantProvisioning{
			TenantID: "t_1", Scenario: scenarioS2, TrustTier: trustTierTrusted,
			AccessMode: accessModeASegmented, PluginSetJSON: chain, Segment1Enabled: true,
			Segment2Mode: segment2VendorSDK, TemplateVersion: pluginTemplateVersion,
		},
		Keys: []*APIKey{
			{KeyID: "k-1", TenantID: "t_1", Name: "prod", JTI: "jti-1", Status: apiKeyStatusActive, ExpiresAt: 999},
			{KeyID: "k-2", TenantID: "t_1", Name: "old", JTI: "jti-2", Status: apiKeyStatusRevoked},
		},
		Policy: &PolicyOverlay{TenantID: "t_1", Version: 2, WhitelistJSON: `{"entries":[]}`, BlacklistJSON: `{"entries":[]}`, CategoryActionsJSON: `{}`},
		Models: &ModelConfig{TenantID: "t_1", AllowedModelsJSON: `["qwen-max"]`, DefaultModel: "qwen-max", Version: 1},
		Quota:  &dispatchQuota{PlanID: "pro", MonthlyTokens: 100, Concurrency: 10, CacheTier: "semantic"},
	}
	plan, err := BuildDispatch(in)
	if err != nil {
		t.Fatalf("BuildDispatch: %v", err)
	}
	if plan.ConfigVersion != 3 || plan.TenantID != "t_1" {
		t.Errorf("plan 头不对: %+v", plan)
	}
	kinds := map[string]bool{}
	for _, tg := range plan.Targets {
		kinds[tg.Kind] = true
	}
	for _, want := range []string{dispatchTargetWasmPlugin, dispatchTargetConsumerCredentials,
		dispatchTargetConsumerQuota, dispatchTargetPrescription} {
		if !kinds[want] {
			t.Errorf("缺目标类型 %s: %+v", want, kinds)
		}
	}
	// 吊销 Key 不应出现在凭证目标中；且不得含任何明文指纹/密钥字段
	raw, _ := json.Marshal(plan)
	if strings.Contains(string(raw), "jti-2") {
		t.Error("吊销 Key 不应下发")
	}
	for _, banned := range []string{"fingerprint", "\"api_key\"", "secret"} {
		if strings.Contains(string(raw), banned) {
			t.Errorf("下发计划不应含 %q: %s", banned, raw)
		}
	}
}

func TestBuildDispatch_NoProvisioning_OnlyPrescription(t *testing.T) {
	plan, err := BuildDispatch(DispatchInput{TenantID: "t_x", ConfigVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Targets) != 1 || plan.Targets[0].Kind != dispatchTargetPrescription {
		t.Fatalf("无开通配置时仅应有处方目标: %+v", plan.Targets)
	}
}

// ---------- 状态机 ----------

func TestDispatchStateMachine_Applied(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "d1@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)

	bump(t, store, tid)
	d.Enqueue(tid)
	d.Wait()

	st, _ := store.GetDispatchState(tid)
	if st == nil {
		t.Fatal("状态行应存在")
	}
	if st.Status != dispatchStatusApplied || st.ConfigVersion != 1 || st.AppliedVersion != 1 {
		t.Errorf("状态机应 pending→applied: %+v", st)
	}
	if applier.callCount() != 1 {
		t.Errorf("应下发 1 次, got=%d", applier.callCount())
	}
	if applier.plans[0].ConfigVersion != 1 {
		t.Errorf("计划版本不对: %d", applier.plans[0].ConfigVersion)
	}
}

func TestDispatchVersionMonotonic(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "d2@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	bump(t, store, tid)
	bump(t, store, tid)
	st, _ := store.GetDispatchState(tid)
	if st.ConfigVersion != 2 || st.Status != dispatchStatusPending {
		t.Errorf("config_version 应单调递增且 pending: %+v", st)
	}
}

// ---------- C-20 fail-closed：失败保留旧版 ----------

func TestDispatch_FailureKeepsOldVersion(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "d3@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	// 先成功下发 v1，建立"旧版生效配置"
	ok := &fakeDispatchApplier{}
	d1 := newTestDispatcher(store, ok)
	bump(t, store, tid)
	d1.Enqueue(tid)
	d1.Wait()
	if st, _ := store.GetDispatchState(tid); st.AppliedVersion != 1 {
		t.Fatalf("前置：应已生效 v1: %+v", st)
	}

	// 再写一次，下发失败（拒接）→ 保留 v1
	bad := &fakeDispatchApplier{applyFn: func(int, *DispatchPlan) (int64, error) {
		return 0, &dispatchApplyError{Class: "rejected", Status: 403}
	}}
	d2 := newTestDispatcher(store, bad)
	var alarmKind string
	d2.alarm = func(_, kind, _ string) { alarmKind = kind }
	bump(t, store, tid) // config_version=2
	d2.Enqueue(tid)
	d2.Wait()

	st, _ := store.GetDispatchState(tid)
	if st.Status != dispatchStatusFailed {
		t.Errorf("失败应置 failed: %+v", st)
	}
	if st.AppliedVersion != 1 {
		t.Errorf("C-20：失败须保留旧版 applied_version=1, got=%d", st.AppliedVersion)
	}
	if st.ConfigVersion != 2 {
		t.Errorf("config_version 应为 2, got=%d", st.ConfigVersion)
	}
	if !strings.Contains(st.LastError, "rejected") || !strings.Contains(st.LastError, "403") {
		t.Errorf("last_error 应为脱敏分类: %q", st.LastError)
	}
	if st.RetryCount != 3 {
		t.Errorf("重试计数应为 3, got=%d", st.RetryCount)
	}
	if bad.callCount() != 4 {
		t.Errorf("应尝试 1+3 次, got=%d", bad.callCount())
	}
	if alarmKind != "dispatch_failed" {
		t.Errorf("应触发 dispatch_failed 告警, got=%q", alarmKind)
	}
}

func TestDispatch_RetryThenSuccess(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "d4@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	applier := &fakeDispatchApplier{applyFn: func(call int, plan *DispatchPlan) (int64, error) {
		if call < 3 {
			return 0, &dispatchApplyError{Class: "timeout"}
		}
		return plan.ConfigVersion, nil
	}}
	d := newTestDispatcher(store, applier)
	bump(t, store, tid)
	d.Enqueue(tid)
	d.Wait()
	st, _ := store.GetDispatchState(tid)
	if st.Status != dispatchStatusApplied || st.AppliedVersion != 1 {
		t.Errorf("重试后应成功: %+v", st)
	}
	if applier.callCount() != 3 {
		t.Errorf("应第 3 次成功, got=%d", applier.callCount())
	}
}

// TestDispatch_FaultInjection 故障注入（gateway-core 拒接/超时/返回非预期）→ 保留旧版 + failed。
func TestDispatch_FaultInjection(t *testing.T) {
	cases := []struct {
		name string
		err  error
		key  string
	}{
		{"拒接", &dispatchApplyError{Class: "rejected", Status: 503}, "rejected"},
		{"超时", &dispatchApplyError{Class: "timeout"}, "timeout"},
		{"非预期", &dispatchApplyError{Class: "unexpected", Status: 500}, "unexpected"},
		{"不可达", &dispatchApplyError{Class: "unreachable"}, "unreachable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := newTestStore(t)
			tid, _ := seedTenantUser(t, store, "fx"+c.key+"@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
			applier := &fakeDispatchApplier{applyFn: func(int, *DispatchPlan) (int64, error) { return 0, c.err }}
			d := newTestDispatcher(store, applier)
			bump(t, store, tid)
			d.Enqueue(tid)
			d.Wait()
			st, _ := store.GetDispatchState(tid)
			if st.Status != dispatchStatusFailed || st.AppliedVersion != 0 {
				t.Errorf("%s：应 failed 且未生效: %+v", c.name, st)
			}
			if !strings.Contains(st.LastError, c.key) {
				t.Errorf("%s：last_error=%q 应含 %q", c.name, st.LastError, c.key)
			}
		})
	}
}

// TestDispatch_DriftAlarm 数据面回执版本落后 → 漂移告警且以数据面版本为准（C-20）。
func TestDispatch_DriftAlarm(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "d5@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	applier := &fakeDispatchApplier{applyFn: func(_ int, plan *DispatchPlan) (int64, error) {
		return plan.ConfigVersion - 1, nil // 仅部分生效（回执落后一版）
	}}
	d := newTestDispatcher(store, applier)
	var alarmKind, alarmDetail string
	d.alarm = func(_, kind, detail string) { alarmKind, alarmDetail = kind, detail }
	bump(t, store, tid) // v1
	bump(t, store, tid) // v2
	d.Enqueue(tid)
	d.Wait()
	st, _ := store.GetDispatchState(tid)
	if st.AppliedVersion != 1 || st.ConfigVersion != 2 {
		t.Errorf("漂移时应以数据面版本为准: %+v", st)
	}
	if alarmKind != "version_drift" {
		t.Errorf("应触发 version_drift 告警, got=%q", alarmKind)
	}
	if !strings.Contains(alarmDetail, "config=2") {
		t.Errorf("告警明细应含版本, got=%q", alarmDetail)
	}
}

// ---------- 重启重放 / 幂等 ----------

func TestDispatch_ReplayIdempotent(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "d6@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	bump(t, store, tid)
	d.Enqueue(tid)
	d.Wait()
	if applier.callCount() != 1 {
		t.Fatalf("首次应 1 次, got=%d", applier.callCount())
	}
	// 已 applied：重放/重复入队不再调用（幂等，不产生重复副作用）
	if n, err := d.ReplayPending(); err != nil || n != 0 {
		t.Errorf("已 applied 重放数应为 0, got=%d err=%v", n, err)
	}
	d.Enqueue(tid)
	d.Wait()
	if applier.callCount() != 1 {
		t.Errorf("重复入队不应再下发, got=%d", applier.callCount())
	}
}

func TestDispatch_RestartReplay(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "d7@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	// 模拟崩溃：config_version=1、status=applying（未完成）
	bump(t, store, tid)
	tx, _ := store.Begin()
	if err := store.MarkDispatchApplying(tx, tid, time.Now().Unix()); err != nil {
		t.Fatal(err)
	}
	_ = tx.Commit()

	// 重启：扫描 pending/applying 重放
	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	n, err := d.ReplayPending()
	if err != nil || n != 1 {
		t.Fatalf("重启重放应命中 1, got=%d err=%v", n, err)
	}
	d.Wait()
	st, _ := store.GetDispatchState(tid)
	if st.Status != dispatchStatusApplied || st.AppliedVersion != 1 {
		t.Errorf("重放后应 applied: %+v", st)
	}
	if applier.plans[0].ConfigVersion != 1 {
		t.Errorf("重放应携带原 config_version: %d", applier.plans[0].ConfigVersion)
	}
}

// ---------- 每租户单飞 ----------

func TestDispatch_SingleFlightPerTenant(t *testing.T) {
	store := newTestStore(t)
	tid, _ := seedTenantUser(t, store, "d8@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	block := make(chan struct{})
	entered := make(chan struct{}, 1)
	applier := &fakeDispatchApplier{block: block, entered: entered}
	d := newTestDispatcher(store, applier)

	bump(t, store, tid) // v1
	d.Enqueue(tid)
	<-entered // 首次已进入 Apply 并阻塞

	// 执行期间连续触发（含新版本）→ 合并为一次重跑
	bump(t, store, tid) // v2
	bump(t, store, tid) // v3
	d.Enqueue(tid)
	d.Enqueue(tid)

	close(block)
	d.Wait()

	if applier.maxCur != 1 {
		t.Errorf("每租户须单飞（并发上限 1）, got=%d", applier.maxCur)
	}
	st, _ := store.GetDispatchState(tid)
	if st.Status != dispatchStatusApplied || st.AppliedVersion != 3 || st.ConfigVersion != 3 {
		t.Errorf("最终应收敛到 v3: %+v", st)
	}
}

// ---------- 端点 ----------

func TestDispatchStatus_Endpoint(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "d9@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)

	// 未建行 → idle
	w := httptest.NewRecorder()
	h.handleDispatchStatus(w, tenantRequest("GET", tenantDispatchStatusPath, "", tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var v dispatchStatusView
	json.NewDecoder(w.Body).Decode(&v)
	if v.Status != dispatchStatusIdle || v.Drift {
		t.Errorf("默认应为 idle 无漂移: %+v", v)
	}

	// 建行后
	bump(t, store, tid)
	w2 := httptest.NewRecorder()
	h.handleDispatchStatus(w2, tenantRequest("GET", tenantDispatchStatusPath, "", tid, "u1"))
	var v2 dispatchStatusView
	json.NewDecoder(w2.Body).Decode(&v2)
	if v2.ConfigVersion != 1 || v2.Status != dispatchStatusPending || !v2.Drift {
		t.Errorf("应为 pending + 漂移: %+v", v2)
	}
}

func TestDispatchStatus_NoScope_403(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	// 无租户上下文（未过中间件）
	req := httptest.NewRequest("GET", tenantDispatchStatusPath, nil)
	w := httptest.NewRecorder()
	h.handleDispatchStatus(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("无租户作用域应 403, got=%d", w.Code)
	}
}

func TestDispatchReplay_AdminOnly(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "d10@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	applier := &fakeDispatchApplier{}
	d := newTestDispatcher(store, applier)
	h.dispatch = d

	// 非 admin → 403
	w := httptest.NewRecorder()
	h.handleDispatchReplay(w, tenantRequest("POST", tenantDispatchReplayPath, `{"reason":"manual"}`, tid, "u1"))
	if w.Code != http.StatusForbidden {
		t.Fatalf("非 admin 应 403, got=%d", w.Code)
	}

	// admin 接管 + reason → 200 并入队
	bump(t, store, tid)
	w2 := httptest.NewRecorder()
	h.handleDispatchReplay(w2, adminTakeoverRequest("POST", tenantDispatchReplayPath, `{"reason":"运维手动重放"}`, tid, "alice"))
	if w2.Code != http.StatusOK {
		t.Fatalf("admin 重放应 200, got=%d body=%s", w2.Code, w2.Body.String())
	}
	d.Wait()
	if applier.callCount() != 1 {
		t.Errorf("重放应触发一次下发, got=%d", applier.callCount())
	}
}

func TestDispatchReplay_RequiresReason(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "d11@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	h.dispatch = newTestDispatcher(store, &fakeDispatchApplier{})
	w := httptest.NewRecorder()
	h.handleDispatchReplay(w, adminTakeoverRequest("POST", tenantDispatchReplayPath, `{"reason":""}`, tid, "alice"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("缺 reason 应 400, got=%d", w.Code)
	}
}

func TestDispatchReplay_Audit(t *testing.T) {
	h, store, auditFile := newAuditTestHandler(t)
	tid, _ := seedTenantUser(t, store, "d12@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	d := newTestDispatcher(store, &fakeDispatchApplier{})
	h.dispatch = d
	bump(t, store, tid)

	w := httptest.NewRecorder()
	h.handleDispatchReplay(w, adminTakeoverRequest("POST", tenantDispatchReplayPath, `{"reason":"drill"}`, tid, "alice"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	d.Wait()
	body := readAudit(t, auditFile)
	if !strings.Contains(body, auditActionDispatchReplay) {
		t.Errorf("应落 %s 审计:\n%s", auditActionDispatchReplay, body)
	}
	if !strings.Contains(body, "config_version=1") {
		t.Errorf("审计应记录 config_version:\n%s", body)
	}
}

// ---------- 写路径挂接 ----------

func TestWritePaths_BumpDispatchVersion(t *testing.T) {
	provisionBody := `{"scenario":"s1","trust_tier":"trusted"}`
	policyBody := `{"whitelist":{"entries":[{"id":"e-1","kind":"literal","value":"x"}]},"blacklist":{"entries":[]},"category_actions":{}}`

	cases := []struct {
		name  string
		write func(t *testing.T, h *tenantHandler, tid string)
	}{
		{"provisioning", func(t *testing.T, h *tenantHandler, tid string) {
			w := httptest.NewRecorder()
			h.handleTenantProvisioningPut(w, tenantRequest("PUT", tenantProvisioningPath, provisionBody, tid, "u1"))
			if w.Code != http.StatusOK {
				t.Fatalf("开通应 200, got=%d body=%s", w.Code, w.Body.String())
			}
		}},
		{"policy", func(t *testing.T, h *tenantHandler, tid string) {
			w := httptest.NewRecorder()
			req := tenantRequest("PUT", tenantPolicyPath, policyBody, tid, "u1")
			req.Header.Set("If-Match", "0")
			h.handleTenantPolicyPut(w, req)
			if w.Code != http.StatusOK {
				t.Fatalf("策略应 200, got=%d body=%s", w.Code, w.Body.String())
			}
		}},
		{"key_create", func(t *testing.T, h *tenantHandler, tid string) {
			h.issuer = &fakeKeyIssuer{}
			w := httptest.NewRecorder()
			h.handleKeyCreate(w, tenantRequest("POST", apiKeysPath, `{"name":"prod"}`, tid, "u1"))
			if w.Code != http.StatusOK {
				t.Fatalf("建 Key 应 200, got=%d body=%s", w.Code, w.Body.String())
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
			tid, _ := seedTenantUser(t, store, c.name+"@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
			applier := &fakeDispatchApplier{}
			d := newTestDispatcher(store, applier)
			h.dispatch = d
			h.effects.bumpDispatchVersion = d.BumpInTx
			h.effects.enqueueDispatch = d.Enqueue

			c.write(t, h, tid)
			d.Wait()

			st, _ := store.GetDispatchState(tid)
			if st == nil || st.ConfigVersion != 1 {
				t.Fatalf("%s：应同事务 config_version=1, got=%+v", c.name, st)
			}
			if st.Status != dispatchStatusApplied || applier.callCount() != 1 {
				t.Errorf("%s：应下发生效一次, st=%+v calls=%d", c.name, st, applier.callCount())
			}
		})
	}
}

// ---------- 脱敏 ----------

func TestSanitizeDispatchError(t *testing.T) {
	s := sanitizeDispatchError(&dispatchApplyError{Class: "rejected", Status: 403})
	if s != "rejected(status=403)" {
		t.Errorf("分类串不对: %q", s)
	}
	long := strings.Repeat("x", 500) + "\n" + strings.Repeat("y", 500)
	s2 := sanitizeDispatchError(errors.New(long))
	if len(s2) > dispatchMaxErrorLen {
		t.Errorf("应截断到 %d, got=%d", dispatchMaxErrorLen, len(s2))
	}
	if strings.ContainsAny(s2, "\n\r") {
		t.Errorf("不得含换行: %q", s2)
	}
}

// ---------- HTTP 下发通道 ----------

func TestHTTPDispatchApplier_OK(t *testing.T) {
	var gotAuth, gotRoute string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotRoute = r.Header.Get("X-Otp-Route")
		if r.URL.Path != dispatchPrescriptionPath {
			t.Errorf("路径不对: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"applied_version":7}`))
	}))
	defer srv.Close()

	a := newHTTPDispatchApplier(srv.URL, "tok-1", time.Second)
	if a == nil {
		t.Fatal("applier 不应为 nil")
	}
	v, err := a.Apply(context.Background(), &DispatchPlan{TenantID: "t_1", ConfigVersion: 7})
	if err != nil || v != 7 {
		t.Fatalf("应返回 7, got=%d err=%v", v, err)
	}
	if gotAuth != "Bearer tok-1" {
		t.Errorf("Authorization 不对: %q", gotAuth)
	}
	if gotRoute != "tenant/t_1" {
		t.Errorf("X-Otp-Route 不对: %q", gotRoute)
	}
}

func TestHTTPDispatchApplier_Rejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 伪造内部令牌被拒
	}))
	defer srv.Close()
	a := newHTTPDispatchApplier(srv.URL, "tok", time.Second)
	_, err := a.Apply(context.Background(), &DispatchPlan{TenantID: "t_1", ConfigVersion: 1})
	var ae *dispatchApplyError
	if !errors.As(err, &ae) || ae.Class != "rejected" || ae.Status != 403 {
		t.Fatalf("应分类 rejected(403), got=%v", err)
	}
}

func TestHTTPDispatchApplier_Timeout(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		<-block
	}))
	defer func() { close(block); srv.Close() }()
	a := newHTTPDispatchApplier(srv.URL, "tok", 30*time.Millisecond)
	_, err := a.Apply(context.Background(), &DispatchPlan{TenantID: "t_1", ConfigVersion: 1})
	var ae *dispatchApplyError
	if !errors.As(err, &ae) || ae.Class != "timeout" {
		t.Fatalf("应分类 timeout, got=%v", err)
	}
}

func TestHTTPDispatchApplier_Unconfigured(t *testing.T) {
	if newHTTPDispatchApplier("", "tok", time.Second) != nil {
		t.Error("空 baseURL 应返回 nil")
	}
	a := &httpDispatchApplier{}
	_, err := a.Apply(context.Background(), &DispatchPlan{})
	var ae *dispatchApplyError
	if !errors.As(err, &ae) || ae.Class != "channel_unconfigured" {
		t.Fatalf("应分类 channel_unconfigured, got=%v", err)
	}
}

func TestHTTPDispatchApplier_NoToken(t *testing.T) {
	a := newHTTPDispatchApplier("http://127.0.0.1:1", "", time.Second)
	_, err := a.Apply(context.Background(), &DispatchPlan{TenantID: "t_1"})
	var ae *dispatchApplyError
	if !errors.As(err, &ae) || ae.Class != "unauthorized" {
		t.Fatalf("缺内部服务令牌应 fail-closed（unauthorized）, got=%v", err)
	}
}

// ---------- 补充：错误分类与端点兜底 ----------

func TestDispatchApplyError_Error(t *testing.T) {
	withStatus := (&dispatchApplyError{Class: "rejected", Status: 403, Msg: "denied"}).Error()
	if !strings.Contains(withStatus, "rejected") || !strings.Contains(withStatus, "status=403") {
		t.Errorf("含状态码的 Error() 不对: %q", withStatus)
	}
	noStatus := (&dispatchApplyError{Class: "unreachable", Msg: "dial fail"}).Error()
	if !strings.Contains(noStatus, "unreachable") || strings.Contains(noStatus, "status=") {
		t.Errorf("无状态码的 Error() 不对: %q", noStatus)
	}
}

func TestBuildDispatch_InvalidPluginSet(t *testing.T) {
	_, err := BuildDispatch(DispatchInput{
		TenantID:      "t_bad",
		ConfigVersion: 1,
		Provisioning:  &TenantProvisioning{TenantID: "t_bad", PluginSetJSON: "{not-json"},
	})
	if err == nil {
		t.Fatal("非法 plugin_set 应报错")
	}
}

func TestModelsPrescription_EmptyAllowed(t *testing.T) {
	m := modelsPrescription(&ModelConfig{TenantID: "t_1", DefaultModel: "qwen-max"})
	allowed, ok := m["allowed_models"].([]string)
	if !ok || allowed == nil || len(allowed) != 0 {
		t.Errorf("空允许清单应归一为非 nil 空切片: %#v", m["allowed_models"])
	}
}

func TestDispatchReplay_NoScope_403(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	req := httptest.NewRequest("POST", tenantDispatchReplayPath, strings.NewReader(`{"reason":"x"}`))
	w := httptest.NewRecorder()
	h.handleDispatchReplay(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("无租户作用域应 403, got=%d", w.Code)
	}
}

func TestDispatchReplay_NilDispatcher_503(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "d13@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	if h.dispatch != nil {
		t.Fatal("前置：默认 handler 不应配置 dispatch")
	}
	w := httptest.NewRecorder()
	h.handleDispatchReplay(w, adminTakeoverRequest("POST", tenantDispatchReplayPath, `{"reason":"x"}`, tid, "alice"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("下发通道未就绪应 503, got=%d", w.Code)
	}
}

func TestDispatchReplay_BadJSON_400(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "d14@example.com", "Password123!", tenantUserStatusActive, tenantStatusPending)
	h.dispatch = newTestDispatcher(store, &fakeDispatchApplier{})
	w := httptest.NewRecorder()
	h.handleDispatchReplay(w, adminTakeoverRequest("POST", tenantDispatchReplayPath, `{`, tid, "alice"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法请求体应 400, got=%d", w.Code)
	}
}
