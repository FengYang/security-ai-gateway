package main

// audit_canary_test.go — P1-7 T15（§7.10）：租户级灰度开关与一键回退的单元测试。
//
// 覆盖（验收判据「可灰度、可回退」的可机器复算部分；人工演练见 SOP）：
//   - 缺省档 all：所有租户落链，与未装配开关行为一致（零回归）；
//   - canary 档：仅名单内租户落链；名单外事件不构造哈希/不写 WORM/不进链，但**不报错**；
//   - off 档：租户归属事件不落链；**控制类事件（tenant 空/"-"）恒落链**（回退动作自身留痕）；
//   - 跨跳过点的哈希链连续性 + WORM 文件无空洞（load 恢复成功 ⇒ audit-verify 可复核）；
//   - 端点校验 fail-closed（canary 空名单 / 未知模式 → 400；未授权 → 403 且落链）；
//   - 开关变更自身落链（action=audit_canary_change，tenant="-"）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// canaryTestServer 构造带审计链的测试服务（管理令牌留空 = 开发模式不拦截；
// 需要验鉴权的用例自行设置 adminToken 与请求头）。
func canaryTestServer() *teeServer {
	return &teeServer{audit: newAuditChain(), metrics: newMetrics()}
}

// ① 缺省档 all：所有租户落链（零行为变化）。
func TestT15CanaryDefaultAll(t *testing.T) {
	c := newAuditChain()
	mode, tenants, skipped := c.CanarySnapshot()
	if mode != canaryAll || len(tenants) != 0 || skipped != 0 {
		t.Fatalf("缺省快照应为 all/空名单/0 跳过，实际 %q/%v/%d", mode, tenants, skipped)
	}
	for _, tn := range []string{"t1", "t2", "_unauthenticated"} {
		c.append(AuditEvent{TenantID: tn, Action: "infer", Result: "ok"})
	}
	if len(c.events) != 3 {
		t.Fatalf("all 档应全部落链，实际 %d", len(c.events))
	}
}

// ② canary 档：仅名单内租户落链；名单外不落链、不报错、计数递增。
func TestT15CanaryListFiltersTenants(t *testing.T) {
	c := newAuditChain()
	if err := c.SetCanary("canary", "t1, t2"); err != nil {
		t.Fatalf("SetCanary(canary) 失败: %v", err)
	}
	// 名单内：落链。
	c.append(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"})
	c.append(AuditEvent{TenantID: "t2", Action: "infer", Result: "ok"})
	// 名单外：跳过（无 error、无链上事件）。
	c.append(AuditEvent{TenantID: "t9", Action: "infer", Result: "ok"})
	c.append(AuditEvent{TenantID: "_unauthenticated", Action: "request", Result: "ok"})
	// 控制类：恒落链（任何档位）。
	c.append(AuditEvent{TenantID: "-", Action: "output_guard_policy_reload", Result: "applied"})
	c.append(AuditEvent{TenantID: "", Action: "audit_anchor", Result: "ok"})

	if len(c.events) != 4 {
		t.Fatalf("期望落链 4 条（t1/t2/-/空租户），实际 %d", len(c.events))
	}
	mode, tenants, skipped := c.CanarySnapshot()
	if mode != canaryList || len(tenants) != 2 || skipped != 2 {
		t.Fatalf("快照不符: mode=%q tenants=%v skipped=%d", mode, tenants, skipped)
	}
	// 跳过事件不得携带哈希链字段（从未入链：PrevHash 与 EventID 均应为空）。
	ev := c.append(AuditEvent{TenantID: "t9", Action: "infer", Result: "ok"})
	if ev.PrevHash != "" || ev.EventID != "" {
		t.Fatalf("跳过事件不应被构造链字段: prev=%q event_id=%q", ev.PrevHash, ev.EventID)
	}
}

// ③ off 档：租户归属事件不落链；控制类事件仍落链。
func TestT15CanaryOffSkipsTenantEvents(t *testing.T) {
	c := newAuditChain()
	if err := c.SetCanary("off", ""); err != nil {
		t.Fatalf("SetCanary(off) 失败: %v", err)
	}
	c.append(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"})
	c.append(AuditEvent{TenantID: "_unauthenticated", Action: "request", Result: "ok"})
	c.append(AuditEvent{TenantID: "-", Action: "audit_canary_change", Result: "ok"})
	c.append(AuditEvent{TenantID: "", Action: "audit_anchor", Result: "ok"})
	if len(c.events) != 2 {
		t.Fatalf("off 档应仅落链 2 条控制类事件，实际 %d", len(c.events))
	}
	for _, ev := range c.events {
		if ev.TenantID != "-" && ev.TenantID != "" {
			t.Fatalf("off 档落链了租户事件: %q", ev.TenantID)
		}
	}
}

// ④ 跨跳过点的哈希链连续性 + WORM 文件无空洞（load 成功 ⇒ 可被 audit-verify 复核）。
func TestT15CanaryChainContinuityAcrossSkips(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/audit.jsonl"
	c, err := newAuditChainWORM(path, "")
	if err != nil {
		t.Fatalf("构造 WORM 链失败: %v", err)
	}
	defer func() { _ = c.Close() }()
	if err := c.SetCanary("canary", "t1"); err != nil {
		t.Fatalf("SetCanary 失败: %v", err)
	}
	seq := []string{"t1", "t9", "t1", "t9", "t1"} // 交替：名单内落链、名单外跳过
	for _, tn := range seq {
		c.append(AuditEvent{TenantID: tn, Action: "infer", Result: "ok"})
	}
	if len(c.events) != 3 {
		t.Fatalf("期望落链 3 条（t1×3），实际 %d", len(c.events))
	}
	// 链连续：每条 prev_hash 指向上一条已落链事件。
	for i := 1; i < len(c.events); i++ {
		if c.events[i].PrevHash != c.events[i-1].hash() {
			t.Fatalf("第 %d 条链断裂（跳过后未续接）", i)
		}
	}
	// WORM 文件行数 = 已落链事件数（无空洞）；重新 load 成功（verify 前提）。
	c2, err := newAuditChainWORM(path, "")
	if err != nil {
		t.Fatalf("WORM 文件重新 load 失败（文件可能含空洞/断裂）: %v", err)
	}
	defer func() { _ = c2.Close() }()
	if len(c2.events) != 3 {
		t.Fatalf("load 恢复事件数=%d, want 3", len(c2.events))
	}
	if ok, bad := c2.verify(); !ok {
		t.Fatalf("load 后 verify 未通过（第 %d 条断裂）", bad)
	}
}

// ⑤ 端点 PUT：切换成功并把变更自身落链（tenant="-" ⇒ off 档下回退动作仍有留痕）。
func TestT15CanaryEndpointPutChainsChange(t *testing.T) {
	s := canaryTestServer()
	// 先落一条业务事件（t1），再切 off。
	s.audit.append(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"})

	body := `{"mode":"off"}`
	r := httptest.NewRequest(http.MethodPut, "/audit/canary", strings.NewReader(body))
	r.Header.Set("X-Admin-Actor", "alice")
	r.Header.Set("X-Request-ID", "rid-canary-1")
	w := httptest.NewRecorder()
	s.handleAuditCanary(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT /audit/canary 应 200，实际 %d: %s", w.Code, w.Body.String())
	}
	var view canaryView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatalf("响应体解析失败: %v", err)
	}
	if view.Mode != "off" {
		t.Fatalf("切换后模式应为 off，实际 %q", view.Mode)
	}
	// 变更事件落链（off 档下控制类事件仍落链 ⇒ 回退动作可追溯）。
	last := s.audit.events[len(s.audit.events)-1]
	if last.Action != "audit_canary_change" || last.TenantID != "-" ||
		last.UserID != "alice" || last.RequestID != "rid-canary-1" {
		t.Fatalf("开关变更事件未按控制类口径落链: %+v", last)
	}
	// off 档生效：后续租户事件被跳过。
	s.audit.append(AuditEvent{TenantID: "t1", Action: "infer", Result: "ok"})
	if len(s.audit.events) != 2 {
		t.Fatalf("off 档应跳过后续租户事件，链长=%d", len(s.audit.events))
	}
}

// ⑥ 端点校验 fail-closed：canary 空名单 / 未知模式 → 400 且落链；未授权 → 403。
func TestT15CanaryEndpointValidation(t *testing.T) {
	// canary 空名单拒绝（状态不变）。
	s := canaryTestServer()
	r := httptest.NewRequest(http.MethodPut, "/audit/canary", strings.NewReader(`{"mode":"canary","tenants":[]}`))
	w := httptest.NewRecorder()
	s.handleAuditCanary(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("canary 空名单应 400，实际 %d", w.Code)
	}
	if mode, _, _ := s.audit.CanarySnapshot(); mode != canaryAll {
		t.Fatalf("拒绝后模式应保持 all，实际 %q", mode)
	}
	// 未知模式拒绝。
	r = httptest.NewRequest(http.MethodPut, "/audit/canary", strings.NewReader(`{"mode":"gray"}`))
	w = httptest.NewRecorder()
	s.handleAuditCanary(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未知模式应 400，实际 %d", w.Code)
	}
	// 拒绝事件均落链（tenant="-"）。
	if n := countByActionResult(s.audit, "audit_canary_change", "rejected_bad_request"); n != 2 {
		t.Fatalf("拒绝应落链 2 条，实际 %d", n)
	}

	// 未授权（配置管理令牌且缺头）→ 403 且落链。
	s2 := canaryTestServer()
	s2.adminToken = "secret-tok"
	r = httptest.NewRequest(http.MethodGet, "/audit/canary", nil)
	w = httptest.NewRecorder()
	s2.handleAuditCanary(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("未授权应 403，实际 %d", w.Code)
	}
	if n := countByActionResult(s2.audit, "audit_canary_change", "rejected_forbidden"); n != 1 {
		t.Fatalf("未授权应落链 1 条，实际 %d", n)
	}
	// 持令牌可达。
	r = httptest.NewRequest(http.MethodGet, "/audit/canary", nil)
	r.Header.Set(adminHeader, "secret-tok")
	w = httptest.NewRecorder()
	s2.handleAuditCanary(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("持令牌应 200，实际 %d", w.Code)
	}
}

// ⑦ 运行时来回切换 all→canary→off→all，每档语义正确。
func TestT15CanaryRuntimeSwitchBackAndForth(t *testing.T) {
	c := newAuditChain()
	switchTo := func(mode, tenants string) {
		t.Helper()
		if err := c.SetCanary(mode, tenants); err != nil {
			t.Fatalf("SetCanary(%q,%q) 失败: %v", mode, tenants, err)
		}
	}
	countFor := func(tn string) int {
		n := 0
		for _, ev := range c.events {
			if ev.TenantID == tn {
				n++
			}
		}
		return n
	}
	switchTo("all", "")
	c.append(AuditEvent{TenantID: "t1", Action: "infer"}) // 落链
	switchTo("canary", "t1")
	c.append(AuditEvent{TenantID: "t1", Action: "infer"}) // 落链（名单内）
	c.append(AuditEvent{TenantID: "t2", Action: "infer"}) // 跳过
	switchTo("off", "")
	c.append(AuditEvent{TenantID: "t1", Action: "infer"}) // 跳过
	switchTo("all", "")
	c.append(AuditEvent{TenantID: "t1", Action: "infer"}) // 恢复落链

	if got := countFor("t1"); got != 3 {
		t.Fatalf("t1 应落链 3 条（all/canary/all 各 1），实际 %d", got)
	}
	if got := countFor("t2"); got != 0 {
		t.Fatalf("t2 应 0 条，实际 %d", got)
	}
	if _, _, skipped := c.CanarySnapshot(); skipped != 2 {
		t.Fatalf("累计跳过应为 2（canary 档 t2 + off 档 t1），实际 %d", skipped)
	}
}

// ⑧ SetCanary 校验：模式字面量非法 / canary 空名单 → 拒绝且不改现状态。
func TestT15CanarySetValidation(t *testing.T) {
	c := newAuditChain()
	if err := c.SetCanary("canary", ""); err == nil {
		t.Fatal("canary 空名单应被拒绝")
	}
	if err := c.SetCanary("gray", ""); err == nil {
		t.Fatal("未知模式应被拒绝")
	}
	if mode, _, _ := c.CanarySnapshot(); mode != canaryAll {
		t.Fatalf("拒绝后状态应保持 all，实际 %q", mode)
	}
	// 合法：all / off 允许空名单；canary 要求非空。
	for _, tc := range []struct{ mode, tenants string }{
		{"all", ""}, {"off", ""}, {"canary", "t1"}, {"", ""},
	} {
		if err := c.SetCanary(tc.mode, tc.tenants); err != nil {
			t.Fatalf("SetCanary(%q,%q) 应成功: %v", tc.mode, tc.tenants, err)
		}
	}
	if mode, _, _ := c.CanarySnapshot(); mode != canaryAll {
		t.Fatalf("空串模式应归一化为 all，实际 %q", mode)
	}
}

// ⑨ 灰度跳过计数挂钩到 /metrics（otpmask_audit_canary_skipped_total）。
func TestT15CanarySkipMetric(t *testing.T) {
	s := canaryTestServer()
	s.audit.SetCanarySkipHook(func() { s.metrics.incAuditCanarySkipped() })
	if err := s.audit.SetCanary("off", ""); err != nil {
		t.Fatalf("SetCanary(off) 失败: %v", err)
	}
	s.audit.append(AuditEvent{TenantID: "t1", Action: "infer"})
	s.audit.append(AuditEvent{TenantID: "t2", Action: "infer"})
	if s.metrics.auditCanarySkipped != 2 {
		t.Fatalf("metrics 跳过计数=%d, want 2", s.metrics.auditCanarySkipped)
	}
	w := httptest.NewRecorder()
	s.metrics.render(w, s.audit.len())
	if !strings.Contains(w.Body.String(), "otpmask_audit_canary_skipped_total 2") {
		t.Fatal("/metrics 未暴露 otpmask_audit_canary_skipped_total")
	}
}

// ⑩ GET 快照含 note（SOP 口径随快照返回，避免文档与实现漂移）。
func TestT15CanaryGetViewNote(t *testing.T) {
	s := canaryTestServer()
	r := httptest.NewRequest(http.MethodGet, "/audit/canary", nil)
	w := httptest.NewRecorder()
	s.handleAuditCanary(w, r)
	var view canaryView
	if err := json.Unmarshal(w.Body.Bytes(), &view); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if view.Mode != "all" || view.Note == "" {
		t.Fatalf("GET 快照缺 mode/note: %+v", view)
	}
}
