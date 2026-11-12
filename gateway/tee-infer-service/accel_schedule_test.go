package main

// accel_schedule_test.go — M5-2 动态调度单测（hint 优先级 / 校验 / 管理端点 / 审计）。

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func testAccelScheduler(candidates ...string) *accelScheduler {
	s := &accelScheduler{candidates: map[string]bool{}, candidateLs: append([]string(nil), candidates...)}
	for _, c := range candidates {
		s.candidates[c] = true
	}
	s.cur.Store(&accelRouteTable{routes: map[string]string{}, raw: []accelRoute{}})
	return s
}

func testServer(s *accelScheduler, token string) *teeServer {
	return &teeServer{accelSched: s, adminToken: token}
}

// TestM52HintPriority 判据：按请求/租户/模型优先级解析 hint（请求级仅接受受信 key）。
func TestM52HintPriority(t *testing.T) {
	const soA, soB = "/opt/accel/libaccel_a.so", "/opt/accel/libaccel_b.so"
	s := testAccelScheduler(soA, soB)
	_, err := s.SetRoutes([]accelRoute{
		{Tenant: "acme", Model: "m1", Backend: soB}, // 精确
		{Tenant: "acme", Model: "*", Backend: soA},  // 租户通配
		{Tenant: "*", Model: "m2", Backend: soB},    // 模型通配
		{Tenant: "*", Model: "*", Backend: soA},     // 全局通配
	})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ tenant, model, reqHint, want string }{
		{"acme", "m1", "", soB},          // 精确优先
		{"acme", "mX", "", soA},          // 租户通配
		{"other", "m2", "", soB},         // 模型通配
		{"other", "mX", "", soA},         // 全局通配
		{"acme", "m1", soA, soA},         // 请求级覆盖（受信）
		{"acme", "m1", "/tmp/evil", soB}, // 非受信请求 hint 忽略，回落精确规则
	}
	for _, c := range cases {
		if got := s.HintFor(c.tenant, c.model, c.reqHint); got != c.want {
			t.Errorf("HintFor(%s,%s,%s)=%q，want %q", c.tenant, c.model, c.reqHint, got, c.want)
		}
	}
}

// TestM52RouteValidation 非法规则 fail-closed 拒绝，保持旧表；变更落审计。
func TestM52RouteValidation(t *testing.T) {
	const soA = "/opt/accel/libaccel_a.so"
	var events []string
	s := testAccelScheduler(soA)
	s.onAudit = func(action, result, detail string) { events = append(events, action+"/"+result) }
	v0, err := s.SetRoutes([]accelRoute{{Tenant: "*", Model: "*", Backend: soA}})
	if err != nil {
		t.Fatal(err)
	}
	bads := [][]accelRoute{
		{{Tenant: "t", Model: "m", Backend: "/tmp/evil.so"}},                               // 非受信 key
		{{Tenant: "", Model: "m", Backend: soA}},                                           // 空 tenant
		{{Tenant: "t", Model: "", Backend: soA}},                                           // 空 model
		{{Tenant: "t", Model: "m", Backend: soA}, {Tenant: "t", Model: "m", Backend: soA}}, // 重复
	}
	for i, b := range bads {
		if _, err := s.SetRoutes(b); err == nil {
			t.Errorf("负例 %d 应拒绝", i)
		}
	}
	if s.cur.Load().version != v0 {
		t.Fatal("失败换入不应改变表版本（旧表保持）")
	}
	v1, err := s.SetRoutes([]accelRoute{{Tenant: "acme", Model: "m", Backend: ""}})
	if err != nil || v1 == v0 {
		t.Fatalf("合法空表/新规则应换入并改版本: v=%s err=%v", v1, err)
	}
	if len(events) < 6 {
		t.Fatalf("变更与拒绝均应落审计，got %v", events)
	}
}

// TestM52AdminEndpoints 管理端点：鉴权、路由表读写、切换拒绝非受信 key、审计留痕。
func TestM52AdminEndpoints(t *testing.T) {
	const soA = "/opt/accel/libaccel_a.so"
	s := testAccelScheduler(soA)
	var events []string
	s.onAudit = func(action, result, detail string) { events = append(events, action+"/"+result) }
	srv := testServer(s, "secret")

	// 无令牌 → 401。
	w := httptest.NewRecorder()
	srv.handleAccelConfig(w, httptest.NewRequest(http.MethodGet, "/config/accel", nil))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("无管理令牌 status=%d，want 401", w.Code)
	}
	// 有令牌 → 快照 200。
	w = httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/config/accel", nil)
	r.Header.Set(adminHeader, "secret")
	srv.handleAccelConfig(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("快照 status=%d", w.Code)
	}
	var snap map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &snap); err != nil || snap["candidates"] == nil {
		t.Fatalf("快照格式异常: %s", w.Body.String())
	}
	// POST 路由表（合法）→ applied。
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/config/accel/routes",
		strings.NewReader(`{"routes":[{"tenant":"acme","model":"m","backend":"/opt/accel/libaccel_a.so"}]}`))
	r.Header.Set(adminHeader, "secret")
	srv.handleAccelRoutes(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "applied") {
		t.Fatalf("路由表换入失败: %d %s", w.Code, w.Body.String())
	}
	if got := s.HintFor("acme", "m", ""); got != soA {
		t.Fatalf("换入后 HintFor=%q，want %q", got, soA)
	}
	// POST 非法路由表 → 400 且旧表保持。
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/config/accel/routes",
		strings.NewReader(`{"routes":[{"tenant":"x","model":"y","backend":"/tmp/evil.so"}]}`))
	r.Header.Set(adminHeader, "secret")
	srv.handleAccelRoutes(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非法路由表应 400，got %d", w.Code)
	}
	// POST switch 非受信 key → 400（不进入引擎）。
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodPost, "/config/accel/switch",
		strings.NewReader(`{"backend":"/tmp/evil.so"}`))
	r.Header.Set(adminHeader, "secret")
	srv.handleAccelSwitch(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("非受信切换应 400，got %d: %s", w.Code, w.Body.String())
	}
	if len(events) < 2 {
		t.Fatalf("拒绝/放行事件均应留痕，got %v", events)
	}
}
