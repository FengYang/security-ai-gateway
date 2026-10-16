// Package main — N3 · 远程证明状态与度量看板单测（§4.3.3，V-S4）。
//
// 覆盖：状态推导与「未闭环不得绿色」（capable 强制）、降级语义（源不可达/未接线 → unknown +
// 各 item 同值 + 场景目录 + 强制披露，C-19）、HTTP 状态源（正常/非 200/坏 JSON/超时/不可达/
// 未配置/非法 URL）、租户端点与路由注册。
package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeAttestSource 可注入的证明状态源（nil 值 = 未接线由 handler 另行覆盖）。
type fakeAttestSource struct {
	items []attestItem
	err   error
}

func (f *fakeAttestSource) FetchAttestStatus(context.Context) ([]attestItem, error) {
	return f.items, f.err
}

// ---------- 组装与降级（纯函数）----------

func TestAssembleAttestView_Unreachable(t *testing.T) {
	boom := errors.New("dial tcp 127.0.0.1:19191: connection refused")
	cases := []struct {
		scenario string
		want     []string
	}{
		{scenarioS1, nil}, // S1 明文路径：无证明项
		{scenarioS2, []string{"vendor_tee", "cmaas_attest"}}, // S2 厂商侧证明 + 我方锚点
		{scenarioS3a, []string{"tee-infer"}},
		{scenarioS3b, []string{"tee-infer"}},
		{scenarioS4, []string{"tee-infer"}},
	}
	for _, c := range cases {
		t.Run(c.scenario, func(t *testing.T) {
			v := assembleAttestView(c.scenario, "t_1", 7, nil, boom)
			if v.Overall != attestStatusUnknown || v.Capable {
				t.Fatalf("不可达应 overall=unknown 且 capable=false（C-19）: %+v", v)
			}
			if len(v.Items) != len(c.want) {
				t.Fatalf("应按场景目录渲染 %d 项, got=%d: %+v", len(c.want), len(v.Items), v.Items)
			}
			for i, it := range v.Items {
				if it.Component != c.want[i] {
					t.Errorf("item[%d] 组件应=%s, got=%s", i, c.want[i], it.Component)
				}
				if it.Status != attestStatusUnknown || it.ClosedLoop || it.Capable {
					t.Errorf("降级 item 应全 unknown/未闭环/不可用: %+v", it)
				}
				if !strings.Contains(it.Note, "未闭环") {
					t.Errorf("降级 item 必须强制披露未闭环: %q", it.Note)
				}
			}
		})
	}
}

func TestAssembleAttestView_ClosedLoopEnforcement(t *testing.T) {
	// 全部 verified 且闭环 → 整体 verified、可绿。
	ok := []attestItem{{Component: "tee-infer", Status: attestStatusVerified, ClosedLoop: true}}
	v := assembleAttestView(scenarioS3a, "t_1", 1, ok, nil)
	if v.Overall != attestStatusVerified || !v.Capable || !v.Items[0].Capable {
		t.Errorf("全闭环 verified 应整体可绿: %+v", v)
	}

	// verified 但未闭环（如 S2 厂商百炼未接入）→ 整体 unverified、组件不可绿、强制披露。
	open := []attestItem{{Component: "vendor_tee", Status: attestStatusVerified, ClosedLoop: false,
		Note: "厂商证明未闭环（百炼未接入）"}}
	v2 := assembleAttestView(scenarioS2, "t_1", 1, open, nil)
	if v2.Overall != attestStatusUnverified || v2.Capable || v2.Items[0].Capable {
		t.Errorf("未闭环不得整体/组件可绿（C-19）: %+v", v2)
	}
	if !strings.Contains(v2.Items[0].Note, "未闭环") {
		t.Errorf("未闭环须保留披露: %q", v2.Items[0].Note)
	}

	// verified 但未闭环且无 note → 后端强制补披露文案（不依赖 UI）。
	openNoNote := []attestItem{{Component: "vendor_tee", Status: attestStatusVerified, ClosedLoop: false}}
	v3 := assembleAttestView(scenarioS2, "t_1", 1, openNoNote, nil)
	if !strings.Contains(v3.Items[0].Note, "不构成已具备能力") {
		t.Errorf("缺 note 时后端应强制补 C-19 披露: %q", v3.Items[0].Note)
	}

	// mock_signed → 整体 mock_signed、不可绿。
	mock := []attestItem{{Component: "tee-infer", Status: attestStatusMockSigned, ClosedLoop: false}}
	v4 := assembleAttestView(scenarioS3a, "t_1", 1, mock, nil)
	if v4.Overall != attestStatusMockSigned || v4.Capable || v4.Items[0].Capable {
		t.Errorf("mock 自签应整体 mock_signed 且不可绿: %+v", v4)
	}

	// 未识别状态值 → 归一化为 unknown（fail-closed，不得误判为已验证）。
	weird := []attestItem{{Component: "tee-infer", Status: "weird_value", ClosedLoop: true}}
	v5 := assembleAttestView(scenarioS3a, "t_1", 1, weird, nil)
	if v5.Overall != attestStatusUnknown || v5.Items[0].Capable {
		t.Errorf("未知状态应归一化 unknown 且不可绿: %+v", v5)
	}

	// 源可用但无 item（如 S1 无证明）→ unverified（不得绿色），items 为空数组。
	v6 := assembleAttestView(scenarioS1, "t_1", 1, nil, nil)
	if v6.Overall != attestStatusUnverified || v6.Capable || len(v6.Items) != 0 {
		t.Errorf("无证明项应 unverified 且不可绿: %+v", v6)
	}
}

func TestDeriveAttestOverall(t *testing.T) {
	cases := []struct {
		name  string
		items []attestItem
		want  string
	}{
		{"空 → unverified", nil, attestStatusUnverified},
		{"全闭环 verified", []attestItem{
			{Status: attestStatusVerified, ClosedLoop: true},
			{Status: attestStatusVerified, ClosedLoop: true},
		}, attestStatusVerified},
		{"unknown 最谨慎优先", []attestItem{
			{Status: attestStatusVerified, ClosedLoop: true},
			{Status: attestStatusUnknown},
		}, attestStatusUnknown},
		{"mock 优先于 unverified", []attestItem{
			{Status: attestStatusUnverified},
			{Status: attestStatusMockSigned},
		}, attestStatusMockSigned},
		{"未闭环判 unverified", []attestItem{
			{Status: attestStatusVerified, ClosedLoop: false},
		}, attestStatusUnverified},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := deriveAttestOverall(c.items); got != c.want {
				t.Errorf("want=%s got=%s", c.want, got)
			}
		})
	}
}

func TestNormalizeAttestStatus(t *testing.T) {
	cases := map[string]string{
		"verified": attestStatusVerified, "VERIFIED": attestStatusVerified,
		" unverified ": attestStatusUnverified, "mock_signed": attestStatusMockSigned,
		"unknown": attestStatusUnknown, "": attestStatusUnknown, "bogus": attestStatusUnknown,
	}
	for in, want := range cases {
		if got := normalizeAttestStatus(in); got != want {
			t.Errorf("normalize(%q)=%s, want=%s", in, got, want)
		}
	}
}

// ---------- 租户端点 ----------

func TestHandleTenantAttest_Endpoint(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "n3a@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, store, tid, scenarioS2, trustTierUntrusted)
	h.attest = &fakeAttestSource{items: []attestItem{
		{Component: "vendor_tee", Status: attestStatusMockSigned, ClosedLoop: false},
		{Component: "cmaas_attest", Status: attestStatusVerified, ClosedLoop: true},
	}}

	w := httptest.NewRecorder()
	h.handleTenantAttest(w, tenantRequest("GET", tenantAttestPath, "", tid, "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var v attestView
	if err := json.NewDecoder(w.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Tenant != tid || v.Overall != attestStatusMockSigned || v.Capable {
		t.Errorf("mock 自签应整体 mock_signed 且不可绿: %+v", v)
	}
	if len(v.Items) != 2 {
		t.Fatalf("应 2 项: %+v", v.Items)
	}

	// 无租户作用域 → 403（fail-closed）。
	w2 := httptest.NewRecorder()
	h.handleTenantAttest(w2, httptest.NewRequest("GET", tenantAttestPath, nil))
	if w2.Code != http.StatusForbidden {
		t.Errorf("无作用域应 403, got=%d", w2.Code)
	}
}

func TestHandleTenantAttest_Degraded(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tid, _ := seedTenantUser(t, store, "n3b@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, store, tid, scenarioS3a, trustTierTrusted)

	// 源报错 → unknown + tee-infer 同值 unknown + 强制未闭环。
	h.attest = &fakeAttestSource{err: errors.New("timeout")}
	w := httptest.NewRecorder()
	h.handleTenantAttest(w, tenantRequest("GET", tenantAttestPath, "", tid, "u1"))
	var v attestView
	if err := json.NewDecoder(w.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Overall != attestStatusUnknown || v.Capable || len(v.Items) != 1 ||
		v.Items[0].Component != "tee-infer" || !strings.Contains(v.Items[0].Note, "未闭环") {
		t.Errorf("源错误应降级 unknown + 目录项 + 强制披露: %+v", v)
	}

	// 未接线（nil 源）→ 同样降级 unknown。
	h.attest = nil
	w2 := httptest.NewRecorder()
	h.handleTenantAttest(w2, tenantRequest("GET", tenantAttestPath, "", tid, "u1"))
	var v2 attestView
	if err := json.NewDecoder(w2.Body).Decode(&v2); err != nil {
		t.Fatal(err)
	}
	if v2.Overall != attestStatusUnknown || v2.Capable {
		t.Errorf("未接线应降级 unknown: %+v", v2)
	}
}

func TestHandleTenantAttest_StoreErrorStillServes(t *testing.T) {
	base := newTestStore(t)
	h := newTenantHandler(&errTenantStore{TenantStore: base, provisioningErr: errors.New("boom")},
		testTenantCfg(), nil, nil, nil, nil, nil)
	h.attest = &fakeAttestSource{items: []attestItem{{Component: "tee-infer", Status: attestStatusVerified, ClosedLoop: true}}}

	w := httptest.NewRecorder()
	h.handleTenantAttest(w, tenantRequest("GET", tenantAttestPath, "", "t_x", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("读配置失败不应阻断面板（源可用）: got=%d", w.Code)
	}
	var v attestView
	if err := json.NewDecoder(w.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.Overall != attestStatusVerified {
		t.Errorf("源可用应正常返回 verified: %+v", v)
	}
}

func TestRegisterTenantAttestMux(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	mux := http.NewServeMux()
	h.registerTenantAttestMux(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", tenantAttestPath, nil))
	if w.Code != http.StatusUnauthorized {
		t.Errorf("无令牌应 401, got=%d", w.Code)
	}
}

// ---------- HTTP 状态源 ----------

func TestNewHTTPAttestStatusSource(t *testing.T) {
	if newHTTPAttestStatusSource("", "tok", time.Second) != nil {
		t.Error("空 baseURL 应返回 nil（未接线）")
	}
	s := newHTTPAttestStatusSource("http://attest-verify:19191/", "", 0)
	if s == nil || strings.HasSuffix(s.baseURL, "/") {
		t.Errorf("baseURL 应去除尾斜杠: %+v", s)
	}
	if s.client.Timeout != attestFetchTimeout {
		t.Errorf("超时应回退缺省 %s, got=%s", attestFetchTimeout, s.client.Timeout)
	}
}

func TestHTTPAttestStatusSource_Fetch(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"items":[{"component":"tee-infer","status":"verified","closed_loop":true},` +
			`{"component":"cmaas_attest","status":"mock_signed","closed_loop":false,"note":"mock 自签"}]}`))
	}))
	defer srv.Close()

	s := newHTTPAttestStatusSource(srv.URL, "tok-1", time.Second)
	items, err := s.FetchAttestStatus(context.Background())
	if err != nil {
		t.Fatalf("拉取失败: %v", err)
	}
	if gotAuth != "Bearer tok-1" || gotPath != attestStatusPath {
		t.Errorf("应携带令牌并请求 %s: auth=%q path=%q", attestStatusPath, gotAuth, gotPath)
	}
	if len(items) != 2 || items[0].Component != "tee-infer" || items[1].Status != attestStatusMockSigned {
		t.Errorf("解析结果不符: %+v", items)
	}
}

func TestHTTPAttestStatusSource_Errors(t *testing.T) {
	ctx := context.Background()

	// nil / 未配置 → error（触发降级）。
	var nilSrc *httpAttestStatusSource
	if _, err := nilSrc.FetchAttestStatus(ctx); err == nil {
		t.Error("nil 源应报错")
	}
	if _, err := (&httpAttestStatusSource{}).FetchAttestStatus(ctx); err == nil {
		t.Error("未配置 baseURL 应报错")
	}

	// 非法 URL → 构造请求失败。
	if _, err := (&httpAttestStatusSource{baseURL: "http://%zz"}).FetchAttestStatus(ctx); err == nil {
		t.Error("非法 URL 应报错")
	}

	// 非 200 → error。
	srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv500.Close()
	if _, err := newHTTPAttestStatusSource(srv500.URL, "", time.Second).FetchAttestStatus(ctx); err == nil {
		t.Error("500 应报错")
	}

	// 坏 JSON → error。
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not-json"))
	}))
	defer srvBad.Close()
	if _, err := newHTTPAttestStatusSource(srvBad.URL, "", time.Second).FetchAttestStatus(ctx); err == nil {
		t.Error("坏 JSON 应报错")
	}

	// 超时 → error。
	srvSlow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(80 * time.Millisecond)
	}))
	defer srvSlow.Close()
	if _, err := newHTTPAttestStatusSource(srvSlow.URL, "", 10*time.Millisecond).FetchAttestStatus(ctx); err == nil {
		t.Error("超时应报错")
	}

	// 不可达（已关闭）→ error。
	srvClosed := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srvClosed.URL
	srvClosed.Close()
	if _, err := newHTTPAttestStatusSource(url, "", time.Second).FetchAttestStatus(ctx); err == nil {
		t.Error("不可达应报错")
	}
}

// ---------- N10 启动自检（§4.3.10，V-S3）----------

func TestPortalTrustAxis(t *testing.T) {
	store := newTestStore(t)

	// 无开通租户 → trusted（fresh 部署可启动）。
	if untrusted, err := portalTrustAxis(store); err != nil || untrusted {
		t.Fatalf("无租户应 trusted: untrusted=%v err=%v", untrusted, err)
	}

	// 仅 trusted 租户 → trusted。
	tid1, _ := seedTenantUser(t, store, "n10a@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, store, tid1, scenarioS1, trustTierTrusted)
	if untrusted, err := portalTrustAxis(store); err != nil || untrusted {
		t.Fatalf("仅 trusted 租户应 trusted: untrusted=%v err=%v", untrusted, err)
	}

	// 出现 untrusted 租户 → untrusted（须强制自检）。
	tid2, _ := seedTenantUser(t, store, "n10b@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
	provisionForTest(t, store, tid2, scenarioS2, trustTierUntrusted)
	if untrusted, err := portalTrustAxis(store); err != nil || !untrusted {
		t.Fatalf("含 untrusted 租户应 untrusted: untrusted=%v err=%v", untrusted, err)
	}

	// 判定数据读取失败 → 错误（fail-closed，不默认 trusted）。
	if _, err := portalTrustAxis(&errTenantStore{TenantStore: store, listProvErr: errors.New("boom")}); err == nil {
		t.Error("枚举失败应报错（fail-closed）")
	}
}

func TestN10StartupSelfCheck(t *testing.T) {
	// trusted 档（无 untrusted 租户）→ 跳过自检（即使未接线也可启动）。
	t.Run("trusted 跳过", func(t *testing.T) {
		store := newTestStore(t)
		tid, _ := seedTenantUser(t, store, "n10c@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
		provisionForTest(t, store, tid, scenarioS3a, trustTierTrusted)
		if err := n10StartupSelfCheck(store, nil); err != nil {
			t.Errorf("trusted 档应跳过自检正常启动: %v", err)
		}
	})

	untrustedStore := func(t *testing.T) *sqliteTenantStore {
		t.Helper()
		store := newTestStore(t)
		tid, _ := seedTenantUser(t, store, "n10d@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)
		provisionForTest(t, store, tid, scenarioS2, trustTierUntrusted)
		return store
	}

	// untrusted 档异常若干类 → fail-closed 拒启动。
	t.Run("untrusted 未接线拒启动", func(t *testing.T) {
		if err := n10StartupSelfCheck(untrustedStore(t), nil); err == nil {
			t.Error("untrusted 且未接线应拒启动")
		}
	})
	t.Run("untrusted 源不可用拒启动", func(t *testing.T) {
		src := &fakeAttestSource{err: errors.New("timeout")}
		if err := n10StartupSelfCheck(untrustedStore(t), src); err == nil {
			t.Error("untrusted 且源不可用应拒启动")
		}
	})
	t.Run("untrusted mock 自签拒启动", func(t *testing.T) {
		src := &fakeAttestSource{items: []attestItem{
			{Component: "tee-infer", Status: attestStatusMockSigned, ClosedLoop: false}}}
		if err := n10StartupSelfCheck(untrustedStore(t), src); err == nil {
			t.Error("untrusted 且 mock 自签应拒启动（V-S3 异度量）")
		}
	})
	t.Run("untrusted 未闭环拒启动", func(t *testing.T) {
		src := &fakeAttestSource{items: []attestItem{
			{Component: "tee-infer", Status: attestStatusVerified, ClosedLoop: false}}}
		if err := n10StartupSelfCheck(untrustedStore(t), src); err == nil {
			t.Error("untrusted 且未闭环应拒启动（V-S3 异度量）")
		}
	})
	t.Run("untrusted 度量 verified 通过", func(t *testing.T) {
		src := &fakeAttestSource{items: []attestItem{
			{Component: "tee-infer", Status: attestStatusVerified, ClosedLoop: true}}}
		if err := n10StartupSelfCheck(untrustedStore(t), src); err != nil {
			t.Errorf("untrusted 且度量 verified 应通过: %v", err)
		}
	})
	t.Run("判定失败拒启动", func(t *testing.T) {
		store := untrustedStore(t)
		poisoned := &errTenantStore{TenantStore: store, listProvErr: errors.New("boom")}
		if err := n10StartupSelfCheck(poisoned, nil); err == nil {
			t.Error("轴 A 判定失败应拒启动（fail-closed）")
		}
	})
}
