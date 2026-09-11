// Package main — HTTP 端点端到端单测（httptest）。
//
// 覆盖：
//   - 基础端点（healthz / metrics / echo 鉴权闭环）
//   - M2 A-2：双 listener 路由隔离（管理面 vs broker）与 /readyz 三态
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer 组装管理面测试路由（与 main 同构；broker 未启用、无兼容期中转）。
func newTestServer(cfg *config) *http.ServeMux {
	return buildAdminMux(cfg, nil, nil, nil, nil, nil, false)
}

// bearerToken 构造合法内部令牌（sub/role/iss/aud 齐全）。
func bearerToken(t *testing.T) string {
	t.Helper()
	return "Bearer " + testSignToken(t, testSecret, claims{
		Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
	})
}

func TestEndpoints(t *testing.T) {
	srv := httptest.NewServer(newTestServer(testCfg()))
	defer srv.Close()

	t.Run("healthz 无鉴权 200", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("healthz 期望 200，实际 %d", resp.StatusCode)
		}
	})

	t.Run("metrics 暴露指标族", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/metrics")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(resp.Body)
		for _, want := range []string{
			"gateway_admin_requests_total",
			"gateway_admin_auth_rejected_total",
			"gateway_admin_broker_config_reload_failed_total",
			"gateway_admin_audit_events",
			"gateway_admin_broker_audit_write_failed_total",
		} {
			if !bytes.Contains(buf.Bytes(), []byte(want)) {
				t.Fatalf("metrics 缺族 %q", want)
			}
		}
	})

	t.Run("echo 无令牌 401", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/v1/adminext/echo")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("无令牌期望 401，实际 %d", resp.StatusCode)
		}
	})

	t.Run("echo 坏令牌 401", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/adminext/echo", nil)
		req.Header.Set("Authorization", "Bearer not-a-jwt")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("坏令牌期望 401，实际 %d", resp.StatusCode)
		}
	})

	t.Run("echo 合法令牌 200 回显身份", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/adminext/echo", nil)
		req.Header.Set("Authorization", bearerToken(t))
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("合法令牌期望 200，实际 %d", resp.StatusCode)
		}
		var got echoResponse
		if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
			t.Fatal(err)
		}
		if got.Sub != testAdminUser || got.Role != roleAdmin {
			t.Fatalf("回显身份不符：%+v", got)
		}
	})
}

func TestMetricsCountersIncrease(t *testing.T) {
	m := newAdminMetrics()
	if m.requests != 0 || m.authRejected != 0 {
		t.Fatalf("初始计数应为 0")
	}
	m.request()
	m.request()
	m.incAuthRejected()
	if m.requests != 2 || m.authRejected != 1 {
		t.Fatalf("计数异常：requests=%d rejected=%d", m.requests, m.authRejected)
	}
	var buf bytes.Buffer
	m.render(&buf)
	for _, want := range []string{"gateway_admin_requests_total 2", "gateway_admin_auth_rejected_total 1"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Fatalf("渲染缺 %q：\n%s", want, buf.String())
		}
	}
}

// ---------- M2 A-2：/readyz 三态 ----------

func TestReadyzThreeStates(t *testing.T) {
	t.Run("broker 未启用 → ready（不阻塞 Deployment）", func(t *testing.T) {
		rec := httptest.NewRecorder()
		handleReadyz(nil)(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK || rec.Body.String() != "ready" {
			t.Fatalf("期望 200 ready，实际 %d %q", rec.Code, rec.Body.String())
		}
	})

	t.Run("broker 正常 → ready", func(t *testing.T) {
		bs := testSettings(t)
		sh := newBrokerSecretHandler(bs, newBrokerHandler(&brokerConfig{providers: map[string]*brokerProvider{}}), nil)
		rec := httptest.NewRecorder()
		handleReadyz(sh.healthy)(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", rec.Code)
		}
	})

	t.Run("broker 连续重载失败超阈值 → 503", func(t *testing.T) {
		bs := testSettings(t)
		sh := newBrokerSecretHandler(bs, newBrokerHandler(&brokerConfig{providers: map[string]*brokerProvider{}}), nil)

		// 未达阈值（2 次）仍 ready
		sh.markFail()
		sh.markFail()
		if !sh.healthy() {
			t.Fatalf("连续失败 %d 次（阈值 %d）应仍视为健康", 2, readyzFailThreshold)
		}
		// 达阈值 → not ready
		sh.markFail()
		if sh.healthy() {
			t.Fatalf("连续失败达阈值 %d 应判 not ready", readyzFailThreshold)
		}
		rec := httptest.NewRecorder()
		handleReadyz(sh.healthy)(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("期望 503，实际 %d", rec.Code)
		}
	})

	t.Run("重载成功清零连续失败", func(t *testing.T) {
		bs := testSettings(t)
		sh := newBrokerSecretHandler(bs, newBrokerHandler(&brokerConfig{providers: map[string]*brokerProvider{}}), nil)
		sh.markFail()
		sh.markFail()
		sh.markFail()
		if sh.healthy() {
			t.Fatal("失败的连续计数应已触发 not ready")
		}
		sh.markOK("sig")
		if !sh.healthy() {
			t.Fatal("重载成功后应恢复 ready")
		}
	})
}

// ---------- M2 A-2：双 listener 路由隔离 ----------

// brokerRouteServed 判定响应是否由 broker handler 处理。
//
// broker handler 一律回写 X-Request-ID（S-3）；mux 级 404（路径未注册）不带该头，
// 故以此区分"端口未暴露 broker"与"已暴露但 provider 未知"。
func brokerRouteServed(resp *httptest.ResponseRecorder) bool {
	return resp.Header().Get("X-Request-ID") != ""
}

func TestListenerRouteIsolation(t *testing.T) {
	bs := testSettings(t)
	cfg := testCfg()
	bc := &brokerConfig{providers: map[string]*brokerProvider{"phala": testProvider(t)}}
	bh := newBrokerHandler(bc)
	sh := newBrokerSecretHandler(bs, bh, nil)

	t.Run("broker 专用 listener：仅中转端点可达", func(t *testing.T) {
		brokerMux := buildBrokerMux(bh)

		// 中转端点在位
		rec := httptest.NewRecorder()
		brokerMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/llm-broker/phala/v1/__probe", nil))
		if !brokerRouteServed(rec) {
			t.Fatal("broker listener 应处理 /llm-broker/** 请求")
		}

		// 管理面路径一律 404（不暴露 healthz/readyz/metrics/凭据端点）
		for _, p := range []string{"/healthz", "/readyz", "/metrics", brokerAPIBase, brokerAPIBase + "/phala"} {
			rec := httptest.NewRecorder()
			brokerMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
			if rec.Code != http.StatusNotFound {
				t.Fatalf("broker listener 上 %s 期望 404，实际 %d", p, rec.Code)
			}
			if brokerRouteServed(rec) {
				t.Fatalf("broker listener 上 %s 不应由 broker handler 处理", p)
			}
		}
	})

	t.Run("管理面 listener（收口期 legacy=false）：不含中转端点", func(t *testing.T) {
		adminMux := buildAdminMux(cfg, sh, bh, nil, nil, nil, false)

		rec := httptest.NewRecorder()
		adminMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/llm-broker/phala/v1/__probe", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("收口期管理面端口不应暴露 broker，实际 %d", rec.Code)
		}
		if brokerRouteServed(rec) {
			t.Fatal("收口期管理面端口应返回 mux 级 404（不带 X-Request-ID）")
		}

		// 管理面端点仍可用
		rec = httptest.NewRecorder()
		adminMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("管理面 healthz 期望 200，实际 %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		adminMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("管理面 readyz 期望 200，实际 %d", rec.Code)
		}
	})

	t.Run("管理面 listener（兼容期 legacy=true）：同时暴露中转端点", func(t *testing.T) {
		adminMux := buildAdminMux(cfg, sh, bh, nil, nil, nil, true)

		rec := httptest.NewRecorder()
		adminMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/llm-broker/phala/v1/__probe", nil))
		if !brokerRouteServed(rec) {
			t.Fatal("兼容期管理面端口应保留 broker 中转（M1 链路不中断）")
		}
	})

	t.Run("broker 未启用：管理面无凭据端点且 readyz 正常", func(t *testing.T) {
		adminMux := buildAdminMux(cfg, nil, nil, nil, nil, nil, true)

		rec := httptest.NewRecorder()
		adminMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, brokerAPIBase, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("broker 未启用时凭据端点应不存在，实际 %d", rec.Code)
		}
		rec = httptest.NewRecorder()
		adminMux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("broker 未启用时 readyz 期望 200，实际 %d", rec.Code)
		}
	})
}

// brokerListen 缺省与显式配置解析。
func TestLoadBrokerSettingsListenerDefaults(t *testing.T) {
	t.Setenv("ADMIN_SVC_BROKER_LISTEN", "")
	t.Setenv("ADMIN_SVC_BROKER_LEGACY_PORT", "")
	s := loadBrokerSettings()
	if s.brokerListen != defaultBrokerListen {
		t.Fatalf("brokerListen 缺省应为 %s，实际 %s", defaultBrokerListen, s.brokerListen)
	}
	if !s.legacyPort {
		t.Fatal("兼容期缺省应为 true（保持 M1 链路可用）")
	}

	t.Setenv("ADMIN_SVC_BROKER_LISTEN", ":19999")
	t.Setenv("ADMIN_SVC_BROKER_LEGACY_PORT", "false")
	s = loadBrokerSettings()
	if s.brokerListen != ":19999" {
		t.Fatalf("brokerListen 应为 :19999，实际 %s", s.brokerListen)
	}
	if s.legacyPort {
		t.Fatal("显式 ADMIN_SVC_BROKER_LEGACY_PORT=false 应关闭兼容期暴露")
	}
}
