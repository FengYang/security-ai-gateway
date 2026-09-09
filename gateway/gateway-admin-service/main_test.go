// Package main — HTTP 端点端到端单测（httptest）。
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTestServer 组装测试路由（与 main 同构，避免 main() 无法直接注入）。
func newTestServer(cfg *config) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/metrics", handleMetrics)
	mux.HandleFunc("/v1/adminext/echo", authMiddleware(cfg, handleEcho))
	return mux
}

// bearerToken 构造合法内部令牌（sub/role/iss/aud 齐全）。
func bearerToken(t *testing.T) string {
	t.Helper()
	return "Bearer " + testSignToken(t, testSecret, claims{
		Sub: "alice", Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
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
		if got.Sub != "alice" || got.Role != roleAdmin {
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
