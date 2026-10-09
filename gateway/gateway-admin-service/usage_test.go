// usage_test.go — A-2' 用量代理与配额端点单测（管理门户 M2）。
//
// 覆盖：503 语义（未配置/不可达/数据源 5xx，不静默返回空数据）、角色授权（§6.2 三权分立：
// billing:read 归 system_admin/audit_admin/billing_reader；写配额 system_admin + 会话级 MFA）、
// 透传保真（query 白名单 + X-Admin-Token 服务间令牌注入）、quota 落审计链、
// 审计写失败 fail-closed 拒绝 2xx。
package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// teeInferRecorder 记录 fake tee-infer 收到的请求（供透传保真断言）。
type teeInferRecorder struct {
	gotQuery  url.Values
	gotHeader string
	gotBody   string
}

// newFakeTeeInfer 模拟 tee-infer 的 /usage 与 /usage/quota。
// usageStatus/quotaStatus 控制返回状态码（200 = 正常 JSON）。
func newFakeTeeInfer(t *testing.T, rec *teeInferRecorder, usageStatus, quotaStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/usage", func(w http.ResponseWriter, r *http.Request) {
		rec.gotQuery = r.URL.Query()
		rec.gotHeader = r.Header.Get(teeAdminHeader)
		if usageStatus != http.StatusOK {
			w.WriteHeader(usageStatus)
			_, _ = w.Write([]byte("upstream boom"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenants":{"acme":{"tokens_in":100,"tokens_out":50,"requests":2,"by_model":{"qwen/qwen3":{"tokens_in":100,"tokens_out":50,"requests":2}}}}}`))
	})
	mux.HandleFunc("/usage/quota", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec.gotBody = string(body)
		rec.gotHeader = r.Header.Get(teeAdminHeader)
		if quotaStatus != http.StatusOK {
			w.WriteHeader(quotaStatus)
			_, _ = w.Write([]byte("quota boom"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenant":"acme","quota":1000000}`))
	})
	// S5：对账快照（沿用 usageStatus 作为上游状态开关）
	mux.HandleFunc("/reconcile", func(w http.ResponseWriter, r *http.Request) {
		rec.gotQuery = r.URL.Query()
		rec.gotHeader = r.Header.Get(teeAdminHeader)
		if usageStatus != http.StatusOK {
			w.WriteHeader(usageStatus)
			_, _ = w.Write([]byte("reconcile boom"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"tolerance_tokens":0,"instance_id":"inst-test","chain_intact":true,"billing_blocked":false}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// newTestUsageMux 组装与 main 同构的用量端点路由。
func newTestUsageMux(s *usageSettings, audit *adminAuditChain) *http.ServeMux {
	uh := newUsageHandler(s, audit)
	mux := http.NewServeMux()
	mux.HandleFunc(usageAPIBase, authMiddleware(testCfg(), uh.handleUsage))
	mux.HandleFunc(usageQuotaPath, authMiddleware(testCfg(), uh.handleQuota))
	mux.HandleFunc(meteringReconcilePath, authMiddleware(testCfg(), uh.handleMeteringReconcile))
	return mux
}

// doUsage 以指定角色发起请求（body 非 nil 时 JSON 编码）。
func doUsage(t *testing.T, mux *http.ServeMux, role, method, target string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	reader := strings.NewReader("")
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = strings.NewReader(string(raw))
	}
	sub := testAdminUser
	if role == roleAuditor {
		sub = "auditor-user"
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{
		Sub: sub, Role: role, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// doUsageMFA 同 doUsage，但令牌带 MFA 第二步声明（mfa=true + 新鲜 mfa_at），
// 用于验证写端点的 step-up（authz.go requireRule 的 mfaSessionFreshness/mfaStepUpFreshness）。
func doUsageMFA(t *testing.T, mux *http.ServeMux, role, method, target string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	reader := strings.NewReader("")
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{
		Sub: testAdminUser, Role: role, Iss: defaultIssuer, Aud: defaultAudience,
		MFA: true, MFAAt: time.Now().Unix(),
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// doUsageAs 同 doUsage，但显式指定令牌 sub。
// 用途：doUsage 对多数角色用 testAdminUser（在 testCfg 白名单内 → resolveRole 恒加成 admin），
// 会掩盖 JWT 声明的真实角色；验证"非白名单主体"的角色语义须用本函数。
func doUsageAs(t *testing.T, mux *http.ServeMux, role, sub, method, target string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	reader := strings.NewReader("")
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = strings.NewReader(string(raw))
	}
	req := httptest.NewRequest(method, target, reader)
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, testSecret, claims{
		Sub: sub, Role: role, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// ---------- 503 语义（完成定义③） ----------

func TestUsageUnconfiguredReturns503(t *testing.T) {
	mux := newTestUsageMux(&usageSettings{}, nil)

	for _, tc := range []struct {
		name   string
		method string
		target string
	}{
		{"usage GET", http.MethodGet, usageAPIBase},
		{"quota POST", http.MethodPost, usageQuotaPath},
		{"metering reconcile GET", http.MethodGet, meteringReconcilePath},
	} {
		t.Run(tc.name+" 未配置 → 503（不静默空数据）", func(t *testing.T) {
			rec := doUsage(t, mux, roleAdmin, tc.method, tc.target, nil)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("期望 503，实际 %d: %s", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestUsageUpstreamFailuresReturn503(t *testing.T) {
	rec := &teeInferRecorder{}

	t.Run("数据源 5xx → 503", func(t *testing.T) {
		srv := newFakeTeeInfer(t, rec, http.StatusInternalServerError, http.StatusOK)
		mux := newTestUsageMux(&usageSettings{url: srv.URL, token: "tok"}, nil)
		if r := doUsage(t, mux, roleAdmin, http.MethodGet, usageAPIBase, nil); r.Code != http.StatusServiceUnavailable {
			t.Fatalf("期望 503，实际 %d", r.Code)
		}
	})

	t.Run("数据源不可达 → 503", func(t *testing.T) {
		srv := newFakeTeeInfer(t, rec, http.StatusOK, http.StatusOK)
		url := srv.URL
		srv.Close() // 立即关闭模拟不可达
		mux := newTestUsageMux(&usageSettings{url: url, token: "tok"}, nil)
		if r := doUsage(t, mux, roleAdmin, http.MethodGet, usageAPIBase, nil); r.Code != http.StatusServiceUnavailable {
			t.Fatalf("期望 503，实际 %d", r.Code)
		}
	})

	t.Run("数据源 400（参数错）→ 400 透传", func(t *testing.T) {
		srv := newFakeTeeInfer(t, rec, http.StatusBadRequest, http.StatusOK)
		mux := newTestUsageMux(&usageSettings{url: srv.URL, token: "tok"}, nil)
		if r := doUsage(t, mux, roleAdmin, http.MethodGet, usageAPIBase, nil); r.Code != http.StatusBadRequest {
			t.Fatalf("期望 400 透传，实际 %d", r.Code)
		}
	})
}

// ---------- 角色授权（完成定义②）+ 透传保真（完成定义①前提） ----------

func TestUsageProxyRolesAndRelay(t *testing.T) {
	rec := &teeInferRecorder{}
	srv := newFakeTeeInfer(t, rec, http.StatusOK, http.StatusOK)
	mux := newTestUsageMux(&usageSettings{url: srv.URL, token: "svc-tok"}, nil)

	t.Run("usage 无令牌 401", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, usageAPIBase, nil)
		rw := httptest.NewRecorder()
		mux.ServeHTTP(rw, req)
		if rw.Code != http.StatusUnauthorized {
			t.Fatalf("期望 401，实际 %d", rw.Code)
		}
	})

	t.Run("billing_reader 可读 usage（只读全量）", func(t *testing.T) {
		r := doUsage(t, mux, roleBillingReader, http.MethodGet,
			usageAPIBase+"?from=2026-01-01T00:00:00Z&to=2026-01-02T00:00:00Z&tenant=acme", nil)
		if r.Code != http.StatusOK {
			t.Fatalf("billing_reader 读 usage 期望 200，实际 %d: %s", r.Code, r.Body.String())
		}
		// 透传保真：from/to/tenant 白名单参数原样到达数据源；服务间令牌已注入
		if rec.gotQuery.Get("from") != "2026-01-01T00:00:00Z" || rec.gotQuery.Get("to") != "2026-01-02T00:00:00Z" ||
			rec.gotQuery.Get("tenant") != "acme" {
			t.Fatalf("query 透传不符：%v", rec.gotQuery)
		}
		if rec.gotHeader != "svc-tok" {
			t.Fatalf("X-Admin-Token 应注入服务间令牌，实际 %q", rec.gotHeader)
		}
		// 响应体原样透传（数字与真源一致的前提）
		var got map[string]interface{}
		if err := json.Unmarshal(r.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		tenants, ok := got["tenants"].(map[string]interface{})
		if !ok || tenants["acme"] == nil {
			t.Fatalf("tenants.acme 应透传，实际 %v", got)
		}
	})

	t.Run("query 白名单外的参数不透传", func(t *testing.T) {
		r := doUsage(t, mux, roleAdmin, http.MethodGet, usageAPIBase+"?tenant=acme&evil=1", nil)
		if r.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d", r.Code)
		}
		if rec.gotQuery.Get("evil") != "" {
			t.Fatalf("白名单外参数不得透传：%v", rec.gotQuery)
		}
	})

	t.Run("auditor 写 quota → 403", func(t *testing.T) {
		r := doUsage(t, mux, roleAuditor, http.MethodPost, usageQuotaPath, quotaSetRequest{Tenant: "acme", MaxTokens: 100})
		if r.Code != http.StatusForbidden {
			t.Fatalf("auditor 写 quota 期望 403，实际 %d", r.Code)
		}
	})

	// F-5 回归：写操作（billing:write）不得由只读角色承担。
	// 注：须用非白名单 sub，否则 resolveRole 会把 testAdminUser 加成 admin 而掩盖真实角色。
	t.Run("billing_reader 写 quota → 403（F-5 回归）", func(t *testing.T) {
		r := doUsageAs(t, mux, roleBillingReader, "billing-reader-user", http.MethodPost, usageQuotaPath, quotaSetRequest{Tenant: "acme", MaxTokens: 100})
		if r.Code != http.StatusForbidden {
			t.Fatalf("billing_reader 写 quota 期望 403，实际 %d", r.Code)
		}
	})

	// F-1 回归：§6.2 映射表收窄后 auditor 不含 billing:read。
	t.Run("auditor 读 usage → 403（§6.2 收窄）", func(t *testing.T) {
		r := doUsage(t, mux, roleAuditor, http.MethodGet, usageAPIBase+"?tenant=acme", nil)
		if r.Code != http.StatusForbidden {
			t.Fatalf("auditor 读 usage 期望 403，实际 %d", r.Code)
		}
	})

	// 注：MFA step-up（epQuotaWrite 的 mfaSessionFreshness）对"未绑定 MFA 的账号"按
	// mfa.go 灰度语义不阻断（mfaSatisfied → true），故此处不断言 403；
	// MFA 自身行为（enroll/verify/重放/锁定/step-up）应由 mfa_test.go 覆盖（遗留项 F-6）。
}

// ---------- S5：对账快照代理（只读代理，billing:read；F-2 修正：实现为 GET 只读） ----------

func TestMeteringReconcileProxy(t *testing.T) {
	rec := &teeInferRecorder{}
	srv := newFakeTeeInfer(t, rec, http.StatusOK, http.StatusOK)
	mux := newTestUsageMux(&usageSettings{url: srv.URL, token: "svc-tok"}, nil)

	t.Run("billing_reader 可读（只读代理，注入服务间令牌）", func(t *testing.T) {
		r := doUsage(t, mux, roleBillingReader, http.MethodGet, meteringReconcilePath, nil)
		if r.Code != http.StatusOK {
			t.Fatalf("billing_reader 读对账快照期望 200，实际 %d: %s", r.Code, r.Body.String())
		}
		if rec.gotHeader != "svc-tok" {
			t.Fatalf("X-Admin-Token 应注入服务间令牌，实际 %q", rec.gotHeader)
		}
		var got map[string]interface{}
		if err := json.Unmarshal(r.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got["ok"] != true || got["tolerance_tokens"] != float64(0) || got["billing_blocked"] != false {
			t.Fatalf("快照应原样透传，实际 %v", got)
		}
	})

	t.Run("非 GET → 405", func(t *testing.T) {
		if r := doUsage(t, mux, roleAdmin, http.MethodPost, meteringReconcilePath, nil); r.Code != http.StatusMethodNotAllowed {
			t.Fatalf("期望 405，实际 %d", r.Code)
		}
	})
}

func TestMeteringReconcileUpstreamFailuresReturn503(t *testing.T) {
	rec := &teeInferRecorder{}

	t.Run("数据源 5xx → 503 且文案指明对账数据源", func(t *testing.T) {
		srv := newFakeTeeInfer(t, rec, http.StatusInternalServerError, http.StatusOK)
		mux := newTestUsageMux(&usageSettings{url: srv.URL, token: "tok"}, nil)
		r := doUsage(t, mux, roleAdmin, http.MethodGet, meteringReconcilePath, nil)
		if r.Code != http.StatusServiceUnavailable {
			t.Fatalf("期望 503，实际 %d", r.Code)
		}
		if !strings.Contains(r.Body.String(), "对账数据源") {
			t.Fatalf("文案应指明对账数据源，实际 %s", r.Body.String())
		}
	})

	t.Run("数据源不可达 → 503", func(t *testing.T) {
		srv := newFakeTeeInfer(t, rec, http.StatusOK, http.StatusOK)
		url := srv.URL
		srv.Close()
		mux := newTestUsageMux(&usageSettings{url: url, token: "tok"}, nil)
		if r := doUsage(t, mux, roleAdmin, http.MethodGet, meteringReconcilePath, nil); r.Code != http.StatusServiceUnavailable {
			t.Fatalf("期望 503，实际 %d", r.Code)
		}
	})
}

// ---------- 配额写：落链 + fail-closed ----------

func TestQuotaSetAuditedAndFailClosed(t *testing.T) {
	rec := &teeInferRecorder{}
	srv := newFakeTeeInfer(t, rec, http.StatusOK, http.StatusOK)

	t.Run("admin 设置配额 → 2xx 且落链 quota_set", func(t *testing.T) {
		c := newAuditTestChain(t, false)
		mux := newTestUsageMux(&usageSettings{url: srv.URL, token: "svc-tok"}, c)

		r := doUsageMFA(t, mux, roleAdmin, http.MethodPost, usageQuotaPath, quotaSetRequest{Tenant: "acme", MaxTokens: 1000000})
		if r.Code != http.StatusOK {
			t.Fatalf("期望 200，实际 %d: %s", r.Code, r.Body.String())
		}
		// 转发体保真
		var sent quotaSetRequest
		if err := json.Unmarshal([]byte(rec.gotBody), &sent); err != nil || sent != (quotaSetRequest{Tenant: "acme", MaxTokens: 1000000}) {
			t.Fatalf("转发体不符：%s", rec.gotBody)
		}
		// 审计事件内容（先数据源生效再落链）
		if c.len() != 1 {
			t.Fatalf("应落 1 条 quota_set，实际 %d", c.len())
		}
		c.mu.Lock()
		evt := c.events[0]
		c.mu.Unlock()
		if evt.Action != auditActionQuotaSet || evt.Tenant != "acme" || evt.MaxTokens != 1000000 || evt.Actor != testAdminUser {
			t.Fatalf("quota_set 事件内容不符：%+v", evt)
		}
	})

	t.Run("tenant 缺失 → 400（本地校验，不打数据源）", func(t *testing.T) {
		c := newAuditTestChain(t, false)
		mux := newTestUsageMux(&usageSettings{url: srv.URL, token: "svc-tok"}, c)
		r := doUsageMFA(t, mux, roleAdmin, http.MethodPost, usageQuotaPath, map[string]interface{}{"max_tokens": 100})
		if r.Code != http.StatusBadRequest {
			t.Fatalf("期望 400，实际 %d", r.Code)
		}
		if c.len() != 0 {
			t.Fatal("校验失败不应落链")
		}
	})

	t.Run("审计写失败 → 500 fail-closed（配额已生效但拒绝确认）", func(t *testing.T) {
		c := newAuditTestChain(t, false)
		mux := newTestUsageMux(&usageSettings{url: srv.URL, token: "svc-tok"}, c)
		_ = c.Close() // 模拟审计文件不可写

		r := doUsageMFA(t, mux, roleAdmin, http.MethodPost, usageQuotaPath, quotaSetRequest{Tenant: "acme", MaxTokens: 2000000})
		if r.Code != http.StatusInternalServerError {
			t.Fatalf("审计写失败应 500（fail-closed），实际 %d: %s", r.Code, r.Body.String())
		}
	})
}
