// Package main — /v1/confllm/* 策略链 parity 验收网（D3，K8 风险 = 新入口旁路）。
//
// 覆盖：
//  1. parity 网：注册表逐条目断言「无令牌 401 / 角色不符 403 / 合法角色进业务 handler」，
//     证明没有任何路由裸奔（认证 + 授权 + 配额 + 审计全链收口）；
//  2. 审计：合法调用后审计链收到对应 action 事件，且事件**不含**请求/响应体（canary 举证）；
//  3. 配额：ratio<=0 → 429 quota_exceeded；checker nil / tenant 空 / ok=false →
//     放行且 quota_unenforced 可观测（metrics 计数，绝不静默）。
//
// 测试离线（P0-5）：全程 httptest，无真实网络。
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	confllm "security-ai-gateway/gateway/confllm-adapter"
)

// fakeConfllmHandler 记录业务 handler 调用的假 handler：把请求体原样回显到响应，
// 供审计 canary 断言（响应含敏感串时审计事件仍不得泄漏）。
type fakeConfllmHandler struct{ calls int }

func (f *fakeConfllmHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.calls++
	body, _ := io.ReadAll(r.Body)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"echo":` + string(mustJSONString(string(body))) + `}`))
}

func mustJSONString(s string) []byte {
	b, _ := json.Marshal(s)
	return b
}

// confllmTestToken 签发测试内部令牌（sub 不在 testCfg 白名单，角色按声明采信）。
func confllmTestToken(t *testing.T, sub, role, tenant string) string {
	t.Helper()
	return testSignToken(t, testSecret, claims{
		Sub: sub, Role: role, Tenant: tenant, Iss: defaultIssuer, Aud: defaultAudience,
	})
}

// confllmSpecMethodPath 把注册表条目展开为可命中的具体方法+路径（{id}/{jobID} 取实例值）。
func confllmSpecMethodPath(rt confllmRouteSpec) (method, path string) {
	method, path = http.MethodPost, rt.pattern
	switch {
	case strings.HasPrefix(path, http.MethodGet+" "):
		method = http.MethodGet
		path = strings.TrimPrefix(path, http.MethodGet+" ")
	case strings.HasPrefix(path, http.MethodPost+" "):
		path = strings.TrimPrefix(path, http.MethodPost+" ")
	default:
		// 无方法前缀（既有条目照旧）：按动作取自然方法。
		switch rt.action {
		case auditActionConfllmModels, auditActionConfllmHealth, auditActionConfllmGraphPoll:
			method = http.MethodGet
		}
	}
	path = strings.NewReplacer("{id}", "qa-parity-provider", "{jobID}", "qa-parity-job").Replace(path)
	return method, path
}

// quotaUnenforcedCount 读取 quota_unenforced 计数（同包直读，测试可做前后差值断言）。
func quotaUnenforcedCount(reason string) int64 {
	metrics.mu.Lock()
	defer metrics.mu.Unlock()
	return metrics.confllmQuotaUnenforced[reason]
}

// TestConfllmPolicyParityNoRouteBypasses 【parity 网】注册表全部条目逐条三态断言：
// 无令牌 401（不进 handler）；角色不符 403（不进 handler）；合法角色进业务 handler。
// 任一新增 /v1/confllm/* 路由只要进注册表即自动纳入本网。
func TestConfllmPolicyParityNoRouteBypasses(t *testing.T) {
	cfg := testCfg()
	mux := http.NewServeMux()
	fakes := make([]*fakeConfllmHandler, len(confllmRouteSpecs))
	for i, rt := range confllmRouteSpecs {
		fk := &fakeConfllmHandler{}
		fakes[i] = fk
		mux.HandleFunc(rt.pattern, confllmPolicy(cfg, rt.rule, rt.action, nil, nil, fk.ServeHTTP))
	}

	for i, rt := range confllmRouteSpecs {
		i, rt := i, rt
		method, path := confllmSpecMethodPath(rt)
		t.Run(fmt.Sprintf("%d %s %s", i, method, path), func(t *testing.T) {
			// ① 无令牌 → 401，业务 handler 不得被调用。
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("无令牌期望 401，实际 %d（裸奔 = 策略链缺口）", rec.Code)
			}
			if fakes[i].calls != 0 {
				t.Fatalf("无令牌不得进业务 handler，实际调用 %d 次", fakes[i].calls)
			}

			// ② 角色不符（auditor 打推理端点 epConfllmInfer）→ 403。
			// 读端点 epConfllmRead = roleAny（已认证可读），不设此分支。
			if rt.rule.domain == domInference {
				req := httptest.NewRequest(method, path, nil)
				req.Header.Set("Authorization", "Bearer "+confllmTestToken(t, "carol", roleAuditor, ""))
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				if rec.Code != http.StatusForbidden {
					t.Fatalf("auditor 打 %s:%s 期望 403，实际 %d", rt.rule.domain, rt.rule.action, rec.Code)
				}
				if fakes[i].calls != 0 {
					t.Fatalf("越权请求不得进业务 handler，实际调用 %d 次", fakes[i].calls)
				}
			}

			// ③ 合法角色（system_admin）→ 业务 handler 被调用一次。
			req := httptest.NewRequest(method, path, nil)
			req.Header.Set("Authorization", "Bearer "+confllmTestToken(t, "bob", roleSystemAdmin, "tenant-parity"))
			rec3 := httptest.NewRecorder()
			mux.ServeHTTP(rec3, req)
			if rec3.Code != http.StatusOK {
				t.Fatalf("合法角色期望 200，实际 %d（body=%s）", rec3.Code, rec3.Body.String())
			}
			if fakes[i].calls != 1 {
				t.Fatalf("合法请求应恰好调用业务 handler 1 次，实际 %d 次", fakes[i].calls)
			}
		})
	}
}

// TestConfllmAuditRecordsActionWithoutBody 【审计】逐条目：合法调用后审计链收到
// 对应 action 事件（action/sub/tenant/rid/方法+路径+状态码），且事件与落盘文件
// **均不含**请求/响应体 canary（P0-4 红线）。
func TestConfllmAuditRecordsActionWithoutBody(t *testing.T) {
	const canary = "CANARY-BODY-MUST-NOT-LEAK"
	cfg := testCfg()
	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	chain, err := newAdminAuditChain(auditFile, "")
	if err != nil {
		t.Fatalf("审计链初始化失败：%v", err)
	}
	defer chain.Close()

	for _, rt := range confllmRouteSpecs {
		rt := rt
		method, path := confllmSpecMethodPath(rt)
		t.Run(rt.action+" "+path, func(t *testing.T) {
			fk := &fakeConfllmHandler{}
			h := confllmPolicy(cfg, rt.rule, rt.action, chain, nil, fk.ServeHTTP)

			req := httptest.NewRequest(method, path, strings.NewReader(`{"prompt":"`+canary+`"}`))
			req.Header.Set("Authorization", "Bearer "+confllmTestToken(t, "bob", roleSystemAdmin, "tenant-audit"))
			req.Header.Set("X-Request-ID", "rid-"+rt.action)
			rec := httptest.NewRecorder()
			h(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("合法调用期望 200，实际 %d（body=%s）", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), canary) {
				t.Fatalf("测试自检失败：假 handler 应回显 canary（验证断言非空跑），body=%s", rec.Body.String())
			}

			events, total := chain.list(1, 0)
			if total < 1 || len(events) != 1 {
				t.Fatalf("期望至少 1 条审计事件，实际 total=%d len=%d", total, len(events))
			}
			e := events[0] // 倒序：最新在前
			if e.Action != rt.action {
				t.Fatalf("审计 action=%q 期望 %q", e.Action, rt.action)
			}
			if e.Actor != "bob" || e.Tenant != "tenant-audit" {
				t.Fatalf("审计身份映射不符：actor=%q tenant=%q", e.Actor, e.Tenant)
			}
			if e.RequestID != "rid-"+rt.action {
				t.Fatalf("审计 request_id=%q 期望 rid-%s", e.RequestID, rt.action)
			}
			if !strings.Contains(e.Detail, method) || !strings.Contains(e.Detail, path) || !strings.Contains(e.Detail, "status=200") {
				t.Fatalf("审计 Detail 缺方法/路径/状态码：%q", e.Detail)
			}

			// P0-4 红线：事件序列化后不得出现请求/响应体 canary。
			raw, merr := json.Marshal(e)
			if merr != nil {
				t.Fatalf("事件序列化失败：%v", merr)
			}
			if strings.Contains(string(raw), canary) {
				t.Fatalf("审计事件泄漏请求/响应体：%s", raw)
			}
		})
	}

	// 文件级断言：canary 绝不落盘。
	fileBytes, rerr := os.ReadFile(auditFile)
	if rerr != nil {
		t.Fatalf("读取审计文件失败：%v", rerr)
	}
	if strings.Contains(string(fileBytes), canary) {
		t.Fatalf("审计文件泄漏请求/响应体 canary")
	}
}

// TestRegisterConfllmRoutesWiresPolicy 【接线】registerConfllmRoutes 注册的真实路由必须
// 带策略链（无令牌 401）；注册本身不 panic = 10 物理路径互不冲突（含 graphs 方法前缀
// 隔离——GET /graphs/{jobID} 与 POST /{id}/graphs 若缺方法前缀会注册期 panic）。
func TestRegisterConfllmRoutesWiresPolicy(t *testing.T) {
	cfg := testCfg()
	mux := http.NewServeMux()
	registerConfllmRoutes(mux, cfg, newConfllmHandler(nil), nil, nil) // 注册期不 panic = 无冲突

	for _, rt := range confllmRouteSpecs {
		method, path := confllmSpecMethodPath(rt)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(method, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s 无令牌期望 401（策略链未接线 = 路由裸奔），实际 %d", method, path, rec.Code)
		}
	}
}

// fakeQuotaChecker 配额查询测试桩（三种状态皆可构造）。
type fakeQuotaChecker struct {
	ratio      float64
	ok         bool
	calls      int
	lastTenant string
	lastDay    string
}

func (f *fakeQuotaChecker) QuotaRemaining(tenant, day string) (float64, bool) {
	f.calls++
	f.lastTenant, f.lastDay = tenant, day
	return f.ratio, f.ok
}

// TestConfllmQuotaGateStates 【配额】三态全可观测：
// ① ratio<=0 → 429 + code=quota_exceeded（handler 不被调用）；
// ② checker nil / tenant 空 / ok=false → 放行 + quota_unenforced 计数；
// ③ ratio>0 → 放行且不影响业务响应。
func TestConfllmQuotaGateStates(t *testing.T) {
	cfg := testCfg()
	rt := confllmRouteSpecs[0] // chat（epConfllmInfer）
	method, path := confllmSpecMethodPath(rt)
	token := confllmTestToken(t, "bob", roleSystemAdmin, "tenant-quota")

	call := func(t *testing.T, quota confllmQuotaChecker, tok string) (*httptest.ResponseRecorder, *fakeConfllmHandler) {
		t.Helper()
		fk := &fakeConfllmHandler{}
		h := confllmPolicy(cfg, rt.rule, rt.action, nil, quota, fk.ServeHTTP)
		req := httptest.NewRequest(method, path, nil)
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
		rec := httptest.NewRecorder()
		h(rec, req)
		return rec, fk
	}

	t.Run("ratio<=0 → 429 quota_exceeded", func(t *testing.T) {
		fq := &fakeQuotaChecker{ratio: 0, ok: true}
		rec, fk := call(t, fq, token)
		if rec.Code != http.StatusTooManyRequests {
			t.Fatalf("配额耗尽期望 429，实际 %d（body=%s）", rec.Code, rec.Body.String())
		}
		var body struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("429 响应体解析失败：%v（body=%s）", err, rec.Body.String())
		}
		if body.Error.Code != confllm.CodeQuotaExceeded {
			t.Fatalf("错误码=%q 期望 %q", body.Error.Code, confllm.CodeQuotaExceeded)
		}
		if fk.calls != 0 {
			t.Fatalf("配额耗尽不得进业务 handler，实际调用 %d 次", fk.calls)
		}
		if fq.calls != 1 {
			t.Fatalf("应恰好查询配额 1 次，实际 %d 次", fq.calls)
		}
	})

	t.Run("ratio>0 → 放行且不影响响应", func(t *testing.T) {
		fq := &fakeQuotaChecker{ratio: 0.5, ok: true}
		rec, fk := call(t, fq, token)
		if rec.Code != http.StatusOK || fk.calls != 1 {
			t.Fatalf("有余量应放行：status=%d handler=%d", rec.Code, fk.calls)
		}
		if fq.lastTenant != "tenant-quota" {
			t.Fatalf("配额查询租户=%q 期望 tenant-quota", fq.lastTenant)
		}
		if len(fq.lastDay) != 10 {
			t.Fatalf("配额查询 day=%q 期望 YYYY-MM-DD（billing.QuotaRemaining 语义）", fq.lastDay)
		}
	})

	t.Run("checker nil → 放行 + quota_unenforced(checker_disabled)", func(t *testing.T) {
		before := quotaUnenforcedCount("checker_disabled")
		rec, fk := call(t, nil, token)
		if rec.Code != http.StatusOK || fk.calls != 1 {
			t.Fatalf("未启用配额应放行：status=%d handler=%d", rec.Code, fk.calls)
		}
		if got := quotaUnenforcedCount("checker_disabled") - before; got != 1 {
			t.Fatalf("quota_unenforced(checker_disabled) 应 +1，实际 +%d（未强制必须可观测）", got)
		}
	})

	t.Run("tenant 空 → 放行 + quota_unenforced(tenant_empty)", func(t *testing.T) {
		before := quotaUnenforcedCount("tenant_empty")
		fq := &fakeQuotaChecker{ratio: 0, ok: true} // 有 checker 也不得误拒（无租户可查）
		rec, fk := call(t, fq, confllmTestToken(t, "bob", roleSystemAdmin, ""))
		if rec.Code != http.StatusOK || fk.calls != 1 {
			t.Fatalf("无租户声明应放行：status=%d handler=%d", rec.Code, fk.calls)
		}
		if fq.calls != 0 {
			t.Fatalf("无租户不得查询配额，实际 %d 次", fq.calls)
		}
		if got := quotaUnenforcedCount("tenant_empty") - before; got != 1 {
			t.Fatalf("quota_unenforced(tenant_empty) 应 +1，实际 +%d", got)
		}
	})

	t.Run("ok=false → 放行 + quota_unenforced(no_quota_data)", func(t *testing.T) {
		before := quotaUnenforcedCount("no_quota_data")
		fq := &fakeQuotaChecker{ratio: 0, ok: false}
		rec, fk := call(t, fq, token)
		if rec.Code != http.StatusOK || fk.calls != 1 {
			t.Fatalf("无套餐/不限量应放行：status=%d handler=%d", rec.Code, fk.calls)
		}
		if got := quotaUnenforcedCount("no_quota_data") - before; got != 1 {
			t.Fatalf("quota_unenforced(no_quota_data) 应 +1，实际 +%d", got)
		}
	})
}
