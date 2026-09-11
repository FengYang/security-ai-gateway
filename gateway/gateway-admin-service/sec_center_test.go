// Package main — M3-B 安全中心数据端点单测。
//
// 覆盖：G1 链查询（分页/倒序）/ 校验 / 导出 / 未启用 503 / 鉴权，
// 以及 sec-status 的 tee-infer 聚合（可达 → ok；不可达 → 如实标注 unreachable）。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newSecTestMux 组装安全中心端点 mux（teeURL 为空 = 未配置数据源）。
func newSecTestMux(cfg *config, chain *adminAuditChain, teeURL string) *http.ServeMux {
	us := &usageSettings{url: teeURL, token: "tee-tok"}
	return buildAdminMux(cfg, nil, nil, nil, nil, nil, newSecCenterHandler(chain, us), nil, false)
}

// secGet 以指定角色发起 GET 请求。
func secGet(t *testing.T, mux *http.ServeMux, cfg *config, sub, role, target string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Authorization", "Bearer "+testSignToken(t, cfg.jwtSecret, claims{
		Sub: sub, Role: role, Iss: defaultIssuer, Aud: defaultAudience,
	}))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// seedChain 向审计链追加 n 条事件。
func seedChain(t *testing.T, c *adminAuditChain, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if err := c.append(adminAuditEvent{
			Actor: "admin", Action: auditActionQuotaSet, Tenant: "t1", Result: "ok",
		}); err != nil {
			t.Fatalf("append 审计事件失败: %v", err)
		}
	}
}

func TestSecCenterAuditChainQueryPagedDesc(t *testing.T) {
	cfg := testCfg()
	chain := newAuditTestChain(t, false)
	seedChain(t, chain, 3)
	mux := newSecTestMux(cfg, chain, "")

	rec := secGet(t, mux, cfg, testAdminUser, roleAdmin, auditChainPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("查询应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Events []adminAuditEvent `json:"events"`
		Total  int               `json:"total"`
		Limit  int               `json:"limit"`
		Offset int               `json:"offset"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应非合法 JSON：%v", err)
	}
	if resp.Total != 3 || len(resp.Events) != 3 {
		t.Fatalf("期望 3 条事件，实际 total=%d len=%d", resp.Total, len(resp.Events))
	}
	// 倒序：最新在前（末条 PrevHash 应等于第二条哈希，即事件顺序被反转）。
	if resp.Events[0].PrevHash == "" {
		t.Fatal("倒序首条应为最新事件（PrevHash 非空）")
	}
	if resp.Events[2].PrevHash != "" {
		t.Fatal("倒序末条应为创世事件（PrevHash 为空）")
	}

	// 分页：limit=1&offset=1 → 仅 1 条，total 仍为 3。
	rec = secGet(t, mux, cfg, testAdminUser, roleAdmin, auditChainPath+"?limit=1&offset=1")
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Total != 3 || len(resp.Events) != 1 {
		t.Fatalf("分页期望 total=3 len=1，实际 total=%d len=%d", resp.Total, len(resp.Events))
	}
}

func TestSecCenterAuditChainDisabledReturns503(t *testing.T) {
	cfg := testCfg()
	mux := newSecTestMux(cfg, nil, "") // 审计链未启用

	for _, p := range []string{auditChainPath, auditChainVerifyPath, auditChainExportPath} {
		rec := secGet(t, mux, cfg, testAdminUser, roleAdmin, p)
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s 未启用审计链应 503（不静默返回空链），实际 %d", p, rec.Code)
		}
	}
}

func TestSecCenterAuditChainVerifyAndExport(t *testing.T) {
	cfg := testCfg()
	chain := newAuditTestChain(t, false)
	seedChain(t, chain, 2)
	mux := newSecTestMux(cfg, chain, "")

	rec := secGet(t, mux, cfg, testAdminUser, roleAdmin, auditChainVerifyPath)
	var v auditChainVerifyView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if !v.OK || v.Events != 2 {
		t.Fatalf("校验应 ok 且 2 条事件，实际 %+v", v)
	}

	rec = secGet(t, mux, cfg, testAdminUser, roleAdmin, auditChainExportPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("导出应 200，实际 %d", rec.Code)
	}
	if cd := rec.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("导出应带 attachment 头，实际 %q", cd)
	}
	lines := strings.Split(strings.TrimSpace(rec.Body.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("导出应为 2 行 JSONL，实际 %d", len(lines))
	}
}

func TestSecCenterRequiresAuth(t *testing.T) {
	cfg := testCfg()
	chain := newAuditTestChain(t, false)
	mux := newSecTestMux(cfg, chain, "")

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, auditChainPath, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，实际 %d", rec.Code)
	}
}

// newTeeStub 构造 tee-infer 假上游：healthz 返回指定状态码，/config 返回摘要。
func newTeeStub(t *testing.T, healthStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(healthStatus)
	})
	mux.HandleFunc("/config", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(teeAdminHeader) != "tee-tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"pii_mode":"mask","guardrail":{"enabled":true,"pii_rules":4,"sql_rules":8}}`))
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func TestSecCenterStatusAggregatesTee(t *testing.T) {
	cfg := testCfg()
	chain := newAuditTestChain(t, false)
	seedChain(t, chain, 1)
	ts := newTeeStub(t, http.StatusOK)
	mux := newSecTestMux(cfg, chain, ts.URL)

	// auditor 可读（D10 只读定位）。
	rec := secGet(t, mux, cfg, "bob", roleAuditor, secStatusPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("sec-status 应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	var view secStatusView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("响应非合法 JSON：%v", err)
	}
	if view.TEEHealth != "ok" || view.TEEHTTPStatus != http.StatusOK {
		t.Fatalf("tee 可达应 ok/200，实际 %s/%d", view.TEEHealth, view.TEEHTTPStatus)
	}
	if len(view.TEEConfig) == 0 {
		t.Fatal("应聚合 tee-infer /config 摘要")
	}
	if !view.AuditChain.Enabled || !view.AuditChain.Verified || view.AuditChain.Events != 1 {
		t.Fatalf("G1 链状态不符：%+v", view.AuditChain)
	}
	if len(view.AuditChain.LastHash) != 8 {
		t.Fatalf("链尾哈希应只给前 8 位（最小披露），实际 %q", view.AuditChain.LastHash)
	}
}

func TestSecCenterStatusTeeUnreachableIsReported(t *testing.T) {
	cfg := testCfg()
	chain := newAuditTestChain(t, false)
	// 127.0.0.1:1 无监听 → 连接失败。
	mux := newSecTestMux(cfg, chain, "http://127.0.0.1:1")

	rec := secGet(t, mux, cfg, testAdminUser, roleAdmin, secStatusPath)
	if rec.Code != http.StatusOK {
		t.Fatalf("tee 不可达时 sec-status 仍应 200（如实展示链路状态），实际 %d", rec.Code)
	}
	var view secStatusView
	_ = json.Unmarshal(rec.Body.Bytes(), &view)
	if view.TEEHealth != "unreachable" {
		t.Fatalf("tee 不可达应标注 unreachable，实际 %q", view.TEEHealth)
	}
}
