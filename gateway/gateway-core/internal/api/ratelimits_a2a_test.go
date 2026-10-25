package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"security-ai-gateway/gateway/a2aproxy"
	"security-ai-gateway/gateway/gateway-core/internal/ratelimit"
	"security-ai-gateway/gateway/gateway-core/internal/route"
	"security-ai-gateway/gateway/gateway-core/internal/store"
	"security-ai-gateway/gateway/mcpsec"
)

// testRLServer 构造带 A2A 限流签名器的测试 Server。
func testRLServer(t *testing.T) (*Server, *a2aproxy.RateLimitSigner) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sig, err := route.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	msig, err := mcpsec.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	rlsig, err := ratelimit.NewSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	a2arlsig, err := a2aproxy.NewRateLimitSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	s := New(sig, msig, rlsig, nil, store.NewMemory(), "tok",
		route.NewRouteTable(1, 1725500000), ratelimit.NewTable(1, time.Unix(1725500000, 0)))
	s.SetRateLimitSigner(a2arlsig)
	return s, a2arlsig
}

// doRL 发起一次限流控制面请求。
func doRL(t *testing.T, s *Server, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	return rec
}

// rlTableJSON 构造一份限流表请求体。
func rlTableJSON(version int, rules ...a2aproxy.RateLimitRule) string {
	tbl := a2aproxy.NewRateLimitTable(version, time.Unix(1725500000, 0))
	tbl.Rules = rules
	b, _ := json.Marshal(tbl)
	return string(b)
}

// TestRLGetEmptyTable 未下发时返回空表占位。
func TestRLGetEmptyTable(t *testing.T) {
	s, _ := testRLServer(t)
	rec := doRL(t, s, http.MethodGet, "/a2a-ratelimits", "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var tbl a2aproxy.RateLimitTable
	if err := json.Unmarshal(rec.Body.Bytes(), &tbl); err != nil {
		t.Fatal(err)
	}
	if tbl.Version != 0 || len(tbl.Rules) != 0 {
		t.Fatalf("空表占位异常: %+v", tbl)
	}
}

// TestRLRequiresAuth 未鉴权 → 401。
func TestRLRequiresAuth(t *testing.T) {
	s, _ := testRLServer(t)
	rec := doRL(t, s, http.MethodGet, "/a2a-ratelimits", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestRLPutAndGet 下发限流表后可拉取（带签名）。
func TestRLPutAndGet(t *testing.T) {
	s, rlsig := testRLServer(t)
	body := rlTableJSON(1, a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize", RPM: 60})
	rec := doRL(t, s, http.MethodPut, "/a2a-ratelimits", body, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	rec = doRL(t, s, http.MethodGet, "/a2a-ratelimits", "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var tbl a2aproxy.RateLimitTable
	if err := json.Unmarshal(rec.Body.Bytes(), &tbl); err != nil {
		t.Fatal(err)
	}
	if tbl.Version != 1 || len(tbl.Rules) != 1 {
		t.Fatalf("表内容异常: %+v", tbl)
	}
	if !rlsig.VerifyTable(&tbl) {
		t.Fatal("下发的限流表签名不可验")
	}
}

// TestRLPutRejectsUnknownFields 未知字段 → 400（策略通道不得当高权通道）。
func TestRLPutRejectsUnknownFields(t *testing.T) {
	s, _ := testRLServer(t)
	body := `{"version":1,"issued_at":"2026-10-20T00:00:00Z","rules":[],"consumers":["x"]}`
	rec := doRL(t, s, http.MethodPut, "/a2a-ratelimits", body, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestRLPutRejectsInvalidRule 非法规则（rpm<=0）→ 400。
func TestRLPutRejectsInvalidRule(t *testing.T) {
	s, _ := testRLServer(t)
	body := `{"version":1,"issued_at":"2026-10-20T00:00:00Z","rules":[{"tenant":"t","agent":"a","skill":"s","rpm":0}]}`
	rec := doRL(t, s, http.MethodPut, "/a2a-ratelimits", body, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestRLPutRejectsStaleVersion 防回滚：低/同版本 → 409。
func TestRLPutRejectsStaleVersion(t *testing.T) {
	s, _ := testRLServer(t)
	body := rlTableJSON(5, a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "a", Skill: "s", RPM: 10})
	if rec := doRL(t, s, http.MethodPut, "/a2a-ratelimits", body, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("首次下发失败: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doRL(t, s, http.MethodPut, "/a2a-ratelimits", body, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("同版本 status = %d, want 409", rec.Code)
	}
	older := rlTableJSON(3, a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "a", Skill: "s", RPM: 10})
	if rec := doRL(t, s, http.MethodPut, "/a2a-ratelimits", older, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("低版本 status = %d, want 409", rec.Code)
	}
}

// TestRLRollback 回滚：以历史版本规则生成新版本（版本仍单调）。
func TestRLRollback(t *testing.T) {
	s, _ := testRLServer(t)
	v1 := rlTableJSON(1, a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "a", Skill: "s1", RPM: 10})
	if rec := doRL(t, s, http.MethodPut, "/a2a-ratelimits", v1, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("下发 v1 失败: %d %s", rec.Code, rec.Body.String())
	}
	v2 := rlTableJSON(2, a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "a", Skill: "s2", RPM: 20})
	if rec := doRL(t, s, http.MethodPut, "/a2a-ratelimits", v2, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("下发 v2 失败: %d %s", rec.Code, rec.Body.String())
	}
	rec := doRL(t, s, http.MethodPost, "/a2a-ratelimits/rollback", `{"version":1}`, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	rec = doRL(t, s, http.MethodGet, "/a2a-ratelimits", "", "tok")
	var tbl a2aproxy.RateLimitTable
	if err := json.Unmarshal(rec.Body.Bytes(), &tbl); err != nil {
		t.Fatal(err)
	}
	if tbl.Version != 3 {
		t.Fatalf("回滚后版本 = %d, want 3（版本须单调）", tbl.Version)
	}
	if len(tbl.Rules) != 1 || tbl.Rules[0].Skill != "s1" {
		t.Fatalf("回滚后规则异常: %+v", tbl.Rules)
	}
}

// TestRLRollbackUnknownVersion 回滚到不存在的版本 → 400。
func TestRLRollbackUnknownVersion(t *testing.T) {
	s, _ := testRLServer(t)
	body := rlTableJSON(1, a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "a", Skill: "s", RPM: 10})
	doRL(t, s, http.MethodPut, "/a2a-ratelimits", body, "tok")
	rec := doRL(t, s, http.MethodPost, "/a2a-ratelimits/rollback", `{"version":99}`, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestRLPutWithoutSignerFailsClosed 未配置签名器 → 503（不得签表）。
func TestRLPutWithoutSignerFailsClosed(t *testing.T) {
	s, _ := testRLServer(t)
	s.SetRateLimitSigner(nil)
	body := rlTableJSON(1, a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "a", Skill: "s", RPM: 10})
	rec := doRL(t, s, http.MethodPut, "/a2a-ratelimits", body, "tok")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestRLAuditOnChange 变更落审计链（谁/何时/哪条/旧→新）。
func TestRLAuditOnChange(t *testing.T) {
	s, _ := testRLServer(t)
	v1 := rlTableJSON(1, a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "a", Skill: "s1", RPM: 10})
	doRL(t, s, http.MethodPut, "/a2a-ratelimits", v1, "tok")
	v2 := rlTableJSON(2,
		a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "a", Skill: "s1", RPM: 10},
		a2aproxy.RateLimitRule{Tenant: "tenant-a", Agent: "b", Skill: "s2", RPM: 20})
	doRL(t, s, http.MethodPut, "/a2a-ratelimits", v2, "tok")

	events := s.audit.List(0)
	var added int
	for _, e := range events {
		if e.Action != rlAuditAction {
			continue
		}
		if e.Change == "added" && e.RuleID == "tenant-a/b/s2" {
			added++
		}
	}
	if added == 0 {
		t.Fatalf("审计链缺新增规则事件: %+v", events)
	}
	if ok, idx := s.audit.Verify(); !ok {
		t.Fatalf("审计链断裂于第 %d 条", idx)
	}
	rec := doRL(t, s, http.MethodGet, "/a2a-ratelimits/history", "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tenant-a/b/s2") {
		t.Fatalf("history 未含新增规则: %s", rec.Body.String())
	}
}

// TestRLDiffRules 差异计算：新增/删除/修改。
func TestRLDiffRules(t *testing.T) {
	prev := &a2aproxy.RateLimitTable{Rules: []a2aproxy.RateLimitRule{
		{Tenant: "t", Agent: "a", Skill: "s1", RPM: 10},
		{Tenant: "t", Agent: "b", Skill: "s2", RPM: 20},
	}}
	next := &a2aproxy.RateLimitTable{Rules: []a2aproxy.RateLimitRule{
		{Tenant: "t", Agent: "a", Skill: "s1", RPM: 10},
		{Tenant: "t", Agent: "c", Skill: "s3", RPM: 30},
	}}
	changes := rlDiffRules(prev, next)
	kinds := map[string]int{}
	for _, c := range changes {
		kinds[c.Change]++
	}
	if kinds["removed"] != 1 || kinds["added"] != 1 {
		t.Fatalf("差异计算异常: %+v", changes)
	}
	if len(rlDiffRules(next, next)) != 0 {
		t.Fatal("无变化时不应有差异")
	}
}
