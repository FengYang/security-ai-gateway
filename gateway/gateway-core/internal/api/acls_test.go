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

// testACLServer 构造带 ACL 签名器的测试 Server。
func testACLServer(t *testing.T) (*Server, *a2aproxy.ACLSigner) {
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
	aclsig, err := a2aproxy.NewACLSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	s := New(sig, msig, rlsig, nil, store.NewMemory(), "tok",
		route.NewRouteTable(1, 1725500000), ratelimit.NewTable(1, time.Unix(1725500000, 0)))
	s.SetACLSigner(aclsig)
	return s, aclsig
}

// doACL 发起一次 ACL 控制面请求。
func doACL(t *testing.T, s *Server, method, path, body, token string) *httptest.ResponseRecorder {
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

// aclTableJSON 构造一份 ACL 表请求体。
func aclTableJSON(version int, rules ...a2aproxy.ACLRule) string {
	tbl := a2aproxy.NewACLTable(version, time.Unix(1725500000, 0))
	tbl.Rules = rules
	b, _ := json.Marshal(tbl)
	return string(b)
}

// TestACLGetEmptyTable 未下发时返回空表占位。
func TestACLGetEmptyTable(t *testing.T) {
	s, _ := testACLServer(t)
	rec := doACL(t, s, http.MethodGet, "/a2a-acls", "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var tbl a2aproxy.ACLTable
	if err := json.Unmarshal(rec.Body.Bytes(), &tbl); err != nil {
		t.Fatal(err)
	}
	if tbl.Version != 0 || len(tbl.Rules) != 0 {
		t.Fatalf("空表占位异常: %+v", tbl)
	}
}

// TestACLRequiresAuth 未鉴权 → 401。
func TestACLRequiresAuth(t *testing.T) {
	s, _ := testACLServer(t)
	rec := doACL(t, s, http.MethodGet, "/a2a-acls", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}

// TestACLPutAndGet 下发 ACL 表后可拉取（带签名）。
func TestACLPutAndGet(t *testing.T) {
	s, aclsig := testACLServer(t)
	body := aclTableJSON(1, a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"})
	rec := doACL(t, s, http.MethodPut, "/a2a-acls", body, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	rec = doACL(t, s, http.MethodGet, "/a2a-acls", "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	var tbl a2aproxy.ACLTable
	if err := json.Unmarshal(rec.Body.Bytes(), &tbl); err != nil {
		t.Fatal(err)
	}
	if tbl.Version != 1 || len(tbl.Rules) != 1 {
		t.Fatalf("表内容异常: %+v", tbl)
	}
	// 签名须可验（数据面据此替换生效策略）。
	if !aclsig.VerifyTable(&tbl) {
		t.Fatal("下发的 ACL 表签名不可验")
	}
}

// TestACLPutRejectsUnknownFields 未知字段 → 400（策略通道不得当高权通道）。
func TestACLPutRejectsUnknownFields(t *testing.T) {
	s, _ := testACLServer(t)
	body := `{"version":1,"issued_at":"2026-10-20T00:00:00Z","rules":[],"consumers":["x"]}`
	rec := doACL(t, s, http.MethodPut, "/a2a-acls", body, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestACLPutRejectsInvalidRule 非法规则 → 400。
func TestACLPutRejectsInvalidRule(t *testing.T) {
	s, _ := testACLServer(t)
	body := `{"version":1,"issued_at":"2026-10-20T00:00:00Z","rules":[{"tenant":"t"}]}`
	rec := doACL(t, s, http.MethodPut, "/a2a-acls", body, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestACLPutRejectsStaleVersion 防回滚：低版本 → 409。
func TestACLPutRejectsStaleVersion(t *testing.T) {
	s, _ := testACLServer(t)
	body := aclTableJSON(5, a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "a", Skill: "s"})
	if rec := doACL(t, s, http.MethodPut, "/a2a-acls", body, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("首次下发失败: %d %s", rec.Code, rec.Body.String())
	}
	// 同版本 → 409（防同版本内容漂移）。
	if rec := doACL(t, s, http.MethodPut, "/a2a-acls", body, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("同版本 status = %d, want 409", rec.Code)
	}
	// 低版本 → 409（防回滚）。
	older := aclTableJSON(3, a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "a", Skill: "s"})
	if rec := doACL(t, s, http.MethodPut, "/a2a-acls", older, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("低版本 status = %d, want 409", rec.Code)
	}
}

// TestACLRollback 回滚：以历史版本规则生成新版本（版本仍单调）。
func TestACLRollback(t *testing.T) {
	s, _ := testACLServer(t)
	v1 := aclTableJSON(1, a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "a", Skill: "s1"})
	if rec := doACL(t, s, http.MethodPut, "/a2a-acls", v1, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("下发 v1 失败: %d %s", rec.Code, rec.Body.String())
	}
	v2 := aclTableJSON(2, a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "a", Skill: "s2"})
	if rec := doACL(t, s, http.MethodPut, "/a2a-acls", v2, "tok"); rec.Code != http.StatusOK {
		t.Fatalf("下发 v2 失败: %d %s", rec.Code, rec.Body.String())
	}
	rec := doACL(t, s, http.MethodPost, "/a2a-acls/rollback", `{"version":1}`, "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	// 回滚后版本为 3（单调递增），规则回到 v1。
	rec = doACL(t, s, http.MethodGet, "/a2a-acls", "", "tok")
	var tbl a2aproxy.ACLTable
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

// TestACLRollbackUnknownVersion 回滚到不存在的版本 → 400。
func TestACLRollbackUnknownVersion(t *testing.T) {
	s, _ := testACLServer(t)
	body := aclTableJSON(1, a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "a", Skill: "s"})
	doACL(t, s, http.MethodPut, "/a2a-acls", body, "tok")
	rec := doACL(t, s, http.MethodPost, "/a2a-acls/rollback", `{"version":99}`, "tok")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

// TestACLPutWithoutSignerFailsClosed 未配置签名器 → 503（不得签表）。
func TestACLPutWithoutSignerFailsClosed(t *testing.T) {
	s, _ := testACLServer(t)
	s.SetACLSigner(nil)
	body := aclTableJSON(1, a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "a", Skill: "s"})
	rec := doACL(t, s, http.MethodPut, "/a2a-acls", body, "tok")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}
}

// TestACLAuditOnChange 变更落审计链（谁/何时/哪条/旧→新）。
func TestACLAuditOnChange(t *testing.T) {
	s, _ := testACLServer(t)
	v1 := aclTableJSON(1, a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "a", Skill: "s1"})
	doACL(t, s, http.MethodPut, "/a2a-acls", v1, "tok")
	v2 := aclTableJSON(2,
		a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "a", Skill: "s1"},
		a2aproxy.ACLRule{Tenant: "tenant-a", Agent: "b", Skill: "s2"})
	doACL(t, s, http.MethodPut, "/a2a-acls", v2, "tok")

	events := s.audit.List(0)
	var added int
	for _, e := range events {
		if e.Action != aclAuditAction {
			continue
		}
		if e.Change == "added" && e.RuleID == "tenant-a/b/s2" {
			added++
		}
	}
	if added == 0 {
		t.Fatalf("审计链缺新增规则事件: %+v", events)
	}
	// 链完整性。
	if ok, idx := s.audit.Verify(); !ok {
		t.Fatalf("审计链断裂于第 %d 条", idx)
	}
	// history 端点可见。
	rec := doACL(t, s, http.MethodGet, "/a2a-acls/history", "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tenant-a/b/s2") {
		t.Fatalf("history 未含新增规则: %s", rec.Body.String())
	}
}

// TestACLDiffRules 差异计算：新增/删除/修改。
func TestACLDiffRules(t *testing.T) {
	prev := &a2aproxy.ACLTable{Rules: []a2aproxy.ACLRule{
		{Tenant: "t", Agent: "a", Skill: "s1"},
		{Tenant: "t", Agent: "b", Skill: "s2"},
	}}
	next := &a2aproxy.ACLTable{Rules: []a2aproxy.ACLRule{
		{Tenant: "t", Agent: "a", Skill: "s1"},
		{Tenant: "t", Agent: "c", Skill: "s3"},
	}}
	changes := aclDiffRules(prev, next)
	kinds := map[string]int{}
	for _, c := range changes {
		kinds[c.Change]++
	}
	if kinds["removed"] != 1 || kinds["added"] != 1 {
		t.Fatalf("差异计算异常: %+v", changes)
	}
	// 无变化时无差异。
	if len(aclDiffRules(next, next)) != 0 {
		t.Fatal("无变化时不应有差异")
	}
}

// TestACLSignerRoundTrip 签名/验签往返 + 篡改检测。
func TestACLSignerRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	sig, err := a2aproxy.NewACLSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	tbl := a2aproxy.NewACLTable(1, time.Unix(0, 0))
	tbl.Rules = []a2aproxy.ACLRule{{Tenant: "t", Agent: "a", Skill: "s"}}
	if err := sig.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	if !sig.VerifyTable(tbl) {
		t.Fatal("签名后应可验")
	}
	// 篡改规则 → 验签失败。
	tbl.Rules[0].Skill = "other"
	if sig.VerifyTable(tbl) {
		t.Fatal("篡改后不应验签通过")
	}
	// 验签字节流入口。
	tbl2 := a2aproxy.NewACLTable(1, time.Unix(0, 0))
	tbl2.Rules = []a2aproxy.ACLRule{{Tenant: "t", Agent: "a", Skill: "s"}}
	if err := sig.SignTable(tbl2); err != nil {
		t.Fatal(err)
	}
	raw, err := tbl2.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// 用带签名的 JSON 验证（签名在 JSON 的 signature 字段）。
	full, err := json.Marshal(tbl2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sig.VerifyACLTableBytes(full); err != nil {
		t.Fatalf("字节流验签失败: %v", err)
	}
	_ = raw
}
