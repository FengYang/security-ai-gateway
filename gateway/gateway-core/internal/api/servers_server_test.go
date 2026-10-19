package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"security-ai-gateway/gateway/gateway-core/internal/mcpsrv"
	"security-ai-gateway/gateway/gateway-core/internal/policyaudit"
	"security-ai-gateway/gateway/mcpsec"
)

// doServers 发起 /tools/servers* 请求（T-3）。
func doServers(s *Server, method, path, body, token string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, req)
	return rec
}

// mustServer 注册一个后端（断言 201）。
func mustServer(t *testing.T, s *Server, body string) {
	t.Helper()
	if rec := doServers(s, http.MethodPost, "/tools/servers", body, "tok"); rec.Code != http.StatusCreated {
		t.Fatalf("注册应 201，got %d body=%s", rec.Code, rec.Body.String())
	}
}

type serversListResp struct {
	CatalogVersion int             `json:"catalog_version"`
	Servers        []mcpsrv.Server `json:"servers"`
}

func TestServersAuthRequired(t *testing.T) {
	s := testServer()
	if rec := doServers(s, http.MethodGet, "/tools/servers", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET 无 token 应 401，got %d", rec.Code)
	}
	if rec := doServers(s, http.MethodPost, "/tools/servers", `{}`, ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST 无 token 应 401，got %d", rec.Code)
	}
	if rec := doServers(s, http.MethodDelete, "/tools/servers/x", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("DELETE 无 token 应 401，got %d", rec.Code)
	}
}

// TestServersCRUDAndCatalogVersions T-3：注册 CRUD + 每次变更重签目录（版本单调，R-9）
// + mcp_server_changed 审计（added/updated/removed，旧→新与版本区间）。
func TestServersCRUDAndCatalogVersions(t *testing.T) {
	s := testServer()
	// 初始：空注册、目录版本 0
	rec := doServers(s, http.MethodGet, "/tools/servers", "", "tok")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET 应 200，got %d", rec.Code)
	}
	var env serversListResp
	_ = json.Unmarshal(rec.Body.Bytes(), &env)
	if env.CatalogVersion != 0 || len(env.Servers) != 0 {
		t.Fatalf("初始应为空注册/版本 0: %+v", env)
	}
	// 注册 s1（尾斜杠/大小写 host 应被规范化；health 缺省 unknown）
	add := doServers(s, http.MethodPost, "/tools/servers",
		`{"id":"s1","base_url":"http://10.0.0.1:8080/","track":"public","prefix":"fin"}`, "tok")
	if add.Code != http.StatusCreated {
		t.Fatalf("注册应 201，got %d body=%s", add.Code, add.Body.String())
	}
	var addResp struct {
		Server         mcpsrv.Server `json:"server"`
		CatalogVersion int           `json:"catalog_version"`
	}
	_ = json.Unmarshal(add.Body.Bytes(), &addResp)
	if addResp.CatalogVersion != 1 {
		t.Fatalf("首次注册应重签目录到版本 1，got %d", addResp.CatalogVersion)
	}
	if addResp.Server.BaseURL != "http://10.0.0.1:8080" || addResp.Server.Health != "unknown" {
		t.Fatalf("登记条目规范化/缺省不符: %+v", addResp.Server)
	}
	// 单查
	if g := doServers(s, http.MethodGet, "/tools/servers/s1", "", "tok"); g.Code != http.StatusOK {
		t.Fatalf("GET s1 应 200，got %d", g.Code)
	}
	// 更新 base_url/health → 版本 2；审计 added(1) + updated(2)
	up := doServers(s, http.MethodPost, "/tools/servers",
		`{"id":"s1","base_url":"http://10.0.0.2:8080","track":"public","prefix":"fin","health":"healthy"}`, "tok")
	if up.Code != http.StatusCreated {
		t.Fatalf("更新应 201，got %d body=%s", up.Code, up.Body.String())
	}
	var upResp struct {
		CatalogVersion int `json:"catalog_version"`
	}
	_ = json.Unmarshal(up.Body.Bytes(), &upResp)
	if upResp.CatalogVersion != 2 {
		t.Fatalf("更新应重签到版本 2，got %d", upResp.CatalogVersion)
	}
	evs := s.audit.List(0)
	if len(evs) != 3 {
		t.Fatalf("应累计 3 条审计（added+updated×2），got %d: %+v", len(evs), evs)
	}
	if evs[0].Action != policyaudit.ActionMCPServerChanged || evs[0].Change != policyaudit.ChangeAdded ||
		evs[0].RuleID != "s1" || evs[0].VersionFrom != 0 || evs[0].VersionTo != 1 {
		t.Fatalf("added 事件字段不符: %+v", evs[0])
	}
	for _, e := range evs[1:] {
		if e.Change != policyaudit.ChangeUpdated || e.VersionFrom != 1 || e.VersionTo != 2 {
			t.Fatalf("updated 事件字段不符: %+v", e)
		}
	}
	// 注册 s2 → 版本 3
	mustServer(t, s, `{"id":"s2","base_url":"http://10.0.0.3:8080","prefix":"ops","track":"secure"}`)
	if v := s.catalogVersion(); v != 3 {
		t.Fatalf("注册 s2 后目录版本应为 3，got %d", v)
	}
	// 删除 s2 → 版本 4
	del := doServers(s, http.MethodDelete, "/tools/servers/s2", "", "tok")
	if del.Code != http.StatusOK {
		t.Fatalf("摘除应 200，got %d body=%s", del.Code, del.Body.String())
	}
	var delResp struct {
		Removed        bool `json:"removed"`
		ToolsConverged int  `json:"tools_converged"`
		CatalogVersion int  `json:"catalog_version"`
	}
	_ = json.Unmarshal(del.Body.Bytes(), &delResp)
	if !delResp.Removed || delResp.CatalogVersion != 4 {
		t.Fatalf("摘除响应不符: %+v", delResp)
	}
	// 已摘除：单查/重复摘除均 404
	if rec := doServers(s, http.MethodGet, "/tools/servers/s2", "", "tok"); rec.Code != http.StatusNotFound {
		t.Fatalf("已摘除应 404，got %d", rec.Code)
	}
	if rec := doServers(s, http.MethodDelete, "/tools/servers/s2", "", "tok"); rec.Code != http.StatusNotFound {
		t.Fatalf("重复摘除应 404，got %d", rec.Code)
	}
	// 列表剩 s1
	gl := doServers(s, http.MethodGet, "/tools/servers", "", "tok")
	var glEnv serversListResp
	_ = json.Unmarshal(gl.Body.Bytes(), &glEnv)
	if glEnv.CatalogVersion != 4 || len(glEnv.Servers) != 1 || glEnv.Servers[0].ID != "s1" {
		t.Fatalf("收口列表不符: %+v", glEnv)
	}
	if ok, at := s.audit.Verify(); !ok {
		t.Fatalf("审计链校验应通过，断点 %d", at)
	}
}

func TestServersValidationAndConflict(t *testing.T) {
	s := testServer()
	bad := []string{
		`{"id":"Bad!","base_url":"http://h","prefix":"p"}`,
		`{"id":"ok","base_url":"http://u:pw@h","prefix":"p"}`,
		`{"id":"ok","base_url":"http://h","prefix":"p","track":"internal"}`,
		`{"id":"ok","base_url":"http://h","prefix":""}`,
		`not-json`,
	}
	for _, b := range bad {
		if rec := doServers(s, http.MethodPost, "/tools/servers", b, "tok"); rec.Code != http.StatusBadRequest {
			t.Fatalf("非法载荷应 400，got %d body=%s", rec.Code, rec.Body.String())
		}
	}
	mustServer(t, s, `{"id":"a","base_url":"http://a:1","prefix":"fin"}`)
	// prefix 冲突 → 409
	if rec := doServers(s, http.MethodPost, "/tools/servers", `{"id":"b","base_url":"http://b:1","prefix":"fin"}`, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("prefix 冲突应 409，got %d body=%s", rec.Code, rec.Body.String())
	}
	// 生效命名空间冲突 → 409
	if rec := doServers(s, http.MethodPost, "/tools/servers", `{"id":"b","base_url":"http://b:1","prefix":"ops","namespace":"fin"}`, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("命名空间冲突应 409，got %d", rec.Code)
	}
	// 自身更新放行（同 prefix 改 base_url）
	if rec := doServers(s, http.MethodPost, "/tools/servers", `{"id":"a","base_url":"http://a:2","prefix":"fin"}`, "tok"); rec.Code != http.StatusCreated {
		t.Fatalf("自身更新应放行，got %d body=%s", rec.Code, rec.Body.String())
	}
	// 被拒操作不产生审计事件
	if n := s.audit.Len(); n != 2 { // added a + 自身更新（base_url） → 2 条
		t.Fatalf("审计应仅含成功变更（2 条），got %d", n)
	}
	if ok, at := s.audit.Verify(); !ok {
		t.Fatalf("审计链校验应通过，断点 %d", at)
	}
}

// TestServersCatalogLinkageAndConvergence T-3：命名空间缺省补全、servers[] 摘要镜像、
// 摘除收敛（tools/list 不再返回）与审计留痕。
func TestServersCatalogLinkageAndConvergence(t *testing.T) {
	s := testServer()
	mustServer(t, s, `{"id":"s1","base_url":"http://s1:8080","track":"public","prefix":"fin"}`)
	mustServer(t, s, `{"id":"s2","base_url":"http://s2:8080","track":"secure","prefix":"ops"}`)
	body := `{"kind":"catalog","data":{"tools":[` +
		`{"name":"t1","catalog_owner":"o","server":"s1"},` +
		`{"name":"t2","catalog_owner":"o","server":"s2"},` +
		`{"name":"t3","catalog_owner":"o"}]}}`
	rec := doToolPolicy(s, body, "tok")
	if rec.Code != http.StatusCreated {
		t.Fatalf("目录签发应 201，got %d body=%s", rec.Code, rec.Body.String())
	}
	var c mcpsec.ToolCatalog
	_ = json.Unmarshal(rec.Body.Bytes(), &c)
	if c.Version != 3 {
		t.Fatalf("目录版本应为 3（注册×2 各 +1），got %d", c.Version)
	}
	if !s.msigner.ValidCatalog(&c) {
		t.Fatal("目录应验签通过")
	}
	if c.Tools[0].Namespace != "fin" || c.Tools[1].Namespace != "ops" || c.Tools[2].Namespace != "" {
		t.Fatalf("命名空间缺省补全不符: %+v", c.Tools)
	}
	if len(c.Servers) != 2 || c.Servers[0].ID != "s1" || c.Servers[1].ID != "s2" {
		t.Fatalf("servers[] 摘要应镜像注册域: %+v", c.Servers)
	}
	// 摘除 s1 → t1 收敛；版本 4
	del := doServers(s, http.MethodDelete, "/tools/servers/s1", "", "tok")
	var delResp struct {
		ToolsConverged int `json:"tools_converged"`
		CatalogVersion int `json:"catalog_version"`
	}
	_ = json.Unmarshal(del.Body.Bytes(), &delResp)
	if delResp.ToolsConverged != 1 || delResp.CatalogVersion != 4 {
		t.Fatalf("摘除收敛不符: %+v", delResp)
	}
	g := doGetToolPolicy(s, "catalog", "tok")
	var got mcpsec.ToolCatalog
	_ = json.Unmarshal(g.Body.Bytes(), &got)
	if !s.msigner.ValidCatalog(&got) || got.Version != 4 {
		t.Fatalf("收敛后目录验签/版本不符: version=%d", got.Version)
	}
	if len(got.Tools) != 2 || got.Tools[0].NamespacedName() != "ops__t2" || got.Tools[1].NamespacedName() != "t3" {
		t.Fatalf("目录收敛结果不符: %+v", got.Tools)
	}
	if len(got.Servers) != 1 || got.Servers[0].ID != "s2" {
		t.Fatalf("servers[] 应收敛到 s2: %+v", got.Servers)
	}
	evs := s.audit.List(0)
	last := evs[len(evs)-1]
	if last.Change != policyaudit.ChangeRemoved || last.RuleID != "s1" || !strings.Contains(last.OldValue, "fin") {
		t.Fatalf("removed 事件不符: %+v", last)
	}
	if last.VersionFrom != 3 || last.VersionTo != 4 {
		t.Fatalf("removed 版本区间应为 3→4: %+v", last)
	}
	if ok, at := s.audit.Verify(); !ok {
		t.Fatalf("审计链校验应通过，断点 %d", at)
	}
}

// TestCatalogToolsConflictRejected T-3：目录校验 fail-closed（未注册引用/同名冲突/非法名）。
func TestCatalogToolsConflictRejected(t *testing.T) {
	s := testServer()
	mustServer(t, s, `{"id":"s1","base_url":"http://s1:8080","prefix":"fin"}`)
	// 同一后端同名工具（同命名空间名）→ 409
	dup := `{"kind":"catalog","data":{"tools":[
		{"name":"q","catalog_owner":"o","server":"s1"},
		{"name":"q","catalog_owner":"o","server":"s1"}]}}`
	if rec := doToolPolicy(s, dup, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("同名冲突应 409，got %d body=%s", rec.Code, rec.Body.String())
	}
	// 显式 namespace 与 server 前缀派生撞车（fin__q vs fin__q）→ 409
	clash := `{"kind":"catalog","data":{"tools":[
		{"name":"q","catalog_owner":"o","namespace":"fin"},
		{"name":"q","catalog_owner":"o","server":"s1"}]}}`
	if rec := doToolPolicy(s, clash, "tok"); rec.Code != http.StatusConflict {
		t.Fatalf("跨来源命名空间名撞车应 409，got %d", rec.Code)
	}
	// 未注册后端引用 → 400
	unknown := `{"kind":"catalog","data":{"tools":[{"name":"q","catalog_owner":"o","server":"nope"}]}}`
	if rec := doToolPolicy(s, unknown, "tok"); rec.Code != http.StatusBadRequest {
		t.Fatalf("未注册后端应 400，got %d", rec.Code)
	}
	// namespace 非法（含 `_`，破坏 "<ns>__<name>" 无歧义解析）→ 400
	badNS := `{"kind":"catalog","data":{"tools":[{"name":"q","catalog_owner":"o","namespace":"a_b"}]}}`
	if rec := doToolPolicy(s, badNS, "tok"); rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 namespace 应 400，got %d", rec.Code)
	}
	// 同名不同命名空间：放行（前缀命名空间化后不冲突）
	ok := `{"kind":"catalog","data":{"tools":[
		{"name":"q","catalog_owner":"o"},
		{"name":"q","catalog_owner":"o","server":"s1"}]}}`
	if rec := doToolPolicy(s, ok, "tok"); rec.Code != http.StatusCreated {
		t.Fatalf("不同命名空间同名应放行，got %d body=%s", rec.Code, rec.Body.String())
	}
	// 被拒操作不推进目录版本：注册 v1 + 放行签发 v2
	if v := s.catalogVersion(); v != 2 {
		t.Fatalf("目录版本应仅由成功变更推进，got %d", v)
	}
}
