package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// policyReq 构造带租户上下文与 If-Match 的策略请求。
func policyReq(method, target, body string, version int64) *http.Request {
	req := tenantRequest(method, target, body, "t_1", "u1")
	req.Header.Set("If-Match", itoa64(version))
	return req
}

func itoa64(v int64) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ---------- 策略 ----------

func TestPolicyGet_Default(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	w := httptest.NewRecorder()
	h.handleTenantPolicyGet(w, tenantRequest("GET", tenantPolicyPath, "", "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var v policyView
	json.NewDecoder(w.Body).Decode(&v)
	if v.Version != 0 {
		t.Errorf("未初始化 version 应为 0, got=%d", v.Version)
	}
	if v.Whitelist.Entries == nil || v.CategoryActions == nil {
		t.Error("空结构应为非 nil（便于前端消费）")
	}
}

func TestPolicyPut_CreateAndGet(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	body := `{"whitelist":{"entries":[{"id":"e-1","kind":"literal","value":"内部代号"}]},
	  "blacklist":{"entries":[{"id":"e-2","kind":"regex","value":"AKIA[0-9A-Z]{16}"}]},
	  "category_actions":{"pii_id_card":"mask","violence":"block"}}`
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, policyReq("PUT", tenantPolicyPath, body, 0))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var v policyView
	json.NewDecoder(w.Body).Decode(&v)
	if v.Version != 1 {
		t.Errorf("创建后 version 应为 1, got=%d", v.Version)
	}
	if len(v.Whitelist.Entries) != 1 || len(v.Blacklist.Entries) != 1 {
		t.Errorf("条目数不对: %+v", v)
	}
	// 回读
	w2 := httptest.NewRecorder()
	h.handleTenantPolicyGet(w2, tenantRequest("GET", tenantPolicyPath, "", "t_1", "u1"))
	var v2 policyView
	json.NewDecoder(w2.Body).Decode(&v2)
	if v2.Version != 1 || v2.CategoryActions["pii_id_card"] != "mask" {
		t.Errorf("回读不对: %+v", v2)
	}
}

func TestPolicyPut_VersionConflict(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	body := `{"whitelist":{"entries":[]},"blacklist":{"entries":[]},"category_actions":{}}`
	// 先创建（version 0 → 1）
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, policyReq("PUT", tenantPolicyPath, body, 0))
	if w.Code != http.StatusOK {
		t.Fatal("创建应成功")
	}
	// 再用过期 If-Match=0 → 409
	w2 := httptest.NewRecorder()
	h.handleTenantPolicyPut(w2, policyReq("PUT", tenantPolicyPath, body, 0))
	if w2.Code != http.StatusConflict {
		t.Errorf("版本冲突应 409, got=%d", w2.Code)
	}
}

func TestPolicyPut_MissingIfMatch_400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	req := tenantRequest("PUT", tenantPolicyPath, `{}`, "t_1", "u1") // 无 If-Match
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("缺 If-Match 应 400, got=%d", w.Code)
	}
}

func TestPolicyPut_UnknownCategory_400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	body := `{"whitelist":{"entries":[]},"blacklist":{"entries":[]},"category_actions":{"not_a_category":"block"}}`
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, policyReq("PUT", tenantPolicyPath, body, 0))
	if w.Code != http.StatusBadRequest {
		t.Errorf("未知类目应 400, got=%d", w.Code)
	}
}

func TestPolicyPut_InvalidAction_400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	body := `{"whitelist":{"entries":[]},"blacklist":{"entries":[]},"category_actions":{"violence":"destroy"}}`
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, policyReq("PUT", tenantPolicyPath, body, 0))
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法动作应 400, got=%d", w.Code)
	}
}

func TestPolicyPut_BadKind_400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	body := `{"whitelist":{"entries":[{"kind":"glob","value":"x"}]},"blacklist":{"entries":[]},"category_actions":{}}`
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, policyReq("PUT", tenantPolicyPath, body, 0))
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法 kind 应 400, got=%d", w.Code)
	}
}

func TestPolicyPut_ValueTooLong_400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	long := strings.Repeat("a", 257)
	body := `{"whitelist":{"entries":[{"kind":"literal","value":"` + long + `"}]},"blacklist":{"entries":[]},"category_actions":{}}`
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, policyReq("PUT", tenantPolicyPath, body, 0))
	if w.Code != http.StatusBadRequest {
		t.Errorf("超长 value 应 400, got=%d", w.Code)
	}
}

func TestPolicyPut_BadRegex_400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	body := `{"whitelist":{"entries":[]},"blacklist":{"entries":[{"kind":"regex","value":"("}]},"category_actions":{}}`
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, policyReq("PUT", tenantPolicyPath, body, 0))
	if w.Code != http.StatusBadRequest {
		t.Errorf("非法 regex 应 400, got=%d", w.Code)
	}
}

func TestPolicyPut_EntryLimit_400(t *testing.T) {
	cfg := testTenantCfg()
	cfg.policyLimits = map[string]int{"free": 1}
	h, _, _ := newAPITestHandler(t, cfg, nil)
	body := `{"whitelist":{"entries":[{"kind":"literal","value":"a"},{"kind":"literal","value":"b"}]},"blacklist":{"entries":[]},"category_actions":{}}`
	w := httptest.NewRecorder()
	h.handleTenantPolicyPut(w, policyReq("PUT", tenantPolicyPath, body, 0))
	if w.Code != http.StatusBadRequest {
		t.Errorf("超套餐条目上限应 400, got=%d", w.Code)
	}
}

func TestPolicyApply_Returns503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	w := httptest.NewRecorder()
	h.handleTenantPolicyApply(w, tenantRequest("POST", tenantPolicyApplyPath, "{}", "t_1", "u1"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("依赖未就绪应 503, got=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "tenant_scope_unavailable") {
		t.Errorf("应返回明确原因: %s", w.Body.String())
	}
}

// ---------- 模型 ----------

func TestModels_EmptyCatalog(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, _ := newTenantBillingTestHandler(t)
	h.billing = bh
	// h.catalog == nil → 目录为空
	w := httptest.NewRecorder()
	h.handleTenantModels(w, tenantRequest("GET", tenantModelsPath, "", "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var resp struct {
		Models []any `json:"models"`
	}
	json.NewDecoder(w.Body).Decode(&resp)
	if len(resp.Models) != 0 {
		t.Errorf("空目录应返回空列表, got=%d", len(resp.Models))
	}
}

func TestModels_BillingDisabled_503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil) // billing nil
	w := httptest.NewRecorder()
	h.handleTenantModels(w, tenantRequest("GET", tenantModelsPath, "", "t_1", "u1"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("billing 未启用应 503, got=%d", w.Code)
	}
}

func TestModelsConfigPut_EmptyAllowed_Success(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, _ := newTenantBillingTestHandler(t)
	h.billing = bh

	req := tenantRequest("PUT", tenantModelsConfigPath, `{"allowed_models":[],"default_model":""}`, "t_1", "u1")
	req.Header.Set("If-Match", "0")
	w := httptest.NewRecorder()
	h.handleTenantModelsConfigPut(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var v modelsConfigView
	json.NewDecoder(w.Body).Decode(&v)
	if v.Version != 1 {
		t.Errorf("创建后 version 应为 1, got=%d", v.Version)
	}
}

func TestModelsConfigPut_RejectedID_400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, _ := newTenantBillingTestHandler(t)
	h.billing = bh // 目录空 → 任何 ID 均被拒

	req := tenantRequest("PUT", tenantModelsConfigPath, `{"allowed_models":["gpt-4o-mini"],"default_model":""}`, "t_1", "u1")
	req.Header.Set("If-Match", "0")
	w := httptest.NewRecorder()
	h.handleTenantModelsConfigPut(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("交集外 ID 应 400, got=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "gpt-4o-mini") {
		t.Errorf("应回带被拒 ID 列表: %s", w.Body.String())
	}
}

func TestModelsConfigPut_DefaultNotInAllowed_400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, _ := newTenantBillingTestHandler(t)
	h.billing = bh

	req := tenantRequest("PUT", tenantModelsConfigPath, `{"allowed_models":[],"default_model":"x"}`, "t_1", "u1")
	req.Header.Set("If-Match", "0")
	w := httptest.NewRecorder()
	h.handleTenantModelsConfigPut(w, req)
	if w.Code != http.StatusBadRequest {
		t.Errorf("default 不在 allowed 应 400, got=%d（body=%s）", w.Code, w.Body.String())
	}
}

func TestModelsConfigPut_VersionConflict_409(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	bh, _ := newTenantBillingTestHandler(t)
	h.billing = bh

	req := tenantRequest("PUT", tenantModelsConfigPath, `{"allowed_models":[],"default_model":""}`, "t_1", "u1")
	req.Header.Set("If-Match", "0")
	w := httptest.NewRecorder()
	h.handleTenantModelsConfigPut(w, req)
	if w.Code != http.StatusOK {
		t.Fatal("首次应成功")
	}
	req2 := tenantRequest("PUT", tenantModelsConfigPath, `{"allowed_models":[],"default_model":""}`, "t_1", "u1")
	req2.Header.Set("If-Match", "0")
	w2 := httptest.NewRecorder()
	h.handleTenantModelsConfigPut(w2, req2)
	if w2.Code != http.StatusConflict {
		t.Errorf("版本冲突应 409, got=%d", w2.Code)
	}
}

func TestModelsConfigGet_Default(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	w := httptest.NewRecorder()
	h.handleTenantModelsConfigGet(w, tenantRequest("GET", tenantModelsConfigPath, "", "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var v modelsConfigView
	json.NewDecoder(w.Body).Decode(&v)
	if v.Version != 0 || v.AllowedModels == nil {
		t.Errorf("未初始化应 version=0 + 非 nil 列表: %+v", v)
	}
}

// ---------- 工具 ----------

func TestParseIfMatch(t *testing.T) {
	cases := map[string]struct {
		v  int64
		ok bool
	}{
		"0": {0, true}, "3": {3, true}, `"5"`: {5, true},
		"": {0, false}, "abc": {0, false}, "-1": {0, false},
	}
	for in, want := range cases {
		v, ok := parseIfMatch(in)
		if ok != want.ok || (ok && v != want.v) {
			t.Errorf("parseIfMatch(%q)=(%d,%v) want=(%d,%v)", in, v, ok, want.v, want.ok)
		}
	}
}

func TestNormalizePolicyEntries(t *testing.T) {
	in := policyListView{Entries: []policyEntry{{Kind: "literal", Value: "x"}}}
	out := normalizePolicyEntries(in)
	if len(out.Entries) != 1 {
		t.Fatal("条目数不应变")
	}
	if out.Entries[0].ID == "" || out.Entries[0].CreatedAt == 0 {
		t.Errorf("应补齐 id/created_at: %+v", out.Entries[0])
	}
}

func TestRegexCompilesWithin(t *testing.T) {
	if !regexCompilesWithin("AKIA[0-9A-Z]{16}") {
		t.Error("合法 regex 应通过")
	}
	if regexCompilesWithin("(") {
		t.Error("非法 regex 应拒绝")
	}
}
