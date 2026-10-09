package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------- 测试辅助 ----------

// fakeKeyIssuer 记录签发调用（token 随 jti 变化，保证指纹唯一）。
type fakeKeyIssuer struct {
	err    error
	calls  int
	tenant string
}

func (f *fakeKeyIssuer) IssueKey(_ context.Context, tenant, _, jti string, _ int64) (string, error) {
	f.calls++
	f.tenant = tenant
	if f.err != nil {
		return "", f.err
	}
	return "jwt-token-for-" + jti, nil
}

// tenantRequest 构造带租户上下文的请求。
func tenantRequest(method, target, body, tenantID, sub string) *http.Request {
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, bytes.NewBufferString(body))
	}
	req.RemoteAddr = "10.0.0.1:1234"
	return req.WithContext(withTenantClaims(req.Context(), &tenantClaims{
		Sub: sub, Tenant: tenantID, Role: tenantRole,
	}))
}

// createKey 便捷创建（返回响应体）。
func createKey(t *testing.T, h *tenantHandler, name string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	h.handleKeyCreate(w, tenantRequest("POST", apiKeysPath, `{"name":"`+name+`"}`, "t_1", "u1"))
	if w.Code != http.StatusOK {
		t.Fatalf("创建失败: %d %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("解析创建响应失败: %v", err)
	}
	return resp
}

// ---------- 创建 ----------

func TestKeyCreate_Success(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}

	resp := createKey(t, h, "prod")
	if resp["api_key"] == nil || resp["api_key"] == "" {
		t.Error("创建响应应含明文 api_key")
	}
	if resp["id"] == "" || resp["fingerprint"] == "" {
		t.Errorf("响应缺字段: %+v", resp)
	}
	keys, _ := store.ListAPIKeysByTenant("t_1")
	if len(keys) != 1 {
		t.Fatalf("应落库 1 条, got=%d", len(keys))
	}
	if keys[0].Status != apiKeyStatusActive || keys[0].JTI == "" || keys[0].CreatedBy != "u1" {
		t.Errorf("落库字段不对: %+v", keys[0])
	}

	// 列表不含明文
	w := httptest.NewRecorder()
	h.handleKeyList(w, tenantRequest("GET", apiKeysPath, "", "t_1", "u1"))
	if bytes.Contains(w.Body.Bytes(), []byte(resp["api_key"].(string))) {
		t.Error("列表不应含明文")
	}
}

func TestKeyCreate_IssuerNil_Returns503(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil) // authServiceURL 空 → issuer nil
	w := httptest.NewRecorder()
	h.handleKeyCreate(w, tenantRequest("POST", apiKeysPath, `{"name":"x"}`, "t_1", "u1"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("签发通道未就绪应 503, got=%d", w.Code)
	}
}

func TestKeyCreate_IssuerError_Returns503NoRecord(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{err: errors.New("connection refused")}
	w := httptest.NewRecorder()
	h.handleKeyCreate(w, tenantRequest("POST", apiKeysPath, `{"name":"x"}`, "t_1", "u1"))
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("签发失败应 503, got=%d", w.Code)
	}
	keys, _ := store.ListAPIKeysByTenant("t_1")
	if len(keys) != 0 {
		t.Error("签发失败不应留半成品（§9.1 判据 6）")
	}
}

func TestKeyCreate_DuplicateName_Returns409(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	createKey(t, h, "dup")

	w := httptest.NewRecorder()
	h.handleKeyCreate(w, tenantRequest("POST", apiKeysPath, `{"name":"dup"}`, "t_1", "u1"))
	if w.Code != http.StatusConflict {
		t.Errorf("重名应 409, got=%d", w.Code)
	}
}

func TestKeyCreate_InvalidName_Returns400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	w := httptest.NewRecorder()
	h.handleKeyCreate(w, tenantRequest("POST", apiKeysPath, `{"name":""}`, "t_1", "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("空 name 应 400, got=%d", w.Code)
	}
}

func TestKeyCreate_ExpireExceed_Returns400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	w := httptest.NewRecorder()
	h.handleKeyCreate(w, tenantRequest("POST", apiKeysPath, `{"name":"x","expire_days":9999}`, "t_1", "u1"))
	if w.Code != http.StatusBadRequest {
		t.Errorf("超上限应 400, got=%d", w.Code)
	}
}

func TestKeyCreate_NoTenantScope_Returns403(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	req := httptest.NewRequest("POST", apiKeysPath, bytes.NewBufferString(`{"name":"x"}`))
	w := httptest.NewRecorder()
	h.handleKeyCreate(w, req) // 无租户上下文
	if w.Code != http.StatusForbidden {
		t.Errorf("无租户上下文应 403, got=%d", w.Code)
	}
}

// ---------- 轮换 ----------

func TestKeyRotate_Success(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	old := createKey(t, h, "rot")
	oldID := old["id"].(string)

	req := tenantRequest("POST", apiKeysPath+"/"+oldID+"/rotate", "", "t_1", "u1")
	req.SetPathValue("id", oldID)
	w := httptest.NewRecorder()
	h.handleKeyRotate(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("轮换应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var resp map[string]any
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["api_key"] == "" || resp["id"] == oldID {
		t.Errorf("轮换应返回新 Key: %+v", resp)
	}

	oldKey, _ := store.GetAPIKeyByID(oldID)
	if oldKey.Status != apiKeyStatusRevoked {
		t.Errorf("旧 Key 应 revoked, got=%s", oldKey.Status)
	}
	keys, _ := store.ListAPIKeysByTenant("t_1")
	active := 0
	for _, k := range keys {
		if k.Status == apiKeyStatusActive {
			active++
		}
	}
	if active != 1 {
		t.Errorf("应恰有 1 个 active, got=%d", active)
	}
}

// ---------- 吊销 ----------

func TestKeyRevoke_Idempotent(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	created := createKey(t, h, "rev")
	id := created["id"].(string)

	for i := 0; i < 2; i++ {
		req := tenantRequest("DELETE", apiKeysPath+"/"+id, "", "t_1", "u1")
		req.SetPathValue("id", id)
		w := httptest.NewRecorder()
		h.handleKeyRevoke(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("第 %d 次吊销应 200（幂等）, got=%d", i+1, w.Code)
		}
	}
	got, _ := store.GetAPIKeyByID(id)
	if got.Status != apiKeyStatusRevoked || got.RevokedAt == 0 {
		t.Errorf("应已吊销且记 revoked_at: %+v", got)
	}
}

func TestKey_CrossTenant_Returns404(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	created := createKey(t, h, "cross")
	id := created["id"].(string)

	req := tenantRequest("DELETE", apiKeysPath+"/"+id, "", "t_2", "u2") // 另一租户
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	h.handleKeyRevoke(w, req)
	if w.Code != http.StatusNotFound {
		t.Errorf("跨租户应 404（不泄露存在性）, got=%d", w.Code)
	}
}

// ---------- 吊销拉取 ----------

func TestKeyRevocations_Since(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	h.issuer = &fakeKeyIssuer{}
	for _, name := range []string{"a", "b"} {
		created := createKey(t, h, name)
		id := created["id"].(string)
		req := tenantRequest("DELETE", apiKeysPath+"/"+id, "", "t_1", "u1")
		req.SetPathValue("id", id)
		h.handleKeyRevoke(httptest.NewRecorder(), req)
	}

	w := httptest.NewRecorder()
	h.handleKeyRevocations(w, httptest.NewRequest("GET", keyRevocationsPath+"?since=0", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("拉取应 200, got=%d", w.Code)
	}
	var resp struct {
		Revoked []struct {
			JTI       string `json:"jti"`
			RevokedAt int64  `json:"revoked_at"`
		} `json:"revoked"`
		ServerTime int64 `json:"server_time"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(resp.Revoked) != 2 {
		t.Errorf("应有 2 条吊销, got=%d", len(resp.Revoked))
	}
	if resp.ServerTime == 0 {
		t.Error("应含 server_time")
	}

	// since=未来 → 空
	w2 := httptest.NewRecorder()
	h.handleKeyRevocations(w2, httptest.NewRequest("GET", keyRevocationsPath+"?since=9999999999", nil))
	var resp2 struct {
		Revoked []any `json:"revoked"`
	}
	json.NewDecoder(w2.Body).Decode(&resp2)
	if len(resp2.Revoked) != 0 {
		t.Errorf("since 未来应返回空, got=%d", len(resp2.Revoked))
	}
}

// ---------- store 层 ----------

func TestAPIKeyStore_ActiveNameUnique(t *testing.T) {
	s := newTestStore(t)
	k := &APIKey{KeyID: "k-1", TenantID: "t_1", Name: "n", JTI: "j1",
		Fingerprint: "fp1", Status: apiKeyStatusActive, CreatedBy: "u", CreatedAt: 1, ExpiresAt: 2}
	tx, _ := s.Begin()
	if err := s.CreateAPIKey(tx, k); err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	tx.Commit()

	// 同租户同名 active → 唯一约束冲突
	tx2, _ := s.Begin()
	dup := &APIKey{KeyID: "k-2", TenantID: "t_1", Name: "n", JTI: "j2",
		Fingerprint: "fp2", Status: apiKeyStatusActive, CreatedBy: "u", CreatedAt: 1, ExpiresAt: 2}
	err := s.CreateAPIKey(tx2, dup)
	tx2.Rollback()
	if err == nil {
		t.Error("同名 active 应唯一约束冲突")
	}

	// 吊销旧 Key 后同名可再建
	tx3, _ := s.Begin()
	if err := s.RevokeAPIKey(tx3, "k-1", 99); err != nil {
		t.Fatal(err)
	}
	tx3.Commit()
	tx4, _ := s.Begin()
	if err := s.CreateAPIKey(tx4, dup); err != nil {
		t.Errorf("吊销后同名应可再建: %v", err)
	}
	tx4.Commit()
}

func TestAPIKeyStore_MigrationFromLegacy(t *testing.T) {
	// 旧占位表（M1）在打开时被迁移为 §3.5 结构
	s := newTestStore(t)
	var col string
	err := s.db.QueryRow(`SELECT name FROM pragma_table_info('api_keys') WHERE name='key_id'`).Scan(&col)
	if err != nil {
		t.Fatalf("迁移后应含 key_id 列: %v", err)
	}
}
