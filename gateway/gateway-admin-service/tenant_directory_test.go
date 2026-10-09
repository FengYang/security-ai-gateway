package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTenantDirectory_Hit(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	tenantID, _ := seedTenantUser(t, store, "dir@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	w := httptest.NewRecorder()
	h.handleTenantDirectoryLookup(w, httptest.NewRequest("GET",
		tenantDirectoryLookupPath+"?email=dir@example.com", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("命中应 200, got=%d body=%s", w.Code, w.Body.String())
	}
	var v tenantDirectoryView
	if err := json.NewDecoder(w.Body).Decode(&v); err != nil {
		t.Fatal(err)
	}
	if v.TenantID != tenantID || v.TenantRole != tenantRole || v.Status != tenantUserStatusActive {
		t.Errorf("响应不对: %+v", v)
	}
	// 不含邮箱明文/密码等敏感字段（最小披露）
	body := w.Body.String()
	for _, forbidden := range []string{"dir@example.com", "password", "PasswordHash"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("响应不应含 %s: %s", forbidden, body)
		}
	}
}

func TestTenantDirectory_EmailNormalized(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	seedTenantUser(t, store, "norm@example.com", "Password123!", tenantUserStatusActive, tenantStatusActive)

	// 大小写 + 空格 → 应归一化命中
	w := httptest.NewRecorder()
	h.handleTenantDirectoryLookup(w, httptest.NewRequest("GET",
		tenantDirectoryLookupPath+"?email=%20NORM@Example.COM%20", nil))
	if w.Code != http.StatusOK {
		t.Errorf("归一化后应命中 200, got=%d", w.Code)
	}
}

func TestTenantDirectory_PendingStatus(t *testing.T) {
	h, store, _ := newAPITestHandler(t, testTenantCfg(), nil)
	seedTenantUser(t, store, "pend@example.com", "Password123!", tenantUserStatusPending, tenantStatusPending)

	w := httptest.NewRecorder()
	h.handleTenantDirectoryLookup(w, httptest.NewRequest("GET",
		tenantDirectoryLookupPath+"?email=pend@example.com", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("应 200, got=%d", w.Code)
	}
	var v tenantDirectoryView
	json.NewDecoder(w.Body).Decode(&v)
	if v.Status != tenantUserStatusPending {
		t.Errorf("status 应为 pending, got=%s", v.Status)
	}
}

func TestTenantDirectory_NotFound_404(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	w := httptest.NewRecorder()
	h.handleTenantDirectoryLookup(w, httptest.NewRequest("GET",
		tenantDirectoryLookupPath+"?email=nobody@example.com", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("未命中应 404（禁止兜底 admin，C-14）, got=%d", w.Code)
	}
}

func TestTenantDirectory_InvalidEmail_400(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	for _, bad := range []string{"", "not-an-email", "@x.com"} {
		w := httptest.NewRecorder()
		h.handleTenantDirectoryLookup(w, httptest.NewRequest("GET",
			tenantDirectoryLookupPath+"?email="+bad, nil))
		if w.Code != http.StatusBadRequest {
			t.Errorf("非法邮箱 %q 应 400, got=%d", bad, w.Code)
		}
	}
}

func TestTenantDirectory_MethodNotAllowed_405(t *testing.T) {
	h, _, _ := newAPITestHandler(t, testTenantCfg(), nil)
	w := httptest.NewRecorder()
	h.handleTenantDirectoryLookup(w, httptest.NewRequest("POST", tenantDirectoryLookupPath, nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("非 GET 应 405, got=%d", w.Code)
	}
}
