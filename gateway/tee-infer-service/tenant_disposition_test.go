// S4-4：租户处置状态机单元测试（SaaS 构建）。
//
//go:build saas

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func s44NewStore(t *testing.T) *tenantDispositionStore {
	t.Helper()
	return newTenantDispositionStore(newAuditChain())
}

// TestDispositionStates 四状态流转与放行/阻断行为。
func TestDispositionStates(t *testing.T) {
	store := s44NewStore(t)

	// 默认无记录 = 放行
	if allowed, _ := store.Check("t-001"); !allowed {
		t.Fatal("无记录应放行")
	}

	// warning → 放行
	_ = store.Set("t-001", dispositionWarning, "admin", "首次违规警告", "req-1")
	if allowed, _ := store.Check("t-001"); !allowed {
		t.Fatal("warning 应放行")
	}

	// throttled → 放行（由 quota 系统限流，此处仅打标）
	_ = store.Set("t-001", dispositionThrottled, "admin", "高频调用限流", "req-2")
	if allowed, _ := store.Check("t-001"); !allowed {
		t.Fatal("throttled 应放行")
	}

	// suspended → 拒绝
	_ = store.Set("t-001", dispositionSuspended, "admin", "欠费暂停", "req-3")
	if allowed, reason := store.Check("t-001"); allowed {
		t.Fatal("suspended 应拒绝")
	} else if !strings.Contains(reason, "suspended") {
		t.Fatalf("拒绝原因应包含 suspended，got %s", reason)
	}

	// terminated → 拒绝
	_ = store.Set("t-001", dispositionTerminated, "admin", "违规终止", "req-4")
	if allowed, _ := store.Check("t-001"); allowed {
		t.Fatal("terminated 应拒绝")
	}
}

// TestDispositionInvalidState 非法状态应报错。
func TestDispositionInvalidState(t *testing.T) {
	store := s44NewStore(t)
	err := store.Set("t-001", "banned", "admin", "", "req-1")
	if err == nil {
		t.Fatal("非法状态应报错")
	}
	// 旧状态不变（warning 状态设置过吗？没设置过，应仍为"无记录"）
	if allowed, _ := store.Check("t-001"); !allowed {
		t.Fatal("非法设置不生效，应仍放行")
	}
}

// TestDispositionEmptyTenant 空 tenant 应报错。
func TestDispositionEmptyTenant(t *testing.T) {
	store := s44NewStore(t)
	err := store.Set("", dispositionWarning, "admin", "", "req-1")
	if err == nil {
		t.Fatal("空 tenant 应报错")
	}
}

// TestDispositionAudit 设置处置应落审计链。
func TestDispositionAudit(t *testing.T) {
	store := s44NewStore(t)
	_ = store.Set("t-001", dispositionSuspended, "ops-admin", "合规封禁", "req-audit-1")
	count := 0
	for _, ev := range store.audit.events {
		if ev.Action == "tenant_disposition_change" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("应有 1 条处置变更审计，got %d", count)
	}
	found := false
	for _, ev := range store.audit.events {
		if ev.Action == "tenant_disposition_change" &&
			ev.TenantID == "t-001" &&
			ev.Result == dispositionSuspended &&
			ev.UserID == "ops-admin" &&
			strings.Contains(ev.TransformedHash, "to=suspended") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("审计事件字段不匹配")
	}
}

// TestDispositionHandler GET 视图与 POST 设置。
func TestDispositionHandler(t *testing.T) {
	audit := newAuditChain()
	store := newTenantDispositionStore(audit)
	srv := &teeServer{
		disposition: store,
		audit:       audit,
		// adminToken 空 = 开发模式放行
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/config/tenant-disposition", srv.handleTenantDisposition)

	// 初始 GET 应为空列表
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/tenant-disposition", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET 应 200，got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Dispositions []map[string]any `json:"dispositions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(resp.Dispositions) != 0 {
		t.Fatalf("初始应为空，got %d", len(resp.Dispositions))
	}

	// POST 设置 suspended
	body := `{"tenant":"t-999","state":"suspended","reason":"测试封禁"}`
	req := httptest.NewRequest(http.MethodPost, "/config/tenant-disposition", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Actor", "test-admin")
	req.Header.Set("X-Request-ID", "test-req-1")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("POST 应 200，got %d: %s", rec.Code, rec.Body.String())
	}

	// GET 验证存在
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config/tenant-disposition", nil))
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析响应失败: %v", err)
	}
	if len(resp.Dispositions) != 1 {
		t.Fatalf("应有 1 条，got %d", len(resp.Dispositions))
	}
	if resp.Dispositions[0]["tenant"] != "t-999" || resp.Dispositions[0]["state"] != "suspended" {
		t.Fatalf("记录不匹配: %+v", resp.Dispositions[0])
	}

	// POST 非法 state → 400
	body = `{"tenant":"t-999","state":"invalid"}`
	req = httptest.NewRequest(http.MethodPost, "/config/tenant-disposition", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("非法 state 应 400，got %d", rec.Code)
	}
}

// TestDispositionSnapshot 幂等与并发安全（基本冒烟）。
func TestDispositionSnapshotIsCopy(t *testing.T) {
	store := s44NewStore(t)
	_ = store.Set("t-001", dispositionWarning, "a", "", "r")
	snap := store.Snapshot()
	snap["t-001"].State = dispositionTerminated // 修改快照副本

	// 原 store 不应变
	rec, _ := store.dispositions["t-001"]
	if rec.State != dispositionWarning {
		t.Fatalf("快照修改不应影响原 store，got %s", rec.State)
	}
}
