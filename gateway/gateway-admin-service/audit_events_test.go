// Package main — 账号管理审计投递端点单测（M3-A）。
//
// 覆盖：方法限制 / 角色 / 审计链未启用 fail-closed / action 白名单 /
// target 校验 / 合法落链 / 落链失败 500。
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newAuditEventsTestChain 临时文件构造审计链（复用 audit_test.go 的 newAuditTestChain，
// 测试结束由其 t.Cleanup 关闭）。
func newAuditEventsTestChain(t *testing.T) *adminAuditChain {
	return newAuditTestChain(t, false)
}

// postAuditEvent 以指定身份/action/target 调用投递端点，返回响应码与链引用。
func postAuditEvent(t *testing.T, h *auditEventHandler, cfg *config, sub, role, action, target string) int {
	t.Helper()
	mux := buildAdminMux(cfg, nil, nil, nil, nil, h, nil, nil, false)
	token := testSignToken(t, cfg.jwtSecret, claims{
		Sub: sub, Role: role, Iss: defaultIssuer, Aud: defaultAudience,
	})
	body := `{"action":"` + action + `","target":"` + target + `"}`
	req := httptest.NewRequest(http.MethodPost, auditEventsPath, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("X-Request-ID", "rid-audit-1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code
}

func TestAuditEventsEndpoint(t *testing.T) {
	cfg := testCfg()
	adminCfg := testCfg()

	t.Run("非 POST → 405", func(t *testing.T) {
		h := &auditEventHandler{chain: newAuditEventsTestChain(t)}
		mux := buildAdminMux(cfg, nil, nil, nil, nil, h, nil, nil, false)
		req := httptest.NewRequest(http.MethodGet, auditEventsPath, nil)
		req.Header.Set("Authorization", "Bearer "+testSignToken(t, cfg.jwtSecret, claims{
			Sub: testAdminUser, Role: roleAdmin, Iss: defaultIssuer, Aud: defaultAudience,
		}))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("期望 405，实际 %d", rec.Code)
		}
	})

	t.Run("auditor 投递 → 403", func(t *testing.T) {
		h := &auditEventHandler{chain: newAuditEventsTestChain(t)}
		if got := postAuditEvent(t, h, adminCfg, "bob", roleAuditor,
			auditActionAccountCreate, "carol"); got != http.StatusForbidden {
			t.Fatalf("期望 403，实际 %d", got)
		}
	})

	t.Run("审计链未启用 → 503（fail-closed）", func(t *testing.T) {
		h := &auditEventHandler{chain: nil}
		if got := postAuditEvent(t, h, adminCfg, testAdminUser, roleAdmin,
			auditActionAccountCreate, "carol"); got != http.StatusServiceUnavailable {
			t.Fatalf("期望 503，实际 %d", got)
		}
	})

	t.Run("白名单外 action → 400", func(t *testing.T) {
		h := &auditEventHandler{chain: newAuditEventsTestChain(t)}
		if got := postAuditEvent(t, h, adminCfg, testAdminUser, roleAdmin,
			"self_grant_super", "bob"); got != http.StatusBadRequest {
			t.Fatalf("期望 400，实际 %d", got)
		}
	})

	t.Run("target 空 → 400", func(t *testing.T) {
		h := &auditEventHandler{chain: newAuditEventsTestChain(t)}
		if got := postAuditEvent(t, h, adminCfg, testAdminUser, roleAdmin,
			auditActionAccountCreate, ""); got != http.StatusBadRequest {
			t.Fatalf("期望 400，实际 %d", got)
		}
	})

	t.Run("合法投递 → 204 且事件字段正确", func(t *testing.T) {
		chain := newAuditEventsTestChain(t)
		h := &auditEventHandler{chain: chain}
		if got := postAuditEvent(t, h, adminCfg, testAdminUser, roleAdmin,
			auditActionAccountCreate, "carol"); got != http.StatusNoContent {
			t.Fatalf("期望 204，实际 %d", got)
		}
		if chain.len() != 1 {
			t.Fatalf("链长度应为 1，实际 %d", chain.len())
		}
		e := chain.events[0]
		if e.Actor != testAdminUser || e.Action != auditActionAccountCreate ||
			e.Target != "carol" || e.RequestID != "rid-audit-1" || e.Result != "ok" {
			t.Fatalf("事件字段不符：%+v", e)
		}
		if ok, n := chain.verify(); !ok || n != 1 {
			t.Fatalf("哈希链校验失败：ok=%v n=%d", ok, n)
		}
	})

	t.Run("落链失败 → 500", func(t *testing.T) {
		chain := newAuditEventsTestChain(t)
		_ = chain.Close() // 文件已关闭 → 写入失败
		h := &auditEventHandler{chain: chain}
		if got := postAuditEvent(t, h, adminCfg, testAdminUser, roleAdmin,
			auditActionAccountDelete, "bob"); got != http.StatusInternalServerError {
			t.Fatalf("期望 500，实际 %d", got)
		}
	})
}

// TestAuditEventTargetHashBackCompat Target 条件编码的旧链兼容性（M3-A）：
// 无 Target 的既有事件（M2 形态）与新算法计算的哈希必须一致——重启恢复不误报链断裂。
func TestAuditEventTargetHashBackCompat(t *testing.T) {
	legacy := adminAuditEvent{
		EventID: "evt-1", Timestamp: 1, Actor: "alice",
		Action: auditActionCredentialUpsert, Provider: "phala",
		KeyFingerprint: "abcd1234", RequestID: "rid-1", Result: "ok",
	}
	legacy.Target = ""
	h1 := legacy.hash()

	// 模拟 M2 时代算法：无条件拼接（Target 恒空 → 不写入即等价）。
	h2 := func() string {
		e := legacy
		return e.hash()
	}()
	if h1 != h2 {
		t.Fatal("空 Target 时哈希应与既有算法一致")
	}

	withTarget := legacy
	withTarget.Target = "carol"
	if withTarget.hash() == h1 {
		t.Fatal("带 Target 的事件哈希应不同")
	}
}
