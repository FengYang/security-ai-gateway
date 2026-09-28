// S1-5：公众形态总开关锁定（审核总开关不可关闭）。
// 覆盖：启动期校验（publicFacing=true + mode=off → fatal）、运行时切换到 off 被拒（400 + 审计）、
//      非公众形态不受限、GET /config 返回 public_facing 字段。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// s15NewMinimalServer 构造最小 srv（仅满足 S1-5 测试所需字段）。
func s15NewMinimalServer(t *testing.T, mode string, publicFacing bool) *teeServer {
	t.Helper()
	srv := &teeServer{
		outputGuardMode:       mode,
		publicFacing:          publicFacing,
		outputGuardParams:     defaultOutputGuardParams(),
		outputGuardCascade:    defaultOutputGuardCascadeParams(),
		outputGuardStrategy:   "", // 缺省 A
		audit:                 newAuditChain(),
		metrics:               newMetrics(),
		// adminToken 为空 = 开发/测试模式，checkAdmin 直接放行
	}
	srv.metrics.setOutputGuardMode(mode, "test")
	return srv
}

func s15PostMode(t *testing.T, srv *teeServer, mode string) *httptest.ResponseRecorder {
	t.Helper()
	body := `{"mode":"` + mode + `"}`
	req := httptest.NewRequest(http.MethodPost, "/config/output-guard", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Admin-Actor", "tester")
	req.Header.Set("X-Request-ID", "s15-test-1")
	rec := httptest.NewRecorder()
	srv.handleOutputGuardConfig(rec, req)
	return rec
}

// TestS15PublicFacingLockRuntime 公众形态下运行时切 off 被 400 + 审计拒绝。
func TestS15PublicFacingLockRuntime(t *testing.T) {
	srv := s15NewMinimalServer(t, outputGuardShadow, true)

	// shadow → off 被拒绝
	rec := s15PostMode(t, srv, outputGuardOff)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("公众形态切 off 应 400，got %d: %s", rec.Code, rec.Body.String())
	}
	// mode 不应变
	if srv.currentOutputGuardMode() != outputGuardShadow {
		t.Fatalf("被拒后 mode 应仍为 shadow，got %s", srv.currentOutputGuardMode())
	}
	// 审计应有 rejected_public_facing_lock 事件
	if n := srv.audit.countByAction("output_guard_mode_change"); n == 0 {
		t.Fatal("应有 mode_change 审计事件")
	}
	found := false
	for _, ev := range srv.audit.query("-") {
		if ev.Action == "output_guard_mode_change" && ev.Result == "rejected_public_facing_lock" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("审计事件中应有 rejected_public_facing_lock 结果")
	}

	// shadow → shadow 允许（无变化）
	rec = s15PostMode(t, srv, outputGuardShadow)
	if rec.Code != http.StatusOK {
		t.Fatalf("切 shadow 应 200，got %d: %s", rec.Code, rec.Body.String())
	}
}

// TestS15NonPublicFacingCanTurnOff 非公众形态可以正常切 off。
func TestS15NonPublicFacingCanTurnOff(t *testing.T) {
	srv := s15NewMinimalServer(t, outputGuardShadow, false)

	rec := s15PostMode(t, srv, outputGuardOff)
	if rec.Code != http.StatusOK {
		t.Fatalf("非公众形态切 off 应 200，got %d: %s", rec.Code, rec.Body.String())
	}
	if srv.currentOutputGuardMode() != outputGuardOff {
		t.Fatalf("mode 应为 off，got %s", srv.currentOutputGuardMode())
	}
}

// TestS15ConfigSnapshotPublicFacing GET /config 返回 public_facing 字段。
func TestS15ConfigSnapshotPublicFacing(t *testing.T) {
	// 公众形态
	srv := s15NewMinimalServer(t, outputGuardShadow, true)
	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	rec := httptest.NewRecorder()
	srv.handleConfig(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/config 应 200，got %d", rec.Code)
	}
	var resp struct {
		OutputGuard struct {
			PublicFacing bool `json:"public_facing"`
		} `json:"output_guard"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析 /config 响应失败: %v", err)
	}
	if !resp.OutputGuard.PublicFacing {
		t.Fatal("public_facing 应为 true")
	}

	// 非公众形态
	srv2 := s15NewMinimalServer(t, outputGuardShadow, false)
	rec2 := httptest.NewRecorder()
	srv2.handleConfig(rec2, req)
	var resp2 struct {
		OutputGuard struct {
			PublicFacing bool `json:"public_facing"`
		} `json:"output_guard"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &resp2); err != nil {
		t.Fatalf("解析 /config 响应失败: %v", err)
	}
	if resp2.OutputGuard.PublicFacing {
		t.Fatal("public_facing 应为 false")
	}
}

// TestS15PublicFacingFromEnforcingDowngrade 公众形态下 enforcing → off 也应被锁（公众形态一律不可关）。
func TestS15PublicFacingEnforcingToOffBlocked(t *testing.T) {
	srv := s15NewMinimalServer(t, outputGuardEnforcing, true)

	// enforcing → off 拒绝
	rec := s15PostMode(t, srv, outputGuardOff)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("公众形态 enforcing→off 应 400，got %d: %s", rec.Code, rec.Body.String())
	}
	// enforcing → shadow 允许（回滚演练）
	rec = s15PostMode(t, srv, outputGuardShadow)
	if rec.Code != http.StatusOK {
		t.Fatalf("enforcing→shadow 应 200，got %d: %s", rec.Code, rec.Body.String())
	}
}
