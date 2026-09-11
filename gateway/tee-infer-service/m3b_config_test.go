// M3-B 安全中心配置端点单测：/config 只读快照与 /config/guardrail 运行时降级。
package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// newM3BConfigServer 构造仅含 M3-B 配置端点的最小 server（避免拉起完整推理栈）。
func newM3BConfigServer(cfgPath, adminToken string) *teeServer {
	return &teeServer{
		guard:            newGuardrail(),
		audit:            newAuditChain(),
		metrics:          newMetrics(),
		adminToken:       adminToken,
		piiMode:          "block",
		guardrailCfgPath: cfgPath,
		protoVersion:     "v-test",
		usage:            map[string]*usageRecord{},
	}
}

// newM3BConfigMux 注册 M3-B 端点（与 main 同构）。
func newM3BConfigMux(srv *teeServer) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/config", srv.handleConfig)
	mux.HandleFunc("/config/guardrail", srv.handleGuardrailConfig)
	return mux
}

func TestConfigEndpointRequiresAdmin(t *testing.T) {
	mux := newM3BConfigMux(newM3BConfigServer("", "tok"))

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/config", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无管理令牌应 401，实际 %d", rec.Code)
	}

	// 方法校验先于认证（与既有读端点 handleUsage 一致），非 GET 一律 405。
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/config", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("非 GET 应 405，实际 %d", rec.Code)
	}
}

func TestConfigSnapshotIsSummaryOnly(t *testing.T) {
	mux := newM3BConfigMux(newM3BConfigServer("", "tok"))

	req := httptest.NewRequest(http.MethodGet, "/config", nil)
	req.Header.Set(adminHeader, "tok")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /config 应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}

	var view secConfigView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("响应非合法 JSON：%v", err)
	}
	if view.PIIMode != "block" || view.PIIModeSource != "startup" {
		t.Fatalf("初始 pii_mode 应为 block/startup，实际 %s/%s", view.PIIMode, view.PIIModeSource)
	}
	if !view.Guardrail.Enabled {
		t.Fatal("Guardrail 在 fail-closed 设计下恒 enabled")
	}
	if view.Guardrail.PIIRules == 0 || view.Guardrail.SQLRules == 0 || view.Guardrail.InjectionTerms == 0 {
		t.Fatalf("规则条数不得为 0：%+v", view.Guardrail)
	}
	// 安全取舍：快照只给类别与条数，不得泄露正则/关键词原文（原文等同绕过手册）。
	body := rec.Body.String()
	for _, leak := range []string{"(?i)", `\b`, "[0-9]", "ignore previous instructions"} {
		if strings.Contains(body, leak) {
			t.Fatalf("快照泄露规则原文（%q）：%s", leak, body)
		}
	}
}

func TestGuardrailConfigRejectsInvalidAndUnauthorized(t *testing.T) {
	mux := newM3BConfigMux(newM3BConfigServer("", "tok"))

	// 未授权
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/config/guardrail", bytes.NewReader([]byte(`{"pii_mode":"mask"}`)))
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("无令牌应 401，实际 %d", rec.Code)
	}

	// 非法取值（含"关闭"意图）：只允许 block|mask
	for _, bad := range []string{"off", "disabled", ""} {
		body, _ := json.Marshal(map[string]string{"pii_mode": bad})
		req = httptest.NewRequest(http.MethodPost, "/config/guardrail", bytes.NewReader(body))
		req.Header.Set(adminHeader, "tok")
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("pii_mode=%q 应 400（不提供关闭开关），实际 %d", bad, rec.Code)
		}
	}
}

func TestGuardrailConfigApplyAndRestoreAcrossRestart(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "guardrail.json")
	srv := newM3BConfigServer(cfgPath, "tok")
	mux := newM3BConfigMux(srv)

	body, _ := json.Marshal(map[string]string{"pii_mode": "mask"})
	req := httptest.NewRequest(http.MethodPost, "/config/guardrail", bytes.NewReader(body))
	req.Header.Set(adminHeader, "tok")
	req.Header.Set("X-Admin-Actor", "auditor-checker")
	req.Header.Set("X-Request-ID", "req-m3b-1")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("合法降级应 200，实际 %d：%s", rec.Code, rec.Body.String())
	}
	if got := srv.currentPiiMode(); got != "mask" {
		t.Fatalf("运行时模式应生效为 mask，实际 %s", got)
	}

	// 模拟重启：新 server 指向同一持久化文件，启动恢复运行时配置。
	restarted := newM3BConfigServer(cfgPath, "tok")
	restarted.loadGuardrailOverride()
	if got := restarted.currentPiiMode(); got != "mask" {
		t.Fatalf("重启后应恢复 mask（否则降级被重启静默回滚），实际 %s", got)
	}
	// 存活（进程内覆盖）语义：未配置持久化文件时不恢复。
	noPersist := newM3BConfigServer("", "tok")
	noPersist.loadGuardrailOverride()
	if got := noPersist.currentPiiMode(); got != "block" {
		t.Fatalf("未配置持久化时应回退启动参数 block，实际 %s", got)
	}
}
