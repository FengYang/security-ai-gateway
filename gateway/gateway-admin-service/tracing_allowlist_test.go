// P1-2：Collector allow-list 热更 wiring（方案 B3）单测。
//
// 覆盖：锚点渲染（幂等/锚点缺失 fail-closed）、apply 编排（GET→PATCH ConfigMap→触发滚动）、
// 失败路径（ConfigMap/Deployment PATCH 403 → 报错不掩盖）、端点接线语义（200 已应用 / 503 未接线）。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// sampleCollectorCfg 模拟 Collector 配置（含唯一锚点 + 两处 YAML 别名）。
const sampleCollectorCfg = `receivers:
  otlp:
processors:
  tail_sampling:
    policies:
      - name: tenant-http-err
        and:
          and_sub_policy:
            - string_attribute:
                key: tenant.id
                values: &tenant_allowlist []
      - name: tenant-span-err
        and:
          and_sub_policy:
            - string_attribute:
                key: tenant.id
                values: *tenant_allowlist
`

// fakeK8s 极简 K8s API 仿真（仅本测试所需的三条路径）。
type fakeK8s struct {
	mu       sync.Mutex
	ns       string
	cmName   string
	cmKey    string
	deploy   string
	cfg      string
	cmAnn    map[string]string
	depAnn   map[string]string
	cmPatch  int // 强制返回的状态码（0 = 正常）
	depPatch int
	cmCalls  int
	depCalls int
}

func newFakeK8sServer(t *testing.T, ns, cmName, cmKey, deploy, cfg string) (*fakeK8s, *httptest.Server) {
	t.Helper()
	f := &fakeK8s{ns: ns, cmName: cmName, cmKey: cmKey, deploy: deploy, cfg: cfg,
		cmAnn: map[string]string{}, depAnn: map[string]string{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodGet {
			writeJSON(w, 200, map[string]any{"data": map[string]string{f.cmKey: f.cfg}})
			return
		}
		if r.Method == http.MethodPatch {
			f.cmCalls++
			if f.cmPatch != 0 {
				writeJSON(w, f.cmPatch, map[string]string{"message": "forbidden"})
				return
			}
			var body struct {
				Data     map[string]string `json:"data"`
				Metadata struct {
					Annotations map[string]string `json:"annotations"`
				} `json:"metadata"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				writeJSON(w, 400, map[string]string{"message": err.Error()})
				return
			}
			if v, ok := body.Data[f.cmKey]; ok {
				f.cfg = v
			}
			for k, v := range body.Metadata.Annotations {
				f.cmAnn[k] = v
			}
			writeJSON(w, 200, map[string]any{"data": map[string]string{f.cmKey: f.cfg}})
			return
		}
		writeJSON(w, 405, map[string]string{"message": "method"})
	})
	mux.HandleFunc("/apis/apps/v1/namespaces/", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.depCalls++
		if f.depPatch != 0 {
			writeJSON(w, f.depPatch, map[string]string{"message": "forbidden"})
			return
		}
		var body struct {
			Spec struct {
				Template struct {
					Metadata struct {
						Annotations map[string]string `json:"annotations"`
					} `json:"metadata"`
				} `json:"template"`
			} `json:"spec"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"message": err.Error()})
			return
		}
		for k, v := range body.Spec.Template.Metadata.Annotations {
			f.depAnn[k] = v
		}
		writeJSON(w, 200, map[string]any{"metadata": map[string]string{"name": f.deploy}})
	})
	return f, httptest.NewServer(mux)
}

// newTestApplier 用仿真 API 构造应用器（纯 HTTP，不走 TLS）。
func newTestApplier(srv *httptest.Server, ns string) *allowlistApplier {
	return &allowlistApplier{
		k8s:        &k8sClient{baseURL: srv.URL, token: "t", ns: ns, httpc: srv.Client()},
		cmName:     "otel-collector-config",
		cmKey:      "otel-collector.yaml",
		deployName: "otel-collector",
		restart:    true,
	}
}

// ---- 渲染 ----

func TestRenderAllowlist_ReplaceAndIdempotent(t *testing.T) {
	out, err := renderAllowlist(sampleCollectorCfg, []string{"t-001", "t-002"})
	if err != nil {
		t.Fatalf("渲染失败：%v", err)
	}
	if !strings.Contains(out, `values: &tenant_allowlist ["t-001","t-002"]`) {
		t.Fatalf("未正确替换锚点：\n%s", out)
	}
	// 别名行保持不变
	if strings.Count(out, "*tenant_allowlist") != strings.Count(sampleCollectorCfg, "*tenant_allowlist") {
		t.Fatal("别名行不应被改动")
	}
	// 幂等：同输入再渲染结果一致
	out2, _ := renderAllowlist(out, []string{"t-001", "t-002"})
	if out != out2 {
		t.Fatal("渲染应幂等")
	}
	// 空列表
	empty, err := renderAllowlist(sampleCollectorCfg, nil)
	if err != nil || !strings.Contains(empty, "values: &tenant_allowlist []") {
		t.Fatalf("空列表渲染异常：%v %q", err, empty)
	}
}

func TestRenderAllowlist_AnchorMissing(t *testing.T) {
	if _, err := renderAllowlist("processors:\n  tail_sampling: {}\n", []string{"x"}); err == nil {
		t.Fatal("锚点缺失应报错（fail-closed）")
	}
}

// TestParseAllowlist_RoundTrip 验证渲染后解析往返一致、空列表解析为空。
func TestParseAllowlist_RoundTrip(t *testing.T) {
	out, _ := renderAllowlist(sampleCollectorCfg, []string{"t-001"})
	got, err := parseAllowlist(out)
	if err != nil || len(got) != 1 || got[0] != "t-001" {
		t.Fatalf("解析异常：%v %v", err, got)
	}
	empty, err := parseAllowlist(sampleCollectorCfg)
	if err != nil || len(empty) != 0 {
		t.Fatalf("空列表解析异常：%v %v", err, empty)
	}
}

// TestParseAllowlist_EmptyAnchorValue 验证锚点后为空值时返回 nil,nil（未设置 = 空列表）。
func TestParseAllowlist_EmptyAnchorValue(t *testing.T) {
	cfg := "processors:\n  tail_sampling:\n    x: values: &tenant_allowlist\n"
	got, err := parseAllowlist(cfg)
	if err != nil || got != nil {
		t.Fatalf("空值锚点应返回 nil,nil：err=%v got=%v", err, got)
	}
}

// TestParseAllowlist_InvalidJSON 验证锚点后非合法 JSON 时 fail-closed 报错。
func TestParseAllowlist_InvalidJSON(t *testing.T) {
	cfg := "        values: &tenant_allowlist not-a-json"
	if _, err := parseAllowlist(cfg); err == nil {
		t.Fatal("非法 JSON 应报错（fail-closed）")
	}
}

// TestParseAllowlist_AnchorMissing 验证锚点缺失时返回错误。
func TestParseAllowlist_AnchorMissing(t *testing.T) {
	if _, err := parseAllowlist("processors:\n  tail_sampling: {}\n"); err == nil {
		t.Fatal("锚点缺失应报错")
	}
}

// newFailingK8sServer 返回对任意请求一律 500 的仿真 K8s（用于失败路径编排）。
func newFailingK8sServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"message": "boom"})
	}))
}

// TestAllowlistCurrent_GetError 验证读事实源失败时 current 返回错误（fail-closed）。
func TestAllowlistCurrent_GetError(t *testing.T) {
	srv := newFailingK8sServer(t)
	defer srv.Close()
	a := newTestApplier(srv, "otpmask")
	if _, err := a.current(t.Context()); err == nil {
		t.Fatal("ConfigMap GET 失败应返回错误")
	}
}

// TestAllowlistApply_GetError 验证读事实源失败时 apply 返回错误（fail-closed）。
func TestAllowlistApply_GetError(t *testing.T) {
	srv := newFailingK8sServer(t)
	defer srv.Close()
	a := newTestApplier(srv, "otpmask")
	if _, _, _, err := a.apply(t.Context(), "t-001", true); err == nil {
		t.Fatal("ConfigMap GET 失败应返回错误")
	}
}

// TestAllowlistApply_ParseError 验证事实源缺锚点时 apply 返回错误（不静默 no-op）。
func TestAllowlistApply_ParseError(t *testing.T) {
	_, srv := newFakeK8sServer(t, "otpmask", "otel-collector-config", "otel-collector.yaml", "otel-collector", "processors:\n  tail_sampling: {}\n")
	defer srv.Close()
	a := newTestApplier(srv, "otpmask")
	if _, _, _, err := a.apply(t.Context(), "t-001", true); err == nil {
		t.Fatal("缺锚点应返回错误")
	}
}

// ---- apply 编排 ----

func TestAllowlistApply_FlowAndIdempotent(t *testing.T) {
	f, srv := newFakeK8sServer(t, "otpmask", "otel-collector-config", "otel-collector.yaml", "otel-collector", sampleCollectorCfg)
	defer srv.Close()
	a := newTestApplier(srv, "otpmask")

	rev, restarted, tenants, err := a.apply(t.Context(), "t-001", true)
	if err != nil {
		t.Fatalf("apply 失败：%v", err)
	}
	if rev == "" || !restarted || len(tenants) != 1 || tenants[0] != "t-001" {
		t.Fatalf("apply 结果异常：rev=%q restarted=%v tenants=%v", rev, restarted, tenants)
	}
	f.mu.Lock()
	cfg, cmAnn, depAnn := f.cfg, f.cmAnn[allowlistRevAnnotation], f.depAnn[allowlistRevAnnotation]
	f.mu.Unlock()
	if !strings.Contains(cfg, `["t-001"]`) {
		t.Fatalf("ConfigMap 未写入新 allow-list：\n%s", cfg)
	}
	if cmAnn != rev || depAnn != rev {
		t.Fatalf("修订号注解不一致：cm=%q dep=%q rev=%q", cmAnn, depAnn, rev)
	}

	// 幂等：重复启用同一租户 → rev 不变
	rev2, _, _, err := a.apply(t.Context(), "t-001", true)
	if err != nil || rev2 != rev {
		t.Fatalf("幂等性异常：rev2=%q rev=%q err=%v", rev2, rev, err)
	}

	// 停用 → 回空
	if _, _, tenants, err = a.apply(t.Context(), "t-001", false); err != nil || len(tenants) != 0 {
		t.Fatalf("停用异常：%v %v", err, tenants)
	}
}

func TestAllowlistApply_ConfigMapPatchForbidden(t *testing.T) {
	f, srv := newFakeK8sServer(t, "otpmask", "otel-collector-config", "otel-collector.yaml", "otel-collector", sampleCollectorCfg)
	defer srv.Close()
	f.cmPatch = http.StatusForbidden
	a := newTestApplier(srv, "otpmask")

	if _, _, _, err := a.apply(t.Context(), "t-001", true); err == nil {
		t.Fatal("ConfigMap PATCH 403 应报错（fail-closed）")
	}
}

func TestAllowlistApply_RestartFailure(t *testing.T) {
	f, srv := newFakeK8sServer(t, "otpmask", "otel-collector-config", "otel-collector.yaml", "otel-collector", sampleCollectorCfg)
	defer srv.Close()
	f.depPatch = http.StatusForbidden
	a := newTestApplier(srv, "otpmask")

	_, restarted, _, err := a.apply(t.Context(), "t-001", true)
	if err == nil {
		t.Fatal("Deployment PATCH 403 应报错（配置已写但未生效，不得掩盖）")
	}
	if restarted {
		t.Fatal("未成功触发滚动时 restarted 应为 false")
	}
}

// ---- 端点语义 ----

func newWiredSLOHandler(t *testing.T, a *allowlistApplier) *sloHandler {
	t.Helper()
	dir := t.TempDir()
	chain, err := newAdminAuditChain(filepath.Join(dir, "audit.jsonl"), "")
	if err != nil {
		t.Fatalf("构造审计链失败：%v", err)
	}
	t.Cleanup(func() { _ = chain.Close() })
	h := newSLOHandler(filepath.Join(dir, "slo.json"), "", chain)
	h.applier = a // 注入仿真应用器（覆盖 newSLOHandler 的 in-cluster 探测）
	return h
}

func TestHandleTracingTenant_WiredAppliesAndAudits(t *testing.T) {
	f, srv := newFakeK8sServer(t, "otpmask", "otel-collector-config", "otel-collector.yaml", "otel-collector", sampleCollectorCfg)
	defer srv.Close()
	h := newWiredSLOHandler(t, newTestApplier(srv, "otpmask"))

	req := httptest.NewRequest(http.MethodPost, tracingTenantPath, strings.NewReader(`{"tenant":"t-001","enabled":true}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTracingTenant(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("接线后应 200，实际 %d：%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Applied   bool     `json:"applied"`
		Rev       string   `json:"rev"`
		Restarted bool     `json:"restarted"`
		Tenants   []string `json:"tenants"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("响应解析失败：%v", err)
	}
	if !resp.Applied || resp.Rev == "" || !resp.Restarted || len(resp.Tenants) != 1 {
		t.Fatalf("响应异常：%+v", resp)
	}
	if h.chain.len() != 1 {
		t.Fatalf("应落 1 条审计，实际 %d", h.chain.len())
	}
	f.mu.Lock()
	cfg := f.cfg
	f.mu.Unlock()
	if !strings.Contains(cfg, `["t-001"]`) {
		t.Fatalf("ConfigMap 未生效：\n%s", cfg)
	}
}

func TestHandleTracingTenant_ApplyFailureReturns503(t *testing.T) {
	f, srv := newFakeK8sServer(t, "otpmask", "otel-collector-config", "otel-collector.yaml", "otel-collector", sampleCollectorCfg)
	defer srv.Close()
	f.cmPatch = http.StatusForbidden
	h := newWiredSLOHandler(t, newTestApplier(srv, "otpmask"))

	req := httptest.NewRequest(http.MethodPost, tracingTenantPath, strings.NewReader(`{"tenant":"t-001","enabled":true}`))
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleTracingTenant(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("应用失败应 503，实际 %d", rr.Code)
	}
	// 未成功 → 不得改本地缓存
	h.mu.Lock()
	cached := append([]string(nil), h.state.TracingTenants...)
	h.mu.Unlock()
	if len(cached) != 0 {
		t.Fatalf("应用失败不得改本地缓存：%v", cached)
	}
}

func TestGetSLO_TracingSourceFromConfigMap(t *testing.T) {
	cfg, _ := renderAllowlist(sampleCollectorCfg, []string{"t-001"})
	_, srv := newFakeK8sServer(t, "otpmask", "otel-collector-config", "otel-collector.yaml", "otel-collector", cfg)
	defer srv.Close()
	h := newWiredSLOHandler(t, newTestApplier(srv, "otpmask"))

	req := httptest.NewRequest(http.MethodGet, sloPath, nil)
	req = req.WithContext(withClaims(req.Context(), &claims{Sub: "admin", Role: roleAdmin}))
	rr := httptest.NewRecorder()
	h.handleSLO(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("应 200，实际 %d", rr.Code)
	}
	var out struct {
		TracingTenants []string `json:"tracing_tenants"`
		Wired          bool     `json:"tracing_wired"`
		Source         string   `json:"tracing_source"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("解析失败：%v", err)
	}
	if !out.Wired || out.Source != "collector-configmap" || len(out.TracingTenants) != 1 || out.TracingTenants[0] != "t-001" {
		t.Fatalf("事实源回显异常：%+v", out)
	}
}
