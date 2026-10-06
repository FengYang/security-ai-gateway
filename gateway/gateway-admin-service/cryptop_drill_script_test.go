// cryptop_drill_script_test.go — §13 切换演练脚本测试（B6#13）。
//
// 覆盖：
//   T-13.1 演练脚本化：bash -n 语法；有状态 mock 全链路（三次切换状态变迁）；
//          可选钩子缺省 SKIP；失败路径 exit 1
//   T-13.2 报告模板校验：报告含 §13.4 六段（演练环境/profile 切换记录/
//          功能·性能·双读·回滚结果/异常与处置/compliance_note/结论）
//
// Windows 上仅用 Git for Windows bash（同包 bashForScripts 既有口径）。
package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"security-ai-gateway/gateway/cryptop"
)

// drillState sidecar 生效态（admin 受理后立即变迁，模拟滚动重启后态）。
type drillState struct {
	sync.Mutex
	profile string
	prg     string
}

// drillMocks 三服务 mock + admin 收到的请求序列。
type drillMocks struct {
	state          *drillState
	adminURL       string
	sidecarURL     string
	pluginURL      string
	adminRequests  []map[string]any
	pluginVersions []string
	rejectAll      bool
}

func newDrillMocks(t *testing.T, rejectAll bool) *drillMocks {
	t.Helper()
	m := &drillMocks{
		state:     &drillState{profile: "intl", prg: "hmac-sha256"},
		rejectAll: rejectAll,
	}

	// sidecar：GET /v1/capabilities。
	sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.state.Lock()
		defer m.state.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{
			"profile":         m.state.profile,
			"mask_prg":        m.state.prg,
			"compliance_note": "国密算法软件实现（SM2/SM3/SM4）；不满足密评要求，仅限功能验证",
		})
	}))
	t.Cleanup(sidecar.Close)

	// admin：POST /v1/adminext/cryptop/profile，按真实端点规则校验并变迁状态。
	admin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var req cryptopProfileSwitchRequest
		_ = json.Unmarshal(raw, &req)
		var rec map[string]any
		_ = json.Unmarshal(raw, &rec)

		m.state.Lock()
		defer m.state.Unlock()
		m.adminRequests = append(m.adminRequests, rec)

		w.Header().Set("Content-Type", "application/json")
		if m.rejectAll || req.From != m.state.profile {
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"ok":false,"error":{"code":"stale_from"}}`))
			return
		}
		effectivePRG := req.MaskPRG
		if !maskPRGAllowedForProfile(cryptop.Profile(req.To), effectivePRG) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"ok":false,"error":{"code":"bad_request"}}`))
			return
		}
		if req.From == req.To && effectivePRG == m.state.prg {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"ok":false,"error":{"code":"bad_request"}}`))
			return
		}
		m.state.profile = req.To
		m.state.prg = effectivePRG
		_, _ = w.Write([]byte(`{"ok":true,"applied":"` + req.To + `","mode":"restart","consistency":{"mask_prg":"` + effectivePRG + `"}}`))
	}))
	t.Cleanup(admin.Close)

	// plugin：任意请求记录 MaskVersion 后 200。
	plugin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.pluginVersions = append(m.pluginVersions, r.Header.Get("X-OTPMask-MaskVersion"))
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(plugin.Close)

	m.adminURL = admin.URL
	m.sidecarURL = sidecar.URL
	m.pluginURL = plugin.URL
	return m
}

// runDrill 执行演练脚本，返回退出码与报告（若产出）。
func runDrill(t *testing.T, m *drillMocks, env [][2]string) (int, map[string]any) {
	t.Helper()
	bashForScripts(t)
	outDir := t.TempDir()
	root := repoRootAbs(t)

	base := [][2]string{
		{"ADMIN", m.adminURL},
		{"CRYPTOPSVC_URL", m.sidecarURL},
		{"ADMIN_TOKEN", "dummy-test-token"},
		{"DRILL_OUT", outDir},
	}
	cmd := exec.Command(bashForScripts(t),
		filepath.ToSlash(filepath.Join("scripts", "cryptop-drill.sh")))
	cmd.Dir = root
	// 剔除代理变量：curl 对 127.0.0.1 若继承 HTTP(S)_PROXY 会走代理并等待超时。
	cleanedEnv := make([]string, 0, len(os.Environ()))
	for _, e := range os.Environ() {
		k := e
		if i := strings.IndexByte(e, '='); i >= 0 {
			k = e[:i]
		}
		lk := strings.ToLower(k)
		if strings.HasSuffix(lk, "_proxy") {
			continue
		}
		cleanedEnv = append(cleanedEnv, e)
	}
	cmd.Env = append(cleanedEnv, flattenEnv(append(base, env...))...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	rc := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			rc = ee.ExitCode()
		} else {
			t.Fatalf("脚本异常: %v stderr=%s", err, stderr.String())
		}
	}
	t.Logf("drill stderr: %s", stderr.String())

	reportPath := filepath.Join(outDir, "drill-report.json")
	report := map[string]any{}
	if raw, rerr := os.ReadFile(reportPath); rerr == nil {
		if jerr := json.Unmarshal(raw, &report); jerr != nil {
			t.Fatalf("报告非合法 JSON: %v\n%s", jerr, raw)
		}
	}
	return rc, report
}

func flattenEnv(kv [][2]string) []string {
	out := make([]string, 0, len(kv))
	for _, p := range kv {
		out = append(out, p[0]+"="+p[1])
	}
	return out
}

// stepResults 从报告 steps 提取 id→result。
func stepResults(t *testing.T, report map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	steps, ok := report["steps"].([]any)
	if !ok {
		t.Fatalf("报告 steps 缺失或类型错: %+v", report["steps"])
	}
	for _, s := range steps {
		sm := s.(map[string]any)
		out[sm["id"].(string)] = sm["result"].(string)
	}
	return out
}

func switchRecords(t *testing.T, report map[string]any) []map[string]string {
	t.Helper()
	raw, ok := report["profile_switch_records"].([]any)
	if !ok {
		t.Fatalf("profile_switch_records 缺失")
	}
	out := make([]map[string]string, 0, len(raw))
	for _, r := range raw {
		rm := r.(map[string]any)
		out = append(out, map[string]string{
			"step":     rm["step"].(string),
			"from":     rm["from"].(string),
			"to":       rm["to"].(string),
			"mask_prg": rm["mask_prg"].(string),
			"result":   rm["result"].(string),
		})
	}
	return out
}

func TestDrillScriptSyntax(t *testing.T) {
	root := repoRootAbs(t)
	cmd := exec.Command(bashForScripts(t), "-n",
		filepath.ToSlash(filepath.Join("scripts", "cryptop-drill.sh")))
	cmd.Dir = root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n: %v\n%s", err, out)
	}
}

// TestDrillFullPath 全钩子全链路：exit 0，三次切换顺序正确，T-13.2 六段齐全。
func TestDrillFullPath(t *testing.T) {
	m := newDrillMocks(t, false)
	rc, report := runDrill(t, m, [][2]string{
		{"PLUGIN_PROBE_URL", m.pluginURL},
		{"DRILL_FUNCTION_CMD", "true"},
		{"DRILL_DUALREAD_CMD", "true"},
		{"DRILL_PERF_CMD", "true"},
	})
	if rc != 0 {
		t.Fatalf("期望 exit 0，实际 %d", rc)
	}

	// T-13.2：§13.4 六段字段。
	for _, k := range []string{
		"environment", "profile_switch_records", "steps",
		"incidents", "compliance_note", "conclusion",
	} {
		if _, ok := report[k]; !ok {
			t.Errorf("报告缺 §13.4 字段: %s", k)
		}
	}

	// 步骤全部 pass。
	results := stepResults(t, report)
	for _, id := range []string{"precheck", "baseline", "3.1", "3.2", "3.3", "4", "5", "6", "7"} {
		if results[id] != "pass" {
			t.Errorf("步骤 %s result=%s，期望 pass", id, results[id])
		}
	}

	// 三次切换序列（含收桥 from==to、回滚 PRG=hmac-sha256）。
	sw := switchRecords(t, report)
	if len(sw) != 3 {
		t.Fatalf("切换记录数=%d，期望 3", len(sw))
	}
	want := []map[string]string{
		{"step": "3.1", "from": "intl", "to": "sm-software", "mask_prg": "bridge"},
		{"step": "3.3", "from": "sm-software", "to": "sm-software", "mask_prg": "sm4"},
		{"step": "7", "from": "sm-software", "to": "intl", "mask_prg": "hmac-sha256"},
	}
	for i, w := range want {
		for k, v := range w {
			if sw[i][k] != v {
				t.Errorf("切换 %d 字段 %s=%s，期望 %s", i, k, sw[i][k], v)
			}
		}
		if sw[i]["result"] != "pass" {
			t.Errorf("切换 %d result=%s", i, sw[i]["result"])
		}
	}

	// 无 incident，总结 pass，切后终态 intl/hmac-sha256。
	incs, _ := report["incidents"].([]any)
	if len(incs) != 0 {
		t.Errorf("incidents 非空: %+v", incs)
	}
	summary := report["summary"].(map[string]any)
	if summary["result"] != "pass" {
		t.Errorf("summary=%v", summary)
	}
	m.state.Lock()
	defer m.state.Unlock()
	if m.state.profile != "intl" || m.state.prg != "hmac-sha256" {
		t.Errorf("终态残留: %+v", m.state)
	}
	if len(m.pluginVersions) != 1 || m.pluginVersions[0] != "sm4" {
		t.Errorf("插件探活头记录: %v", m.pluginVersions)
	}
}

// TestDrillOptionalSkipped 不注入插件 URL 与钩子：可选步全 SKIP，仍 exit 0。
func TestDrillOptionalSkipped(t *testing.T) {
	m := newDrillMocks(t, false)
	rc, report := runDrill(t, m, nil)
	if rc != 0 {
		t.Fatalf("期望 exit 0，实际 %d", rc)
	}
	results := stepResults(t, report)
	for _, id := range []string{"3.2", "4", "5", "6"} {
		if results[id] != "skip" {
			t.Errorf("步骤 %s result=%s，期望 skip", id, results[id])
		}
	}
	for _, id := range []string{"precheck", "3.1", "3.3", "7"} {
		if results[id] != "pass" {
			t.Errorf("步骤 %s result=%s，期望 pass", id, results[id])
		}
	}
}

// TestDrillFailureExit1 3.1 被拒：exit 1，报告照出，后续依赖步 blocked，incident 非空。
func TestDrillFailureExit1(t *testing.T) {
	m := newDrillMocks(t, true)
	rc, report := runDrill(t, m, nil)
	if rc != 1 {
		t.Fatalf("期望 exit 1，实际 %d", rc)
	}
	if len(report) == 0 {
		t.Fatal("失败路径未产出报告")
	}
	results := stepResults(t, report)
	if results["3.1"] != "fail" {
		t.Errorf("3.1 result=%s，期望 fail", results["3.1"])
	}
	for _, id := range []string{"3.2", "3.3", "4", "5", "6"} {
		if results[id] != "blocked" {
			t.Errorf("步骤 %s result=%s，期望 blocked", id, results[id])
		}
	}
	if results["7"] != "skip" {
		t.Errorf("回滚步 result=%s，期望 skip（状态未离开 intl）", results["7"])
	}
	incs, _ := report["incidents"].([]any)
	if len(incs) == 0 {
		t.Error("incidents 为空，期望记录失败")
	}
	summary := report["summary"].(map[string]any)
	if summary["result"] != "fail" {
		t.Errorf("summary=%v，期望 fail", summary)
	}
}
