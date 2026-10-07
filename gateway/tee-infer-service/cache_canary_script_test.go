// cache_canary_script_test.go — P0-2 §12 缓存灰度脚本测试（G3）。
//
// 覆盖：
//   - bash -n 语法检查（Windows 只用 Git for Windows bash，排除 WSL）
//   - 参数错误 exit 2；门禁 PASS exit 0 / FAIL exit 1；回滚指引 exit 0
//   - 证据 JSON 产出可解析
//
// 真实灰度放量（配置下发 + 观测期）依赖运行环境与热更新通路（§6.10 未接线），属运维外依。
package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// bashForScripts Windows 上只接受 Git for Windows bash；其他平台用 PATH 的 bash。
func bashForScripts(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		if _, err := exec.LookPath("bash"); err != nil {
			t.Skip("bash 不可用，跳过脚本测试")
		}
		return "bash"
	}
	candidates := make([]string, 0, 2)
	if root := os.Getenv("GIT_INSTALL_ROOT"); root != "" {
		candidates = append(candidates, filepath.Join(root, "bin", "bash.exe"))
	}
	candidates = append(candidates, `C:\Program Files\Git\bin\bash.exe`)
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	t.Skip("未找到 Git for Windows bash，跳过脚本测试")
	return ""
}

// cacheCanaryScript 返回脚本绝对路径（测试工作目录 = gateway/tee-infer-service）。
func cacheCanaryScript(t *testing.T) string {
	t.Helper()
	p := filepath.Join("..", "..", "scripts", "cache-canary.sh")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("脚本不存在: %s", p)
	}
	return p
}

// runCanary 运行脚本；返回 exit code 与 stderr+stdout。
func runCanary(t *testing.T, bash, metricsURL, outDir string, args ...string) (int, string) {
	t.Helper()
	full := append([]string{cacheCanaryScript(t)}, args...)
	cmd := exec.Command(bash, full...)
	cmd.Env = append(os.Environ(),
		"CACHE_METRICS_URL="+metricsURL,
		"CACHE_CANARY_OUT="+outDir,
	)
	out, err := cmd.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("执行脚本失败: %v (%s)", err, out)
		}
	}
	return code, string(out)
}

// writeMetrics 写临时 metrics 文本，返回 file:/// URL。
func writeMetrics(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "metrics.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("写 metrics: %v", err)
	}
	return "file:///" + strings.ReplaceAll(p, `\`, "/")
}

func TestCacheCanaryScript_Syntax(t *testing.T) {
	bash := bashForScripts(t)
	cmd := exec.Command(bash, "-n", cacheCanaryScript(t))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("bash -n 失败: %v\n%s", err, out)
	}
}

func TestCacheCanaryScript_BadArgsExit2(t *testing.T) {
	bash := bashForScripts(t)
	if code, _ := runCanary(t, bash, "", t.TempDir()); code != 2 {
		t.Fatalf("无参数应 exit 2，实际 %d", code)
	}
	if code, _ := runCanary(t, bash, "", t.TempDir(), "--stage", "G-9"); code != 2 {
		t.Fatalf("非法阶段应 exit 2，实际 %d", code)
	}
	if code, _ := runCanary(t, bash, "", t.TempDir(), "--stage", "G-1"); code != 2 {
		t.Fatalf("缺 CACHE_METRICS_URL 应 exit 2，实际 %d", code)
	}
}

func TestCacheCanaryScript_GatePass(t *testing.T) {
	bash := bashForScripts(t)
	outDir := t.TempDir()
	// 精确命中率 20%（>10%）→ G-1 PASS
	url := writeMetrics(t, strings.Join([]string{
		`otpmask_cache_lookups_total{kind="exact",result="hit"} 20`,
		`otpmask_cache_lookups_total{kind="exact",result="miss"} 80`,
		`otpmask_cache_lookups_total{kind="exact",result="fastcheck_miss"} 0`,
	}, "\n")+"\n")

	code, out := runCanary(t, bash, url, outDir, "--stage", "G-1")
	if code != 0 {
		t.Fatalf("门禁应 PASS(exit 0)，实际 %d\n%s", code, out)
	}
	assertEvidence(t, outDir, "PASS")
}

func TestCacheCanaryScript_GateFail(t *testing.T) {
	bash := bashForScripts(t)
	outDir := t.TempDir()
	// 精确命中率 5%（<=10%）→ G-1 FAIL
	url := writeMetrics(t, strings.Join([]string{
		`otpmask_cache_lookups_total{kind="exact",result="hit"} 5`,
		`otpmask_cache_lookups_total{kind="exact",result="miss"} 95`,
	}, "\n")+"\n")

	code, _ := runCanary(t, bash, url, outDir, "--stage", "G-1")
	if code != 1 {
		t.Fatalf("门禁未过应 exit 1，实际 %d", code)
	}
	assertEvidence(t, outDir, "FAIL")
}

func TestCacheCanaryScript_RollbackDirective(t *testing.T) {
	bash := bashForScripts(t)
	outDir := t.TempDir()
	code, out := runCanary(t, bash, "", outDir, "--rollback", "--to", "G-1")
	if code != 0 {
		t.Fatalf("回滚指引应 exit 0，实际 %d\n%s", code, out)
	}
	assertEvidence(t, outDir, "MANUAL")
}

// assertEvidence 校验证据 JSON 已产出、可解析且 overall 符合预期。
func assertEvidence(t *testing.T, outDir, wantOverall string) {
	t.Helper()
	var found string
	_ = filepath.WalkDir(outDir, func(path string, d os.DirEntry, _ error) error {
		if d != nil && !d.IsDir() && strings.HasSuffix(path, ".json") {
			found = path
		}
		return nil
	})
	if found == "" {
		t.Fatalf("未产出证据 JSON（dir=%s）", outDir)
	}
	raw, _ := os.ReadFile(found)
	var ev struct {
		Script   string `json:"script"`
		Overall  string `json:"overall"`
		Checks   []any  `json:"checks"`
		Kind     string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &ev); err != nil {
		t.Fatalf("证据 JSON 非法: %v\n%s", err, raw)
	}
	if ev.Script != "cache-canary" || ev.Overall != wantOverall {
		t.Fatalf("证据字段异常：script=%q overall=%q（want %q）", ev.Script, ev.Overall, wantOverall)
	}
}
