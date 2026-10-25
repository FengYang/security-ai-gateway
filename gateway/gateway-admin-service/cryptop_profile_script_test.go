// cryptop_profile_script_test.go — §12.6 切换脚本退出码测试（B5-c）。
//
// 覆盖附录 C：
//   T-12.6-1 脚本 from≠current（409 stale_from）→ 退出码 2
//   T-12.6-2 跨 provider MODE=hot（409 restart_required）→ 退出码 3
//   T-12.6-3 成功路径 → 退出码 0 + verify 一致性校验通过
//   T-12.6-4 脚本侧 PRG 透传：admin 收到的请求体含 mask_prg
//
// Windows 上必须使用 Git for Windows 的 bash：PATH 中的 bash 可能是 WSL，
// WSL 不继承 Windows 进程环境变量且其 127.0.0.1 不通 Windows 侧 mock。
// Git bash / Linux bash 均不可用 → skip（对齐 PrometheusRule 缺文件 skip 先例）。
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
	"runtime"
	"strings"
	"testing"
)

// newAdminMock 构造 admin 端点 mock：固定返回 status/body，并记录收到的请求体。
func newAdminMock(t *testing.T, status int, body string, gotBody *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		*gotBody = string(raw)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

// repoRootAbs 定位仓库根绝对路径（gateway/gateway-admin-service → 上两级）。
func repoRootAbs(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Skipf("仓库根不可达: %v", err)
	}
	return root
}

// bashForScripts 返回可用于本测试的 bash：
// Windows 上只接受 Git for Windows bash（排除 WSL bash）；其他平台用 PATH 的 bash。
func bashForScripts(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "windows" {
		if _, err := exec.LookPath("bash"); err != nil {
			t.Skip("bash 不可用，跳过脚本退出码测试")
		}
		probeBash(t, "bash")
		return "bash"
	}
	candidates := make([]string, 0, 2)
	if root := os.Getenv("GIT_INSTALL_ROOT"); root != "" {
		candidates = append(candidates, filepath.Join(root, "bin", "bash.exe"))
	}
	candidates = append(candidates, `C:\Program Files\Git\bin\bash.exe`)
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			probeBash(t, c)
			return c
		}
	}
	t.Skip("未找到 Git for Windows bash，跳过脚本退出码测试")
	return ""
}

// probeBash 探测 bash 是否**可执行**：部分受限环境能定位到 bash.exe 但禁止执行
// （fork/exec ...bash.exe: Access is denied）→ 此时应**跳过**脚本类用例
// （环境限制 ≠ 用例失败），对齐 PrometheusRule 缺文件 skip 先例。
func probeBash(t *testing.T, bash string) {
	t.Helper()
	out, err := exec.Command(bash, "--version").CombinedOutput()
	if err == nil {
		return
	}
	if _, ok := err.(*exec.ExitError); ok {
		return // bash 可执行（自身非零退出 ≠ 不可用）
	}
	msg := strings.ToLower(err.Error())
	for _, k := range []string{"access is denied", "permission denied", "operation is not permitted", "exec format error"} {
		if strings.Contains(msg, k) {
			t.Skipf("当前环境禁止执行 bash（%v）→ 跳过脚本用例（环境限制，非用例失败）", err)
		}
	}
	t.Fatalf("bash 探测失败: %v\n%s", err, out)
}

// runSwitchScript 执行切换脚本，返回退出码。
// 工作目录经 cmd.Dir（宽字符 API，中文路径不失真），脚本参数用纯 ASCII 相对路径；
// 脚本内 BASH_SOURCE 自解析同目录 verify。
func runSwitchScript(t *testing.T, adminURL, sidecarURL string, env [][2]string) int {
	t.Helper()
	root := repoRootAbs(t)
	cmd := exec.Command(bashForScripts(t),
		filepath.ToSlash(filepath.Join("scripts", "cryptop-switch-profile.sh")))
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"ADMIN="+adminURL,
		"ADMIN_TOKEN=dummy-test-token",
	)
	if sidecarURL != "" {
		cmd.Env = append(cmd.Env, "CRYPTOPSVC_URL="+sidecarURL)
	}
	for _, kv := range env {
		cmd.Env = append(cmd.Env, kv[0]+"="+kv[1])
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err == nil {
		return 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		t.Logf("脚本 stderr: %s", stderr.String())
		return ee.ExitCode()
	}
	t.Fatalf("脚本异常（非退出码错误）: %v stderr=%s", err, stderr.String())
	return -1
}

func TestCryptopSwitchScriptExitCodes(t *testing.T) {
	bashForScripts(t) // 前置探测：不可用即 skip

	t.Run("T-12.6-1 stale_from → exit 2", func(t *testing.T) {
		var gotBody string
		admin := newAdminMock(t, http.StatusConflict,
			`{"ok":false,"error":{"code":"stale_from"}}`, &gotBody)
		defer admin.Close()

		code := runSwitchScript(t, admin.URL, "", [][2]string{
			{"FROM", "intl"}, {"TO", "intl"},
		})
		if code != 2 {
			t.Fatalf("期望退出码 2，实际 %d", code)
		}
	})

	t.Run("T-12.6-2 restart_required → exit 3", func(t *testing.T) {
		var gotBody string
		admin := newAdminMock(t, http.StatusConflict,
			`{"ok":false,"error":{"code":"restart_required"}}`, &gotBody)
		defer admin.Close()

		code := runSwitchScript(t, admin.URL, "", [][2]string{
			{"FROM", "intl"}, {"TO", "sm-software"},
			{"MODE", "hot"}, {"PRG", "bridge"},
		})
		if code != 3 {
			t.Fatalf("期望退出码 3，实际 %d", code)
		}
	})

	t.Run("T-12.6-3/4 成功 + PRG 透传 + verify → exit 0", func(t *testing.T) {
		// sidecar mock：capabilities 返回目标态 sm-software/bridge，供 verify 校验通过。
		sidecar := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"profile": "sm-software", "mask_prg": "bridge",
			})
		}))
		defer sidecar.Close()

		var gotBody string
		admin := newAdminMock(t, http.StatusOK,
			`{"ok":true,"applied":"sm-software","mode":"restart","consistency":{"mask_prg":"bridge"}}`,
			&gotBody)
		defer admin.Close()

		code := runSwitchScript(t, admin.URL, sidecar.URL, [][2]string{
			{"FROM", "intl"}, {"TO", "sm-software"},
			{"MODE", "restart"}, {"PRG", "bridge"},
		})
		if code != 0 {
			t.Fatalf("期望退出码 0，实际 %d", code)
		}

		// T-12.6-4：admin 收到的请求体须含 mask_prg=bridge。
		var sent cryptopProfileSwitchRequest
		if err := json.Unmarshal([]byte(gotBody), &sent); err != nil {
			t.Fatalf("请求体解析失败: %v body=%s", err, gotBody)
		}
		if sent.MaskPRG != "bridge" || sent.From != "intl" || sent.To != "sm-software" {
			t.Fatalf("PRG 透传不符：%+v", sent)
		}
	})

	t.Run("inconsistent → exit 2", func(t *testing.T) {
		var gotBody string
		admin := newAdminMock(t, http.StatusConflict,
			`{"ok":false,"error":{"code":"inconsistent"}}`, &gotBody)
		defer admin.Close()

		code := runSwitchScript(t, admin.URL, "", [][2]string{
			{"FROM", "intl"}, {"TO", "sm-software"}, {"PRG", "bridge"},
		})
		if code != 2 {
			t.Fatalf("期望退出码 2，实际 %d", code)
		}
	})
}
