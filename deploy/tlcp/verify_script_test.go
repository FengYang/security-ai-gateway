package tlcp

// verify_script_test.go —— B6#10 verify.sh 脚本测试（对齐 B5-c 脚本测试惯例）。
//
//   - bash -n 语法检查（Windows 只接受 Git for Windows bash，排除 WSL）
//   - Tongsuo 不可用路径：退出码 7 + 证据 JSON，三项 result=skip
//
// 真实 TLCP 握手（T-12.4-1..3 运行面）依赖 Tongsuo/网关二进制，属运维外依（§12.4）。

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

func TestVerifyScriptSyntax(t *testing.T) {
	bash := bashForScripts(t)
	cmd := exec.Command(bash, "-n", "verify.sh")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verify.sh 语法错误: %v\n%s", err, out)
	}
}

func TestVerifyScriptNoTongsuo(t *testing.T) {
	bash := bashForScripts(t)
	cmd := exec.Command(bash, "verify.sh")
	cmd.Env = append(os.Environ(), "TONGSUO_BIN=otpmask-no-such-tongsuo-binary")
	out, err := cmd.CombinedOutput()

	// 退出码 7
	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("期望退出码 7，实际脚本成功：\n%s", out)
	}
	if code := exitErr.ExitCode(); code != 7 {
		t.Fatalf("期望退出码 7，实际 %d：\n%s", code, out)
	}

	// 证据 JSON 可解析
	var evidence map[string]any
	if err := json.Unmarshal(out, &evidence); err != nil {
		t.Fatalf("证据非合法 JSON: %v\n%s", err, out)
	}
	for _, key := range []string{"T-12.4-1", "T-12.4-2", "T-12.4-3"} {
		entry, ok := evidence[key].(map[string]any)
		if !ok {
			t.Fatalf("证据缺 %s", key)
		}
		if entry["result"] != "skip" {
			t.Fatalf("%s result=%v 期望 skip", key, entry["result"])
		}
		if !strings.Contains(entry["detail"].(string), "tongsuo") {
			t.Fatalf("%s detail 未说明 tongsuo 不可用: %v", key, entry["detail"])
		}
	}
}
