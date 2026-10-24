// p11pin.go —— 模块登录口令解析（R-S3-2；无后端依赖，默认构建可单测）。
//
// 契约（P1-5 §6.4 R-S3-2）：module_pin_ref 仅存**引用名**，口令字面值不得出现
// 在配置/命令行/日志。本文件把引用名解析为实际口令，只接受两种载体：
//
//	file:<path>   挂载文件（Secret/Vault 投影；权限须 0600，否则拒绝）
//	env:<NAME>    环境变量名
//
// 纯引用名（无 file:/env: 前缀）一律拒绝——防止把引用名当口令字面值误用。
// 解析出的口令调用方负责尽快零化（pkcs11.go 登录后即从内存视图零化）。
package cryptopmodule

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// pinRefFilePrefix / pinRefEnvPrefix 口令引用名载体前缀。
const (
	pinRefFilePrefix = "file:"
	pinRefEnvPrefix  = "env:"
)

// resolveModulePIN 按载体前缀解析登录口令引用名（R-S3-2）。
func resolveModulePIN(pinRef string) (string, error) {
	ref := strings.TrimSpace(pinRef)
	if ref == "" {
		return "", fmt.Errorf("module_pin_ref 为空（R-S3-2）")
	}
	switch {
	case strings.HasPrefix(ref, pinRefFilePrefix):
		return readPINFile(strings.TrimSpace(strings.TrimPrefix(ref, pinRefFilePrefix)))
	case strings.HasPrefix(ref, pinRefEnvPrefix):
		name := strings.TrimSpace(strings.TrimPrefix(ref, pinRefEnvPrefix))
		if name == "" {
			return "", fmt.Errorf("module_pin_ref=%q：env: 后须跟环境变量名（R-S3-2）", pinRef)
		}
		pin := os.Getenv(name)
		if pin == "" {
			return "", fmt.Errorf("module_pin_ref 引用的环境变量 %s 未设置或为空（R-S3-2）", name)
		}
		return strings.TrimRight(pin, "\r\n"), nil
	default:
		return "", fmt.Errorf("module_pin_ref=%q 须带载体前缀 file: 或 env:（R-S3-2 禁止口令字面值/裸引用名）", pinRef)
	}
}

// readPINFile 从挂载文件读口令（权限 0600 校验，防误配宽权限文件）。
// 注：0600 校验按 POSIX 语义执行；Windows 开发机无 POSIX 权限位
// （os.Stat 恒返回 0666），故仅在非 Windows 平台强制——部署目标为 Linux。
func readPINFile(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("module_pin_ref：file: 后须跟路径（R-S3-2）")
	}
	fi, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("module_pin_ref 口令文件 %s 不可访问: %w", path, err)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("module_pin_ref 口令文件 %s 权限 %04o 过宽，须 0600（R-S3-2）", path, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("module_pin_ref 口令文件 %s 读取失败: %w", path, err)
	}
	pin := strings.TrimRight(string(raw), "\r\n")
	if pin == "" {
		return "", fmt.Errorf("module_pin_ref 口令文件 %s 内容为空（R-S3-2）", path)
	}
	return pin, nil
}
