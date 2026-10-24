//go:build !pkcs11

// pkcs11_test.go —— 默认构建（无 pkcs11 tag）下的 fail-closed 与 PIN 解析单测。
// 真机（-tags pkcs11）用例见 pkcs11_live_test.go。
package cryptopmodule

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestNewBackendPKCS11FailClosedWithoutTag 默认构建下 backend=pkcs11 必须
// fail-closed（ErrNotImplemented），不得静默回退 mock（C-3）。
func TestNewBackendPKCS11FailClosedWithoutTag(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Backend = BackendPKCS11
	// Validate 会先因 LibPath 不存在失败；用存在的路径以隔离 stub 行为。
	cfg.LibPath = os.Args[0] // 任一存在文件（不会真正加载：stub 在前）
	cfg.PinRef = "env:X"
	_, err := NewBackend(cfg)
	if err == nil {
		t.Fatal("默认构建下 NewBackend(pkcs11) 应 fail-closed")
	}
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("应返回 ErrNotImplemented，实得: %v", err)
	}
}

// TestNewBackendRouting 路由回归：mock 正常、sdf 仍报 SDK 未接入、未知值拒绝。
func TestNewBackendRouting(t *testing.T) {
	mockCfg := DefaultConfig()
	mockCfg.Backend = BackendMock
	if _, err := NewBackend(mockCfg); err != nil {
		t.Fatalf("mock 后端应可用: %v", err)
	}

	sdfCfg := DefaultConfig()
	sdfCfg.Backend = BackendSDF
	sdfCfg.LibPath = os.Args[0]
	sdfCfg.PinRef = "env:X"
	_, err := NewBackend(sdfCfg)
	if !errors.Is(err, ErrNotImplemented) {
		t.Fatalf("sdf 应报 ErrNotImplemented（SDK 未接入），实得: %v", err)
	}

	badCfg := DefaultConfig()
	badCfg.Backend = "unknown-backend"
	if _, err := NewBackend(badCfg); err == nil {
		t.Fatal("未知 backend 应报错")
	}
}

// TestResolveModulePINWideFileRejected 0600 校验（POSIX 平台专属：
// Windows 无 POSIX 权限位，os.Stat 恒 0666，故跳过——部署目标为 Linux）。
func TestResolveModulePINWideFileRejected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows 无 POSIX 权限位；0600 校验仅 POSIX 平台强制")
	}
	dir := t.TempDir()
	wide := filepath.Join(dir, "pin-wide")
	if err := os.WriteFile(wide, []byte("s3cr3t-pin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveModulePIN("file:" + wide); err == nil {
		t.Fatal("宽权限口令文件应被拒（R-S3-2）")
	}
}

// TestResolveModulePIN R-S3-2 口令引用解析规则。
func TestResolveModulePIN(t *testing.T) {
	dir := t.TempDir()

	okFile := filepath.Join(dir, "pin")
	if err := os.WriteFile(okFile, []byte("s3cr3t-pin\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wideFile := filepath.Join(dir, "pin-wide")
	if err := os.WriteFile(wideFile, []byte("s3cr3t-pin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	emptyFile := filepath.Join(dir, "pin-empty")
	if err := os.WriteFile(emptyFile, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("P11_PIN_OK", "pin-from-env")
	t.Setenv("P11_PIN_EMPTY", "")

	cases := []struct {
		name    string
		ref     string
		want    string
		wantErr bool
	}{
		{"file 载体（去尾换行）", "file:" + okFile, "s3cr3t-pin", false},
		{"env 载体", "env:P11_PIN_OK", "pin-from-env", false},
		{"字面值拒绝", "12345678", "", true},
		{"空拒绝", "  ", "", true},
		{"file: 无路径", "file:", "", true},
		{"file: 不存在", "file:" + filepath.Join(dir, "nope"), "", true},
		{"file: 内容空", "file:" + emptyFile, "", true},
		{"env: 未设置", "env:P11_PIN_UNSET", "", true},
		{"env: 空名", "env:", "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := resolveModulePIN(c.ref)
			if c.wantErr {
				if err == nil {
					t.Fatalf("应拒绝 ref=%q，实得 pin=%q", c.ref, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ref=%q 不应出错: %v", c.ref, err)
			}
			if got != c.want {
				t.Fatalf("ref=%q: got %q want %q", c.ref, got, c.want)
			}
		})
	}
}
