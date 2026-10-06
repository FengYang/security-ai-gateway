package main

import (
	"strings"
	"testing"
)

// TestValidateStartupSecurity 覆盖 GAP-01（mock 飞地）与 GAP-05（空管理令牌）
// 在生产/开发两种形态下的组合判定，并校验错误文案携带可追溯的 GAP 编号。
func TestValidateStartupSecurity(t *testing.T) {
	cases := []struct {
		name        string
		enclaveMode string
		adminToken  string
		devMode     bool
		wantErr     bool
		wantGAPs    []string // 期望错误文案包含的 GAP 编号（若 wantErr）
	}{
		{name: "生产 tdx + 令牌：通过", enclaveMode: "tdx", adminToken: "t"},
		{name: "生产 sgx + 令牌：通过（sgx 由飞地构造另行 fail-closed）", enclaveMode: "sgx", adminToken: "t"},
		{name: "生产 nv-cc + 令牌：通过", enclaveMode: "nv-cc", adminToken: "t"},
		{name: "生产 mock：命中 GAP-01", enclaveMode: "mock", adminToken: "t", wantErr: true, wantGAPs: []string{"GAP-01"}},
		{name: "生产 空令牌：命中 GAP-05", enclaveMode: "tdx", wantErr: true, wantGAPs: []string{"GAP-05"}},
		{name: "生产 mock + 空令牌：同时命中 GAP-01/GAP-05", enclaveMode: "mock", wantErr: true, wantGAPs: []string{"GAP-01", "GAP-05"}},
		{name: "生产 mock 大小写与空白归一", enclaveMode: "  MOCK ", adminToken: "t", wantErr: true, wantGAPs: []string{"GAP-01"}},
		{name: "生产 空白令牌视为空", enclaveMode: "tdx", adminToken: "   ", wantErr: true, wantGAPs: []string{"GAP-05"}},
		{name: "开发 mock + 空令牌：放行", enclaveMode: "mock", devMode: true},
		{name: "开发 tdx + 令牌：放行", enclaveMode: "tdx", adminToken: "t", devMode: true},
		{name: "开发 未知飞地取值：放行（由 main 的飞地分支处理）", enclaveMode: "weird", devMode: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateStartupSecurity(c.enclaveMode, c.adminToken, c.devMode)
			if c.wantErr && err == nil {
				t.Fatalf("期望拒绝启动，实际通过（enclave=%q token=%q dev=%v）", c.enclaveMode, c.adminToken, c.devMode)
			}
			if !c.wantErr {
				if err != nil {
					t.Fatalf("期望通过，实际报错: %v", err)
				}
				return
			}
			msg := err.Error()
			for _, g := range c.wantGAPs {
				if !strings.Contains(msg, g) {
					t.Fatalf("错误文案缺少 %s: %s", g, msg)
				}
			}
			// 反向断言：未被命中的 GAP 不得误报。
			for _, g := range []string{gapMockEnclave, gapEmptyAdminToken} {
				if contains(c.wantGAPs, g) {
					continue
				}
				if strings.Contains(msg, g) {
					t.Fatalf("错误文案误报未命中项 %s: %s", g, msg)
				}
			}
		})
	}
}

func contains(xs []string, target string) bool {
	for _, x := range xs {
		if x == target {
			return true
		}
	}
	return false
}
