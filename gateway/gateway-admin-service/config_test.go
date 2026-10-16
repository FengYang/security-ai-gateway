// Package main — 配置加载单测（N3/N5 env 覆盖：证明状态源 + 下发通道 fail-closed）。
package main

import (
	"strings"
	"testing"
)

// enableTenantEnv 启用租户门户所需的最小 env（AUTH_SERVICE_URL 为启用必填项，fail-closed）。
func enableTenantEnv(t *testing.T) {
	t.Helper()
	t.Setenv("TENANT_STORE_PATH", ":memory:")
	t.Setenv("TENANT_TOKEN_PEPPER", strings.Repeat("p", 32))
	t.Setenv("AUTH_SERVICE_URL", "http://auth-service:19086")
	t.Setenv("GATEWAY_CORE_URL", "")
	t.Setenv("GATEWAY_CORE_DISPATCH_TOKEN", "")
	t.Setenv("ATTEST_STATUS_URL", "")
	t.Setenv("ATTEST_STATUS_TOKEN", "")
	t.Setenv("ATTEST_STATUS_TIMEOUT_SEC", "")
}

func TestLoadTenantConfig_DisabledWithoutStorePath(t *testing.T) {
	t.Setenv("TENANT_STORE_PATH", "")
	cfg := &config{}
	if err := loadTenantConfig(cfg); err != nil {
		t.Fatalf("未配置 store 应关闭门户而非报错: %v", err)
	}
	if cfg.tenantEnabled {
		t.Error("未配置 store 不应启用门户")
	}
}

func TestLoadTenantConfig_AttestSourceEnv(t *testing.T) {
	t.Run("未配置 = 未接线 + 缺省超时", func(t *testing.T) {
		enableTenantEnv(t)
		cfg := &config{}
		if err := loadTenantConfig(cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.attestStatusURL != "" || cfg.attestStatusToken != "" {
			t.Errorf("未配置应留空: url=%q token=%q", cfg.attestStatusURL, cfg.attestStatusToken)
		}
		if cfg.attestStatusTimeoutSec != defaultAttestTimeoutSec {
			t.Errorf("超时缺省应=%d, got=%d", defaultAttestTimeoutSec, cfg.attestStatusTimeoutSec)
		}
	})
	t.Run("读取 + 去尾斜杠 + 超时回退", func(t *testing.T) {
		enableTenantEnv(t)
		t.Setenv("ATTEST_STATUS_URL", "http://attest-verify:19191/")
		t.Setenv("ATTEST_STATUS_TOKEN", "attest-tok")
		t.Setenv("ATTEST_STATUS_TIMEOUT_SEC", "0")
		cfg := &config{}
		if err := loadTenantConfig(cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.attestStatusURL != "http://attest-verify:19191" {
			t.Errorf("URL 应去尾斜杠: %q", cfg.attestStatusURL)
		}
		if cfg.attestStatusToken != "attest-tok" {
			t.Errorf("令牌应读取: %q", cfg.attestStatusToken)
		}
		if cfg.attestStatusTimeoutSec != defaultAttestTimeoutSec {
			t.Errorf("0 应回退缺省 %d, got=%d", defaultAttestTimeoutSec, cfg.attestStatusTimeoutSec)
		}
	})
	t.Run("正数超时保留", func(t *testing.T) {
		enableTenantEnv(t)
		t.Setenv("ATTEST_STATUS_TIMEOUT_SEC", "9")
		cfg := &config{}
		if err := loadTenantConfig(cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.attestStatusTimeoutSec != 9 {
			t.Errorf("超时应=9, got=%d", cfg.attestStatusTimeoutSec)
		}
	})
}

func TestLoadTenantConfig_DispatchEnv(t *testing.T) {
	t.Run("URL 已配置但令牌缺失 fail-closed", func(t *testing.T) {
		enableTenantEnv(t)
		t.Setenv("GATEWAY_CORE_URL", "http://gateway-core:19090")
		cfg := &config{}
		if err := loadTenantConfig(cfg); err == nil {
			t.Error("GATEWAY_CORE_URL 已配置但内部服务令牌缺失应 fail-closed")
		}
	})
	t.Run("URL + 令牌 + 超时缺省回退", func(t *testing.T) {
		enableTenantEnv(t)
		t.Setenv("GATEWAY_CORE_URL", "http://gateway-core:19090/")
		t.Setenv("GATEWAY_CORE_DISPATCH_TOKEN", "dispatch-tok")
		t.Setenv("GATEWAY_CORE_DISPATCH_TIMEOUT_SEC", "0")
		cfg := &config{}
		if err := loadTenantConfig(cfg); err != nil {
			t.Fatal(err)
		}
		if cfg.gatewayCoreURL != "http://gateway-core:19090" {
			t.Errorf("URL 应去尾斜杠: %q", cfg.gatewayCoreURL)
		}
		if cfg.gatewayCoreToken != "dispatch-tok" {
			t.Errorf("令牌应读取: %q", cfg.gatewayCoreToken)
		}
		if cfg.dispatchTimeoutSec != defaultDispatchTimeoutSec {
			t.Errorf("0 应回退缺省 %d, got=%d", defaultDispatchTimeoutSec, cfg.dispatchTimeoutSec)
		}
	})
}
