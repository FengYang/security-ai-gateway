package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// P2-4 T-1.2b tenant store PG 装配（env 驱动的方言选择）的单测。

// 配置解析：三种组合分别决定"未启用 / SQLite / PG"。
func TestTenantStoreConfig_DialectSelection(t *testing.T) {
	t.Setenv("TENANT_TOKEN_PEPPER", strings.Repeat("p", 32))
	t.Setenv("AUTH_SERVICE_URL", "http://127.0.0.1:1/auth")

	// ① 两者都空 → 租户门户未启用
	t.Setenv("TENANT_STORE_PATH", "")
	t.Setenv("TENANT_STORE_PG_DSN", "")
	cfg := &config{}
	if err := loadTenantConfig(cfg); err != nil {
		t.Fatalf("未启用不应报错: %v", err)
	}
	if cfg.tenantEnabled {
		t.Error("两者都空时 tenantEnabled 应为 false")
	}

	// ② 仅 path → SQLite
	t.Setenv("TENANT_STORE_PATH", filepath.Join(t.TempDir(), "tenant.db"))
	cfg = &config{}
	if err := loadTenantConfig(cfg); err != nil {
		t.Fatalf("sqlite 配置不应报错: %v", err)
	}
	if !cfg.tenantEnabled || cfg.tenantStorePGDSN != "" {
		t.Errorf("仅 path 时配置不符：enabled=%v pgDSN=%q", cfg.tenantEnabled, cfg.tenantStorePGDSN)
	}

	// ③ 仅 PG DSN → 走共享库（path 可空）
	t.Setenv("TENANT_STORE_PATH", "")
	t.Setenv("TENANT_STORE_PG_DSN", "postgres://u:p@127.0.0.1:5432/db?sslmode=disable")
	cfg = &config{}
	if err := loadTenantConfig(cfg); err != nil {
		t.Fatalf("PG 配置不应报错: %v", err)
	}
	if !cfg.tenantEnabled || cfg.tenantStorePGDSN == "" {
		t.Errorf("仅 PG DSN 时配置不符：enabled=%v pgDSN=%q", cfg.tenantEnabled, cfg.tenantStorePGDSN)
	}

	// ④ 两者都设 → PG 优先（配置里两者都保留，打开时按 PG 选）
	t.Setenv("TENANT_STORE_PATH", filepath.Join(t.TempDir(), "tenant.db"))
	cfg = &config{}
	if err := loadTenantConfig(cfg); err != nil {
		t.Fatalf("双配置不应报错: %v", err)
	}
	if cfg.tenantStorePGDSN == "" || cfg.tenantStorePath == "" {
		t.Errorf("双配置时两项都应保留：path=%q pgDSN=%q", cfg.tenantStorePath, cfg.tenantStorePGDSN)
	}
}

// pepper 缺失时必须 fail-closed（租户门户已启用）。
func TestTenantStoreConfig_PepperRequired(t *testing.T) {
	t.Setenv("TENANT_TOKEN_PEPPER", "")
	t.Setenv("TENANT_STORE_PATH", filepath.Join(t.TempDir(), "tenant.db"))
	t.Setenv("TENANT_STORE_PG_DSN", "")
	cfg := &config{}
	if err := loadTenantConfig(cfg); err == nil {
		t.Fatal("pepper 缺失应报错（fail-closed）")
	}
}

// 打开路径：SQLite 正常打开；PG 不可达时返回错误（fail-closed，由调用方拒启动）。
func TestOpenTenantStoreForConfig(t *testing.T) {
	// SQLite 路径
	cfg := &config{
		tenantStorePath: filepath.Join(t.TempDir(), "tenant.db"),
		tenantPepper:    []byte(strings.Repeat("p", 32)),
	}
	ts, err := openTenantStoreForConfig(cfg)
	if err != nil {
		t.Fatalf("SQLite 打开失败: %v", err)
	}
	if ts == nil {
		t.Fatal("SQLite 打开返回空")
	}
	ts.Close()

	// PG 不可达（端口 1 必然拒绝连接）→ 必须返回错误而不是静默退回 SQLite
	cfgPG := &config{
		tenantStorePGDSN: "postgres://u:p@127.0.0.1:1/db?sslmode=disable&connect_timeout=1",
		tenantPepper:     []byte(strings.Repeat("p", 32)),
	}
	if _, err := openTenantStoreForConfig(cfgPG); err == nil {
		t.Fatal("PG 不可达时应返回错误（fail-closed），不得静默退回 SQLite")
	}

	// 配置为空
	if _, err := openTenantStoreForConfig(nil); err == nil {
		t.Fatal("空配置应返回错误")
	}
}
