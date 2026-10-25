// Package main — 租户存储的方言选择与装配（P2-4 T-1.2b）。
//
// 背景：T-1.2 已实现租户存储的 PostgreSQL 支持，但**生产装配入口仍固定 SQLite**
// （`OpenTenantStore(cfg.tenantStorePath, …)`），没有任何 env 驱动的方言选择 ⇒
// 共享库能力无法启用，多集群形态形同虚设。本文件补齐该装配缺口。
//
// 方言优先级（配置口径见 config.go 的 tenantStorePGDSN 注释）：
//   - `TENANT_STORE_PG_DSN` 非空 → **共享库 PostgreSQL**（多副本共享同一份租户数据）；
//   - 否则 `TENANT_STORE_PATH` 非空 → SQLite（既有单副本行为，逐字不变）；
//   - 两者都空 → 租户门户未启用（不注册 /v1/tenant/*，调用方不会走到本文件）。
//
// fail-closed：PG 打开/建表失败**一律返回错误**，由调用方 `log.Fatalf` 拒启动——
// 共享库不可用时静默退回本地存储会让多副本各持一份租户数据，跨集群一致性直接失效，
// 且故障不可见（R-1 自治前提要求故障可观测）。
//
// 切 PG 前置：必须先跑迁移工具（T-1.6）完成数据迁移并 verify 通过，否则租户数据不可见。
package main

import (
	"fmt"

	"security-ai-gateway/gateway/gateway-admin-service/sqlutil"
)

// openTenantStoreForConfig 按配置选择租户存储方言并打开（P2-4 T-1.2b）。
func openTenantStoreForConfig(cfg *config) (TenantStore, error) {
	if cfg == nil {
		return nil, fmt.Errorf("tenant: 配置为空")
	}
	if cfg.tenantStorePGDSN != "" {
		return OpenTenantStoreWithDialect(sqlutil.Postgres, cfg.tenantStorePGDSN, true, cfg.tenantPepper)
	}
	return OpenTenantStore(cfg.tenantStorePath, true, cfg.tenantPepper)
}
