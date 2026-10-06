package main

import (
	"fmt"
	"strings"
)

// 启动期安全守卫（威胁模型 GAP-01 / GAP-05）。
//
// 原实现存在两处"开发遗留"，生产漏配时会静默降级，密态与治理能力形同虚设：
//   - GAP-01：-enclave 默认 "mock"，生产漏配时飞地为软件模拟，密态保护不成立；
//   - GAP-05：-admin-token 为空时 checkAdmin 直接放行（/metrics /audit /usage 无鉴权）。
//
// 本守卫在生产形态（devMode=false，即未显式声明 -dev-mode）下 fail-closed：
// 命中任一违规即拒绝启动；仅当显式声明 -dev-mode（开发/CI/演示）时才放行。
const (
	// gapMockEnclave：生产禁用 mock 飞地。
	gapMockEnclave = "GAP-01"
	// gapEmptyAdminToken：生产必须配置管理端点令牌。
	gapEmptyAdminToken = "GAP-05"
)

// validateStartupSecurity 校验启动期安全前置条件。
//
// enclaveMode 为 -enclave 取值，adminToken 为 -admin-token 取值，devMode 为 -dev-mode 开关。
// 返回 nil 表示通过；否则返回聚合错误（可同时命中多项，便于一次暴露全部配置问题）。
func validateStartupSecurity(enclaveMode, adminToken string, devMode bool) error {
	if devMode {
		return nil
	}
	var problems []string
	if strings.EqualFold(strings.TrimSpace(enclaveMode), "mock") {
		problems = append(problems, fmt.Sprintf(
			"[%s] 生产形态禁止 mock 飞地（-enclave=mock）：软件模拟飞地不提供密态保护；开发/CI 请显式加 -dev-mode",
			gapMockEnclave))
	}
	if strings.TrimSpace(adminToken) == "" {
		problems = append(problems, fmt.Sprintf(
			"[%s] 生产形态必须配置 -admin-token：为空时管理端点（/metrics /audit /usage）无鉴权放行；开发/CI 请显式加 -dev-mode",
			gapEmptyAdminToken))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("启动安全校验未通过（fail-closed）: %s", strings.Join(problems, "；"))
}
