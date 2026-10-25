// Package main — 三权分立授权（P1-3 等保合规 §6.2，ENB2-07）。
//
// 模型：角色(role) × 资源域(domain) × 动作(action)，矩阵缺省 = 拒绝（fail-closed）。
// 三权分立 6 角色：system_admin / sec_admin / audit_admin / auditor /
// billing_reader / break_glass；既有 admin 过渡期保留（兼容映射 = system_admin ∪
// sec_admin，端点级并集），旧角色向后兼容至 M6（详设 §6.2 迁移策略）。
//
// 数据源：端点 → 资源域:动作 全量映射表（详设 §6.2 A 类通道）为 **唯一映射依据**：
//   - 本表与矩阵不一致时以本表为准（规则②），不一致行以"既有语义变更"注释登记；
//   - 例外通道（HMAC 推送 / 插件内网 Token / 无鉴权运维端点）不入本矩阵（规则③前登记制）；
//   - 矩阵（角色×域×动作）为本表的域级模型，runtime 校验走端点规则，矩阵供
//     越权测试与一致性断言使用。
package main

import (
	"log"
	"net/http"
	"time"
)

// 资源域（详设 §6.2）。
const (
	domAudit      = "audit"      // 审计链/审计事件
	domSec        = "sec"        // 安全状态/链校验/WAF/IDS/密码 profile
	domCredential = "credential" // 托管凭据（broker-providers；仅列表/指纹）
	domBilling    = "billing"    // 账单/套餐/用量
	domTenant     = "tenant"     // 租户/账号
	domConfig     = "config"     // 模型目录/密码 profile/系统配置/变更复核
)

// 动作（详设 §6.2）。
const (
	actRead   = "read"
	actWrite  = "write"
	actExport = "export"
)

// roleAny 映射表"全部认证角色"标记（仅要求已通过第一因素认证）。
const roleAny = "*"

// MFA 新鲜度（§6.1 step-up）：会话级写操作 8h；高敏写操作 10min 须重新核验。
const (
	mfaSessionFreshness = 8 * time.Hour
	mfaStepUpFreshness  = 10 * time.Minute
)

// endpointRule 单端点授权规则（映射表一行的代码化）。
type endpointRule struct {
	domain string
	action string
	roles  []string      // 目标角色；roleAny = 全部认证角色
	mfa    time.Duration // >0 = 须持 MFA 声明且核验时间在该新鲜度内（写端点）
}

// ---- 端点规则登记（详设 §6.2 映射表 A 类通道；路径锚点见各 handler）----

var (
	// /v1/adminext/echo（调试端点，过渡期后考虑移除）。
	epEcho = endpointRule{domConfig, actRead, []string{roleAny}, 0}

	// /v1/adminext/models GET（config:read；与矩阵一致）。
	epModels = endpointRule{domConfig, actRead,
		[]string{roleSystemAdmin, roleSecAdmin, roleAuditAdmin, roleAuditor}, 0}

	// /v1/adminext/usage GET + /v1/adminext/usage/quota GET（billing:read）。
	// 既有语义变更：原"任意认证可读"按映射表收窄为 sys/audit/billing_reader
	//（billing_reader 保留计费读；sec_admin/auditor 不含——表为准，规则②）。
	epUsageRead = endpointRule{domBilling, actRead,
		[]string{roleSystemAdmin, roleAuditAdmin, roleBillingReader}, 0}

	// /v1/adminext/usage/quota POST（billing:write；写配额属计费域写操作，收窄 system_admin + 会话级 MFA）。
	// 2026-10-09 修正（F-5）：本体 §6.2 表原误记为 GET/billing:read，致写操作仅需只读权限（权限降级）；
	// 现以实现语义回改映射表并同步本规则。
	epQuotaWrite = endpointRule{domBilling, actWrite, []string{roleSystemAdmin}, mfaSessionFreshness}

	// /v1/adminext/metering/reconcile GET（billing:read；只读代理，同 epUsageRead 口径）。
	// 2026-10-09 修正（F-2）：本体 §6.2 表原误记为 POST/billing:write（与实现 GET 只读相反）。
	epMeteringReconcile = endpointRule{domBilling, actRead,
		[]string{roleSystemAdmin, roleAuditAdmin, roleBillingReader}, 0}

	// /v1/adminext/audit-events POST（audit:write；账号管理投递）。
	// 既有语义变更：映射表定为 system_admin（账号管理归系统管理员）；矩阵 audit:write
	// 归 audit_admin——以表为准（规则②），矩阵差异登记于此。
	epAuditEvents = endpointRule{domAudit, actWrite, []string{roleSystemAdmin}, mfaSessionFreshness}

	// P2-4 §6.1 集群注册 API：
	//   - 写（注册/审批/摘除）：admin 写 + 会话级 MFA（受控变更，step-up 口径与审计投递一致）；
	//   - 读（列表）：admin/审计角色可读（auditor 需看集群状态与版本，R-5 举证依赖）。
	epClusterWrite = endpointRule{domConfig, actWrite, []string{roleSystemAdmin}, mfaSessionFreshness}
	epClusterRead  = endpointRule{domConfig, actRead,
		[]string{roleSystemAdmin, roleSecAdmin, roleAuditAdmin, roleAuditor}, 0}

	// /v1/adminext/sec-status GET（sec:read；全部管理角色 + auditor）。
	epSecStatus = endpointRule{domSec, actRead,
		[]string{roleSystemAdmin, roleSecAdmin, roleAuditAdmin, roleAuditor}, 0}

	// /v1/adminext/audit-chain GET（audit:read）。
	// 既有语义变更：矩阵含 system_admin，映射表收窄为 audit_admin/auditor/sec_admin。
	epAuditChain = endpointRule{domAudit, actRead,
		[]string{roleAuditAdmin, roleAuditor, roleSecAdmin}, 0}

	// /v1/adminext/audit-chain/verify GET（audit:read；R2-19② 点名变更）。
	// 2026-10-10 修正（F-9）：本体 §6.2 表原误记为 POST（实现与测试均为 GET 只读重算，
	// 与 audit:read 动作一致）；以实现语义回改映射表，避免"方法/动作不一致"类缺陷复发。
	epAuditChainVerify = endpointRule{domAudit, actRead, []string{roleAuditAdmin}, 0}

	// /v1/adminext/audit-chain/export GET（audit:export；R2-19① 点名变更，auditor 不含）。
	epAuditChainExport = endpointRule{domAudit, actExport, []string{roleAuditAdmin}, 0}

	// /v1/adminext/audit-tee GET（audit:read）。
	epAuditTee = endpointRule{domAudit, actRead, []string{roleAuditAdmin, roleAuditor}, 0}

	// P1-7 T8（§6.2/§7.7）：温/冷层归档检索 GET（audit:read；同 audit-tee 口径）。
	epAuditFullSearch = endpointRule{domAudit, actRead, []string{roleAuditAdmin, roleAuditor}, 0}

	// P1-7 T8：归档导出 GET（audit:export；与 audit-chain/export 同口径，auditor 不含）。
	epAuditFullExport = endpointRule{domAudit, actExport, []string{roleAuditAdmin, roleSystemAdmin}, 0}

	// P1-7 T9（§6.4/§7.8）：留存声明读（audit:read；auditor 可读）。
	epAuditRetentionRead = endpointRule{domAudit, actRead, []string{roleAuditAdmin, roleAuditor, roleSecAdmin}, 0}

	// P1-7 T9：留存声明写（audit:write；admin，会话级 MFA）。
	epAuditRetentionWrite = endpointRule{domAudit, actWrite, []string{roleSystemAdmin}, mfaSessionFreshness}

	// /v1/adminext/changes GET（config:read；全部管理角色）。
	epChangesRead = endpointRule{domConfig, actRead,
		[]string{roleSystemAdmin, roleSecAdmin, roleAuditAdmin}, 0}

	// /v1/adminext/changes/ POST/PATCH（config:write；高敏变更复核，step-up）。
	epChangesWrite = endpointRule{domConfig, actWrite, []string{roleSystemAdmin}, mfaStepUpFreshness}

	// P1-2 观测族 GET（audit:read；排障留痕/可用性报表）：trace×3 / sla / slo。
	epTraceFamilyRead = endpointRule{domAudit, actRead,
		[]string{roleAuditAdmin, roleAuditor, roleSystemAdmin, roleSecAdmin}, 0}

	// /v1/adminext/slo POST（config:write）。
	epSloWrite = endpointRule{domConfig, actWrite, []string{roleSystemAdmin}, mfaSessionFreshness}

	// /v1/adminext/tracing/tenant POST（tenant:write）。
	epTracingTenant = endpointRule{domTenant, actWrite, []string{roleSystemAdmin}, mfaSessionFreshness}

	// /v1/adminext/billing/* GET（billing:read；同 epUsageRead 收窄口径）。
	epBillingRead = endpointRule{domBilling, actRead,
		[]string{roleSystemAdmin, roleAuditAdmin, roleBillingReader}, 0}

	// /v1/adminext/billing/* 写（billing:write；freeze/unfreeze 高敏 step-up，
	// subscription/close-daily/close-monthly 会话级）。
	epBillingWrite       = endpointRule{domBilling, actWrite, []string{roleSystemAdmin}, mfaSessionFreshness}
	epBillingFreezeWrite = endpointRule{domBilling, actWrite, []string{roleSystemAdmin}, mfaStepUpFreshness}

	// /v1/adminext/billing/verify-chain POST（billing:read 校验动作；映射表指定
	// audit_admin / system_admin，无 +MFA 标记）。
	epBillingVerifyChain = endpointRule{domBilling, actRead,
		[]string{roleAuditAdmin, roleSystemAdmin}, 0}

	// /v1/adminext/broker-providers GET（credential:read；与矩阵一致）。
	epBrokerRead = endpointRule{domCredential, actRead,
		[]string{roleSystemAdmin, roleSecAdmin, roleAuditAdmin, roleAuditor}, 0}

	// /v1/adminext/broker-providers 写（credential:write；高敏，step-up）。
	epBrokerWrite = endpointRule{domCredential, actWrite, []string{roleSystemAdmin}, mfaStepUpFreshness}

	// /v1/adminext/cryptop/profile POST（sec:write；既有语义变更：现状 admin → 拆分后
	// sec_admin，§6.2 矩阵 sec 域 write 的实义锚点；高敏，step-up）。
	epCryptopProfile = endpointRule{domSec, actWrite, []string{roleSecAdmin}, mfaStepUpFreshness}

	// /v1/adminext/cryptop/partition POST（sec:write；T-4 租户分区编排，高敏，step-up）。
	epCryptopPartitionWrite = endpointRule{domSec, actWrite, []string{roleSecAdmin}, mfaStepUpFreshness}

	// /v1/adminext/cryptop/partition GET（sec:read；分区与配额清单，auditor 可读，§6.3）。
	epCryptopPartitionRead = endpointRule{domSec, actRead,
		[]string{roleSystemAdmin, roleSecAdmin, roleAuditAdmin, roleAuditor}, 0}

	// /v1/adminext/mfa/*（sec:write；各管理角色本人第二因素，第一因素已过）。
	epMFA = endpointRule{domSec, actWrite,
		[]string{roleSystemAdmin, roleSecAdmin, roleAuditAdmin}, 0}
)

// roleAllowsRule 端点级角色判定：目标角色列 + 过渡期 admin 兼容并集 + break_glass。
//
// 过渡期兼容（详设 §6.2 迁移策略）：legacy admin 在"system_admin 或 sec_admin
// 被允许的端点"视同有权（端点级并集）；audit_admin 专属端点（audit-chain/verify、
// /export）对 legacy admin 同样收窄——属 R2-19 登记的既有语义变更。
func roleAllowsRule(rule endpointRule, c *claims) bool {
	if c.Role == roleBreakGlass {
		return breakGlassActive(c)
	}
	for _, r := range rule.roles {
		if r == roleAny {
			return true
		}
		if c.Role == r {
			return true
		}
		// 过渡期：legacy admin 兼容映射（system_admin ∪ sec_admin）。
		if c.Role == roleAdmin && (r == roleSystemAdmin || r == roleSecAdmin) {
			return true
		}
	}
	return false
}

// breakGlassActive break_glass 令牌启用判定（详设 §6.2：正常状态禁用）：
// 须 ADMIN_BREAK_GLASS_ENABLED=true 且令牌短时效（exp-iat ≤ 15min，签发侧契约），
// 双条件 fail-closed。
func breakGlassActive(c *claims) bool {
	if !breakGlassEnabled() {
		return false
	}
	return c.EXP > 0 && c.IAT > 0 && c.EXP-c.IAT <= breakGlassMaxLifetime
}

// requireRule 端点级声明式校验（扩展 requireRole/requireReadAccess，详设 §6.2）：
// 认证 → 角色×域×动作（矩阵缺省=拒绝）→ 写端点 MFA（step-up）→ 放行。
// 拒绝统一 403 + metrics.incAuthRejected + 结构化日志（sub/role/端点/rid）。
func requireRule(w http.ResponseWriter, r *http.Request, rule endpointRule) bool {
	c := claimsFrom(r.Context())
	if c == nil {
		metrics.incAuthRejected()
		log.Printf("[adminext] 403 缺少认证上下文：%s %s rid=%s", r.Method, r.URL.Path, r.Header.Get("X-Request-ID"))
		http.Error(w, "forbidden: 需要已认证会话", http.StatusForbidden)
		return false
	}
	if !roleAllowsRule(rule, c) {
		metrics.incAuthRejected()
		log.Printf("[adminext] 403 越权拒绝：sub=%s role=%s 域=%s 动作=%s %s %s rid=%s",
			c.Sub, c.Role, rule.domain, rule.action, r.Method, r.URL.Path, r.Header.Get("X-Request-ID"))
		http.Error(w, "forbidden: 无权访问该资源（"+rule.domain+":"+rule.action+"）", http.StatusForbidden)
		return false
	}
	if rule.mfa > 0 && !mfaSatisfied(c, rule.mfa) {
		metrics.incAuthRejected()
		log.Printf("[adminext] 403 MFA 第二步未通过：sub=%s role=%s %s %s rid=%s",
			c.Sub, c.Role, r.Method, r.URL.Path, r.Header.Get("X-Request-ID"))
		http.Error(w, "forbidden: 写操作须先通过 MFA 第二步校验", http.StatusForbidden)
		return false
	}
	return true
}

// ---- 角色 × 资源域 × 动作 授权矩阵（详设 §6.2 初始授权矩阵）----
//
// 仅供越权测试与矩阵/端点一致性断言使用；runtime 走端点规则（映射表为准）。
// true = 允许；缺省（无条目）= 拒绝。

type roleMatrix map[string]map[string]bool // domain → action → allowed

var authzMatrix = map[string]roleMatrix{
	roleSystemAdmin: {
		domAudit:      {actRead: true},
		domSec:        {actRead: true},
		domCredential: {actRead: true, actWrite: true},
		domBilling:    {actRead: true, actWrite: true, actExport: true},
		domTenant:     {actRead: true, actWrite: true, actExport: true},
		domConfig:     {actRead: true, actWrite: true, actExport: true},
	},
	roleSecAdmin: {
		domAudit:      {actRead: true},
		domSec:        {actRead: true, actWrite: true, actExport: true},
		domCredential: {actRead: true},
		domBilling:    {actRead: true},
		domTenant:     {actRead: true},
		domConfig:     {actRead: true}, // 安全项可写（详设 §6.2 角色表注）
	},
	roleAuditAdmin: {
		domAudit:      {actRead: true, actWrite: true, actExport: true},
		domSec:        {actRead: true},
		domCredential: {actRead: true},
		domBilling:    {actRead: true},
		domTenant:     {actRead: true},
		domConfig:     {actRead: true},
	},
	roleAuditor: {
		domAudit:      {actRead: true, actExport: true},
		domSec:        {actRead: true},
		domCredential: {actRead: true},
		// domBilling 不含（2026-10-09 修正 F-1）：按 §6.2 映射表，用量/账单读归
		// system_admin / audit_admin / billing_reader；原矩阵误含 billing:read，
		// 与端点规则 epUsageRead 不一致，按改造规则②以表为准回改矩阵。
		domTenant: {actRead: true},
		domConfig: {actRead: true},
	},
	roleBillingReader: {
		domBilling: {actRead: true},
	},
}

// roleAllowsMatrix 矩阵级判定（缺省 = 拒绝）；legacy admin = system ∪ sec 并集。
func roleAllowsMatrix(role, domain, action string) bool {
	grants := func(r string) bool {
		m, ok := authzMatrix[r]
		if !ok {
			return false
		}
		acts, ok := m[domain]
		return ok && acts[action]
	}
	if grants(role) {
		return true
	}
	if role == roleAdmin {
		return grants(roleSystemAdmin) || grants(roleSecAdmin)
	}
	return false
}

// roleUnrestricted 跨租户不受限角色（原"admin 全租户"语义的继任判定）：
// legacy admin 与 system_admin；其余角色按 claims.Tenant 作用域（跨租户 403）。
func roleUnrestricted(c *claims) bool {
	return c != nil && (c.Role == roleAdmin || c.Role == roleSystemAdmin)
}
