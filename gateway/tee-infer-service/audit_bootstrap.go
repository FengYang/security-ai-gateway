package main

// P1-7 T0（本体 §7.1 T0 第 6 项）：审计启动期 fail-closed 自检。
//
// 本体要求三条启动期自检（任一不满足即拒绝启动并给出明确日志）：
//   ① D-14：`replicas>1` 且共享同一 PVC（即 `-audit-file` 启用持久化）→ 拒绝启动
//      —— 多副本写同一 WORM 文件会造成行序交错/覆盖（A4-07 装配期静默故障）。
//   ② A3-03：`failClosed=true` 且 WORM 后端为 nil（纯内存模式）→ 拒绝启动
//      —— 已声明"写失败即拒绝业务请求"，却没有落盘后端 ⇒ 该保证不成立。
//   ③ A3-11：`-audit-report-token` 缺省 → `/audit/report` 端点不注册（fail-closed）。
//
// ⚠️ 第三条口径说明（分歧已登记，待文档裁定）：
//    本体 §7.1 T0 第 6 项原文为「-audit-report-token 为空 → **拒绝注册** /audit/report」，
//    而 v1.11 修订记录 A3-11 记为「缺省即**拒绝启动**」。二者不一致。
//    本实现按 §7.1 T0 第 6 项取「拒绝注册端点」——若改为拒绝启动，则所有未启用
//    数据面上报的部署（含 devMode 形态）将无法启动，破坏既有行为。端点注册与否
//    由 main 处理（见 mux.HandleFunc("/audit/report") 分支），本函数仅落地日志、
//    不阻断启动。

import (
	"fmt"
	"log"
)

// auditStartupConfig 启动期自检入参。
// 全部来自命令行/部署层注入——进程自身无法感知 K8s 副本数等部署形态，
// 故必须由 helm 模板显式传入（见 templates/tee-infer-service.yaml）。
type auditStartupConfig struct {
	// AuditFile：WORM 事件文件路径（-audit-file）。
	// 非空 = 已启用持久化（挂载 PVC；D-14 下为单写者共享卷）。
	AuditFile string
	// Replicas：本服务副本数（部署注入 -audit-replicas，须与 Deployment
	// spec.replicas 一致）。进程无法自行推断，故显式注入。
	Replicas int
	// ReportToken：数据面上报只读令牌（-audit-report-token）。
	ReportToken string
}

// auditStartupGuard 执行启动期 fail-closed 自检。
// 返回非 nil 表示自检未通过，调用方（main）应 log.Fatalf 拒绝启动。
func auditStartupGuard(c *auditChain, cfg auditStartupConfig) error {
	if c == nil {
		return fmt.Errorf("审计链未初始化（auditChain == nil）")
	}

	// ① D-14 单写者：启用持久化（共享 PVC）时副本数必须为 1。
	if cfg.AuditFile != "" && cfg.Replicas > 1 {
		return fmt.Errorf(
			"D-14 单写者约束被破坏：-audit-file=%q 已启用持久化（共享 PVC），但副本数 replicas=%d>1；"+
				"多副本写同一 WORM 文件会导致行序交错/覆盖（A4-07），请设 replicas=1 或关闭持久化",
			cfg.AuditFile, cfg.Replicas)
	}

	// ② A3-03：声明 fail-closed 却没有落盘后端 ⇒ 保证不成立。
	if c.failClosed && c.worm == nil {
		return fmt.Errorf(
			"A3-03 fail-closed 前提缺失：-audit-fail-closed=true 但 WORM 后端为 nil（纯内存模式，"+
				"-audit-file 未配置）；写失败时无落盘可判定，fail-closed 保证不成立，"+
				"请配置 -audit-file 或关闭该开关")
	}

	// ③ A3-11：令牌缺省 → 端点不注册（语义见文件头口径说明）。仅日志，不阻断启动。
	if cfg.ReportToken == "" {
		log.Printf("[audit] 启动期自检③（A3-11）：-audit-report-token 缺省 → /audit/report 不注册" +
			"（fail-closed；按 §7.1 T0 第 6 项取「拒绝注册」语义，不阻断启动）")
	}
	return nil
}
