package main

// P1-7 T0（本体 §7.1 第 6 项）：审计启动期 fail-closed 自检单测。
//   ① D-14 单写者：启用持久化（共享 PVC）且 replicas>1 → 拒绝启动
//   ② A3-03：failClosed=true 且 WORM 后端为 nil → 拒绝启动
//   ③ A3-11：-audit-report-token 缺省 → 不阻断启动（按 §7.1 取「拒绝注册端点」语义）

import "testing"

func TestAuditStartupGuardD14SingleWriter(t *testing.T) {
	c := newAuditChain()
	const f = "/var/lib/otpmask/audit/audit.jsonl"

	// 启用持久化 + replicas>1 → 拒绝（多写者会破坏行序≡链序，A4-07）
	if err := auditStartupGuard(c, auditStartupConfig{AuditFile: f, Replicas: 2, ReportToken: "tok"}); err == nil {
		t.Fatal("D-14：replicas=2 且共享 PVC 应被拒绝，实际通过")
	}
	// 启用持久化 + replicas=1 → 通过（D-14 要求形态）
	if err := auditStartupGuard(c, auditStartupConfig{AuditFile: f, Replicas: 1, ReportToken: "tok"}); err != nil {
		t.Fatalf("D-14：replicas=1 应通过，实际: %v", err)
	}
	// 未启用持久化 + replicas>1 → 通过（无共享卷，不构成多写者）
	if err := auditStartupGuard(c, auditStartupConfig{AuditFile: "", Replicas: 3, ReportToken: "tok"}); err != nil {
		t.Fatalf("D-14：未启用持久化时多副本不应触发，实际: %v", err)
	}
}

func TestAuditStartupGuardA303FailClosedRequiresWorm(t *testing.T) {
	c := newAuditChain()
	c.SetFailClosed(true)
	if c.worm != nil {
		t.Fatal("前置：新建链的 worm 应为 nil（内存模式）")
	}
	// failClosed=true 且 worm==nil → 拒绝
	if err := auditStartupGuard(c, auditStartupConfig{AuditFile: "", Replicas: 1, ReportToken: "tok"}); err == nil {
		t.Fatal("A3-03：failClosed=true 且 worm==nil 应被拒绝，实际通过")
	}
	// 装配 WORM 后端后 → 通过
	c.SetWormBackend(newMemoryWorm())
	if err := auditStartupGuard(c, auditStartupConfig{AuditFile: "", Replicas: 1, ReportToken: "tok"}); err != nil {
		t.Fatalf("A3-03：装配 worm 后应通过，实际: %v", err)
	}
}

func TestAuditStartupGuardA311ReportTokenMissing(t *testing.T) {
	c := newAuditChain()
	// ③ 令牌缺省：按 §7.1 T0 第 6 项取「拒绝注册 /audit/report」语义，自检不阻断启动。
	if err := auditStartupGuard(c, auditStartupConfig{AuditFile: "", Replicas: 1, ReportToken: ""}); err != nil {
		t.Fatalf("A3-11：令牌缺省应仅记录日志、不阻断启动，实际返回: %v", err)
	}
	// 令牌存在 → 通过
	if err := auditStartupGuard(c, auditStartupConfig{AuditFile: "", Replicas: 1, ReportToken: "tok"}); err != nil {
		t.Fatalf("A3-11：令牌存在应通过，实际: %v", err)
	}
}
