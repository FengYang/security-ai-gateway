package main

// S3-2（D8 覆盖扩列）单测：词库/策略**版本发布**动作已接入高敏变更可执行子集。
//
// 背景（S3-2 口径）：词库版本发布、审核开关、策略 A/B/C 切换、类目启停本应全部纳入 D8 复核。
// 本轮**已接入**：词库/策略版本发布（`output_guard_policy_activate` → tee `/config/policy/activate`，须过 bench 硬门禁）。
// **剩余缺口（登记，不伪造端点）**：策略 A/B/C 切换、类目启停 **尚无 tee 运行时端点**。

import "testing"

func TestS3_2_PolicyActivateWiring(t *testing.T) {
	// ① 动作名与门户/文档口径一致（勿改名——改名会让变更单历史与文档失配）。
	if changeActionOutputGuardPolicyActivate != "output_guard_policy_activate" {
		t.Fatalf("动作名应为 output_guard_policy_activate，实际 %q", changeActionOutputGuardPolicyActivate)
	}
	// ② 在可执行子集内（否则提交被拒 = 动作等于没接）。
	if !validChangeAction(changeActionOutputGuardPolicyActivate) {
		t.Fatalf("%q 应在 validChangeAction 可执行子集内", changeActionOutputGuardPolicyActivate)
	}
	// ③ 编译期锁定执行器存在且签名一致（被删/改名即编译失败）。
	var _ func(*changeStore, *changeRequest) error = (*changeStore).execOutputGuardPolicyActivate
}
