package main

// S3-2（D8 覆盖扩列）单测：词库/策略版本发布、策略 A/B 切换、类目启停均已接入高敏变更可执行子集。
//
// 背景（S3-2 口径）：词库版本发布、审核开关、策略 A/B/C 切换、类目启停本应全部纳入 D8 复核。
// 现已接入四项：
//   - output_guard_policy_activate → tee /config/policy/activate（须过 bench 硬门禁）；
//   - output_guard_strategy        → tee /config/output-guard/strategy（A/B 双闸；C 前置未齐备不开放）；
//   - output_guard_category_toggle → tee /config/output-guard/categories（语义由 tee 31 类单一事实源裁决）。
//
// 策略 C 的实际启用仍待：缓冲层首段预审门落地 + P-FIRST-CHUNK 配置 + 法务双通过（登记，不伪造）。

import "testing"

func TestS3_2_Wiring(t *testing.T) {
	cases := []struct {
		name string
		want string
		exec func(*changeStore, *changeRequest) error
	}{
		{"版本发布", "output_guard_policy_activate", (*changeStore).execOutputGuardPolicyActivate},
		{"策略切换", "output_guard_strategy", (*changeStore).execOutputGuardStrategy},
		{"类目启停", "output_guard_category_toggle", (*changeStore).execOutputGuardCategoryToggle},
	}
	for _, tc := range cases {
		// ① 动作名与门户/文档口径一致（改名会让变更单历史与文档失配）。
		// ② 在可执行子集内（否则提交被拒 = 动作等于没接）。
		// ③ 编译期锁定执行器存在且签名一致（被删/改名即编译失败）。
		var _ func(*changeStore, *changeRequest) error = tc.exec
		if !validChangeAction(tc.want) {
			t.Errorf("%s：%q 应在 validChangeAction 可执行子集内", tc.name, tc.want)
		}
	}
	// 动作名硬断言（防常量漂移）。
	if changeActionOutputGuardPolicyActivate != "output_guard_policy_activate" ||
		changeActionOutputGuardStrategy != "output_guard_strategy" ||
		changeActionOutputGuardCategoryToggle != "output_guard_category_toggle" {
		t.Fatalf("S3-2 动作名漂移：%q/%q/%q",
			changeActionOutputGuardPolicyActivate, changeActionOutputGuardStrategy, changeActionOutputGuardCategoryToggle)
	}
}
