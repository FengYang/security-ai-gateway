package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// OG-5（chunk-meta + 终止码）验收单测。

// TestBuildGuardMetaNoHit：未命中时 detected=false，无 category/rule_version。
func TestBuildGuardMetaNoHit(t *testing.T) {
	og, _, _ := newTestOutputGuard(t, outputGuardShadow, "t", "r")
	collectThrough(t, og, []string{"正常文本。"}) // 不命中

	gm := og.BuildGuardMeta()
	if gm == nil {
		t.Fatal("BuildGuardMeta 不应返回 nil（始终返回非 nil，由 omitempty 控制是否输出）")
	}
	if gm.Detected {
		t.Fatal("未命中时 detected 应为 false")
	}
	if gm.Filtered {
		t.Fatal("未命中时 filtered 应为 false")
	}
	if gm.Category != "" {
		t.Fatalf("未命中时 category 应为空，实际 %q", gm.Category)
	}
	if gm.Mode != outputGuardShadow {
		t.Fatalf("mode 应为 shadow，实际 %q", gm.Mode)
	}
	if gm.PolicyVersion != defaultPolicyVersion {
		t.Fatalf("policy_version 不符：%q", gm.PolicyVersion)
	}
}

// TestBuildGuardMetaShadowHit：shadow 命中 → detected=true, filtered=false, action=flag。
func TestBuildGuardMetaShadowHit(t *testing.T) {
	og, _, _ := newTestOutputGuard(t, outputGuardShadow, "t", "r")
	collectThrough(t, og, []string{"-- 注释。"}) // 命中 sql_injection → A1-07

	gm := og.BuildGuardMeta()
	if !gm.Detected {
		t.Fatal("shadow 命中时 detected 应为 true")
	}
	if gm.Filtered {
		t.Fatal("shadow 模式下 filtered 应为 false（只标记不拦截）")
	}
	if gm.Action != catActionFlag {
		t.Fatalf("shadow 命中动作应为 flag，实际 %q", gm.Action)
	}
	if gm.Category != "A1-07" {
		t.Fatalf("category 应为 A1-07（sql_injection 映射后），实际 %q", gm.Category)
	}
	if gm.Mode != outputGuardShadow {
		t.Fatalf("mode 应为 shadow，实际 %q", gm.Mode)
	}
}

// TestBuildGuardMetaFirstHitWins：多次命中只取首次命中的类目（与 would_reject 去重逻辑一致）。
func TestBuildGuardMetaFirstHitWins(t *testing.T) {
	og, _, _ := newTestOutputGuard(t, outputGuardShadow, "t", "r")
	// A1-07 先命中，然后 A4-06
	collectThrough(t, og, []string{"-- 注释。", "手机号13812345678。"})

	gm := og.BuildGuardMeta()
	if gm.Category != "A1-07" {
		t.Fatalf("首次命中应为 A1-07，实际 %q", gm.Category)
	}
}

// TestChunkMetaJSONOmitempty：未命中时 guard 序列化为 detected=false + mode + policy_version，
// category/rule_version/action 不出现（omitempty）。
func TestChunkMetaJSONOmitempty(t *testing.T) {
	og, _, _ := newTestOutputGuard(t, outputGuardShadow, "t", "r")
	collectThrough(t, og, []string{"正常文本。"})

	chunk := textStreamChunk{Seq: 1, Finish: "stop", Guard: og.BuildGuardMeta()}
	data, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(data)

	// 必须有的字段
	for _, want := range []string{
		`"seq":1`,
		`"finish":"stop"`,
		`"guard":`,
		`"detected":false`,
		`"filtered":false`,
		`"policy_version":"` + defaultPolicyVersion + `"`,
		`"mode":"shadow"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("JSON 缺失 %q\n---\n%s", want, s)
		}
	}
	// 不应有的字段（omitempty）
	for _, notWant := range []string{
		`"category"`,
		`"rule_version"`,
		`"action"`,
	} {
		if strings.Contains(s, notWant) {
			t.Fatalf("未命中时不应出现 %q\n---\n%s", notWant, s)
		}
	}
}

// TestChunkMetaJSONShadowHit：shadow 命中时 JSON 包含 category 和 action=flag。
func TestChunkMetaJSONShadowHit(t *testing.T) {
	og, _, _ := newTestOutputGuard(t, outputGuardShadow, "t", "r")
	collectThrough(t, og, []string{"-- 注释。"})

	chunk := textStreamChunk{Seq: 1, Finish: "stop", Guard: og.BuildGuardMeta()}
	data, _ := json.Marshal(chunk)
	s := string(data)

	for _, want := range []string{
		`"detected":true`,
		`"filtered":false`,
		`"action":"flag"`,
		`"category":"A1-07"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("JSON 缺失 %q\n---\n%s", want, s)
		}
	}
	// rule_version 应为空（M1 骨架期 rule_version 未填入；OG-9 词库接入后补）
	if strings.Contains(s, `"rule_version"`) {
		t.Fatalf("M1 骨架期不应有 rule_version 字段\n---\n%s", s)
	}
}

// TestCatActionForMode：动作映射正确。
func TestCatActionForMode(t *testing.T) {
	// shadow 下一律 flag
	if a := catActionForMode("A1-06", outputGuardShadow); a != catActionFlag {
		t.Fatalf("shadow 下 A1-06 期望 flag，实际 %s", a)
	}
	if a := catActionForMode("A4-06", outputGuardShadow); a != catActionFlag {
		t.Fatalf("shadow 下 A4-06 期望 flag，实际 %s", a)
	}
	// enforcing 下按类目默认动作
	if a := catActionForMode("A1-06", outputGuardEnforcing); a != catActionBlock {
		t.Fatalf("enforcing 下 A1-06 期望 block，实际 %s", a)
	}
	// D1'：block-only 深度下 PII mask 冲突降为 flag（P-PII-ACTION；改写归 OG-18）。
	if a := catActionForMode("A4-06", outputGuardEnforcing); a != catActionFlag {
		t.Fatalf("enforcing 下 A4-06（mask 冲突降档）期望 flag，实际 %s", a)
	}
	if a := catActionForMode("A1-07", outputGuardEnforcing); a != catActionFlag {
		t.Fatalf("enforcing 下 A1-07（中级别）期望 flag，实际 %s", a)
	}
}
