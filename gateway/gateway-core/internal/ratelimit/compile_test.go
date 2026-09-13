package ratelimit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

// compileTable 构造用于编译用例的表。
func compileTable(rules ...Rule) *Table {
	t := NewTable(2, time.Unix(1_760_000_000, 0))
	t.Rules = rules
	return t
}

// notesContain 断言 notes 中存在包含子串的条目。
func notesContain(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

// TestCompileDataPlane_tenant 租户维度：rpm → QPS 分桶项（字段与实链验证过的 schema 一致）。
func TestCompileDataPlane_tenant(t *testing.T) {
	cfg, notes, err := CompileDataPlane(compileTable(
		Rule{ID: "t-a-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-a",
			RPM: 600, Action: ActionReject, Enabled: true},
		Rule{ID: "t-b-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-b",
			RPM: 100, Action: ActionReject, Enabled: true},
	), DefaultCompileOptions())
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if cfg.RuleName != "otpmask-ratelimit" || cfg.RejectedCode != 429 || !cfg.ShowLimitQuotaHeader {
		t.Fatalf("部署参数不符: %+v", cfg)
	}
	if cfg.Redis.ServiceName != "redis-ratelimit.dns" || cfg.Redis.ServicePort != 6379 || cfg.Redis.Timeout != 500 {
		t.Fatalf("redis 配置不符: %+v", cfg.Redis)
	}
	if len(cfg.RuleItems) != 1 || cfg.RuleItems[0].LimitByHeader != HeaderTenant {
		t.Fatalf("应合并为一个 x-tenant-id 分桶项: %+v", cfg.RuleItems)
	}
	// 线上字段名回归（2026-09-13 实链事故）：租户精确值必须走 limit_by_header；
	// per 变体只接受 "*"/regexp:，写租户名会被插件拒载（config_fail）。
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	if !strings.Contains(string(raw), `"limit_by_header":"x-tenant-id"`) ||
		strings.Contains(string(raw), "limit_by_per_header") {
		t.Fatalf("线上形态不符（须 limit_by_header）: %s", raw)
	}
	keys := cfg.RuleItems[0].LimitKeys
	if len(keys) != 2 || keys[0].Key != "t-a" || keys[0].QueryPerSecond != 10 {
		t.Fatalf("t-a=600rpm 应换算为 10 QPS: %+v", keys)
	}
	// 100 rpm 非 60 整数倍：向上取整为 2 QPS（120/min，偏紧）并如实记 Note
	if keys[1].QueryPerSecond != 2 {
		t.Fatalf("t-b=100rpm 应向上取整为 2 QPS: %+v", keys[1])
	}
	if !notesContain(notes, "非 60 整数倍") {
		t.Fatalf("应记录 QPS 粒度 Note: %v", notes)
	}
	if cfg.GlobalThreshold != nil {
		t.Fatalf("无 global 规则时不应有 global_threshold: %+v", cfg.GlobalThreshold)
	}
}

// TestCompileDataPlane_skipUnsupported 无 schema 证据或设计暂不实施的维度**不得下发**（防字段静默失效）。
func TestCompileDataPlane_skipUnsupported(t *testing.T) {
	cfg, notes, err := CompileDataPlane(compileTable(
		Rule{ID: "shadow-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-s",
			RPM: 60, Action: ActionShadow, Enabled: true},
		Rule{ID: "apikey-rate", Kind: KindRate, Scope: ScopeAPIKey, Target: "consumer-1",
			RPM: 60, Action: ActionReject, Enabled: true},
		Rule{ID: "model-rate", Kind: KindRate, Scope: ScopeModel, Target: "qwen-plus",
			RPM: 60, Action: ActionReject, Enabled: true},
		Rule{ID: "disabled-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-d",
			RPM: 60, Action: ActionReject, Enabled: false},
		Rule{ID: "burst-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-burst",
			RPM: 600, BurstMultiplier: 2, Action: ActionReject, Enabled: true},
	), DefaultCompileOptions())
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	// 仅 burst-rate 可下发（其余维度/动作/禁用均跳过）
	if len(cfg.RuleItems) != 1 || len(cfg.RuleItems[0].LimitKeys) != 1 || cfg.RuleItems[0].LimitKeys[0].Key != "t-burst" {
		t.Fatalf("应仅下发 burst-rate 的租户项: %+v", cfg.RuleItems)
	}
	for _, want := range []string{"action=shadow", "api_key 维度", "model 维度", "已禁用", "burst_multiplier"} {
		if !notesContain(notes, want) {
			t.Fatalf("缺少 Note(%s): %v", want, notes)
		}
	}
}

// TestCompileDataPlane_budgetAndTPM 预算与 TPM 属 TEE 侧：数据面不下发，且如实记 Note。
func TestCompileDataPlane_budgetAndTPM(t *testing.T) {
	_, notes, err := CompileDataPlane(compileTable(
		Rule{ID: "t-a-budget", Kind: KindBudget, Scope: ScopeTenant, Target: "t-a",
			DailyBudgetTokens: 50_000_000, Action: ActionReject, Enabled: true},
	), DefaultCompileOptions())
	if !errors.Is(err, ErrNoEffectiveRules) {
		t.Fatalf("仅预算规则时数据面无内容，应返回 ErrNoEffectiveRules，实际 %v", err)
	}
	if !notesContain(notes, "tee-infer") {
		t.Fatalf("应说明执行点在 tee-infer: %v", notes)
	}

	cfg, notes, err := CompileDataPlane(compileTable(
		Rule{ID: "t-a-both", Kind: KindRate, Scope: ScopeTenant, Target: "t-a",
			RPM: 600, TPM: 200000, Action: ActionReject, Enabled: true},
	), DefaultCompileOptions())
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if len(cfg.RuleItems) != 1 || cfg.RuleItems[0].LimitKeys[0].QueryPerSecond != 10 {
		t.Fatalf("RPM 应正常下发: %+v", cfg.RuleItems)
	}
	if !notesContain(notes, "tpm=200000 归 tee-infer") {
		t.Fatalf("应记录 TPM 归 TEE 的 Note: %v", notes)
	}
}

// TestCompileDataPlane_global global 维度使用 global_threshold，并标注"未实链验证"。
func TestCompileDataPlane_global(t *testing.T) {
	cfg, notes, err := CompileDataPlane(compileTable(
		Rule{ID: "global-rate", Kind: KindRate, Scope: ScopeGlobal, Target: "",
			RPM: 6000, Action: ActionReject, Enabled: true},
	), DefaultCompileOptions())
	if err != nil {
		t.Fatalf("编译失败: %v", err)
	}
	if cfg.GlobalThreshold == nil || cfg.GlobalThreshold.QueryPerSecond != 100 {
		t.Fatalf("global_threshold 应为 100 QPS: %+v", cfg.GlobalThreshold)
	}
	if len(cfg.RuleItems) != 0 {
		t.Fatalf("无租户规则时不应有 rule_items: %+v", cfg.RuleItems)
	}
	if !notesContain(notes, "尚未实链验证") {
		t.Fatalf("global_threshold 无实链证据，须记 Note: %v", notes)
	}
}

// TestCompileDataPlane_invalidTable 非法表不得编译（复用 Validate）。
func TestCompileDataPlane_invalidTable(t *testing.T) {
	bad := compileTable(Rule{ID: "x", Kind: KindRate, Scope: ScopeTenant, Target: "t-a",
		RPM: 0, TPM: 0, Action: ActionReject, Enabled: true})
	if _, _, err := CompileDataPlane(bad, DefaultCompileOptions()); err == nil {
		t.Fatal("非法表应编译失败")
	}
	if _, _, err := CompileDataPlane(nil, DefaultCompileOptions()); err == nil {
		t.Fatal("nil 表应编译失败")
	}
}

// TestRPMToQPS 换算边界。
func TestRPMToQPS(t *testing.T) {
	cases := map[int64]int64{0: 0, 1: 1, 59: 1, 60: 1, 61: 2, 600: 10, 601: 11}
	for rpm, want := range cases {
		if got := RPMToQPS(rpm); got != want {
			t.Fatalf("RPMToQPS(%d)=%d，期望 %d", rpm, got, want)
		}
	}
}
