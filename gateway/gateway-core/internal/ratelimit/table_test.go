package ratelimit

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// validRateRule 合法 rate 规则（用例基线）。
func validRateRule() Rule {
	return Rule{ID: "t-a-rate", Kind: KindRate, Scope: ScopeTenant, Target: "t-a",
		RPM: 600, TPM: 200000, BurstMultiplier: 2, Action: ActionReject, Enabled: true}
}

// validBudgetRule 合法 budget 规则（用例基线）。
func validBudgetRule() Rule {
	return Rule{ID: "t-a-budget", Kind: KindBudget, Scope: ScopeTenant, Target: "t-a",
		DailyBudgetTokens: 50_000_000, Action: ActionReject, Enabled: true}
}

func validTable(rules ...Rule) *Table {
	if len(rules) == 0 {
		rules = []Rule{validRateRule(), validBudgetRule()}
	}
	t := NewTable(7, time.Unix(1_760_000_000, 0))
	t.Rules = rules
	return t
}

func TestValidate_ok(t *testing.T) {
	if err := validTable().Validate(); err != nil {
		t.Fatalf("合法表被拒: %v", err)
	}
	// 空规则表：合法（表示"全部不限流"，需显式下发更高版本）
	if err := NewTable(1, time.Now()).Validate(); err != nil {
		t.Fatalf("空表应合法: %v", err)
	}
	// global 规则：target 空 + 指纹可空
	g := validRateRule()
	g.ID, g.Scope, g.Target = "global-rate", ScopeGlobal, ""
	if err := validTable(g).Validate(); err != nil {
		t.Fatalf("global 规则应合法: %v", err)
	}
}

func TestValidate_rejects(t *testing.T) {
	cases := map[string]func(r *Rule){
		"kind 非法":              func(r *Rule) { r.Kind = "limit" },
		"scope 非法":             func(r *Rule) { r.Scope = "user" },
		"action 非法":            func(r *Rule) { r.Action = "drop" },
		"id 为空":                func(r *Rule) { r.ID = "" },
		"id 含非法字符":             func(r *Rule) { r.ID = "规则1" },
		"tenant target 为空":     func(r *Rule) { r.Target = "" },
		"target 超长(>64)":       func(r *Rule) { r.Target = strings.Repeat("a", 65) },
		"target 含明文凭据字符(=)":    func(r *Rule) { r.Target = "sk-abc=" },
		"rpm 为负":               func(r *Rule) { r.RPM = -1 },
		"rpm 超上限":              func(r *Rule) { r.RPM = maxRPM + 1 },
		"rate 未设 rpm/tpm":      func(r *Rule) { r.RPM, r.TPM = 0, 0 },
		"rate 误设日预算(应 budget)": func(r *Rule) { r.DailyBudgetTokens = 100 },
		"burst 超上限":            func(r *Rule) { r.BurstMultiplier = maxBurstMultiplier + 1 },
		"指纹非 8 位小写 hex":        func(r *Rule) { r.TargetFingerprint = "AB12CD34" },
	}
	for name, mut := range cases {
		r := validRateRule()
		mut(&r)
		if err := validTable(r).Validate(); err == nil {
			t.Fatalf("%s：期望校验失败，实际通过", name)
		}
	}
	// budget 规则的专属约束
	budgetCases := map[string]func(r *Rule){
		"budget 未设日预算":    func(r *Rule) { r.DailyBudgetTokens = 0 },
		"budget 误设 rpm":   func(r *Rule) { r.RPM = 100 },
		"budget 误设 burst": func(r *Rule) { r.BurstMultiplier = 2 },
	}
	for name, mut := range budgetCases {
		r := validBudgetRule()
		mut(&r)
		if err := validTable(r).Validate(); err == nil {
			t.Fatalf("%s：期望校验失败，实际通过", name)
		}
	}
}

func TestValidate_tableLevel(t *testing.T) {
	// version 必须为正
	tbl := validTable()
	tbl.Version = 0
	if err := tbl.Validate(); err == nil {
		t.Fatal("version=0 应被拒")
	}
	// issued_at 必须 RFC3339
	tbl = validTable()
	tbl.IssuedAt = "2026/09/13 10:00"
	if err := tbl.Validate(); err == nil {
		t.Fatal("非法 issued_at 应被拒")
	}
	// 同 (scope,target,kind) 重复
	tbl = validTable(validRateRule(), validRateRule())
	if err := tbl.Validate(); err == nil {
		t.Fatal("重复规则应被拒")
	}
	// 同租户 rate + budget 各一条：允许
	tbl = validTable(validRateRule(), validBudgetRule())
	if err := tbl.Validate(); err != nil {
		t.Fatalf("同租户 rate+budget 应合法: %v", err)
	}
}

// TestDecodeTable_rejectsUnknownFields 校验"策略通道字段白名单"（设计 §4 最小权限）。
func TestDecodeTable_rejectsUnknownFields(t *testing.T) {
	// 携带认证类配置必须被拒（防止限流通道演化为高权通道）
	for name, body := range map[string]string{
		"consumers(认证)": `{"version":7,"issued_at":"2026-09-13T10:00:00Z","rules":[],"consumers":[{"name":"x","credential":"k"}]}`,
		"allow(路由鉴权)":   `{"version":7,"issued_at":"2026-09-13T10:00:00Z","rules":[],"allow":["c1"]}`,
		"规则内未知字段":       `{"version":7,"issued_at":"2026-09-13T10:00:00Z","rules":[{"id":"r1","kind":"rate","scope":"tenant","target":"t-a","rpm":1,"action":"reject","enabled":true,"ipRestriction":{}}]}`,
	} {
		if _, err := DecodeTable([]byte(body)); err == nil {
			t.Fatalf("%s：未知字段应导致解码失败", name)
		}
	}

	// 正常表：可解码且校验通过
	ok := `{"version":7,"issued_at":"2026-09-13T10:00:00Z","rules":[{"id":"t-a-rate","kind":"rate","scope":"tenant","target":"t-a","rpm":600,"tpm":200000,"burst_multiplier":2,"action":"reject","enabled":true}]}`
	tbl, err := DecodeTable([]byte(ok))
	if err != nil {
		t.Fatalf("正常表解码失败: %v", err)
	}
	if err := tbl.Validate(); err != nil {
		t.Fatalf("正常表校验失败: %v", err)
	}
	if got := tbl.Lookup(ScopeTenant, "t-a", KindRate); got == nil || got.RPM != 600 {
		t.Fatalf("Lookup 未命中或值不符: %+v", got)
	}
}

func TestCheckVersion(t *testing.T) {
	if got := CheckVersion(7, 6); got != VersionStale {
		t.Fatalf("低版本应为 Stale，实际 %v", got)
	}
	if got := CheckVersion(7, 7); got != VersionSame {
		t.Fatalf("同版本应为 Same，实际 %v", got)
	}
	if got := CheckVersion(7, 8); got != VersionAccept {
		t.Fatalf("高版本应为 Accept，实际 %v", got)
	}
}

func TestEffectiveTargetKey(t *testing.T) {
	g := validRateRule()
	g.Scope, g.Target = ScopeGlobal, ""
	if got := EffectiveTargetKey(&g); got != "*" {
		t.Fatalf("global 应归一为 *，实际 %q", got)
	}
	r := validRateRule()
	if got := EffectiveTargetKey(&r); got != "t-a" {
		t.Fatalf("tenant 应返回 target，实际 %q", got)
	}
}

// TestCanonicalBytes_stable 规范字节稳定性：同表两次编码一致，且字段顺序固定（供两侧验签）。
func TestCanonicalBytes_stable(t *testing.T) {
	tbl := validTable()
	b1, err := tbl.CanonicalBytes()
	if err != nil {
		t.Fatalf("CanonicalBytes 失败: %v", err)
	}
	b2, _ := tbl.CanonicalBytes()
	if string(b1) != string(b2) {
		t.Fatal("同表两次编码应完全一致")
	}
	if strings.Index(string(b1), `"version"`) > strings.Index(string(b1), `"issued_at"`) {
		t.Fatal("字段顺序应为 version → issued_at → rules")
	}
	// 规范字节不含 envelope 字段（若后续加入 signature，不得进入规范序列）
	if strings.Contains(string(b1), "signature") {
		t.Fatal("规范字节不得包含 signature 字段")
	}
	// 可反序列化回等价结构（两侧 marshal/unmarshal 一致）
	var back struct {
		Version  int    `json:"version"`
		IssuedAt string `json:"issued_at"`
		Rules    []Rule `json:"rules"`
	}
	if err := json.Unmarshal(b1, &back); err != nil {
		t.Fatalf("规范字节反序列化失败: %v", err)
	}
	if back.Version != tbl.Version || len(back.Rules) != len(tbl.Rules) {
		t.Fatalf("往返不一致: %+v", back)
	}
}
