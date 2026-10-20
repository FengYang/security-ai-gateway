package a2aproxy

import (
	"encoding/json"
	"testing"
	"time"
)

// buildRLTable 构造一张已校验的限流表（用于引擎测试）。
func buildRLTable(t *testing.T, version int, rules ...RateLimitRule) *RateLimitTable {
	t.Helper()
	tbl := &RateLimitTable{Version: version, IssuedAt: time.Unix(1725500000, 0).UTC().Format(time.RFC3339), Rules: rules}
	if err := tbl.Validate(); err != nil {
		t.Fatalf("测试表非法: %v", err)
	}
	return tbl
}

// TestRLTwoKeysBothEffective VT3-05：精确键与通配键各自生效（互斥选键，非同请求双计）。
//
// 场景① 具体 skill "translate" → 命中精确键 tenant|agent|translate（RPM=1）；
// 场景② skill 不可得 "*" → 命中通配键 tenant|agent|*（RPM=10）。
// 两个场景互不影响：精确键计满不影响通配键余量。
func TestRLTwoKeysBothEffective(t *testing.T) {
	e := NewRateLimitEngine()
	if err := e.Replace(buildRLTable(t, 1,
		RateLimitRule{Tenant: "tenant-a", Agent: "agent-x", Skill: "translate", RPM: 1},
		RateLimitRule{Tenant: "tenant-a", Agent: "agent-x", Skill: WildcardSkill, RPM: 10},
	)); err != nil {
		t.Fatal(err)
	}

	// 精确键第 1 次放行，第 2 次限流（RPM=1）。
	if ra, _ := e.Allow("tenant-a", "agent-x", "translate"); ra != 0 {
		t.Fatalf("精确键第1次应放行, got retryAfter=%d", ra)
	}
	if ra, _ := e.Allow("tenant-a", "agent-x", "translate"); ra <= 0 {
		t.Fatalf("精确键第2次应限流, got retryAfter=%d", ra)
	}

	// 通配键仍有余量（RPM=10，仅用 1）：证明两键独立计数。
	if ra, _ := e.Allow("tenant-a", "agent-x", WildcardSkill); ra != 0 {
		t.Fatalf("通配键应仍放行, got retryAfter=%d", ra)
	}
}

// TestRLFallbackToWildcard 限流回退方向是"更严"：具体 skill 无精确规则时
// 回退通配键（与 ACL 不回退相反）。仅通配规则 RPM=1，concrete skill 第 2 次被限流。
func TestRLFallbackToWildcard(t *testing.T) {
	e := NewRateLimitEngine()
	if err := e.Replace(buildRLTable(t, 1,
		RateLimitRule{Tenant: "tenant-a", Agent: "agent-x", Skill: WildcardSkill, RPM: 1},
	)); err != nil {
		t.Fatal(err)
	}
	// 具体 skill "unknown-skill" 无精确规则 → 回退通配键；第 1 次放行、第 2 次限流。
	if ra, _ := e.Allow("tenant-a", "agent-x", "unknown-skill"); ra != 0 {
		t.Fatalf("回退第1次应放行, got retryAfter=%d", ra)
	}
	if ra, _ := e.Allow("tenant-a", "agent-x", "unknown-skill"); ra <= 0 {
		t.Fatalf("回退第2次应限流（更严方向）, got retryAfter=%d", ra)
	}
}

// TestRLDefaultNoLimit 缺省不限流：无规则命中即放行（与 MCP 域"未命中即不限流"一致）。
func TestRLDefaultNoLimit(t *testing.T) {
	e := NewRateLimitEngine() // 空表
	for i := 0; i < 5; i++ {
		if ra, _ := e.Allow("tenant-a", "agent-x", "anything"); ra != 0 {
			t.Fatalf("空表应不限流, 第%d次 got retryAfter=%d", i, ra)
		}
	}
	// 仅精确规则、无通配：无精确规则的 (tenant,agent,skill) 组合放行（不设通配兜底）。
	e2 := NewRateLimitEngine()
	if err := e2.Replace(buildRLTable(t, 1,
		RateLimitRule{Tenant: "tenant-a", Agent: "agent-x", Skill: "translate", RPM: 1},
	)); err != nil {
		t.Fatal(err)
	}
	if ra, _ := e2.Allow("tenant-a", "agent-x", "other-skill"); ra != 0 {
		t.Fatalf("无精确规则且无通配应放行, got retryAfter=%d", ra)
	}
}

// TestRLKeyEncodingAmbiguity 长度前缀编码防拼接歧义：
// ("a","b","c") 与 ("ab","","c") 等不应发生碰撞。
func TestRLKeyEncodingAmbiguity(t *testing.T) {
	k1 := rlKeyHex("a", "b", "c")
	k2 := rlKeyHex("ab", "", "c")
	k3 := rlKeyHex("a", "bc", "")
	if k1 == k2 || k1 == k3 || k2 == k3 {
		t.Fatalf("长度前缀编码发生碰撞: %s / %s / %s", k1, k2, k3)
	}
	// 同一元组稳定可复现。
	if rlKeyHex("tenant-a", "agent-x", "translate") != rlKeyHex("tenant-a", "agent-x", "translate") {
		t.Fatal("同一元组编码应稳定")
	}
}

// TestRLSignerRoundTrip 限流表签名/验签往返 + 篡改检测。
func TestRLSignerRoundTrip(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	sig, err := NewRateLimitSigner(key)
	if err != nil {
		t.Fatal(err)
	}
	tbl := buildRLTable(t, 1, RateLimitRule{Tenant: "t", Agent: "a", Skill: "s", RPM: 5})
	if err := sig.SignTable(tbl); err != nil {
		t.Fatal(err)
	}
	if !sig.VerifyTable(tbl) {
		t.Fatal("签名后应可验")
	}
	// 篡改规则 → 验签失败。
	tbl.Rules[0].RPM = 999
	if sig.VerifyTable(tbl) {
		t.Fatal("篡改后不应验签通过")
	}
	// 字节流验签入口（含严格解码）。
	tbl2 := buildRLTable(t, 1, RateLimitRule{Tenant: "t", Agent: "a", Skill: "s", RPM: 5})
	if err := sig.SignTable(tbl2); err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(tbl2)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sig.VerifyRateLimitTableBytes(raw); err != nil {
		t.Fatalf("字节流验签失败: %v", err)
	}
	// 含未知字段 → 严格解码拒绝。
	bad := `{"version":1,"issued_at":"2026-10-20T00:00:00Z","rules":[{"tenant":"t","agent":"a","skill":"s","rpm":5}],"consumers":["x"]}`
	if _, err := sig.VerifyRateLimitTableBytes([]byte(bad)); err == nil {
		t.Fatal("含未知字段的限流表应被拒")
	}
}

// TestRLValidate 规则校验：缺 tenant/agent、非法 skill、rpm<=0、重复规则。
func TestRLValidate(t *testing.T) {
	rl := func(rules ...RateLimitRule) *RateLimitTable {
		return &RateLimitTable{Version: 1, IssuedAt: time.Unix(1725500000, 0).UTC().Format(time.RFC3339), Rules: rules}
	}
	cases := []struct {
		name string
		tbl  *RateLimitTable
		ok   bool
	}{
		{"缺agent", rl(RateLimitRule{Tenant: "t", Skill: "s", RPM: 1}), false},
		{"非法skill", rl(RateLimitRule{Tenant: "t", Agent: "a", Skill: "bad skill!", RPM: 1}), false},
		{"rpm0", rl(RateLimitRule{Tenant: "t", Agent: "a", Skill: "s", RPM: 0}), false},
		{"重复", rl(
			RateLimitRule{Tenant: "t", Agent: "a", Skill: "s", RPM: 1},
			RateLimitRule{Tenant: "t", Agent: "a", Skill: "s", RPM: 2},
		), false},
		{"合法通配", rl(RateLimitRule{Tenant: "t", Agent: "a", Skill: WildcardSkill, RPM: 1}), true},
		{"合法精确", rl(RateLimitRule{Tenant: "t", Agent: "a", Skill: "s", RPM: 1}), true},
	}
	for _, c := range cases {
		err := c.tbl.Validate()
		if c.ok && err != nil {
			t.Fatalf("%s: 期望合法但报错 %v", c.name, err)
		}
		if !c.ok && err == nil {
			t.Fatalf("%s: 期望非法但通过了", c.name)
		}
	}
}
