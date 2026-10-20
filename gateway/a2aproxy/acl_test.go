package a2aproxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestEngine 构造带给定规则的 ACL 引擎。
func newTestEngine(t *testing.T, rules ...ACLRule) *ACLEngine {
	t.Helper()
	e := NewACLEngine()
	tbl := NewACLTable(1, time.Now())
	tbl.Rules = rules
	if err := e.Replace(tbl); err != nil {
		t.Fatalf("装载 ACL 表失败: %v", err)
	}
	return e
}

// TestACLDenyByDefault 空表 → 缺省 deny（冻结 §2.4）。
func TestACLDenyByDefault(t *testing.T) {
	e := NewACLEngine()
	d := e.Authorize("tenant-a", "research-agent", "summarize", "alice")
	if d.Allowed {
		t.Fatal("空 ACL 表必须缺省 deny")
	}
	if d.Reason != aclDeniedReason {
		t.Fatalf("reason = %q, want %q", d.Reason, aclDeniedReason)
	}
}

// TestACLExactRule 精确 (tenant,agent,skill) 规则命中。
func TestACLExactRule(t *testing.T) {
	e := newTestEngine(t, ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"})
	d := e.Authorize("tenant-a", "research-agent", "summarize", "alice")
	if !d.Allowed {
		t.Fatal("精确规则应放行")
	}
	if d.Rule == nil || d.Rule.Skill != "summarize" {
		t.Fatalf("命中规则异常: %+v", d.Rule)
	}
}

// TestACLDenyOtherSkill 同 agent 的其他 skill 未授权 → 拒。
func TestACLDenyOtherSkill(t *testing.T) {
	e := newTestEngine(t, ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"})
	d := e.Authorize("tenant-a", "research-agent", "translate", "alice")
	if d.Allowed {
		t.Fatal("未授权 skill 必须拒绝")
	}
}

// TestACLDenyOtherTenant 其他租户不可见（跨租户隔离）。
func TestACLDenyOtherTenant(t *testing.T) {
	e := newTestEngine(t, ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"})
	d := e.Authorize("tenant-b", "research-agent", "summarize", "alice")
	if d.Allowed {
		t.Fatal("跨租户必须拒绝")
	}
}

// TestACLDenyOtherAgent 同租户其他 agent 未授权 → 拒。
func TestACLDenyOtherAgent(t *testing.T) {
	e := newTestEngine(t, ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"})
	d := e.Authorize("tenant-a", "other-agent", "summarize", "alice")
	if d.Allowed {
		t.Fatal("未授权 agent 必须拒绝")
	}
}

// TestACLWildcardOnlyForUnobtainableSkill 通配规则只在 skill 不可得时命中。
//
// 冻结 §2.4：「skill 不可得时只命中通配」⇒ 具体 skill **不**回退到通配规则。
func TestACLWildcardOnlyForUnobtainableSkill(t *testing.T) {
	e := newTestEngine(t, ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: WildcardSkill})
	// skill 不可得（"*"）→ 命中通配。
	d := e.Authorize("tenant-a", "research-agent", WildcardSkill, "alice")
	if !d.Allowed {
		t.Fatal("skill 不可得时应命中通配规则")
	}
	// 具体 skill → 不回退通配（allow-only 精确优先，无精确即拒）。
	d2 := e.Authorize("tenant-a", "research-agent", "summarize", "alice")
	if d2.Allowed {
		t.Fatal("具体 skill 不得回退到通配规则")
	}
}

// TestACLExactBeatsWildcard 精确规则与通配规则并存时精确优先。
func TestACLExactBeatsWildcard(t *testing.T) {
	e := newTestEngine(t,
		ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: WildcardSkill},
		ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"},
	)
	d := e.Authorize("tenant-a", "research-agent", "summarize", "alice")
	if !d.Allowed {
		t.Fatal("精确规则应放行")
	}
	if d.Rule.Skill != "summarize" {
		t.Fatalf("应命中精确规则，实际 %q", d.Rule.Skill)
	}
}

// TestACLSubjectScoped 主体级规则：主体特定优先于任意主体。
func TestACLSubjectScoped(t *testing.T) {
	e := newTestEngine(t,
		ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize", Subject: "bob"},
	)
	// bob → 命中主体特定规则。
	if d := e.Authorize("tenant-a", "research-agent", "summarize", "bob"); !d.Allowed {
		t.Fatal("主体特定规则应放行 bob")
	}
	// alice → 无任意主体规则 → 拒。
	if d := e.Authorize("tenant-a", "research-agent", "summarize", "alice"); d.Allowed {
		t.Fatal("主体特定规则不得放行其他主体")
	}
}

// TestACLAnySubjectRule 任意主体规则对所有主体生效。
func TestACLAnySubjectRule(t *testing.T) {
	e := newTestEngine(t, ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"})
	for _, sub := range []string{"alice", "bob", ""} {
		if d := e.Authorize("tenant-a", "research-agent", "summarize", sub); !d.Allowed {
			t.Fatalf("任意主体规则应放行 %q", sub)
		}
	}
}

// TestACLSubjectSpecificBeatsAnySubject 主体特定规则优先于任意主体规则。
func TestACLSubjectSpecificBeatsAnySubject(t *testing.T) {
	e := newTestEngine(t,
		ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"},
		ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize", Subject: "bob"},
	)
	d := e.Authorize("tenant-a", "research-agent", "summarize", "bob")
	if !d.Allowed || d.Rule.Subject != "bob" {
		t.Fatalf("应命中主体特定规则，实际 %+v", d.Rule)
	}
}

// TestACLTableValidate 非法规则被拒（缺字段/非法字符/重复）。
func TestACLTableValidate(t *testing.T) {
	cases := []struct {
		name string
		rule ACLRule
	}{
		{"缺 tenant", ACLRule{Agent: "a", Skill: "s"}},
		{"缺 agent", ACLRule{Tenant: "t", Skill: "s"}},
		{"缺 skill", ACLRule{Tenant: "t", Agent: "a"}},
		{"非法 skill", ACLRule{Tenant: "t", Agent: "a", Skill: "bad skill!"}},
		{"非法 subject", ACLRule{Tenant: "t", Agent: "a", Skill: "s", Subject: "bad subject"}},
	}
	for _, c := range cases {
		tbl := NewACLTable(1, time.Now())
		tbl.Rules = []ACLRule{c.rule}
		if err := tbl.Validate(); err == nil {
			t.Fatalf("%s：应被拒绝", c.name)
		}
	}
	// 重复规则被拒。
	tbl := NewACLTable(1, time.Now())
	tbl.Rules = []ACLRule{
		{Tenant: "t", Agent: "a", Skill: "s"},
		{Tenant: "t", Agent: "a", Skill: "s"},
	}
	if err := tbl.Validate(); err == nil {
		t.Fatal("重复规则应被拒绝")
	}
}

// TestACLDecodeRejectsUnknownFields 策略通道拒绝未知字段（不得当高权通道用）。
func TestACLDecodeRejectsUnknownFields(t *testing.T) {
	raw := `{"version":1,"issued_at":"2026-10-20T00:00:00Z","rules":[],"consumers":["x"]}`
	if _, err := DecodeACLTable([]byte(raw)); err == nil {
		t.Fatal("含未知字段的 ACL 表应解码失败")
	}
}

// TestACLReplaceInvalidKeepsPrevious 非法表不得替换既有表（不得静默放开）。
func TestACLReplaceInvalidKeepsPrevious(t *testing.T) {
	e := newTestEngine(t, ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"})
	before := e.Version()
	bad := NewACLTable(2, time.Now())
	bad.Rules = []ACLRule{{Tenant: "tenant-a"}} // 缺 agent → 非法
	if err := e.Replace(bad); err == nil {
		t.Fatal("非法表应被拒绝")
	}
	if e.Version() != before {
		t.Fatalf("非法表替换后版本变化：%d → %d", before, e.Version())
	}
	if d := e.Authorize("tenant-a", "research-agent", "summarize", "alice"); !d.Allowed {
		t.Fatal("非法表不得影响既有策略")
	}
}

// TestACLCanonicalBytesStable 规范字节稳定（跨副本签发一致）。
func TestACLCanonicalBytesStable(t *testing.T) {
	rules := []ACLRule{
		{Tenant: "tenant-b", Agent: "a2", Skill: "s2"},
		{Tenant: "tenant-a", Agent: "a1", Skill: WildcardSkill},
		{Tenant: "tenant-a", Agent: "a1", Skill: "s1"},
	}
	SortACLRules(rules)
	tbl := NewACLTable(1, time.Unix(0, 0).UTC())
	tbl.Rules = rules
	b1, err := tbl.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	// 再次排序后字节应相同（排序稳定）。
	tbl2 := NewACLTable(1, time.Unix(0, 0).UTC())
	tbl2.Rules = append([]ACLRule{}, rules...)
	SortACLRules(tbl2.Rules)
	b2, err := tbl2.CanonicalBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(b1) != string(b2) {
		t.Fatalf("规范字节不稳定:\n%s\n%s", b1, b2)
	}
}

// TestStaticGovernanceWiring 治理实现接线：ACL 拒绝 → 错误消息含稳定 reason。
func TestStaticGovernanceWiring(t *testing.T) {
	e := newTestEngine(t, ACLRule{Tenant: "tenant-a", Agent: "research-agent", Skill: "summarize"})
	g := &StaticGovernance{
		ResolvePrincipal: func(r *http.Request) *Principal {
			return &Principal{Tenant: "tenant-a", Subject: "alice"}
		},
		ACL: e,
	}
	// 允许的场景。
	if err := g.Authorize(context.Background(), &Principal{Tenant: "tenant-a", Subject: "alice"},
		"tenant-a", "research-agent", "summarize"); err != nil {
		t.Fatalf("应放行: %v", err)
	}
	// 拒绝的场景：错误消息须含 acl_denied（proxy 用它映射 data.reason）。
	err := g.Authorize(context.Background(), &Principal{Tenant: "tenant-a", Subject: "alice"},
		"tenant-a", "research-agent", "translate")
	if err == nil {
		t.Fatal("未授权 skill 应拒绝")
	}
	if !strings.Contains(err.Error(), "acl_denied") {
		t.Fatalf("错误消息须含 acl_denied，实际 %q", err.Error())
	}
	if reason := aclReasonOf(err); reason != "acl_denied" {
		t.Fatalf("aclReasonOf = %q, want acl_denied", reason)
	}
}

// TestStaticGovernanceNoACLFailsClosed 无 ACL 引擎 → 拒绝（不得放开）。
func TestStaticGovernanceNoACLFailsClosed(t *testing.T) {
	g := &StaticGovernance{
		ResolvePrincipal: func(r *http.Request) *Principal { return &Principal{Tenant: "tenant-a"} },
	}
	if err := g.Authorize(context.Background(), &Principal{Tenant: "tenant-a"},
		"tenant-a", "research-agent", "summarize"); err == nil {
		t.Fatal("无 ACL 引擎必须拒绝")
	}
}

// TestStaticGovernanceNoPrincipalFailsClosed 无 principal 解析器 → 认证失败。
func TestStaticGovernanceNoPrincipalFailsClosed(t *testing.T) {
	g := &StaticGovernance{}
	req := httptest.NewRequest(http.MethodPost, "/a2a/x", nil)
	if _, err := g.Authenticate(req); err == nil {
		t.Fatal("无 principal 解析器必须认证失败")
	}
	// 解析器返回 nil → 同样失败。
	g2 := &StaticGovernance{ResolvePrincipal: func(r *http.Request) *Principal { return nil }}
	if _, err := g2.Authenticate(req); err == nil {
		t.Fatal("nil principal 必须认证失败")
	}
}

// TestStaticGovernanceObserver 观测事件透传到 sink（元数据级）。
func TestStaticGovernanceObserver(t *testing.T) {
	var got []AuditEvent
	g := &StaticGovernance{
		Observer: func(_ context.Context, ev AuditEvent) { got = append(got, ev) },
	}
	g.Observe(context.Background(), AuditEvent{Tenant: "tenant-a", Agent: "a", Skill: "s"})
	if len(got) != 1 || got[0].Tenant != "tenant-a" {
		t.Fatalf("观测事件未透传: %+v", got)
	}
}

// TestACLEngineConcurrentReplace 并发替换与读取不 panic（数据面热更新）。
func TestACLEngineConcurrentReplace(t *testing.T) {
	e := NewACLEngine()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 200; i++ {
			tbl := NewACLTable(i+1, time.Now())
			tbl.Rules = []ACLRule{{Tenant: "tenant-a", Agent: "a", Skill: "s"}}
			_ = e.Replace(tbl)
		}
	}()
	for i := 0; i < 200; i++ {
		_ = e.Authorize("tenant-a", "a", "s", "alice")
	}
	<-done
}
