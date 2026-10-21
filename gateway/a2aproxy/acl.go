package a2aproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"sync"
	"time"
)

// ACL policy engine (P2-2 T-3).
//
// Frozen contract (frozen checklist §2.4 "ACL" row + body §7.2 T-3):
//
//   - allow-only: (tenant,agent,skill) exact rule > (tenant,agent,*) wildcard
//     rule > default deny;
//   - when the skill is not obtainable ("*"), only a wildcard rule can match;
//   - no user-level rules and no explicit deny rules in the MVP;
//   - independent policy domain: A2A rules are NOT merged with the MCP
//     domain (R-6) — this engine has its own table and its own key space.
//
// The engine is fail-closed by construction: a missing rule denies.

// WildcardSkill is the skill value used when no carrier supplied a skill
// (frozen §2.4 "unobtainable" row: skill="*", audit skill_source=none).
const WildcardSkill = "*"

// ACLRule is one allow-only ACL rule.
//
// The zero value is not a valid rule: Tenant, Agent and Skill are required
// (Skill may be the wildcard "*").
type ACLRule struct {
	// Tenant is the security tenant the rule applies to.
	Tenant string `json:"tenant"`
	// Agent is the agent name the rule applies to.
	Agent string `json:"agent"`
	// Skill is the skill the rule allows; "*" is the wildcard.
	Skill string `json:"skill"`
	// Subject optionally restricts the rule to one caller subject. Empty
	// means "any subject of the tenant". The MVP does not require user
	// level rules but the key is kept so the table shape does not have to
	// change when user level rules arrive.
	Subject string `json:"subject,omitempty"`
	// Description is an operator-facing note (not used for decisions).
	Description string `json:"description,omitempty"`
}

// ACLTable is a versioned set of ACL rules.
//
// The table is the control-plane source of truth and is distributed to the
// data plane like the rate-limit table (same pull channel, separate domain).
type ACLTable struct {
	Version   int       `json:"version"`
	IssuedAt  string    `json:"issued_at"`
	Rules     []ACLRule `json:"rules"`
	Signature []byte    `json:"signature,omitempty"`
}

// NewACLTable constructs an empty table.
func NewACLTable(version int, now time.Time) *ACLTable {
	return &ACLTable{Version: version, IssuedAt: now.UTC().Format(time.RFC3339), Rules: []ACLRule{}}
}

// CanonicalBytes returns the canonical byte sequence (fixed field order)
// used for signing and verification.
func (t *ACLTable) CanonicalBytes() ([]byte, error) {
	payload := struct {
		Version  int       `json:"version"`
		IssuedAt string    `json:"issued_at"`
		Rules    []ACLRule `json:"rules"`
	}{t.Version, t.IssuedAt, t.Rules}
	return json.Marshal(payload)
}

// DecodeACLTable strictly decodes an ACL table: unknown fields are rejected.
//
// Same rationale as the rate-limit table (frozen §2.4: the policy channel
// must not be usable as a high-privilege configuration channel).
func DecodeACLTable(data []byte) (*ACLTable, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var t ACLTable
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("a2aproxy: ACL 表解码失败（含未知字段或格式错误）: %w", err)
	}
	return &t, nil
}

// Validate validates the table (table level plus every rule).
func (t *ACLTable) Validate() error {
	if t == nil {
		return fmt.Errorf("a2aproxy: ACL 表为空")
	}
	if t.Version <= 0 {
		return fmt.Errorf("a2aproxy: ACL 表 version 非法: %d", t.Version)
	}
	seen := map[string]bool{}
	for i := range t.Rules {
		r := &t.Rules[i]
		if r.Tenant == "" {
			return fmt.Errorf("a2aproxy: ACL 规则 #%d 缺 tenant", i)
		}
		if r.Agent == "" {
			return fmt.Errorf("a2aproxy: ACL 规则 #%d 缺 agent", i)
		}
		if r.Skill == "" {
			return fmt.Errorf("a2aproxy: ACL 规则 #%d 缺 skill", i)
		}
		if r.Skill != WildcardSkill && !aclSkillRE.MatchString(r.Skill) {
			return fmt.Errorf("a2aproxy: ACL 规则 #%d 的 skill %q 非法", i, r.Skill)
		}
		if r.Subject != "" && !aclIdentRE.MatchString(r.Subject) {
			return fmt.Errorf("a2aproxy: ACL 规则 #%d 的 subject %q 非法", i, r.Subject)
		}
		key := aclRuleKey(r.Tenant, r.Agent, r.Skill, r.Subject)
		if seen[key] {
			return fmt.Errorf("a2aproxy: ACL 规则重复 (tenant=%s agent=%s skill=%s subject=%s)",
				r.Tenant, r.Agent, r.Skill, r.Subject)
		}
		seen[key] = true
	}
	return nil
}

// aclIdentRE is the identifier character set for ACL components
// (tenant / agent / subject). The skill character set is the frozen one
// (a2a skill id: ^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$).
var aclIdentRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// aclSkillRE is the frozen skill identifier character set (a2a/skill.go).
var aclSkillRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// aclRuleKey builds the uniqueness key of a rule.
//
// The key is length-prefix free because the components are separated by
// "\x00" and none of them may contain a NUL byte (identifiers are
// restricted to a safe character set).
func aclRuleKey(tenant, agent, skill, subject string) string {
	return tenant + "\x00" + agent + "\x00" + skill + "\x00" + subject
}

// ACLDecision is the outcome of an ACL evaluation.
type ACLDecision struct {
	// Allowed reports whether the call may proceed.
	Allowed bool
	// Reason is the stable audit reason (acl_denied / unknown_skill).
	Reason string
	// Rule is the rule that allowed the call (nil when denied).
	Rule *ACLRule
}

// ACLEngine evaluates ACL rules for the data plane.
//
// The engine is safe for concurrent use: the table is swapped atomically
// (pointer) and readers never mutate it.
type ACLEngine struct {
	mu    sync.RWMutex
	table *ACLTable
	// exact and wildcard indexes: key -> rule.
	exact    map[string]*ACLRule
	wildcard map[string]*ACLRule
}

// NewACLEngine constructs an engine with an empty (deny-all) table.
func NewACLEngine() *ACLEngine {
	e := &ACLEngine{}
	e.replace(&ACLTable{Version: 0, Rules: []ACLRule{}})
	return e
}

// Replace swaps in a new table version (called on policy distribution).
//
// A nil or invalid table leaves the previous table in place: a broken
// distribution must not silently open the policy up.
func (e *ACLEngine) Replace(t *ACLTable) error {
	if t == nil {
		return fmt.Errorf("a2aproxy: ACL 表为空")
	}
	if err := t.Validate(); err != nil {
		return err
	}
	e.replace(t)
	return nil
}

// replace rebuilds the indexes and swaps the table in.
func (e *ACLEngine) replace(t *ACLTable) {
	exact := map[string]*ACLRule{}
	wildcard := map[string]*ACLRule{}
	for i := range t.Rules {
		r := t.Rules[i]
		rule := r
		if r.Skill == WildcardSkill {
			wildcard[aclRuleKey(r.Tenant, r.Agent, WildcardSkill, r.Subject)] = &rule
			continue
		}
		exact[aclRuleKey(r.Tenant, r.Agent, r.Skill, r.Subject)] = &rule
	}
	e.mu.Lock()
	e.table = t
	e.exact = exact
	e.wildcard = wildcard
	e.mu.Unlock()
}

// Version returns the current table version (0 = empty table).
func (e *ACLEngine) Version() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.table == nil {
		return 0
	}
	return e.table.Version
}

// RuleCount returns the number of indexed rules.
func (e *ACLEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.exact) + len(e.wildcard)
}

// Authorize evaluates the ACL for one call.
//
// Precedence (frozen §2.4): an exact (tenant,agent,skill) rule wins over a
// (tenant,agent,*) wildcard rule; with no rule at all the call is denied.
//
// The wildcard is only consulted when the caller did not supply a skill
// ("*"). A concrete skill never matches a wildcard rule — that is the
// "exact > wildcard" precedence with the wildcard applying to the
// skill-unobtainable case only.
func (e *ACLEngine) Authorize(tenant, agent, skill, subject string) ACLDecision {
	if tenant == "" || agent == "" {
		return ACLDecision{Allowed: false, Reason: aclDeniedReason}
	}
	if skill == "" {
		skill = WildcardSkill
	}
	e.mu.RLock()
	defer e.mu.RUnlock()

	// 1) Exact skill rule (subject-specific first, then any-subject).
	if skill != WildcardSkill {
		if r, ok := e.exact[aclRuleKey(tenant, agent, skill, subject)]; ok {
			return ACLDecision{Allowed: true, Rule: r}
		}
		if subject != "" {
			if r, ok := e.exact[aclRuleKey(tenant, agent, skill, "")]; ok {
				return ACLDecision{Allowed: true, Rule: r}
			}
		}
		// 2) A concrete skill does NOT fall back to the wildcard rule:
		// the wildcard covers the "skill unobtainable" case only.
		return ACLDecision{Allowed: false, Reason: aclDeniedReason}
	}

	// 3) Skill unobtainable → only the wildcard rule applies.
	if r, ok := e.wildcard[aclRuleKey(tenant, agent, WildcardSkill, subject)]; ok {
		return ACLDecision{Allowed: true, Rule: r}
	}
	if subject != "" {
		if r, ok := e.wildcard[aclRuleKey(tenant, agent, WildcardSkill, "")]; ok {
			return ACLDecision{Allowed: true, Rule: r}
		}
	}
	return ACLDecision{Allowed: false, Reason: aclDeniedReason}
}

// StaticGovernance is a ready-to-use Governance implementation that combines
// a static principal resolver, the ACL engine and a rate limiter.
//
// It is the T-3 production wiring for the standalone A2A data plane: the
// control plane pushes the ACL table and the rate-limit rules, and the data
// plane evaluates them locally.
//
// StaticGovernance never fails open: an empty ACL table denies everything.
type StaticGovernance struct {
	// ResolvePrincipal maps a request to a principal. A nil principal
	// denies the call.
	ResolvePrincipal func(r *http.Request) *Principal
	// ACL is the policy engine (may be nil → deny all).
	ACL *ACLEngine
	// Limiter applies the tenant|agent|skill budget. Nil → no limit.
	Limiter Limiter
	// Observer receives metadata-only audit events. Nil → dropped.
	Observer func(ctx context.Context, ev AuditEvent)
	// TaskObserver receives normalized A2A Task audit events (T-3b). Nil → dropped.
	TaskObserver TaskObserver
	// ContentObserver receives A2A content-safety action events (T-4; a2a_content_action). Nil → dropped.
	ContentObserver func(ctx context.Context, ev ContentActionEvent)
}

// Authorize implements Governance.
func (g *StaticGovernance) Authorize(_ context.Context, p *Principal, tenant, agent, skill string) error {
	if g.ACL == nil {
		return fmt.Errorf("a2aproxy: no ACL policy configured")
	}
	subject := ""
	if p != nil {
		subject = p.Subject
	}
	d := g.ACL.Authorize(tenant, agent, skill, subject)
	if d.Allowed {
		return nil
	}
	return fmt.Errorf("a2aproxy: %s (tenant=%s agent=%s skill=%s)", d.Reason, tenant, agent, skill)
}

// RateLimit implements Governance.
func (g *StaticGovernance) RateLimit(_ context.Context, tenant, agent, skill string) (int, error) {
	if g.Limiter == nil {
		return 0, nil
	}
	return g.Limiter.Allow(tenant, agent, skill)
}

// LastRateLimitScope implements RateLimitScopeObserver (T-5)：透传限流器上报的键范围。
// Limiter 未接线 → RateLimitScopeNone；已接线但不支持上报 → RateLimitScopeUnknown。
func (g *StaticGovernance) LastRateLimitScope() string {
	if g.Limiter == nil {
		return RateLimitScopeNone
	}
	if obs, ok := g.Limiter.(RateLimitScopeObserver); ok {
		return obs.LastRateLimitScope()
	}
	return RateLimitScopeUnknown
}

// Observe implements Governance.
func (g *StaticGovernance) Observe(ctx context.Context, ev AuditEvent) {
	if g.Observer == nil {
		return
	}
	g.Observer(ctx, ev)
}

// ObserveTask implements Governance (T-3b).
func (g *StaticGovernance) ObserveTask(ctx context.Context, ev TaskEvent) {
	if g.TaskObserver == nil {
		return
	}
	g.TaskObserver(ctx, ev)
}

// ObserveContent implements Governance (T-4).
func (g *StaticGovernance) ObserveContent(ctx context.Context, ev ContentActionEvent) {
	if g.ContentObserver == nil {
		return
	}
	g.ContentObserver(ctx, ev)
}

// Authenticate implements Governance.
func (g *StaticGovernance) Authenticate(_ context.Context, r *http.Request) (*Principal, error) {
	if g.ResolvePrincipal == nil {
		return nil, fmt.Errorf("a2aproxy: no principal resolver configured")
	}
	p := g.ResolvePrincipal(r)
	if p == nil || p.Tenant == "" {
		return nil, fmt.Errorf("a2aproxy: unauthenticated")
	}
	return p, nil
}

// Limiter is the composite rate limit interface (T-3a).
//
// A positive retryAfter means "reject with HTTP 429 + Retry-After".
type Limiter interface {
	Allow(tenant, agent, skill string) (retryAfter int, err error)
}

// SortACLRules sorts rules deterministically (tenant, agent, skill, subject)
// so that canonical bytes are stable across control-plane replicas.
func SortACLRules(rules []ACLRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Tenant != b.Tenant {
			return a.Tenant < b.Tenant
		}
		if a.Agent != b.Agent {
			return a.Agent < b.Agent
		}
		if a.Skill != b.Skill {
			return a.Skill < b.Skill
		}
		return a.Subject < b.Subject
	})
}
