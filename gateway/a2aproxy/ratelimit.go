package a2aproxy

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"
)

// A2A 复合限流引擎（P2-2 T-3a）。
//
// 冻结契约（冻结清单 §1.4 T-3a 行 + 本体 §7.2 T-3a 行）：
//
//   - 复合键＝tenant|agent|skill；skill 不可得时降级为 tenant|agent|*；
//   - 长度前缀编码（LP(s)=uint32_be(len(s))||s）防拼接歧义（与 F-6 §3.1 同族）；
//   - Redis key 前缀 a2a:rl:（与 MCP 域限流隔离，独立键空间）；
//   - 精确键优先，未命中回退通配键（限流回退方向是"更严"，与 ACL 的
//     "具体 skill 不回退通配"相反）；
//   - 429 + Retry-After（数据面 proxy.go 既有钩子发出）；
//   - 缺省不限流：无规则命中即放行（与 MCP 域"未命中该 rule_item 直接跳过"口径一致）。
//
// 与 MCP 域限流（gateway-core/internal/ratelimit）的关系：独立策略域（R-6），
// 不复用其 Scope/Rule 模型与 Higress 插件编译路径——本引擎是 a2aproxy 进程内
// 治理，自建规则/计数/键空间。

// A2ARLRedisPrefix 是 A2A 复合限流计数在 Redis 中的键前缀（与 MCP 域隔离）。
const A2ARLRedisPrefix = "a2a:rl:"

// A2ARateLimitActionLimit 是限流动作取值（MVP 仅 "limit"；保留字段便于扩展）。
const A2ARateLimitActionLimit = "limit"

// RateLimitRule is one A2A composite rate-limit rule.
//
// The zero value is not a valid rule: Tenant, Agent are required; Skill may
// be the wildcard "*". RPM is the request budget per fixed window
// (WindowSeconds, default 60s — RPM 语义同族).
type RateLimitRule struct {
	// Tenant is the security tenant the rule applies to.
	Tenant string `json:"tenant"`
	// Agent is the agent name the rule applies to.
	Agent string `json:"agent"`
	// Skill is the skill the rule limits; "*" is the wildcard (skill
	// unobtainable or fallback bucket for the agent).
	Skill string `json:"skill"`
	// RPM is the request budget per fixed window.
	RPM int `json:"rpm"`
	// WindowSeconds is the fixed window length; 0 → 60s (RPM 语义同族).
	WindowSeconds int `json:"window_seconds,omitempty"`
	// Action is reserved ("limit"); empty defaults to limit.
	Action string `json:"action,omitempty"`
	// Description is an operator-facing note (not used for decisions).
	Description string `json:"description,omitempty"`
}

// RateLimitTable is a versioned set of A2A composite rate-limit rules.
//
// The table is the control-plane source of truth and is distributed to the
// data plane like the ACL table (same pull channel, separate domain).
type RateLimitTable struct {
	Version   int             `json:"version"`
	IssuedAt  string          `json:"issued_at"`
	Rules     []RateLimitRule `json:"rules"`
	Signature []byte          `json:"signature,omitempty"`
}

// NewRateLimitTable constructs an empty table.
func NewRateLimitTable(version int, now time.Time) *RateLimitTable {
	return &RateLimitTable{Version: version, IssuedAt: now.UTC().Format(time.RFC3339), Rules: []RateLimitRule{}}
}

// CanonicalBytes returns the canonical byte sequence (fixed field order)
// used for signing and verification.
func (t *RateLimitTable) CanonicalBytes() ([]byte, error) {
	payload := struct {
		Version  int             `json:"version"`
		IssuedAt string          `json:"issued_at"`
		Rules    []RateLimitRule `json:"rules"`
	}{t.Version, t.IssuedAt, t.Rules}
	return json.Marshal(payload)
}

// DecodeRateLimitTable strictly decodes a rate-limit table: unknown fields
// are rejected (same rationale as the ACL table — the policy channel must
// not be usable as a high-privilege configuration channel).
func DecodeRateLimitTable(data []byte) (*RateLimitTable, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var t RateLimitTable
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("a2aproxy: 限流表解码失败（含未知字段或格式错误）: %w", err)
	}
	return &t, nil
}

// Validate validates the table (table level plus every rule).
func (t *RateLimitTable) Validate() error {
	if t == nil {
		return fmt.Errorf("a2aproxy: 限流表为空")
	}
	if t.Version <= 0 {
		return fmt.Errorf("a2aproxy: 限流表 version 非法: %d", t.Version)
	}
	seen := map[string]bool{}
	for i := range t.Rules {
		r := &t.Rules[i]
		if r.Tenant == "" {
			return fmt.Errorf("a2aproxy: 限流规则 #%d 缺 tenant", i)
		}
		if r.Agent == "" {
			return fmt.Errorf("a2aproxy: 限流规则 #%d 缺 agent", i)
		}
		if r.Skill != WildcardSkill && !aclSkillRE.MatchString(r.Skill) {
			return fmt.Errorf("a2aproxy: 限流规则 #%d 的 skill %q 非法", i, r.Skill)
		}
		if r.RPM <= 0 {
			return fmt.Errorf("a2aproxy: 限流规则 #%d 的 rpm 必须 > 0", i)
		}
		key := rlRuleID(r.Tenant, r.Agent, r.Skill)
		if seen[key] {
			return fmt.Errorf("a2aproxy: 限流规则重复 (tenant=%s agent=%s skill=%s)",
				r.Tenant, r.Agent, r.Skill)
		}
		seen[key] = true
	}
	return nil
}

// rlRuleID 规则标识（用于对齐差异与去重）：tenant/agent/skill。
func rlRuleID(tenant, agent, skill string) string {
	return tenant + "/" + agent + "/" + skill
}

// rlLPEncode length-prefix frames a string: uint32_be(len(s)) || s.
//
// Same family as F-6 §3.1 dedup key (LP(s)=uint32_be(len(s))||s). The frame
// removes any concatenation ambiguity between the three key components
// (tenant/agent/skill), so "a|b" and "a"|"b" can never collide.
func rlLPEncode(s string) []byte {
	b := make([]byte, 4+len(s))
	binary.BigEndian.PutUint32(b[:4], uint32(len(s)))
	copy(b[4:], s)
	return b
}

// rlKeyHex returns the printable composite key for a (tenant,agent,skill)
// tuple: length-prefix framing of the three components, hex-encoded.
//
// Skill "*" denotes the wildcard (skill unobtainable). The result is used
// both as the in-memory index key and as the suffix of the Redis key
// (A2ARLRedisPrefix + rlKeyHex).
func rlKeyHex(tenant, agent, skill string) string {
	var b []byte
	b = append(b, rlLPEncode(tenant)...)
	b = append(b, rlLPEncode(agent)...)
	b = append(b, rlLPEncode(skill)...)
	return hex.EncodeToString(b)
}

// rlWindowOf returns the fixed window for a rule (default 60s = RPM 同族).
func rlWindowOf(r *RateLimitRule) time.Duration {
	if r.WindowSeconds > 0 {
		return time.Duration(r.WindowSeconds) * time.Second
	}
	return 60 * time.Second
}

// RateLimitEngine evaluates A2A composite rate-limit rules for the data
// plane. It implements the Limiter interface (acl.go) via Allow.
//
// The engine is safe for concurrent use: the table is swapped atomically and
// readers never mutate it.
type RateLimitEngine struct {
	mu       sync.RWMutex
	table    *RateLimitTable
	exact    map[string]*RateLimitRule // key = rlKeyHex(tenant,agent,skill), skill != "*"
	wildcard map[string]*RateLimitRule // skill == "*"
	counter  rlCounter

	// T-5：最近一次决策命中的键范围（a2a_rate_limit_decisions_total.scope）。
	// 独立互斥锁，避免观测写入与表替换/查表互相串行。
	scopeMu   sync.Mutex
	lastScope string
}

// NewRateLimitEngine constructs an engine with an empty (no-limit) table,
// backed by the in-memory fixed-window counter (dev/no-Redis mode).
func NewRateLimitEngine() *RateLimitEngine {
	e := &RateLimitEngine{counter: newRLMemCounter()}
	e.replace(&RateLimitTable{Version: 0, Rules: []RateLimitRule{}})
	return e
}

// NewRateLimitEngineWithCounter constructs an engine with a custom counter
// backend (e.g. the Redis backend). Used when Redis is available for shared
// counting across data-plane replicas.
func NewRateLimitEngineWithCounter(c rlCounter) *RateLimitEngine {
	if c == nil {
		c = newRLMemCounter()
	}
	e := &RateLimitEngine{counter: c}
	e.replace(&RateLimitTable{Version: 0, Rules: []RateLimitRule{}})
	return e
}

// Replace swaps in a new table version (called on policy distribution).
//
// A nil or invalid table leaves the previous table in place: a broken
// distribution must not silently open or close the throttle unexpectedly.
func (e *RateLimitEngine) Replace(t *RateLimitTable) error {
	if t == nil {
		return fmt.Errorf("a2aproxy: 限流表为空")
	}
	if err := t.Validate(); err != nil {
		return err
	}
	e.replace(t)
	return nil
}

// replace rebuilds the indexes and swaps the table in.
func (e *RateLimitEngine) replace(t *RateLimitTable) {
	exact := map[string]*RateLimitRule{}
	wildcard := map[string]*RateLimitRule{}
	for i := range t.Rules {
		r := t.Rules[i]
		rule := r
		if r.Skill == WildcardSkill {
			wildcard[rlKeyHex(r.Tenant, r.Agent, WildcardSkill)] = &rule
			continue
		}
		exact[rlKeyHex(r.Tenant, r.Agent, r.Skill)] = &rule
	}
	e.mu.Lock()
	e.table = t
	e.exact = exact
	e.wildcard = wildcard
	e.mu.Unlock()
}

// Version returns the current table version (0 = empty table).
func (e *RateLimitEngine) Version() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.table == nil {
		return 0
	}
	return e.table.Version
}

// RuleCount returns the number of indexed rules.
func (e *RateLimitEngine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.exact) + len(e.wildcard)
}

// lookupLocked resolves the matched rule for a request.
//
// Precedence (frozen §2.4 限流行 + T-3a 裁决):
//
//  1. exact (tenant,agent,skill) rule wins when a concrete skill is given;
//  2. otherwise the (tenant,agent,*) wildcard rule applies — this covers
//     both the skill-unobtainable case ("*") AND a concrete skill that has
//     no exact rule (fallback to the wildcard bucket is the "stricter"
//     direction for quota protection);
//  3. with no rule at all the call is unlimited (default no-limit).
//
// Note: this is the inverse of the ACL engine, where a concrete skill never
// falls back to the wildcard (the wildcard is the "skill unobtainable" case
// only). For rate limiting, falling back to the wildcard bucket is correct
// because it is a stricter (lower) quota, not a looser one.
func (e *RateLimitEngine) lookupLocked(tenant, agent, skill string) *RateLimitRule {
	sk := skill
	if sk == "" {
		sk = WildcardSkill
	}
	if sk != WildcardSkill {
		if r, ok := e.exact[rlKeyHex(tenant, agent, sk)]; ok {
			return r
		}
	}
	if r, ok := e.wildcard[rlKeyHex(tenant, agent, WildcardSkill)]; ok {
		return r
	}
	return nil
}

// Allow implements the Limiter interface.
//
// Returns (retryAfter, nil). retryAfter > 0 means "reject with HTTP 429 +
// Retry-After". A nil error with retryAfter == 0 means the request is
// allowed. On counter backend failure the engine fails OPEN (allows) to
// avoid a data-plane outage — rate limiting is an availability-protective
// measure, not a security-deny control (unlike ACL).
func (e *RateLimitEngine) Allow(tenant, agent, skill string) (int, error) {
	if tenant == "" || agent == "" {
		// Cannot scope without tenant/agent: pass through (no limit).
		e.setScope(RateLimitScopeNone)
		return 0, nil
	}
	e.mu.RLock()
	rule := e.lookupLocked(tenant, agent, skill)
	c := e.counter
	e.mu.RUnlock()

	if rule == nil {
		// 缺省不限流：无规则命中即放行。
		e.setScope(RateLimitScopeNone)
		return 0, nil
	}
	if rule.Skill == WildcardSkill {
		e.setScope(RateLimitScopeWildcard)
	} else {
		e.setScope(RateLimitScopeExact)
	}

	// Count under the matched rule's key (exact or wildcard granularity).
	ckey := rlKeyHex(tenant, agent, rule.Skill)
	allowed, retryAfter := c.allow(context.Background(), ckey, rule.RPM, rlWindowOf(rule))
	if allowed {
		return 0, nil
	}
	return retryAfter, nil
}

// setScope 记录本次决策命中的键范围（T-5；观测用途，失败无副作用）。
func (e *RateLimitEngine) setScope(scope string) {
	e.scopeMu.Lock()
	e.lastScope = scope
	e.scopeMu.Unlock()
}

// LastRateLimitScope implements RateLimitScopeObserver (T-5)：返回最近一次 Allow
// 命中的键范围（精确键 / 通配回退 / 无规则）。并发下为「最近一次」语义，仅用于观测归因，
// 不参与任何协议判定。
func (e *RateLimitEngine) LastRateLimitScope() string {
	e.scopeMu.Lock()
	defer e.scopeMu.Unlock()
	if e.lastScope == "" {
		return RateLimitScopeUnknown
	}
	return e.lastScope
}

// SortRateLimitRules sorts rules deterministically (tenant, agent, skill)
// so that canonical bytes are stable across control-plane replicas.
func SortRateLimitRules(rules []RateLimitRule) {
	sort.SliceStable(rules, func(i, j int) bool {
		a, b := rules[i], rules[j]
		if a.Tenant != b.Tenant {
			return a.Tenant < b.Tenant
		}
		if a.Agent != b.Agent {
			return a.Agent < b.Agent
		}
		return a.Skill < b.Skill
	})
}

// RateLimitSigner signs and verifies A2A rate-limit tables (HMAC over
// CanonicalBytes). Same family as ACLSigner: the control plane signs the
// table with the shared K_rx key and the data plane verifies it before
// replacing the live policy. The A2A rate-limit domain keeps its own key
// namespace ("ratelimit" vs the ACL table) but shares the distribution
// channel and key material (frozen checklist §2.4: independent policy
// domain, not merged with MCP).
type RateLimitSigner struct {
	key []byte
}

// NewRateLimitSigner constructs a signer; the key must be at least 32 bytes.
func NewRateLimitSigner(key []byte) (*RateLimitSigner, error) {
	if len(key) < 32 {
		return nil, fmt.Errorf("a2aproxy: 限流表签名密钥长度不足（%d < 32）", len(key))
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &RateLimitSigner{key: k}, nil
}

// SignTable signs the rate-limit table and writes the Signature field.
func (s *RateLimitSigner) SignTable(t *RateLimitTable) error {
	canon, err := t.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("a2aproxy: 限流表编码失败: %w", err)
	}
	t.Signature = aclCryptoProvider.HMAC(s.key, canon)
	return nil
}

// VerifyTable verifies the rate-limit table signature.
func (s *RateLimitSigner) VerifyTable(t *RateLimitTable) bool {
	if t == nil {
		return false
	}
	canon, err := t.CanonicalBytes()
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(t.Signature, aclCryptoProvider.HMAC(s.key, canon)) == 1
}

// VerifyRateLimitTableBytes verifies a signed rate-limit table received from
// the control plane: strict decode (unknown fields rejected) + signature
// check + validation. A table that fails any step must not replace the live
// policy.
func (s *RateLimitSigner) VerifyRateLimitTableBytes(data []byte) (*RateLimitTable, error) {
	t, err := DecodeRateLimitTable(data)
	if err != nil {
		return nil, err
	}
	if !s.VerifyTable(t) {
		return nil, fmt.Errorf("a2aproxy: 限流表签名校验失败")
	}
	if err := t.Validate(); err != nil {
		return nil, err
	}
	return t, nil
}
