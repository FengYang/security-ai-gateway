// Package ratelimit 控制面限流/预算策略模型与校验（Phase 1 门禁 #7 / 设计 v1.1 §3 §9-S1）。
//
// 职责（S1 范围）：数据模型、**严格字段白名单**解码、校验、版本与防回滚。
// 不含（后续步）：签发/验签与下发接口（S2）、编译为 cluster-key-rate-limit 配置（S2）、
// TEE 侧预算下发（S3）。本包为纯逻辑，无 I/O，便于单测。
//
// 与 internal/route 同构：CanonicalBytes 固定字段顺序（两侧 marshal 必须一致）。
package ratelimit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Kind 策略类型：决定治理语义与告警级别（设计 §3）。
type Kind string

const (
	// KindRate 体验保护（RPM/TPM）：误杀伤可用性。
	KindRate Kind = "rate"
	// KindBudget 成本保护（周期预算）：超支伤成本。
	KindBudget Kind = "budget"
)

// Scope 策略作用域。
type Scope string

const (
	ScopeTenant Scope = "tenant"
	ScopeAPIKey Scope = "api_key"
	ScopeModel  Scope = "model"
	ScopeGlobal Scope = "global"
)

// Action 命中策略时的动作。
type Action string

const (
	// ActionReject 拒绝（429）。
	ActionReject Action = "reject"
	// ActionShadow 影子：只计数并落审计 would_reject，不拒绝。
	ActionShadow Action = "shadow"
)

// 防御性上限：防止误配极端值导致"全量 429"或计数溢出（系统边界校验）。
const (
	maxRPM              = 1_000_000         // 每分钟请求数上限
	maxTPM              = 1_000_000_000     // 每分钟 token 上限
	maxDailyBudgetToken = 1_000_000_000_000 // 日预算上限
	maxBurstMultiplier  = 100
)

// nameRE 标识字符集：租户名 / key-auth 消费者名 / 规则 id（不含明文凭据的合法字符面）。
var nameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// fingerprintRE 审计辅助指纹：SHA-256 前 8 位十六进制。
var fingerprintRE = regexp.MustCompile(`^[0-9a-f]{8}$`)

// Rule 一条限流/预算策略（字段与设计 v1.1 §3 一致）。
type Rule struct {
	ID                string `json:"id"`
	Kind              Kind   `json:"kind"`
	Scope             Scope  `json:"scope"`
	Target            string `json:"target"`
	TargetFingerprint string `json:"target_fingerprint,omitempty"`  // 审计辅助，不参与决策
	RPM               int64  `json:"rpm,omitempty"`                 // 执行点＝数据面
	TPM               int64  `json:"tpm,omitempty"`                 // 执行点＝tee-infer
	DailyBudgetTokens int64  `json:"daily_budget_tokens,omitempty"` // 执行点＝tee-infer（UTC+8 自然日）
	BurstMultiplier   int64  `json:"burst_multiplier,omitempty"`    // 仅 rate 有效
	Action            Action `json:"action"`
	Enabled           bool   `json:"enabled"`
}

// Table 限流/预算表（控制面为事实源，签名后经 pull 通道下发）。
type Table struct {
	Version  int    `json:"version"`
	IssuedAt string `json:"issued_at"` // RFC3339（设计 v1.1 §3）
	Rules    []Rule `json:"rules"`
}

// NewTable 构造空表（rules 由调用方填充）。
func NewTable(version int, now time.Time) *Table {
	return &Table{Version: version, IssuedAt: now.UTC().Format(time.RFC3339), Rules: []Rule{}}
}

// CanonicalBytes 生成规范字节序列（固定字段顺序），供后续签发/验签与两侧 marshal 一致。
func (t *Table) CanonicalBytes() ([]byte, error) {
	payload := struct {
		Version  int    `json:"version"`
		IssuedAt string `json:"issued_at"`
		Rules    []Rule `json:"rules"`
	}{t.Version, t.IssuedAt, t.Rules}
	return json.Marshal(payload)
}

// DecodeTable 严格解码限流表：**拒绝未知字段**。
//
// 这是"策略通道不得携带认证类配置"（设计 §4 最小权限）在解码层的落点：
// 任何非白名单字段（如 consumers/allow/ipRestriction/waf 等）一律解码失败，
// 使限流通道无法被当作高权通道使用。
func DecodeTable(data []byte) (*Table, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var t Table
	if err := dec.Decode(&t); err != nil {
		return nil, fmt.Errorf("ratelimit: 限流表解码失败（含未知字段或格式错误）: %w", err)
	}
	return &t, nil
}

// Validate 校验整表（表级 + 每条规则），返回首个错误。
func (t *Table) Validate() error {
	if t.Version <= 0 {
		return fmt.Errorf("ratelimit: version 必须为正整数，实际 %d", t.Version)
	}
	if _, err := time.Parse(time.RFC3339, t.IssuedAt); err != nil {
		return fmt.Errorf("ratelimit: issued_at 必须为 RFC3339，实际 %q", t.IssuedAt)
	}
	seen := make(map[string]struct{}, len(t.Rules))
	for i := range t.Rules {
		r := &t.Rules[i]
		if err := r.validate(); err != nil {
			return fmt.Errorf("ratelimit: 第 %d 条规则(%s): %w", i, r.ID, err)
		}
		key := string(r.Scope) + "\x00" + r.Target + "\x00" + string(r.Kind)
		if _, dup := seen[key]; dup {
			return fmt.Errorf("ratelimit: (scope=%s,target=%s,kind=%s) 重复", r.Scope, r.Target, r.Kind)
		}
		seen[key] = struct{}{}
	}
	return nil
}

// validate 单条规则校验。
func (r *Rule) validate() error {
	if !nameRE.MatchString(r.ID) {
		return fmt.Errorf("id 非法（须为 [A-Za-z0-9][A-Za-z0-9._-]{0,63}）")
	}
	switch r.Kind {
	case KindRate, KindBudget:
	default:
		return fmt.Errorf("kind 非法（须为 rate|budget），实际 %q", r.Kind)
	}
	switch r.Scope {
	case ScopeTenant, ScopeAPIKey, ScopeModel, ScopeGlobal:
	default:
		return fmt.Errorf("scope 非法（须为 tenant|api_key|model|global），实际 %q", r.Scope)
	}
	// target 语义：global 必须为空；其余必须为合法标识（防止 policy 表承载明文凭据）。
	if r.Scope == ScopeGlobal {
		if r.Target != "" {
			return fmt.Errorf("scope=global 时 target 必须为空，实际 %q", r.Target)
		}
	} else if !nameRE.MatchString(r.Target) {
		return fmt.Errorf("target 非法（scope=%s 时须为合法标识，且不得为明文凭据）", r.Scope)
	}
	if r.TargetFingerprint != "" && !fingerprintRE.MatchString(r.TargetFingerprint) {
		return fmt.Errorf("target_fingerprint 非法（须为 8 位小写十六进制）")
	}
	switch r.Action {
	case ActionReject, ActionShadow:
	default:
		return fmt.Errorf("action 非法（须为 reject|shadow），实际 %q", r.Action)
	}
	if r.RPM < 0 || r.TPM < 0 || r.DailyBudgetTokens < 0 || r.BurstMultiplier < 0 {
		return fmt.Errorf("阈值不得为负（rpm=%d tpm=%d budget=%d burst=%d）",
			r.RPM, r.TPM, r.DailyBudgetTokens, r.BurstMultiplier)
	}
	if r.RPM > maxRPM || r.TPM > maxTPM || r.DailyBudgetTokens > maxDailyBudgetToken {
		return fmt.Errorf("阈值超上限（rpm<=%d tpm<=%d budget<=%d）", maxRPM, maxTPM, maxDailyBudgetToken)
	}
	if r.BurstMultiplier > maxBurstMultiplier {
		return fmt.Errorf("burst_multiplier 超上限（<=%d）", maxBurstMultiplier)
	}

	// kind 语义分离：rate 只管 RPM/TPM；budget 只管日预算。混用即拒绝（避免"看着配了其实不执行"）。
	switch r.Kind {
	case KindRate:
		if r.RPM == 0 && r.TPM == 0 {
			return fmt.Errorf("kind=rate 时 rpm 与 tpm 至少一项 > 0")
		}
		if r.DailyBudgetTokens != 0 {
			return fmt.Errorf("kind=rate 不得设置 daily_budget_tokens（应使用 kind=budget）")
		}
	case KindBudget:
		if r.DailyBudgetTokens == 0 {
			return fmt.Errorf("kind=budget 时 daily_budget_tokens 必须 > 0")
		}
		if r.RPM != 0 || r.TPM != 0 || r.BurstMultiplier != 0 {
			return fmt.Errorf("kind=budget 不得设置 rpm/tpm/burst_multiplier（应使用 kind=rate）")
		}
	}
	return nil
}

// VersionDecision 版本判定结果。
type VersionDecision int

const (
	// VersionAccept 接受（新版本，可下发）。
	VersionAccept VersionDecision = iota
	// VersionStale 过期（低于当前版本，**拒绝下发**，防回滚）。
	VersionStale
	// VersionSame 同版本（视为无变化）。
	VersionSame
)

// CheckVersion 版本与防回滚判定（复用路由表规则：低版本一律拒绝）。
func CheckVersion(current, incoming int) VersionDecision {
	switch {
	case incoming < current:
		return VersionStale
	case incoming == current:
		return VersionSame
	default:
		return VersionAccept
	}
}

// Lookup 按 (scope,target,kind) 精确查找；未命中返回 nil（含 target 为空字符串的 global 规则）。
func (t *Table) Lookup(scope Scope, target string, kind Kind) *Rule {
	for i := range t.Rules {
		r := &t.Rules[i]
		if r.Scope == scope && r.Target == target && r.Kind == kind {
			return r
		}
	}
	return nil
}

// EffectiveTargetKey 返回用于比对/审计的目标键（global 归一为 "*"，避免空串歧义）。
func EffectiveTargetKey(r *Rule) string {
	if r.Scope == ScopeGlobal {
		return "*"
	}
	return strings.TrimSpace(r.Target)
}
