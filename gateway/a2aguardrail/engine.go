// Package a2aguardrail implements the L1 deterministic guardrail used by the
// A2A data plane. It reuses the existing output-guard policy assets
// (categories + keywords + regex) without introducing a new classifier.
package a2aguardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"security-ai-gateway/gateway/a2aguardrail/protocol"
)

// DefaultMaxBytes is the per-request inspection cap. Oversized content is
// denied rather than silently skipped.
const DefaultMaxBytes = 1 << 20 // 1 MiB

// Category is one entry of policy/categories.json.
type Category struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	Family        string `json:"family"`
	DefaultLevel  string `json:"default_level"`
	DefaultAction string `json:"default_action"`
}

type manifest struct {
	PolicyVersion string `json:"policy_version"`
}

type policyFile struct {
	SchemaVersion string       `json:"schema_version"`
	Category      string       `json:"category"`
	Version       string       `json:"version"`
	Level         string       `json:"level"`
	Rules         []policyRule `json:"rules"`
}

type policyRule struct {
	ID        string  `json:"id"`
	Keyword   string  `json:"keyword"`
	Type      string  `json:"type"`
	Weight    float64 `json:"weight"`
	Normalize string  `json:"normalize"`
}

// compiledRule is an immutable rule loaded at startup.
type compiledRule struct {
	category  string
	id        string
	level     string
	action    protocol.Action
	typ       string
	normalize string
	keyword   string // normalized for contains
	re        *regexp.Regexp
}

// Status is the non-sensitive engine snapshot exposed by /v1/policy.
type Status struct {
	PolicyVersion string `json:"policy_version"`
	Rules         int    `json:"rules"`
	ActiveRules   int    `json:"active_rules"`
	Categories    int    `json:"categories"`
	MaxBytes      int    `json:"max_bytes"`
}

// Engine is an immutable policy engine. It is safe for concurrent use.
type Engine struct {
	policyVersion string
	rules         []compiledRule
	categories    map[string]Category
	maxBytes      int
	status        Status
}

// NewEngine loads categories.json plus keywords/*.json and regex/*.json from
// policyDir. A malformed policy is a startup error (fail-closed).
func NewEngine(policyDir string, maxBytes int) (*Engine, error) {
	if strings.TrimSpace(policyDir) == "" {
		return nil, fmt.Errorf("a2aguardrail: policy dir is required")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}

	catsRaw, err := os.ReadFile(filepath.Join(policyDir, "categories.json"))
	if err != nil {
		return nil, fmt.Errorf("a2aguardrail: read categories: %w", err)
	}
	var cats []Category
	if err := json.Unmarshal(catsRaw, &cats); err != nil {
		return nil, fmt.Errorf("a2aguardrail: decode categories: %w", err)
	}
	if len(cats) == 0 {
		return nil, fmt.Errorf("a2aguardrail: empty categories.json")
	}
	catMap := make(map[string]Category, len(cats))
	for _, c := range cats {
		if c.ID == "" {
			return nil, fmt.Errorf("a2aguardrail: category with empty id")
		}
		if _, dup := catMap[c.ID]; dup {
			return nil, fmt.Errorf("a2aguardrail: duplicate category %q", c.ID)
		}
		catMap[c.ID] = c
	}

	version := "unknown"
	if raw, err := os.ReadFile(filepath.Join(policyDir, "manifest.json")); err == nil {
		var m manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("a2aguardrail: decode manifest: %w", err)
		}
		if m.PolicyVersion != "" {
			version = m.PolicyVersion
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("a2aguardrail: read manifest: %w", err)
	}

	e := &Engine{
		policyVersion: version,
		categories:    catMap,
		maxBytes:      maxBytes,
	}
	totalRules := 0
	for _, sub := range []string{"keywords", "regex"} {
		dir := filepath.Join(policyDir, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, fmt.Errorf("a2aguardrail: read %s: %w", sub, err)
		}
		for _, ent := range entries {
			if ent.IsDir() || !strings.EqualFold(filepath.Ext(ent.Name()), ".json") {
				continue
			}
			path := filepath.Join(dir, ent.Name())
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, fmt.Errorf("a2aguardrail: read %s: %w", path, err)
			}
			var pf policyFile
			if err := json.Unmarshal(raw, &pf); err != nil {
				return nil, fmt.Errorf("a2aguardrail: decode %s: %w", path, err)
			}
			if pf.Category == "" {
				return nil, fmt.Errorf("a2aguardrail: %s has empty category", path)
			}
			cat, ok := catMap[pf.Category]
			if !ok {
				return nil, fmt.Errorf("a2aguardrail: %s references unknown category %q", path, pf.Category)
			}
			action, err := categoryAction(cat.DefaultAction)
			if err != nil {
				return nil, fmt.Errorf("a2aguardrail: category %s: %w", cat.ID, err)
			}
			level := cat.DefaultLevel
			if level == "" {
				level = pf.Level
			}
			if level == "" {
				level = "unknown"
			}
			for i, r := range pf.Rules {
				totalRules++
				if strings.TrimSpace(r.Keyword) == "" {
					return nil, fmt.Errorf("a2aguardrail: %s rule #%d has empty keyword", path, i)
				}
				typ := strings.ToLower(strings.TrimSpace(r.Type))
				if typ == "" {
					typ = "contains"
				}
				if typ != "contains" && typ != "regex" {
					return nil, fmt.Errorf("a2aguardrail: %s rule #%d has unsupported type %q", path, i, r.Type)
				}
				norm := strings.ToLower(strings.TrimSpace(r.Normalize))
				switch norm {
				case "", "fold", "compact":
				default:
					return nil, fmt.Errorf("a2aguardrail: %s rule #%d has unsupported normalize %q", path, i, r.Normalize)
				}
				// flag/pass rules are loaded for policy accounting but do not
				// change the data-plane decision; skipping them keeps the hot
				// path small while preserving the existing policy semantics.
				if action == protocol.ActionAllow {
					continue
				}
				cr := compiledRule{
					category:  cat.ID,
					id:        r.ID,
					level:     level,
					action:    action,
					typ:       typ,
					normalize: norm,
				}
				if cr.id == "" {
					cr.id = fmt.Sprintf("%s-%d", cat.ID, i)
				}
				if typ == "contains" {
					cr.keyword = normalizeText(norm, r.Keyword)
				} else {
					pattern := r.Keyword
					if norm == "fold" {
						pattern = "(?i:" + pattern + ")"
					}
					re, err := regexp.Compile(pattern)
					if err != nil {
						return nil, fmt.Errorf("a2aguardrail: %s rule %s compile: %w", path, cr.id, err)
					}
					cr.re = re
				}
				e.rules = append(e.rules, cr)
			}
		}
	}
	if totalRules == 0 {
		return nil, fmt.Errorf("a2aguardrail: no policy rules loaded")
	}
	e.status = Status{
		PolicyVersion: version,
		Rules:         totalRules,
		ActiveRules:   len(e.rules),
		Categories:    len(catMap),
		MaxBytes:      maxBytes,
	}
	return e, nil
}

func categoryAction(raw string) (protocol.Action, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "block":
		return protocol.ActionDeny, nil
	case "mask", "redact":
		return protocol.ActionRedact, nil
	case "flag", "pass", "allow":
		return protocol.ActionAllow, nil
	default:
		return "", fmt.Errorf("unknown default_action %q", raw)
	}
}

// Status returns a copy of the non-sensitive engine status.
func (e *Engine) Status() Status {
	if e == nil {
		return Status{}
	}
	return e.status
}

// Check evaluates all active rules over the request parts. A block hit wins
// over a mask hit; the returned reason contains rule identifiers only, never
// the matched text (R-2).
func (e *Engine) Check(ctx context.Context, req protocol.Request) (protocol.Response, error) {
	if e == nil {
		return protocol.Response{}, fmt.Errorf("a2aguardrail: nil engine")
	}
	if err := ctx.Err(); err != nil {
		return protocol.Response{}, err
	}
	chunks, total := collectChunks(req.Parts)
	if total > e.maxBytes {
		return protocol.Response{
			Action: protocol.ActionDeny,
			Tier:   "limit",
			Reason: "content_too_large",
		}, nil
	}

	var redact *compiledRule
	for _, chunk := range chunks {
		if chunk == "" {
			continue
		}
		raw := normalizeWidth(chunk)
		fold := strings.ToLower(raw)
		compact := compactText(raw)
		for i := range e.rules {
			if err := ctx.Err(); err != nil {
				return protocol.Response{}, err
			}
			r := &e.rules[i]
			hay := raw
			switch r.normalize {
			case "fold":
				hay = fold
			case "compact":
				hay = compact
			}
			var hit bool
			if r.typ == "contains" {
				hit = strings.Contains(hay, r.keyword)
			} else if r.re != nil {
				hit = r.re.MatchString(hay)
			}
			if !hit {
				continue
			}
			switch r.action {
			case protocol.ActionDeny:
				return protocol.Response{
					Action: protocol.ActionDeny,
					Tier:   r.level,
					Reason: "category=" + r.category + ";rule=" + r.id,
				}, nil
			case protocol.ActionRedact:
				if redact == nil {
					redact = r
				}
			}
		}
	}
	if redact != nil {
		return protocol.Response{
			Action: protocol.ActionRedact,
			Tier:   redact.level,
			Reason: "category=" + redact.category + ";rule=" + redact.id,
		}, nil
	}
	return protocol.Response{Action: protocol.ActionAllow}, nil
}

// collectChunks flattens the inspectable content of all parts. File metadata
// is always inspected; file bytes are inspected only when valid UTF-8. Binary
// payloads are not decoded by the L1 rules.
func collectChunks(parts []protocol.Part) ([]string, int) {
	out := make([]string, 0, len(parts))
	total := 0
	add := func(s string) {
		if s == "" {
			return
		}
		total += len(s)
		out = append(out, s)
	}
	for _, p := range parts {
		switch p.Kind {
		case protocol.PartKindText:
			add(p.Text)
		case protocol.PartKindFile:
			if p.File != nil {
				add(p.File.Name)
				add(p.File.URI)
				if len(p.File.Bytes) > 0 && utf8.Valid(p.File.Bytes) {
					add(string(p.File.Bytes))
				}
			}
		case protocol.PartKindData:
			add(string(p.Data))
		default:
			// Be permissive for callers that omit kind but set text/data.
			add(p.Text)
			add(string(p.Data))
		}
	}
	return out, total
}

// normalizeText applies the policy-level normalization to a rule literal.
func normalizeText(norm, s string) string {
	s = normalizeWidth(s)
	switch norm {
	case "fold":
		return strings.ToLower(s)
	case "compact":
		return compactText(s)
	default:
		return s
	}
}

// normalizeWidth converts full-width ASCII letters/digits and ideographic
// spaces to their half-width forms, matching the existing output-guard
// normalization behavior.
func normalizeWidth(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 0xFF10 && r <= 0xFF19:
			b.WriteRune(r - 0xFF10 + '0')
		case r >= 0xFF21 && r <= 0xFF3A:
			b.WriteRune(r - 0xFF21 + 'A')
		case r >= 0xFF41 && r <= 0xFF5A:
			b.WriteRune(r - 0xFF41 + 'a')
		case r == 0x3000:
			b.WriteRune(' ')
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// compactText removes whitespace and hyphens, matching the PII normalization
// used by the existing policy rules.
func compactText(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r', '-':
			return -1
		}
		return r
	}, s)
}
