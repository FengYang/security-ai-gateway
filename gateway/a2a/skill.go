package a2a

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	sdk "github.com/a2aproject/a2a-go/v2/a2a"
)

// SkillSource is the carrier that supplied the effective skill.
type SkillSource string

const (
	SkillSourceHeader          SkillSource = "header"
	SkillSourceRequestMetadata SkillSource = "request_metadata"
	SkillSourceMessageMetadata SkillSource = "message_metadata"
	SkillSourceNone            SkillSource = "none"
)

var skillIDRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)

// Skill is the normalized governance skill.
type Skill struct {
	Name   string
	Source SkillSource
}

// ExtractSkill implements the frozen carrier precedence:
// X-GA-A2A-Skill > params.metadata["ga.skill"] > params.message.metadata["ga.skill"].
//
// Multiple carriers with different values fail closed with -32602
// skill_conflict. If no carrier is present the wildcard skill "*" is returned
// with source "none"; the caller must still apply the agent-level ACL.
func ExtractSkill(header string, params json.RawMessage) (Skill, *RPCError) {
	if len(bytes.TrimSpace(params)) == 0 {
		params = json.RawMessage("{}")
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(params, &top); err != nil || top == nil {
		return Skill{}, NewRPCError(CodeInvalidParams, ReasonInvalidParams)
	}

	requestSkill, requestOK, rpcErr := metadataSkill(top["metadata"])
	if rpcErr != nil {
		return Skill{}, rpcErr
	}
	messageSkill, messageOK := "", false
	if rawMessage, exists := top["message"]; exists {
		var message map[string]json.RawMessage
		if err := json.Unmarshal(rawMessage, &message); err != nil || message == nil {
			return Skill{}, NewRPCError(CodeInvalidParams, ReasonInvalidParams)
		}
		var msgErr *RPCError
		messageSkill, messageOK, msgErr = metadataSkill(message["metadata"])
		if msgErr != nil {
			return Skill{}, msgErr
		}
	}

	type candidate struct {
		value  string
		source SkillSource
	}
	candidates := make([]candidate, 0, 3)
	if v := strings.TrimSpace(header); v != "" {
		if !skillIDRE.MatchString(v) {
			return Skill{}, NewRPCError(CodeInvalidParams, ReasonInvalidSkill)
		}
		candidates = append(candidates, candidate{v, SkillSourceHeader})
	}
	if requestOK {
		if !skillIDRE.MatchString(requestSkill) {
			return Skill{}, NewRPCError(CodeInvalidParams, ReasonInvalidSkill)
		}
		candidates = append(candidates, candidate{requestSkill, SkillSourceRequestMetadata})
	}
	if messageOK {
		if !skillIDRE.MatchString(messageSkill) {
			return Skill{}, NewRPCError(CodeInvalidParams, ReasonInvalidSkill)
		}
		candidates = append(candidates, candidate{messageSkill, SkillSourceMessageMetadata})
	}

	if len(candidates) == 0 {
		return Skill{Name: "*", Source: SkillSourceNone}, nil
	}
	first := candidates[0]
	for _, c := range candidates[1:] {
		if c.value != first.value {
			return Skill{}, NewRPCError(CodeInvalidParams, ReasonSkillConflict)
		}
	}
	return Skill{Name: first.value, Source: first.source}, nil
}

// metadataSkill reads metadata["ga.skill"]. A non-object metadata value or a
// non-string skill value is invalid params. A null/absent metadata object is
// simply absent.
func metadataSkill(raw json.RawMessage) (string, bool, *RPCError) {
	if len(bytes.TrimSpace(raw)) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return "", false, nil
	}
	var metadata map[string]json.RawMessage
	if err := json.Unmarshal(raw, &metadata); err != nil || metadata == nil {
		return "", false, NewRPCError(CodeInvalidParams, ReasonInvalidParams)
	}
	rawSkill, exists := metadata["ga.skill"]
	if !exists || len(bytes.TrimSpace(rawSkill)) == 0 || bytes.Equal(bytes.TrimSpace(rawSkill), []byte("null")) {
		return "", false, nil
	}
	var skill string
	if err := json.Unmarshal(rawSkill, &skill); err != nil {
		return "", false, NewRPCError(CodeInvalidParams, ReasonInvalidSkill)
	}
	return skill, true, nil
}

// ValidateSkillForCard enforces fail-closed registration: a concrete skill
// must exist in the registered card. The wildcard "*" means "no skill
// supplied" and is resolved by the caller's agent-level rules.
func ValidateSkillForCard(skill Skill, card *sdk.AgentCard) *RPCError {
	if skill.Name == "" || skill.Name == "*" {
		return nil
	}
	if card == nil {
		return NewRPCError(CodeUnauthorized, ReasonUnknownSkill)
	}
	for i := range card.Skills {
		if card.Skills[i].ID == skill.Name {
			return nil
		}
	}
	return NewRPCError(CodeUnauthorized, ReasonUnknownSkill)
}
