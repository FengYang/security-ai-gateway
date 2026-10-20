package a2a

import (
	"encoding/json"
	"testing"
)

func TestExtractSkillPrecedence(t *testing.T) {
	params := json.RawMessage(`{"metadata":{"ga.skill":"hello_world"},"message":{"metadata":{"ga.skill":"hello_world"}}}`)
	skill, err := ExtractSkill("hello_world", params)
	if err != nil {
		t.Fatalf("header: %v", err)
	}
	if skill.Name != "hello_world" || skill.Source != SkillSourceHeader {
		t.Fatalf("skill = %+v", skill)
	}

	skill, err = ExtractSkill("", params)
	if err != nil {
		t.Fatalf("request metadata: %v", err)
	}
	if skill.Name != "hello_world" || skill.Source != SkillSourceRequestMetadata {
		t.Fatalf("skill = %+v", skill)
	}

	skill, err = ExtractSkill("", json.RawMessage(`{"message":{"metadata":{"ga.skill":"hello_world"}}}`))
	if err != nil {
		t.Fatalf("message metadata: %v", err)
	}
	if skill.Name != "hello_world" || skill.Source != SkillSourceMessageMetadata {
		t.Fatalf("skill = %+v", skill)
	}
}

func TestExtractSkillWildcard(t *testing.T) {
	skill, err := ExtractSkill("", json.RawMessage(`{}`))
	if err != nil {
		t.Fatalf("ExtractSkill: %v", err)
	}
	if skill.Name != "*" || skill.Source != SkillSourceNone {
		t.Fatalf("skill = %+v", skill)
	}
}

func TestExtractSkillConflict(t *testing.T) {
	_, err := ExtractSkill("hello_world", json.RawMessage(`{"metadata":{"ga.skill":"other"}}`))
	rpc := assertRPCCode(t, err, CodeInvalidParams)
	if rpc.Reason != ReasonSkillConflict {
		t.Fatalf("reason = %q", rpc.Reason)
	}
}

func TestExtractSkillInvalid(t *testing.T) {
	_, err := ExtractSkill("bad skill", json.RawMessage(`{}`))
	rpc := assertRPCCode(t, err, CodeInvalidParams)
	if rpc.Reason != ReasonInvalidSkill {
		t.Fatalf("reason = %q", rpc.Reason)
	}
	_, err = ExtractSkill("", json.RawMessage(`{"metadata":{"ga.skill":""}}`))
	rpc = assertRPCCode(t, err, CodeInvalidParams)
	if rpc.Reason != ReasonInvalidSkill {
		t.Fatalf("empty metadata reason = %q", rpc.Reason)
	}
	_, err = ExtractSkill("", json.RawMessage(`{"metadata":{"ga.skill":1}}`))
	assertRPCCode(t, err, CodeInvalidParams)
}

func TestValidateSkillForCard(t *testing.T) {
	card := testCard()
	if err := ValidateSkillForCard(Skill{Name: "hello_world"}, card); err != nil {
		t.Fatalf("known skill: %v", err)
	}
	if err := ValidateSkillForCard(Skill{Name: "*"}, card); err != nil {
		t.Fatalf("wildcard: %v", err)
	}
	rpc := assertRPCCode(t, ValidateSkillForCard(Skill{Name: "other"}, card), CodeUnauthorized)
	if rpc.Reason != ReasonUnknownSkill {
		t.Fatalf("reason = %q", rpc.Reason)
	}
}
